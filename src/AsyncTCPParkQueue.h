// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright 2016-2026 Hristo Gochkov, Mathieu Carbou, Emil Muratov, Will Miles
//
// Shared TLS park/serve admission queue for both stacks.
//   - ESP8266         -> BearSSL stack (AsyncTCP fork, NO_SYS lwIP)
//   - ESP32/LIBRETINY -> mbedTLS stack (AsyncTCP ESP32Async base)
//
// MUST be included after the stack's lwIP headers (tcp_pcb / pbuf types).
// Only one stack compiles per target, so the file-scope statics below exist
// in exactly one translation unit. Items are drawn from a static pool to
// avoid malloc/free on the admit path, which runs under memory pressure.

#pragma once

struct pending_pcb {
  tcp_pcb *pcb;
  pbuf *pb;             // chained bytes buffered while parked (ClientHello + head)
  uint16_t pb_len;      // total bytes buffered; bounds heap used per slot
  uint32_t parked_ms;   // millis() when this conn was parked
  struct pending_pcb *next;
};

static struct pending_pcb pending_pool[SSL_PARKED_SLOTS];
static uint8_t pool_idx = 0;
static_assert(SSL_PARKED_SLOTS >= 1, "At least one parked slot required");

// A slot is FREE while its pcb == NULL. Every release path (shed, peer-close,
// error drain, promote) must clear p->pcb; park sites must pick a free slot.
// All park sites are guarded by (active < SSL_PARKED_SLOTS), so at least one
// slot is free and the scan always terminates with a hit.
static struct pending_pcb *park_alloc(void) {
  struct pending_pcb *s = NULL;
  for (uint8_t i = 0; i < SSL_PARKED_SLOTS; i++) {
    struct pending_pcb *cand = &pending_pool[pool_idx];
    pool_idx = (pool_idx + 1) % SSL_PARKED_SLOTS;
    if (cand->pcb == NULL) {
      s = cand;
      break;
    }
  }
  return s;
}

// Unlinks `p` from the singly-linked tracked/queued list pointed to by
// *headptr, fixing the head, middle and tail cases.
static void unlink_pending(struct pending_pcb **headptr, struct pending_pcb *p) {
  if (!headptr || !*headptr || !p) return;
  if (*headptr == p) {
    *headptr = p->next;
    return;
  }
  struct pending_pcb *cur = *headptr;
  while (cur->next && cur->next != p) {
    cur = cur->next;
  }
  if (cur->next) {
    cur->next = p->next;
  }
}

// RSTs a parked pcb: nulls its AsyncTCP callbacks, then aborts. Callbacks MUST
// be nulled BEFORE tcp_abort so its synchronous err callback cannot re-enter
// _error()/_s_error() and double-drain the queue. RST (not graceful close):
// a parked pcb never served a byte, so a graceful close would only sit it in
// lwIP TIME_WAIT for 2*MSL with its pbuf bank. Reader of the pcb-retrieval in
// every shed path: call AFTER unlink/slot bookkeeping is done (the abort's err
// callback sees a slot already freed, no double-drain).
static inline void shed_parked_pcb(tcp_pcb *pcb) {
  tcp_arg(pcb, NULL);
  tcp_recv(pcb, NULL);
  tcp_poll(pcb, NULL, 0);
  tcp_err(pcb, NULL);
  tcp_abort(pcb);
}

// Empties a whole queue's bookkeeping (pbufs only) WITHOUT touching the pcbs.
// Used by _error/_s_error (lwIP already freed the errored pcb) and teardown.
// Draws on the static pool, so no item free — slots are reused round-robin.
static inline void free_queued_items(struct pending_pcb **list, volatile int *count) {
  while (*list) {
    struct pending_pcb *p = *list;
    *list = p->next;
    if (p->pb) {
      pbuf_free(p->pb);
    }
    p->pcb = NULL;
    (*count)--;
  }
}

// Sheds a whole queue: RSTs each pcb (shed_parked_pcb), frees pbufs. Draws on
// the static pool, so no item free — slots are reused round-robin.
static int abort_queued_items(struct pending_pcb **list, volatile int *count) {
  int n = 0;
  while (*list) {
    struct pending_pcb *p = *list;
    *list = p->next;
    tcp_pcb *spcb = p->pcb;
    if (p->pb) {
      pbuf_free(p->pb);
    }
    p->pcb = NULL;
    (*count)--;
    if (spcb) {
      shed_parked_pcb(spcb);
    }
    n++;
  }
  return n;
}
