// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright 2016-2026 Hristo Gochkov, Mathieu Carbou, Emil Muratov, Will Miles
//
// Unified dual-stack AsyncTCP. TLS engine.
//   - ESP8266         -> BearSSL stack (AsyncTCP fork, NO_SYS lwIP)
//   - ESP32/LIBRETINY -> mbedTLS stack (AsyncTCP ESP32Async base)
// Selected at compile time via #if defined(ESP8266). Only one stack compiles per target.
#if defined(ESP8266)
// ===== begin BearSSL/ESP8266 AsyncTCPTLS.cpp (AsyncTCP) =====
/*
  BearSSL glue layer for ESP8266AsyncTCP — single combined TU

  This file provides the complete BearSSL bridge in ONE compilation unit:
    - the role-agnostic core (registry, per-connection state, engine pump) that
      is shared by both TLS clients and TLS servers,
    - the TLS-client-specific glue (x509, client engine init, tcp_ssl_new_client),
    - the TLS-server-specific glue (cert/private-key ctx, tcp_ssl_new_server,
      tcp_ssl_has_client / tcp_ssl_client_count).

  Each role block is guarded by its own macro so builds can trim either role.

  FULLY PATCHED & COMPATIBLE VERSION:
  - Uses the correct BearSSL API (`br_ssl_engine_set_buffers_bidi` with
    separate buffers) for full compatibility with ESP8266 Arduino Core versions.
  - Adds PROGMEM awareness to automatically handle certificates from flash,
    fixing LoadStoreError crashes.
  - Resolves incompatibility with older BearSSL PEM decoder APIs.
  - Includes robust NULL checks to prevent crashes from invalid arguments.
  - BearSSL calls use the ESP8266 StackThunk mechanism, swapping to a
    separate heap-allocated stack for crypto operations.
*/

#include "AsyncTCPTLS.h"

// When ASYNC_TCP_SSL_ENABLED is 0, this entire file compiles to nothing.
// This prevents BearSSL types from being linked into non-SSL builds, which
// would corrupt the heap memory layout on ESP8266's constrained DRAM.
#if ASYNC_TCP_SSL_ENABLED
#include "AsyncTCPLogging.h"

#include <StackThunk.h>
#include <ESP8266WiFi.h>  // ESP object (ESP.getFreeHeap) + core <BearSSLHelpers.h> -> complete BearSSL::PrivateKey (safe delete in ~BearSSL_SSL_CTX)
#include <bearssl/bearssl_pem.h>
#include <lwip/tcp.h>
#include <Schedule.h>  // schedule_function()

// Mapped to the ESP8266 core's stack thunks. The thunk_br_ssl_engine_* symbols
// are exported by the core's ESP8266WiFi BearSSLHelpers (libesp8266wifi.a), so
// they are merely declared extern here and never defined locally — defining them
// again via make_stack_thunk would clash with the core's copies in builds that
// also use WiFiClientSecureBearSSL. Declared in namespace BearSSL (extern "C",
// so the emitted symbol is the plain C thunk_* name).
namespace BearSSL {
extern "C" {
extern unsigned char *thunk_br_ssl_engine_recvapp_buf( const br_ssl_engine_context *cc, size_t *len);
extern void thunk_br_ssl_engine_recvapp_ack(br_ssl_engine_context *cc, size_t len);
extern unsigned char *thunk_br_ssl_engine_recvrec_buf( const br_ssl_engine_context *cc, size_t *len);
extern void thunk_br_ssl_engine_recvrec_ack(br_ssl_engine_context *cc, size_t len);
extern unsigned char *thunk_br_ssl_engine_sendapp_buf( const br_ssl_engine_context *cc, size_t *len);
extern void thunk_br_ssl_engine_sendapp_ack(br_ssl_engine_context *cc, size_t len);
extern unsigned char *thunk_br_ssl_engine_sendrec_buf( const br_ssl_engine_context *cc, size_t *len);
extern void thunk_br_ssl_engine_sendrec_ack(br_ssl_engine_context *cc, size_t len);
}
}

// Use thunked BearSSL engine functions — swaps to a heap-allocated stack
// for crypto operations, preventing stack overflow on ESP8266's 4KB CONT stack.
// The thunks also provide a larger working stack for ECDHE P-256 key generation.
#define br_ssl_engine_recvapp_ack  BearSSL::thunk_br_ssl_engine_recvapp_ack
#define br_ssl_engine_recvapp_buf  BearSSL::thunk_br_ssl_engine_recvapp_buf
#define br_ssl_engine_recvrec_ack  BearSSL::thunk_br_ssl_engine_recvrec_ack
#define br_ssl_engine_recvrec_buf  BearSSL::thunk_br_ssl_engine_recvrec_buf
#define br_ssl_engine_sendapp_ack  BearSSL::thunk_br_ssl_engine_sendapp_ack
#define br_ssl_engine_sendapp_buf  BearSSL::thunk_br_ssl_engine_sendapp_buf
#define br_ssl_engine_sendrec_ack  BearSSL::thunk_br_ssl_engine_sendrec_ack
#define br_ssl_engine_sendrec_buf  BearSSL::thunk_br_ssl_engine_sendrec_buf

BearSSL_SSL_CTX::~BearSSL_SSL_CTX() {
  for (auto& cert : chain_vector) {
    free(cert.data);
  }
  delete pk;
}

// Linked list of all active BearSSL connections
tcp_ssl_pcb* tcp_ssl_pcbs = nullptr;

// Helper to find an SSL connection's state from its lwIP pcb
tcp_ssl_pcb* find_ssl_pcb(struct tcp_pcb* pcb) {
  tcp_ssl_pcb* iter = tcp_ssl_pcbs;
  while (iter) {
    if (iter->tcp == pcb) {
      return iter;
    }
    iter = iter->next;
  }
  return nullptr;
}

// Shared between the client and server role TUs: allocate a tcp_ssl_pcb,
// zero its non-role fields, and allocate the in/out/recvrec buffers.
// Returns nullptr on allocation failure. The `tcp` and `is_server` fields are
// set here; the role-specific engine initialization happens after this returns.
tcp_ssl_pcb* tcp_ssl_alloc_pcb(struct tcp_pcb* pcb, bool is_server) {
  tcp_ssl_pcb* ssl_pcb = new (std::nothrow) tcp_ssl_pcb();
  if (!ssl_pcb) return nullptr;

  ssl_pcb->tcp = pcb;
  ssl_pcb->is_server = is_server;
#if ASYNC_TCP_SSL_ENABLE_CLIENT
  ssl_pcb->sc_client = nullptr;
#endif
#if ASYNC_TCP_SSL_ENABLE_SERVER
  ssl_pcb->sc_server = nullptr;
#endif
  ssl_pcb->handshake_done = false;
  ssl_pcb->sendrec_deferred = false;
  ssl_pcb->out_ring_next = 0;
  ssl_pcb->out_ring_pinned = 0;
  ssl_pcb->out_ring_acked = 0;
  ssl_pcb->hard_defer_start = 0;
  ssl_pcb->body_started = false;
  ssl_pcb->arg = nullptr;
  ssl_pcb->on_data = nullptr;
  ssl_pcb->on_handshake = nullptr;
  ssl_pcb->on_error = nullptr;
  ssl_pcb->in_buf_ptr = nullptr;
  ssl_pcb->out_buf_ptr = nullptr;
  ssl_pcb->in_len = 0;
  ssl_pcb->out_len = 0;
  ssl_pcb->inbuf = nullptr;
  ssl_pcb->outbuf = nullptr;
  ssl_pcb->recvrec_accum = nullptr;
  ssl_pcb->_slab = nullptr;
  ssl_pcb->recvrec_accum_len = 0;
  ssl_pcb->max_rec_len = 0;

  // ONE contiguous allocation for inbuf + record ring + accumulator. A single
  // ~8.5KB slab needs one big heap hole instead of three separate allocs, so
  // the admission BLOCK bar can guarantee the whole conn fits in one piece.
  ssl_pcb->recvrec_accum_cap = ASYNC_TCP_SSL_IN_BUFFER_SIZE;
  ssl_pcb->inbuf_cap = ASYNC_TCP_SSL_IN_BUFFER_SIZE;
  ssl_pcb->_slab = new (std::nothrow) unsigned char[ASYNC_TCP_SSL_BUFFER_SLAB];
  if (!ssl_pcb->_slab) {
    async_tcp_log_d("ALLOC FAIL: free heap=%u, need slab=%u (rank=%u)\n",
                    (unsigned)ESP.getFreeHeap(), (unsigned)ASYNC_TCP_SSL_BUFFER_SLAB,
                    (unsigned)(is_server ? 2 : 1));
    delete ssl_pcb;
    return nullptr;
  }
  ssl_pcb->inbuf = ssl_pcb->_slab;
  ssl_pcb->outbuf = ssl_pcb->_slab + ASYNC_TCP_SSL_IN_BUFFER_SIZE;
  ssl_pcb->recvrec_accum = ssl_pcb->_slab + ASYNC_TCP_SSL_IN_BUFFER_SIZE + ASYNC_TCP_SSL_OUT_BUFFER_REGION;
  for (uint8_t i = 0; i < ASYNC_TCP_SSL_RECORD_RING_SLOTS; i++) {
    ssl_pcb->out_ring[i] = ssl_pcb->outbuf + i * ASYNC_TCP_SSL_OUT_BUFFER_SIZE;
    ssl_pcb->out_ring_len[i] = 0;
  }
  async_tcp_log_d("ALLOC: free heap=%u rank=%u slab=%u\n", (unsigned)ESP.getFreeHeap(),
                  (unsigned)(is_server ? 2 : 1), (unsigned)ASYNC_TCP_SSL_BUFFER_SLAB);
  return ssl_pcb;
}

// Shared between the client and server role TUs: register a fully-initialized
// ssl_pcb on the global TLS connection list and take a StackThunk reference.
void tcp_ssl_register_pcb(tcp_ssl_pcb* ssl_pcb) {
  ssl_pcb->next = tcp_ssl_pcbs;
  tcp_ssl_pcbs = ssl_pcb;
  stack_thunk_add_ref();
}

// --- Internal Helper Functions for Parsing ---

struct CertParseCtx {
  std::vector<br_x509_certificate>* certs;
  unsigned char* buf;
  size_t len;
  bool error;
};

static void append_to_cert_vector(void* ctx, const void* data, size_t len) {
  CertParseCtx* pctx = (CertParseCtx*)ctx;
  if (pctx->error) return;

  unsigned char* new_buf = (unsigned char*)realloc(pctx->buf, pctx->len + len);
  if (!new_buf) {
    pctx->error = true;
    free(pctx->buf);
    pctx->buf = nullptr;
    return;
  }
  pctx->buf = new_buf;
  memcpy(pctx->buf + pctx->len, data, len);
  pctx->len += len;
}


// --- Public API Implementation ---

#if ASYNC_TCP_SSL_ENABLE_SERVER
size_t parse_certificates(const char* pem, std::vector<br_x509_certificate>& certs) {
  if (!pem) return 0;

  const unsigned char* data = (const unsigned char*)pem;
  size_t len = strlen(pem);
  async_tcp_log_i("[PARSE] len=%u\n", (unsigned)len);

  br_pem_decoder_context pc;
  br_pem_decoder_init(&pc);

  CertParseCtx pctx;
  pctx.certs = &certs;
  pctx.buf = nullptr;
  pctx.len = 0;
  pctx.error = false;

  br_pem_decoder_setdest(&pc, append_to_cert_vector, &pctx);

  bool in_cert_object = false;   // currently inside a "CERTIFICATE" object?

  size_t pushed = 0;
  for (;;) {
    bool made_progress = false;

    // Feed as much as the decoder accepts right now. br_pem_decoder_push()
    // returns 0 as long as an event (BEGIN_OBJ/END_OBJ) is still pending, so
    // feed and event-drain MUST be interleaved.
    size_t r = br_pem_decoder_push(&pc, data + pushed, len - pushed);
    pushed += r;
    if (r > 0) made_progress = true;

    // Drain every event queued by that push (BEGIN and/or END).
    for (;;) {
      if (pctx.error) {
        for (auto& cert : certs) free(cert.data);
        certs.clear();
        free(pctx.buf);
        return 0;
      }
      int event = br_pem_decoder_event(&pc);
      if (event == BR_PEM_BEGIN_OBJ) {
        in_cert_object = (strcmp(br_pem_decoder_name(&pc), "CERTIFICATE") == 0);
        free(pctx.buf);
        pctx.buf = nullptr;
        pctx.len = 0;
        made_progress = true;
      } else if (event == BR_PEM_END_OBJ) {
        if (in_cert_object && pctx.buf && pctx.len > 0) {
          certs.push_back({pctx.buf, pctx.len});
        } else {
          free(pctx.buf);
        }
        pctx.buf = nullptr;
        pctx.len = 0;
        in_cert_object = false;
        made_progress = true;
      } else {
        // event() == 0 (none pending) or BR_PEM_ERROR (-1): stop draining.
        break;
      }
    }

    if (pushed >= len) break;    // all input consumed
    if (!made_progress) break;   // stalled, no event and no progress -> done/error
  }

  // BearSSL decodes the body to the dest callback but, in this one-shot call
  // pattern, may never emit END_OBJ for the final object (observed: full cert
  // DER received, END_OBJ event never fired). Finalize any leftover buffer.
  if (in_cert_object && pctx.buf && pctx.len > 0) {
    certs.push_back({pctx.buf, pctx.len});
    pctx.buf = nullptr;
    pctx.len = 0;
  } else {
    free(pctx.buf);
  }

  async_tcp_log_i("[PARSE] returning %u certs\n", (unsigned)certs.size());
  return certs.size();
}
#endif  // ASYNC_TCP_SSL_ENABLE_SERVER


int tcp_ssl_free(struct tcp_pcb* pcb) {
  tcp_ssl_pcb* iter = tcp_ssl_pcbs;
  tcp_ssl_pcb* prev = nullptr;
  while (iter) {
    if (iter->tcp == pcb) {
      if (prev) {
        prev->next = iter->next;
      } else {
        tcp_ssl_pcbs = iter->next;
      }
      stack_thunk_del_ref();
      async_tcp_log_i("INREC-FINAL: max record len=%u, free heap=%u\n",
                      (unsigned)iter->max_rec_len, (unsigned)ESP.getFreeHeap());
#if ASYNC_TCP_SSL_ENABLE_CLIENT
      delete iter->insecure_x509;
#endif
      delete iter;
      async_tcp_log_d("FREE: free heap=%u\n", (unsigned)ESP.getFreeHeap());
      return 0;
    }
    prev = iter;
    iter = iter->next;
  }
  return -1;
}

// Graceful TLS close (best effort):
// Flush any buffered plaintext, drain a deferred SENDREC record, assemble a
// close_notify alert, and queue it to lwIP so the subsequent tcp_close() FINs
// only after it is transmitted. Returns the number of bytes queued for this
// close, 0 when nothing could be written (no ssl layer, window/memp starved,
// or the engine already closed). The caller proceeds to free the engine and
// tcp_close() regardless.
size_t tcp_ssl_close(struct tcp_pcb* pcb) {
  size_t pcb_written = 0;
  tcp_ssl_pcb* ssl_pcb = find_ssl_pcb(pcb);
  if (!ssl_pcb) return 0;
  br_ssl_engine_context* eng = tcp_ssl_engine(ssl_pcb);
  if (!eng) return 0;
  // Already closed or never opened: nothing to assemble.
  if (br_ssl_engine_current_state(eng) & BR_SSL_CLOSED) return 0;

  // Flush any buffered plaintext into a TLS record first, so the close_notify
  // below cannot cut trailing application data (a scheduled engine pass may
  // not have run yet when a response finishes and the connection is closed).
  if (br_ssl_engine_current_state(eng) & BR_SSL_SENDAPP) {
    br_ssl_engine_flush(eng, 0);
    size_t plen = 0;
    unsigned char* pbuf = br_ssl_engine_sendrec_buf(eng, &plen);
    if (pbuf && plen && plen <= ASYNC_TCP_SSL_OUT_BUFFER_SIZE) {
      if (tcp_write(pcb, pbuf, plen, TCP_WRITE_FLAG_COPY) != ERR_OK) {
        return pcb_written;  // record still pending — leave it (best effort)
      }
      br_ssl_engine_sendrec_ack(eng, plen);
      pcb_written += plen;
    }
  }

  // Drain any SENDREC record that was deferred earlier (tcp_write blocked on a
  // full window). It is still pending in the engine (not acked); if the window
  // has room now, push it before the close_notify so no response tail is cut.
  if (ssl_pcb->sendrec_deferred && (br_ssl_engine_current_state(eng) & BR_SSL_SENDREC)) {
    size_t plen = 0;
    unsigned char* pbuf = br_ssl_engine_sendrec_buf(eng, &plen);
    if (pbuf && plen && plen <= ASYNC_TCP_SSL_OUT_BUFFER_SIZE) {
      if (tcp_write(pcb, pbuf, plen, TCP_WRITE_FLAG_COPY) != ERR_OK) {
        return pcb_written;
      }
      br_ssl_engine_sendrec_ack(eng, plen);
      ssl_pcb->sendrec_deferred = false;
      ssl_pcb->hard_defer_start = 0;
      pcb_written += plen;
    }
  }

  br_ssl_engine_close(eng);
  size_t len = 0;
  unsigned char* buf = br_ssl_engine_sendrec_buf(eng, &len);
  if (!buf || len == 0 || len > ASYNC_TCP_SSL_OUT_BUFFER_SIZE) return pcb_written;
  if (tcp_write(pcb, buf, len, TCP_WRITE_FLAG_COPY) != ERR_OK) return pcb_written;
  br_ssl_engine_sendrec_ack(eng, len);
  pcb_written += len;
  tcp_output(pcb);
  return pcb_written;
}

// --- Internal Engine Logic ---

// Defer process_ssl_engine to loop() context via schedule_function.
// The BearSSL engine calls made from loop() run on the thunked stack
// (defined above) so crypto operations get a larger working stack than the
// ESP8266's 4KB CONT stack.
void schedule_ssl_engine(tcp_ssl_pcb* ssl_pcb) {
  schedule_function([ssl_pcb]() {
    for (tcp_ssl_pcb* iter = tcp_ssl_pcbs; iter; iter = iter->next) {
      if (iter == ssl_pcb) {
        process_ssl_engine(ssl_pcb);
        return;
      }
    }
  });
}

// Returns true if ssl_pcb is still a live member of tcp_ssl_pcbs.
// process_ssl_engine calls yield() which can re-enter the event loop; while
// yielding, the same connection (or another) may run
// _close() -> tcp_ssl_free() -> delete this ssl_pcb. On return from yield()
// the pointer would be dangling, so every yield() boundary must re-validate
// that the ssl_pcb is still registered before dereferencing it again.
static bool tcp_ssl_pcb_is_alive(tcp_ssl_pcb* ssl_pcb) {
  for (tcp_ssl_pcb* iter = tcp_ssl_pcbs; iter; iter = iter->next) {
    if (iter == ssl_pcb) return true;
  }
  return false;
}

void process_ssl_engine(tcp_ssl_pcb* ssl_pcb) {
  if (!ssl_pcb) return;

  br_ssl_engine_context* eng;
  eng = tcp_ssl_engine(ssl_pcb);

  // --- Feed accumulated data into BearSSL (runs in loop() context, safe to yield) ---
  size_t accum_len = ssl_pcb->recvrec_accum_len;

  if (accum_len > 0) {
    // MEASUREMENT: report the largest inbound TLS record ciphertext length we
    // see. Peek the header bytes (3-4 = big-endian length) of the first pending
    // record, but ONLY when the engine is at a fresh record-start boundary
    // (ixa==ixb==0) so we don't mis-read bytes mid-record. Records are logged
    // only on a new max, to avoid noise from the many small records of normal
    // page loads.
    if (accum_len >= 5 && eng->ixa == 0 && eng->ixb == 0) {
      size_t rlen = ((size_t)ssl_pcb->recvrec_accum[3] << 8) | ssl_pcb->recvrec_accum[4];
      if (rlen > ssl_pcb->max_rec_len) {
        ssl_pcb->max_rec_len = rlen;
        async_tcp_log_i("INREC: len=%u (ciphertext bytes for first pending record), "
                        "free heap=%u, accum=%u, mfln=%d\n",
                        (unsigned)rlen, (unsigned)ESP.getFreeHeap(), (unsigned)accum_len,
                        (int)br_ssl_engine_get_mfln_negotiated(eng));
      }
    }

    size_t consumed = 0;

    while (consumed < accum_len) {
      size_t available;
      unsigned char* buf = br_ssl_engine_recvrec_buf(eng, &available);

      if (available == 0) break;

      size_t to_feed = (accum_len - consumed < available) ?
                       (accum_len - consumed) : available;

      memcpy(buf, ssl_pcb->recvrec_accum + consumed, to_feed);
      br_ssl_engine_recvrec_ack(eng, to_feed);
      consumed += to_feed;
    }

    // Shift remaining un-consumed data to beginning
    if (consumed < accum_len) {
      size_t left = accum_len - consumed;
      memmove(ssl_pcb->recvrec_accum, ssl_pcb->recvrec_accum + consumed, left);
      ssl_pcb->recvrec_accum_len = left;
    } else {
      ssl_pcb->recvrec_accum_len = 0;
    }
  }

  // --- Process BearSSL engine state machine ---
  uint32_t state = br_ssl_engine_current_state(eng);

  for (int i = 0; i < ASYNC_TCP_SSL_MAX_FEED_LOOPS; i++) {
    yield();  // Feed WDT — BearSSL handshake can take many iterations
    if (!tcp_ssl_pcb_is_alive(ssl_pcb)) return;  // freed while yielding
    state = br_ssl_engine_current_state(eng);

    // Flush any buffered plaintext into a TLS record so the SENDREC branch
    // below can transmit it. Done here (not per-write) to keep BR_SSL_SENDAPP
    // open across the synchronous header+content burst in tcp_ssl_write.
    if (state & BR_SSL_SENDAPP) {
      br_ssl_engine_flush(eng, 0);
    }

    if (state & BR_SSL_CLOSED) {
      int err = br_ssl_engine_last_error(eng);
      async_tcp_log_d("PSE: CLOSED err=%d\n", err);
      // Session-resumption debug: if the server dies during the handshake it
      // is usually a resume-path failure (bad_record_mac/decrypt_error on an
      // abbreviated handshake in BearSSL). Log the decoded alert loudly.
      if (!ssl_pcb->handshake_done && ssl_pcb->is_server) {
        async_tcp_log_e("PSE: server handshake FAILED err=%d (%s), free heap=%u, accum=%u\n",
                        err, tcp_ssl_error_string(err), (unsigned)ESP.getFreeHeap(),
                        (unsigned)ssl_pcb->recvrec_accum_len);
      }
      // Re-check liveness: the engine may have been torn down (e.g. a
      // scheduled SSL error callback or an app close) during an intervening
      // yield(). Firing on_error on a freed ssl_pcb would walk freed memory.
      if (!tcp_ssl_pcb_is_alive(ssl_pcb)) return;
      if (ssl_pcb->on_error) {
        ssl_pcb->on_error(ssl_pcb->arg, ssl_pcb->tcp, err);
      }
      return;
    }

    // Declare the handshake complete BEFORE delivering any application data.
    // on_handshake fires the AsyncServer's connect callback, which is what
    // creates the AsyncWebServerRequest and registers its data callback. If
    // RECVAPP data (the first HTTP request) were delivered first, it would be
    // handed to a NULL callback and silently dropped.
    if (!ssl_pcb->handshake_done) {
      bool hs_done = (ssl_pcb->is_server && (state & BR_SSL_RECVAPP)) ||
                     (!ssl_pcb->is_server && (state & BR_SSL_SENDAPP));
      if (hs_done) {
        ssl_pcb->handshake_done = true;
        if (ssl_pcb->on_handshake) {
          ssl_pcb->on_handshake(ssl_pcb->arg, ssl_pcb->tcp, &ssl_pcb->dummy_ssl);
        }
        if (!tcp_ssl_pcb_is_alive(ssl_pcb)) return;  // callback may have closed it
      }
    }

    if (state & BR_SSL_RECVAPP) {
      ssl_pcb->in_buf_ptr = br_ssl_engine_recvapp_buf(eng, &(ssl_pcb->in_len));
      if (ssl_pcb->in_len && ssl_pcb->in_len < ASYNC_TCP_SSL_IN_BUFFER_SIZE) {
        br_ssl_engine_recvapp_ack(eng, ssl_pcb->in_len);
        if (ssl_pcb->on_data) {
          ssl_pcb->on_data(ssl_pcb->arg, ssl_pcb->tcp, ssl_pcb->in_buf_ptr, ssl_pcb->in_len);
        }
        continue;
      }
    }

    // Every outbound record — handshake AND app data — goes through the
    // multi-record NO-COPY ring. Each record is copied out of BearSSL's single
    // engine outbuf into a free slab slot, tcp_write (no-copy) pins the slot
    // until the peer ACKs, and br_ssl_engine_sendrec_ack lets the engine build
    // the NEXT record into outbuf. K slots => K records in flight per RTT with
    // ZERO per-record heap allocation. When all K slots are pinned we wait for
    // ACKs (tcp_ssl_sent frees slots FIFO and re-arms the engine).
    //
    // The handshake MUST stay on this heap-free path too: the old COPY emitter
    // allocated a PBUF_RAM from the heap per record, which failed with ERR_MEM
    // whenever the arena fragmented below record size during refresh churn
    // (largest-block ~176B vs a ~1KB flight record) — the SENDREC hard-stall
    // that wedged all browser loads. No app data exists mid-handshake, so the
    // single ring slot is always available to handshake flights.
    if (ssl_pcb->out_ring_pinned >= ASYNC_TCP_SSL_RECORD_RING_SLOTS) {
      break;  // ring full — wait for ACK; tcp_ssl_sent re-arms if SENDREC is set
    }

    ssl_pcb->out_buf_ptr = br_ssl_engine_sendrec_buf(eng, &(ssl_pcb->out_len));
    if (ssl_pcb->out_len && ssl_pcb->out_len <= ASYNC_TCP_SSL_OUT_BUFFER_SIZE) {
      // lwIP gates tcp_write on BOTH the byte window (snd_buf) and the pbuf
      // queue depth (snd_queuelen vs TCP_SND_QUEUELEN). The sndbuf boost sets
      // only snd_buf (8*TCP_MSS), NOT TCP_SND_QUEUELEN, so a burst of records
      // can fill the pbuf queue while snd_buf still shows room and tcp_write
      // fails with ERR_MEM even though the window looks open. The record is
      // NOT consumed until sendrec_ack, so on failure we leave it pending and
      // defer to a later pass once the queue drains — never abort (that would
      // drop a recoverable stream and tear down a healthy connection).
      if (tcp_sndbuf(ssl_pcb->tcp) >= ssl_pcb->out_len &&
          tcp_sndqueuelen(ssl_pcb->tcp) < TCP_SND_QUEUELEN) {
        // tcp_write still needs a small PBUF_RAM header pbuf from the heap and
        // a MEMP_TCP_SEG/MEMP_PBUF_ROM from the static pools for EACH segment,
        // COPY or not. Data bytes are never heap-allocated: every record
        // (handshake AND app) is memcpy'd into a slab ring slot and written
        // NO-COPY (TCP_WRITE_FLAG_COPY=0), so tcp_write references the slab
        // directly and only the small per-segment memp/header entries come from
        // pools. The ONE exception is the graceful close_notify branch below
        // (tiny, once, at stream end). K slots in flight / RTT.
        err_t werr;
        {
          uint8_t slot = ssl_pcb->out_ring_next;
          memcpy(ssl_pcb->out_ring[slot], ssl_pcb->out_buf_ptr, ssl_pcb->out_len);
          werr = tcp_write(ssl_pcb->tcp, ssl_pcb->out_ring[slot], ssl_pcb->out_len, 0);
          if (werr == ERR_OK) {
            ssl_pcb->out_ring_len[slot] = ssl_pcb->out_len;
            ssl_pcb->out_ring_next = (uint8_t)((slot + 1) % ASYNC_TCP_SSL_RECORD_RING_SLOTS);
            ssl_pcb->out_ring_pinned++;
          }
        }
        if (werr == ERR_OK) {
          // Record queued. Free the ENGINE outbuf now so BearSSL builds the
          // next record: no COPY write moved the bytes (they live in the ring
          // slot's memcpy'd copy), so the engine buffer is always free to
          // reuse. Ring/flag state was committed above.
          br_ssl_engine_sendrec_ack(eng, ssl_pcb->out_len);
          ssl_pcb->sendrec_deferred = false;  // pending record transmitted
          ssl_pcb->hard_defer_start = 0;      // un-wedged; clear the stall clock
          tcp_output(ssl_pcb->tcp);
          continue;
        }
        // tcp_write failed. The record is NOT consumed (we did not ack it),
        // so do not abort — defer and retry once the send window / pbuf queue
        // has room. The ring slot stays free (app path); the engine still
        // holds the record. Mark the record as deferred so tcp_ssl_sent()
        // re-arms the engine on the next ACK; we do NOT reschedule here (that
        // would busy-loop, and schedule_function has a bounded pool).
        ssl_pcb->sendrec_deferred = true;
        // Distinguish a RECOVERABLE defer (send window / pbuf queue full — an
        // ACK will free space and tcp_ssl_sent re-arms us) from a HARD stall
        // (open sndbuf + empty queuelen yet tcp_write still fails: the system
        // heap / static memp pool is exhausted). In the hard case nothing is on
        // the wire, so NO ACK can ever arrive to re-arm the deferred record —
        // the connection is permanently wedged. Start a stall clock so
        // tcp_ssl_is_stalled()/AsyncClient::_poll can reset it after a bounded
        // delay instead of hanging forever. A recoverable defer clears the clock
        // (an ACK is expected shortly).
        if (tcp_sndbuf(ssl_pcb->tcp) >= ssl_pcb->out_len &&
            tcp_sndqueuelen(ssl_pcb->tcp) == 0) {
          if (ssl_pcb->hard_defer_start == 0) {
            ssl_pcb->hard_defer_start = millis();
            // One-shot report at stall onset. With the no-copy ring this can
            // only mean static memp (TCP_SEG/PBUF) exhaustion or a lwIP
            // conservative-window refusal — not the COPY-pbuf fragmentation of
            // the old pipeline. ESP.getFreeHeap() is the LARGEST contiguous
            // free block, not total free; if it is far below the total, the
            // heap is fragmented even though the ring itself needs no heap.
            async_tcp_log_v("SENDREC hard-stall: heap total-free=%u largest-block=%u\n",
                            (unsigned)ESP.getFreeHeap(), (unsigned)ESP.getMaxFreeBlockSize());
          }
        } else {
          ssl_pcb->hard_defer_start = 0;  // window/queue-full: ACK will free space
        }
        // Nudge lwIP to transmit whatever is already queued: the queue may be
        // full with pbufs that are waiting for an output push, and if those
        // never go out the peer never ACKs so the queue never drains and the
        // deferred record can never fit. tcp_output() is idempotent and safe to
        // call repeatedly (it only sends if there is unsent data).
        tcp_output(ssl_pcb->tcp);
        async_tcp_log_v("SENDREC: defer err=%d out=%u sndbuf=%u queuelen=%u/%u freeheap=%u hard=%u\n",
                        (int)werr,
                        (unsigned)ssl_pcb->out_len,
                        (unsigned)tcp_sndbuf(ssl_pcb->tcp),
                        (unsigned)tcp_sndqueuelen(ssl_pcb->tcp),
                        (unsigned)TCP_SND_QUEUELEN,
                        (unsigned)ESP.getFreeHeap(),
                        (unsigned)(ssl_pcb->hard_defer_start ? 1 : 0));
      }
    }

    break;
  }

  if (!tcp_ssl_pcb_is_alive(ssl_pcb)) return;  // freed while yielding

  // If the engine still has a SENDREC record pending that the bounded feed loop
  // reached its iteration cap without emitting (e.g. a handshake flight split
  // into many small records by a small OUT buffer), reschedule so it continues.
  // This must NOT fire on the pbuf-alloc-failure defer path (sendrec_deferred
  // is set) or while the record ring is full (out_ring_pinned == K — we wait
  // for the ACKs in tcp_ssl_sent to open slots), either of which would busy-loop.
  if (ssl_pcb->sendrec_deferred == false &&
      ssl_pcb->out_ring_pinned < ASYNC_TCP_SSL_RECORD_RING_SLOTS) {
    state = br_ssl_engine_current_state(eng);
    if (state & BR_SSL_SENDREC) {
      schedule_ssl_engine(ssl_pcb);
      return;
    }
  }

  state = br_ssl_engine_current_state(eng);
  if (!ssl_pcb->handshake_done) {
    if ((ssl_pcb->is_server && (state & BR_SSL_RECVAPP)) ||
        (!ssl_pcb->is_server && (state & BR_SSL_SENDAPP))) {
      ssl_pcb->handshake_done = true;
      if (ssl_pcb->on_handshake) {
        ssl_pcb->on_handshake(ssl_pcb->arg, ssl_pcb->tcp, &ssl_pcb->dummy_ssl);
      }
    }
  }
}

// Called from the lwIP _sent callback (ESP8266AsyncTCP.cpp) whenever the peer
// ACKs TLS ciphertext, freeing send-window / pbuf-queue space. Released ring
// slots hold the ACKed records (the peer ACKed the ciphertext, so the data is
// safe to overwrite), then re-arms the engine whenever it still has a SENDREC
// record queued to emit. This covers:
//  (1) a record previously deferred on pbuf-alloc ERR_MEM (sendrec_deferred) — retry
//      now that the ACK freed queue/window space, and
//  (2) the end of a ring: all K slots exhausted means the feed loop stopped
//      with the engine still holding the next unfinished record, needing the
//      next ACK's freed slots before it can emit again.
// Gating on the engine's SENDREC state (not on the ring alone) keeps this safe:
// idle / finished connections sit in BR_SSL_SENDAPP waiting for the app, NOT in
// SENDREC, so their ACKs do NOT spam schedule_ssl_engine.
void tcp_ssl_sent(struct tcp_pcb* pcb, size_t acked) {
  if (!pcb) return;
  tcp_ssl_pcb* ssl_pcb = find_ssl_pcb(pcb);
  if (!ssl_pcb) return;
  // Free ring slots FIFO as ciphertext ACKs land. lwIP's sent callback reports
  // the bytes ACKed SINCE the last callback, but application records are
  // larger than a single MSS (1053B ciphertext across two 536B segments), so a
  // record usually completes only after several 536B-ish ACKs. Comparing the
  // per-callback delta against whole record sizes would strand the oldest slot
  // forever (delayed ACK never reports one full record at once) and the ring
  // would wedge mid-transfer. Accumulate into a running total instead:
  // release a slot only once the running total covers its length, then debit
  // exactly that record before checking the next-oldest.
  ssl_pcb->out_ring_acked += (uint32_t)acked;
  while (ssl_pcb->out_ring_pinned > 0) {
    uint8_t oldest = (uint8_t)((ssl_pcb->out_ring_next - ssl_pcb->out_ring_pinned +
                                ASYNC_TCP_SSL_RECORD_RING_SLOTS) % ASYNC_TCP_SSL_RECORD_RING_SLOTS);
    if (ssl_pcb->out_ring_acked >= ssl_pcb->out_ring_len[oldest]) {
      ssl_pcb->out_ring_acked -= ssl_pcb->out_ring_len[oldest];
      ssl_pcb->out_ring_len[oldest] = 0;
      ssl_pcb->out_ring_pinned--;
    } else {
      break;  // oldest record not yet fully ACKed; release it (and any after) on a later ACK
    }
  }
  if (ssl_pcb->out_ring_pinned == 0) ssl_pcb->out_ring_acked = 0;  // anchor; keep total from creeping
  if (ssl_pcb->handshake_done) {
    ssl_pcb->body_started = true;   // peer ACKed app data: the body is streaming
  }
  br_ssl_engine_context* eng = tcp_ssl_engine(ssl_pcb);
  if (!eng) return;
  unsigned int state = br_ssl_engine_current_state(eng);
  if (state & BR_SSL_SENDREC) {
    schedule_ssl_engine(ssl_pcb);
  }
}

// Returns true once this connection has been in a HARD SENDREC stall (open
// send window + empty pbuf queue yet tcp_write still failing = system-heap /
// static-memp-pool exhaustion, with nothing on the wire so no ACK can un-wedge
// it) for longer than stall_ms. AsyncClient::_poll calls this each poll to
// bound an otherwise-permanent wedge, tearing the connection down so the
// browser retries on a fresh connection.
//
// hard_defer_start is armed ONLY when tcp_sndqueuelen == 0 (the emitter sets
// it in the failure branch guarded by that check), so ANY hard defer has
// nothing in flight: no ACK can ever arrive, and the only thing that clears it
// is a later record transmit (poll retry succeeding once a sibling conn frees
// pool/heap). There is therefore no "mid-body = self-recovering" state to
// protect — a hard defer is equally wedged before and after the first app
// record. The reset applies unconditionally; if a records starts streaming the
// stall clock is cleared and this never fires. Truncating a response whose
// allocs cannot resolve is the correct recovery (browser retries cleanly).
bool tcp_ssl_is_stalled(struct tcp_pcb* pcb, uint32_t stall_ms) {
  tcp_ssl_pcb* ssl_pcb = find_ssl_pcb(pcb);
  if (!ssl_pcb) return false;
  if (ssl_pcb->hard_defer_start == 0) return false;  // not in a hard defer
  return (uint32_t)(millis() - ssl_pcb->hard_defer_start) >= stall_ms;
}


// --- Public Read/Write API ---

int tcp_ssl_write(struct tcp_pcb* pcb, const uint8_t* data, size_t len) {
  tcp_ssl_pcb* ssl_pcb = find_ssl_pcb(pcb);
  if (!ssl_pcb) {
    return -1;
  }

  br_ssl_engine_context* eng;
  eng = tcp_ssl_engine(ssl_pcb);

  unsigned int state = br_ssl_engine_current_state(eng);
  if (!(state & BR_SSL_SENDAPP)) {
    return 0;
  }

  size_t wlen;
  unsigned char* buf = br_ssl_engine_sendapp_buf(eng, &wlen);
  if (wlen == 0) {
    schedule_ssl_engine(ssl_pcb);
    return 0;
  }

  size_t clen = (len > wlen) ? wlen : len;
  memcpy(buf, data, clen);
  br_ssl_engine_sendapp_ack(eng, clen);
  br_ssl_engine_flush(eng, 0);
  schedule_ssl_engine(ssl_pcb);
  return clen;
}

int tcp_ssl_read(struct tcp_pcb* pcb, struct pbuf* pb) {

  tcp_ssl_pcb* ssl_pcb = find_ssl_pcb(pcb);
  if (!ssl_pcb) {
    pbuf_free(pb);
    return -1;
  }

  // ---- Accumulate data from lwIP callback into recvrec_accum ----
  // NO BearSSL calls here — we're in lwIP context (no yield allowed).
  // All BearSSL feeding happens in process_ssl_engine (loop() context).

  size_t remaining = pb->tot_len;
  size_t pb_offset = 0;

  while (remaining > 0) {
    size_t accum_space = ASYNC_TCP_SSL_IN_BUFFER_SIZE - ssl_pcb->recvrec_accum_len;
    if (accum_space == 0) {
      // Accumulator full — schedule engine to drain, then retry
      schedule_ssl_engine(ssl_pcb);
      // In lwIP context we can't wait — just drop what doesn't fit
      break;
    }

    size_t to_copy = (remaining < accum_space) ? remaining : accum_space;
    pbuf_copy_partial(pb, ssl_pcb->recvrec_accum + ssl_pcb->recvrec_accum_len,
                      to_copy, pb_offset);
    ssl_pcb->recvrec_accum_len += to_copy;
    pb_offset += to_copy;
    remaining -= to_copy;
  }

  if (remaining > 0) {
    // Overflow — some data couldn't be buffered
    pbuf_free(pb);
    return -1;
  }

  tcp_recved(pcb, pb->tot_len);
  pbuf_free(pb);

  // Schedule BearSSL processing in loop() context
  schedule_ssl_engine(ssl_pcb);
  return 0;
}

// --- Callback and state management functions ---

bool tcp_ssl_has(struct tcp_pcb* pcb) { return find_ssl_pcb(pcb) != nullptr; }

bool tcp_ssl_tx_busy(struct tcp_pcb* pcb) {
  tcp_ssl_pcb* ssl_pcb = find_ssl_pcb(pcb);
  if (!ssl_pcb) return false;
  br_ssl_engine_context* eng = tcp_ssl_engine(ssl_pcb);
  if (!eng) return false;
  // Read-only test, safe in any context. A record either waits in the engine
  // (SENDREC), is deferred awaiting window/queue room, or has pinned ring
  // slots whose ciphertext the peer has not yet ACKed.
  return ssl_pcb->sendrec_deferred || ssl_pcb->out_ring_pinned > 0 ||
         (br_ssl_engine_current_state(eng) & BR_SSL_SENDREC);
}

// set on arg callback
void tcp_ssl_arg(struct tcp_pcb* pcb, void* arg) {
  tcp_ssl_pcb* ssl_pcb = find_ssl_pcb(pcb);
  if (ssl_pcb) ssl_pcb->arg = arg;
}

// set on data callback
void tcp_ssl_data(struct tcp_pcb* pcb, tcp_ssl_data_cb_t cb) {
  tcp_ssl_pcb* ssl_pcb = find_ssl_pcb(pcb);
  if (ssl_pcb) ssl_pcb->on_data = cb;
}

// Set on handshake callback
void tcp_ssl_handshake(struct tcp_pcb* pcb, tcp_ssl_handshake_cb_t cb) {
  tcp_ssl_pcb* ssl_pcb = find_ssl_pcb(pcb);
  if (ssl_pcb) ssl_pcb->on_handshake = cb;
}

// Set on error callback
void tcp_ssl_err(struct tcp_pcb* pcb, tcp_ssl_error_cb_t cb) {
  tcp_ssl_pcb* ssl_pcb = find_ssl_pcb(pcb);
  if (ssl_pcb) ssl_pcb->on_error = cb;
}

const char* tcp_ssl_error_string(int err) {
  if (err >= -0x100 && err < 0) return "TLS alert";
  if (err == 0) return "closed";
  return "TLS error";
}

#endif  // ASYNC_TCP_SSL_ENABLED

/*
  =====================================================================
  Client glue (client role for AsyncTCP TLS)
  =====================================================================
*/
/*
  BearSSL client glue layer for ESP8266AsyncTCP

  This file contains the TLS-client-specific glue: the x509 insecure
  decoder, the client cipher suites, engine base init, and connection
  setup. It is compiled whenever ASYNC_TCP_SSL_ENABLED is set, alongside
  the server glue. Include "ESP8266AsyncTCPClient.h" in a project that uses
  client TLS.
*/

// NOTE: TLS.h must be included FIRST because it defines the
// ASYNC_TCP_SSL_ENABLED / ASYNC_TCP_SSL_ENABLE_CLIENT macros that the guard
// below tests. If this include came after the #if, the macros would be
// undefined here and the whole file would be preprocessed out.
#include "AsyncTCPTLS.h"

#if ASYNC_TCP_SSL_ENABLED && ASYNC_TCP_SSL_ENABLE_CLIENT

#include "AsyncTCPLogging.h"

#include <pgmspace.h>  // PROGMEM (self-contained; not the core's BearSSLHelpers)
#include <StackThunk.h>
#include <bearssl/bearssl_pem.h>
#include <lwip/tcp.h>
#include <Schedule.h>  // schedule_function()

// Private x509 decoder state

// Callback for the x509 decoder subject DN
static void insecure_subject_dn_append(void *ctx, const void *buf, size_t len) {
  x509_insecure_context *xc = (x509_insecure_context *)ctx;
  br_sha256_update(&xc->sha256_subject, buf, len);
}

// Callback for the x509 decoder issuer DN
static void insecure_issuer_dn_append(void *ctx, const void *buf, size_t len) {
  x509_insecure_context *xc = (x509_insecure_context *)ctx;
  br_sha256_update(&xc->sha256_issuer, buf, len);
}

// Callback on the first byte of any certificate
static void insecure_start_chain(const br_x509_class **ctx, const char *server_name) {
  x509_insecure_context *xc = (x509_insecure_context *)ctx;
  br_x509_decoder_init(&xc->ctx, insecure_subject_dn_append, xc, insecure_issuer_dn_append, xc);
  xc->done_cert = false;
  br_sha1_init(&xc->sha1_cert);
  br_sha256_init(&xc->sha256_subject);
  br_sha256_init(&xc->sha256_issuer);
  (void)server_name;
}

// Callback for each certificate present in the chain (but only operates
// on the first one by design).
static void insecure_start_cert(const br_x509_class **ctx, uint32_t length) {
  (void) ctx;
  (void) length;
}

// Callback for each byte stream in the chain.  Only process first cert.
static void insecure_append(const br_x509_class **ctx, const unsigned char *buf, size_t len) {
  x509_insecure_context *xc = (x509_insecure_context *)ctx;
  // Don't process anything but the first certificate in the chain
  if (!xc->done_cert) {
    br_sha1_update(&xc->sha1_cert, buf, len);
    br_x509_decoder_push(&xc->ctx, (const void*)buf, len);
  }
}

// Callback on individual cert end.
static void insecure_end_cert(const br_x509_class **ctx) {
  x509_insecure_context *xc = (x509_insecure_context *)ctx;
  xc->done_cert = true;
}

// Callback when complete chain has been parsed.
// Return 0 on validation success, !0 on validation error
static unsigned insecure_end_chain(const br_x509_class **ctx) {
  const x509_insecure_context *xc = (const x509_insecure_context *)ctx;
  if (!xc->done_cert) {
    async_tcp_log_d("insecure_end_chain: No cert seen\n");
    return 1; // error
  }

  // Handle SHA1 fingerprint matching
  char res[20];
  br_sha1_out(&xc->sha1_cert, res);
  if (xc->match_fingerprint && memcmp(res, xc->match_fingerprint, sizeof(res))) {
    return BR_ERR_X509_NOT_TRUSTED;
  }

  // Handle self-signer certificate acceptance
  char res_issuer[32];
  char res_subject[32];
  br_sha256_out(&xc->sha256_issuer, res_issuer);
  br_sha256_out(&xc->sha256_subject, res_subject);
  if (xc->allow_self_signed && memcmp(res_subject, res_issuer, sizeof(res_issuer))) {
    return BR_ERR_X509_NOT_TRUSTED;
  }

  // Default (no validation at all) or no errors in prior checks = success.
  return 0;
}

// Return the public key from the validator (set by x509_minimal)
static const br_x509_pkey *insecure_get_pkey(const br_x509_class *const *ctx, unsigned *usages) {
  const x509_insecure_context *xc = (const x509_insecure_context *)ctx;
  if (usages != NULL) {
    *usages = BR_KEYTYPE_KEYX | BR_KEYTYPE_SIGN; // I said we were insecure!
  }
  return &xc->ctx.pkey;
}


//  Set up the x509 insecure data structures for BearSSL core to use.
void br_x509_insecure_init(x509_insecure_context *ctx, bool use_fingerprint, const uint8_t* fingerprint, bool allow_self_signed) {
  static const br_x509_class br_x509_insecure_vtable PROGMEM = {
    sizeof(x509_insecure_context),
    insecure_start_chain,
    insecure_start_cert,
    insecure_append,
    insecure_end_cert,
    insecure_end_chain,
    insecure_get_pkey
  };

  memset(ctx, 0, sizeof * ctx);
  ctx->vtable = &br_x509_insecure_vtable;
  ctx->done_cert = false;
  ctx->match_fingerprint = use_fingerprint ? fingerprint : nullptr;
  ctx->allow_self_signed = allow_self_signed ? 1 : 0;
}


// Client cipher suites — TLS 1.2 only, AEAD ciphers only (AES-128-GCM +
// ChaCha20-Poly1305, no CBC), ECDSA key exchange
static const uint16_t suites_P[] PROGMEM = {
    BR_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    BR_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
};


// Install hashes into the SSL engine — SHA-256 only (used by both AEAD suites)
static void br_ssl_client_install_hashes(br_ssl_engine_context *eng) {
  br_ssl_engine_set_hash(eng, br_sha256_ID, &br_sha256_vtable);
}

// Default initialization for our SSL clients — TLS 1.2 only, EC + AEAD ciphers
static void br_ssl_client_base_init(br_ssl_client_context *cc, const uint16_t *cipher_list, int cipher_cnt) {
  uint16_t suites[cipher_cnt];
  memcpy_P(suites, cipher_list, cipher_cnt * sizeof(cipher_list[0]));
  br_ssl_client_zero(cc);
  br_ssl_engine_add_flags(&cc->eng, BR_OPT_NO_RENEGOTIATION);
  br_ssl_engine_set_versions(&cc->eng, BR_TLS12, BR_TLS12);
  br_ssl_engine_set_suites(&cc->eng, suites, (sizeof suites) / (sizeof suites[0]));
  br_ssl_engine_set_ec(&cc->eng, &br_ec_p256_m15);
  br_ssl_engine_set_ecdsa(&cc->eng, &br_ecdsa_i15_vrfy_asn1);
  br_ssl_client_install_hashes(&cc->eng);
  br_ssl_engine_set_prf_sha256(&cc->eng, &br_tls12_sha256_prf);
  br_ssl_engine_set_default_chapol(&cc->eng);
  br_ssl_engine_set_default_aes_gcm(&cc->eng);
}

int tcp_ssl_new_client(struct tcp_pcb* pcb, const char* host, const br_x509_class **x509ctx, BearSSL_SSL_CTX *ssl_ctx) {
  (void)ssl_ctx;

  if (!pcb) return -1;

  tcp_ssl_pcb* ssl_pcb = tcp_ssl_alloc_pcb(pcb, false);
  if (!ssl_pcb) {
    return -1;
  }

  ssl_pcb->sc_client = new (std::nothrow) br_ssl_client_context();
  ssl_pcb->insecure_x509 = nullptr;
  if (!ssl_pcb->sc_client) {
    delete ssl_pcb;
    return -1;
  }

  br_ssl_client_base_init(ssl_pcb->sc_client, suites_P, sizeof(suites_P) / sizeof(suites_P[0]));

  // Install x509 validator. When the caller supplies none (rootCA == NULL),
  // install the accept-any insecure decoder — mirrors mbedTLS
  // beginSecure(host, port, rootCA=NULL), i.e. no server-cert verification.
  if (x509ctx == NULL) {
    ssl_pcb->insecure_x509 = new (std::nothrow) x509_insecure_context();
    if (!ssl_pcb->insecure_x509) {
      delete ssl_pcb;
      return -1;
    }
    br_x509_insecure_init(ssl_pcb->insecure_x509, false, nullptr, false);
    x509ctx = &ssl_pcb->insecure_x509->vtable;
  }

  br_ssl_engine_set_x509(&ssl_pcb->sc_client->eng, x509ctx);

  br_ssl_engine_set_buffers_bidi(&ssl_pcb->sc_client->eng, ssl_pcb->inbuf, ASYNC_TCP_SSL_IN_BUFFER_SIZE,
                                 ssl_pcb->outbuf, ASYNC_TCP_SSL_OUT_BUFFER_SIZE);
  br_ssl_engine_set_versions(&ssl_pcb->sc_client->eng, BR_TLS12, BR_TLS12);

  // Set server name for SNI (required for TLS 1.2+)
  if(!br_ssl_client_reset(ssl_pcb->sc_client, host, 0)) {
    delete ssl_pcb->insecure_x509;
    delete ssl_pcb;
    return -1;
  }

  tcp_ssl_register_pcb(ssl_pcb);
  process_ssl_engine(ssl_pcb);

  return 0;
}

#endif  // ASYNC_TCP_SSL_ENABLED && ASYNC_TCP_SSL_ENABLE_CLIENT

/*
  =====================================================================
  Server glue (server role for AsyncTCP TLS)
  =====================================================================
*/
/*
  BearSSL server glue layer for ESP8266AsyncTCP

  This file contains the TLS-server-specific glue: certificate/private-key
  context parsing and connection setup. It is compiled whenever
  ASYNC_TCP_SSL_ENABLED is set, alongside the client glue. Include
  "ESP8266AsyncTCPServer.h" in a project that uses server TLS.
*/

// NOTE: TLS.h must be included FIRST because it defines the
// ASYNC_TCP_SSL_ENABLED / ASYNC_TCP_SSL_ENABLE_SERVER macros that the guard
// below tests. If this include came after the #if, the macros would be
// undefined here and the whole file would be preprocessed out.
#include "AsyncTCPTLS.h"

#if ASYNC_TCP_SSL_ENABLED && ASYNC_TCP_SSL_ENABLE_SERVER

#include "AsyncTCPLogging.h"

#include <ESP8266WiFi.h>  // core built-in <BearSSLHelpers.h> -> BearSSL::PrivateKey
#include <StackThunk.h>
#include <string.h>  // strlen_P/memcpy_P (PROGMEM patch; <string.h> pulls <sys/string.h>)
#include <bearssl/bearssl_pem.h>
#include <lwip/tcp.h>
#include <Schedule.h>  // schedule_function()

#include <memory>  // For std::unique_ptr (PROGMEM patch)

// br_ssl_engine_new_max_frag_len() is declared in BearSSL's internal
// C-only header (inner.h), which cannot be included from C++. Declare it here
// with correct C linkage so the forced-MFLN path below links against the
// C-compiled BearSSL object.
extern "C" void br_ssl_engine_new_max_frag_len(br_ssl_engine_context* rc, unsigned max_frag_len);

// Fwd decl: defined below; used once at ctx build to init the shared engine.
static void br_ssl_server_init_lean(br_ssl_server_context* cc,
    const br_x509_certificate* chain, size_t chain_len,
    const br_ec_private_key* ec, const br_rsa_private_key* rsa);

// Normalize a PEM string for feeding to BearSSL's decoder: copy it out of flash
// (PROGMEM) into RAM and, unless it already ends with a newline, append one.
// BearSSL's PEM decoder requires the final "-----END ...-----" line to be
// newline-terminated, otherwise the trailing line (and thus the whole object)
// can be dropped, causing the cert/key load to fail. Returns the owning buffer
// (kept alive by the caller) and repoints `out` to the NUL-terminated string.
static std::unique_ptr<char[]> normalize_pem(const char* src, const char*& out) {
  if (!src) { out = nullptr; return nullptr; }
  bool in_flash = (uint32_t)src >= 0x40200000;
  size_t len = in_flash ? strlen_P(src) : strlen(src);
  bool has_nl = (len > 0) && (src[len - 1] == '\n' || src[len - 1] == '\r');
  std::unique_ptr<char[]> buf(new (std::nothrow) char[len + 2]);
  if (!buf) { out = nullptr; return nullptr; }
  if (in_flash) memcpy_P(buf.get(), src, len);
  else          memcpy(buf.get(), src, len);
  if (!has_nl) buf[len++] = '\n';
  buf[len] = '\0';
  out = buf.get();
  return buf;
}

BearSSL_SSL_CTX* tcp_ssl_new_server_ctx(const char* cert_pem, const char* private_key_pem,
                                const char* password) {
  (void)password;
  async_tcp_log_i("[CTX] cert=%p key=%p (flash if >=0x40200000)\n", (const void*)cert_pem, (const void*)private_key_pem);
  if (!cert_pem || !private_key_pem) {
    async_tcp_log_e("[CTX] null PEM ptr -> fail\n");
    return nullptr;
  }

  // --- START: PROGMEM AWARENESS + TRAILING-NEWLINE PATCH ---
  // Copy each PEM out of flash into RAM and ensure a trailing '\n' (BearSSL's
  // PEM decoder drops the final object if its "END" line is not newline
  // terminated). The owning buffers must outlive the parses below, so they are
  // held as locals for the lifetime of this function.
  std::unique_ptr<char[]> cert_ram_buf;
  std::unique_ptr<char[]> key_ram_buf;
  {
    const char* norm_cert = nullptr;
    const char* norm_key  = nullptr;
    cert_ram_buf = normalize_pem(cert_pem, norm_cert);
    key_ram_buf = normalize_pem(private_key_pem, norm_key);
    if (!norm_cert || !norm_key) {
      async_tcp_log_e("[CTX] PEM normalize OOM -> fail\n");
      return nullptr;
    }
    cert_pem = norm_cert;
    private_key_pem = norm_key;
  }
  // --- END: PROGMEM AWARENESS + TRAILING-NEWLINE PATCH ---

  BearSSL_SSL_CTX* ctx = new (std::nothrow) BearSSL_SSL_CTX();
  if (!ctx) {
    async_tcp_log_e("[CTX] ctx alloc OOM -> fail\n");
    return nullptr;
  }

  size_t ncerts = parse_certificates(cert_pem, ctx->chain_vector);
  async_tcp_log_i("[CTX] parse_certificates returned %u certs\n", (unsigned)ncerts);
  if (ncerts == 0) {
    delete ctx;
    return nullptr;
  }

  ctx->pk = new (std::nothrow) BearSSL::PrivateKey(private_key_pem);
  if (!ctx->pk) {
    async_tcp_log_e("[CTX] PrivateKey alloc OOM -> fail\n");
    delete ctx;
    return nullptr;
  }

  bool hasRSA = ctx->pk->getRSA() ? true : false;
  bool hasEC = ctx->pk->getEC() ? true : false;
  async_tcp_log_i("[CTX] pk: RSA=%d EC=%d\n", (int)hasRSA, (int)hasEC);
  if (!hasRSA && !hasEC) {
    async_tcp_log_e("[CTX] PrivateKey parsed but neither RSA nor EC -> fail\n");
    delete ctx;
    return nullptr;
  }

  // Session-resumption cache: initialize once per server context, shared by
  // every connection this server accepts. Without it every reconnect (and
  // every HTTP resource fetched over a new connection) pays a full handshake.
  br_ssl_session_cache_lru_init(&ctx->session_cache, ctx->session_store, sizeof(ctx->session_store));

  // Init the shared server engine once (chain, ciphers, curve). Per-conn
  // tcp_ssl_new_server() reuses it via br_ssl_server_reset() — no per-conn ctx.
  br_ssl_server_init_lean(&ctx->server_ctx, ctx->chain_vector.data(),
                          ctx->chain_vector.size(), ctx->pk->getEC(), ctx->pk->getRSA());
  br_ssl_server_set_cache(&ctx->server_ctx, &ctx->session_cache.vtable);  // persists across resets

  // PIN the shared BearSSL StackThunk stack (6200 B of DRAM) by taking once,
  // at server-setup time when the heap is clean, a reference that is never
  // released during the server's lifetime. The per-connection refs taken in
  // tcp_ssl_register_pcb() keep the count >= 1, so the stack, once allocated
  // here, is never freed and re-malloc'd as serialized connections oscillate
  // the refcount 0<->1. Without this, each new connection after the last one
  // closed re-allocates the stack with a 6200-byte DRAM malloc, which can fail
  // (abort -> "User exception (panic/abort/assert)") when the DRAM heap is
  // fragmented by connection churn (observed on the second page hammer).
  stack_thunk_add_ref();

  return ctx;
}

// Lean TLS 1.2 server init: ECDHE_ECDSA (RSA fallback) + AEAD ciphers only
// (AES-128-GCM + ChaCha20-Poly1305, no CBC) + SHA-256, P-256 only.
// Wires only the ESP8266 core's built-in BearSSL modules.
static void br_ssl_server_init_lean(br_ssl_server_context *cc,
    const br_x509_certificate *chain, size_t chain_len, const br_ec_private_key *ec, const br_rsa_private_key *rsa) {
  static const uint16_t ecdsa_suites[] = {
    BR_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    BR_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
  };
  static const uint16_t rsa_suites[] = {
    BR_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    BR_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
  };
  br_ssl_server_zero(cc);
  br_ssl_engine_set_versions(&cc->eng, BR_TLS12, BR_TLS12);
  br_ssl_engine_set_ec(&cc->eng, &br_ec_p256_m15);
  if (ec) {
    br_ssl_engine_set_suites(&cc->eng, ecdsa_suites, 2);
    br_ssl_server_set_single_ec(cc, chain, chain_len, ec,
        BR_KEYTYPE_KEYX | BR_KEYTYPE_SIGN, 0, &br_ec_p256_m15,
        br_ecdsa_i15_sign_asn1);
  } else if (rsa) {
    br_ssl_engine_set_suites(&cc->eng, rsa_suites, 2);
    br_ssl_server_set_single_rsa(cc, chain, chain_len, rsa,
        BR_KEYTYPE_SIGN, 0, br_rsa_i15_pkcs1_sign);
  }
  br_ssl_engine_set_hash(&cc->eng, br_sha256_ID, &br_sha256_vtable);
  br_ssl_engine_set_prf_sha256(&cc->eng, &br_tls12_sha256_prf);
  br_ssl_engine_set_default_chapol(&cc->eng);
  br_ssl_engine_set_default_aes_gcm(&cc->eng);
}

int tcp_ssl_new_server(struct tcp_pcb* pcb, BearSSL_SSL_CTX* ssl_ctx) {
  if (!pcb || !ssl_ctx) {
    return -1;
  }

  tcp_ssl_pcb* ssl_pcb = tcp_ssl_alloc_pcb(pcb, true);
  if (!ssl_pcb) return -1;

  // Borrow the shared server engine (config set in tcp_ssl_new_server_ctx).
  // No heap allocated here, so "TLS init failed" churn can't happen.
  ssl_pcb->sc_server = &ssl_ctx->server_ctx;

  br_ssl_engine_set_buffers_bidi(&ssl_pcb->sc_server->eng, ssl_pcb->inbuf, ASYNC_TCP_SSL_IN_BUFFER_SIZE,
                                 ssl_pcb->outbuf, ASYNC_TCP_SSL_OUT_BUFFER_SIZE);

  if (!br_ssl_server_reset(ssl_pcb->sc_server)) {
    delete ssl_pcb;
    return -1;
  }

  // Force MFLN (RFC 6066 max_fragment_length) = 1024 on the server.
  // Per br_ssl_engine_new_max_frag_len(), this caps every outbound record's
  // plaintext (including the handshake Certificate flight) at 1024 bytes.
#if ASYNC_TCP_SSL_SERVER_MFLN && ASYNC_TCP_SSL_SERVER_MFLN != 0
  br_ssl_engine_new_max_frag_len(&ssl_pcb->sc_server->eng, ASYNC_TCP_SSL_SERVER_MFLN);
#endif

  tcp_ssl_register_pcb(ssl_pcb);
  return 0;
}

uint8_t tcp_ssl_has_client() {
  for (tcp_ssl_pcb* iter = tcp_ssl_pcbs; iter; iter = iter->next) {
    if (iter->is_server) return 1;
  }
  return 0;
}

uint8_t tcp_ssl_client_count() {
  uint8_t n = 0;
  for (tcp_ssl_pcb* iter = tcp_ssl_pcbs; iter; iter = iter->next) {
    if (iter->is_server) n++;
  }
  return n;
}

#endif  // ASYNC_TCP_SSL_ENABLED && ASYNC_TCP_SSL_ENABLE_SERVER
// ===== end BearSSL/ESP8266 AsyncTCPTLS.cpp =====
#else
// ===== begin mbedTLS/ESP32 AsyncTCPTLS.cpp (AsyncTCP) =====
// SPDX-License-Identifier: LGPL-3.0-or-later
// SSL/TLS support for AsyncTCP using mbedTLS over LwIP raw TCP (tcp_pcb)
// Custom BIO callbacks replace BSD socket mbedtls_net_send/mbedtls_net_recv

#if ASYNC_TCP_SSL_ENABLED

#include <Arduino.h>
#include "AsyncTCPLogging.h"
#include <mbedtls/pem.h>

extern "C" {
#include "lwip/tcp.h"
}

#include "AsyncTCPTLS.h"

#if !defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED) && !defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
#  warning "PSK ciphersuites not configured — PSK TLS overloads will be unavailable"
#endif


// From mbedtls/net_sockets.h — not included since we use custom LwIP BIO
#ifndef MBEDTLS_ERR_NET_SEND_FAILED
#define MBEDTLS_ERR_NET_SEND_FAILED -0x004E
#endif

static int _handle_error(int err) {
    if (err == -30848) {
        return err;
    }
    // Suppress connection reset — normal client disconnect
    if (err == -0x004E) {
        return err;
    }
#ifdef MBEDTLS_ERROR_C
    char error_buf[100];
    mbedtls_strerror(err, error_buf, 100);
    async_tcp_log_e("(%d) %s", err, error_buf);
#else
    async_tcp_log_e("code %d", err);
#endif
    return err;
}

#define handle_error(e) _handle_error(e)

#include "lwip/priv/tcpip_priv.h"

typedef struct {
    struct tcpip_api_call_data call;
    tcp_pcb *pcb;
    const void *data;
    size_t size;
    uint8_t apiflags;
    err_t err;
} ssl_tcp_api_call_t;

static err_t _tcp_ssl_write_api(struct tcpip_api_call_data *api_call_msg) {
    ssl_tcp_api_call_t *msg = (ssl_tcp_api_call_t *)api_call_msg;
    msg->err = tcp_write(msg->pcb, msg->data, msg->size, msg->apiflags);
    if (msg->err == ERR_OK) {
        msg->err = tcp_output(msg->pcb);
    }
    return msg->err;
}

static err_t _tcp_ssl_write(tcp_pcb *pcb, const void *data, size_t size, uint8_t apiflags) {
    if (!pcb) return ERR_CONN;
    ssl_tcp_api_call_t msg;
    msg.pcb = pcb;
    msg.data = data;
    msg.size = size;
    msg.apiflags = apiflags;
    msg.err = ERR_CONN;
    if (tcpip_api_call(_tcp_ssl_write_api, (struct tcpip_api_call_data *)&msg) != ERR_OK) {
        return ERR_CONN;
    }
    return msg.err;
}

/*
 * Custom LwIP BIO callbacks for mbedTLS
 * These bridge mbedTLS's I/O with LwIP raw TCP (tcp_pcb).
 * The void* ctx points to the AsyncTCPTLS instance.
 */

static int _lwip_ssl_send(void *ctx, const unsigned char *buf, size_t len) {
    AsyncTCPTLS *sslctx = (AsyncTCPTLS *)ctx;
    if (!sslctx || !sslctx->pcb()) {
        return MBEDTLS_ERR_NET_SEND_FAILED;
    }
    tcp_pcb *pcb = sslctx->pcb();

    err_t err = _tcp_ssl_write(pcb, buf, len, TCP_WRITE_FLAG_COPY);
    if (err == ERR_OK) {
        return (int)len;
    }
    if (err == ERR_MEM) {
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    }
    return MBEDTLS_ERR_NET_SEND_FAILED;
}

static int _lwip_ssl_recv(void *ctx, unsigned char *buf, size_t len) {
    AsyncTCPTLS *sslctx = (AsyncTCPTLS *)ctx;
    if (!sslctx || !sslctx->hasRxData()) {
        return MBEDTLS_ERR_SSL_WANT_READ;
    }
    return sslctx->read(buf, len);
}

#if ASYNCTCP_MBEDTLS_MAJOR >= 4
// v4: RNG params removed — PSA Crypto provides the RNG internally.
int AsyncTCPTLS::_parse_private_key(mbedtls_pk_context *pk,
        const unsigned char *key, size_t keylen,
        const unsigned char *pwd, size_t pwdlen) {
    return mbedtls_pk_parse_key(pk, key, keylen, pwd, pwdlen);
}
#else
int AsyncTCPTLS::_parse_private_key(mbedtls_pk_context *pk,
        const unsigned char *key, size_t keylen,
        const unsigned char *pwd, size_t pwdlen) {
    return mbedtls_pk_parse_key(pk, key, keylen, pwd, pwdlen,
                                mbedtls_ctr_drbg_random, &drbg_ctx);
}
#endif

/*
 * AsyncTCPTLS implementation
 */

// Static shared RNG — initialized once, serialized on async task
#if ASYNCTCP_MBEDTLS_MAJOR < 4
mbedtls_ctr_drbg_context AsyncTCPTLS::drbg_ctx;
mbedtls_entropy_context AsyncTCPTLS::entropy_ctx;
#endif
bool AsyncTCPTLS::_conf_initialized = false;
int AsyncTCPTLS::_active_count = 0;

#if ASYNCTCP_MBEDTLS_MAJOR >= 4
// Mbed TLS v4: PSA Crypto provides the RNG internally, so no app RNG is
// needed. We only have to ensure PSA is initialised (see _rng_init).
#include <psa/crypto.h>
#endif

int AsyncTCPTLS::_rng_init(void) {
    if (_conf_initialized) return 0;
#if ASYNCTCP_MBEDTLS_MAJOR >= 4
    psa_status_t ps = psa_crypto_init();
    if (ps != PSA_SUCCESS) {
        async_tcp_log_e("psa_crypto_init failed: %d", (int)ps);
        return -1;
    }
    _conf_initialized = true;
#else
    _rng_seed_and_set();
    _conf_initialized = true;
#endif
    return 0;
}

#if ASYNCTCP_MBEDTLS_MAJOR < 4
void AsyncTCPTLS::_rng_seed_and_set(void) {
    mbedtls_ctr_drbg_init(&drbg_ctx);
    mbedtls_entropy_init(&entropy_ctx);
    mbedtls_ctr_drbg_seed(&drbg_ctx, mbedtls_entropy_func,
                          &entropy_ctx, (const unsigned char *)"AsyncTCPTLS", 11);
}
#endif

AsyncTCPTLS::AsyncTCPTLS(void) {
    mbedtls_ssl_init(&ssl_ctx);
    mbedtls_ssl_config_init(&ssl_conf);
    if (_rng_init() != 0) {
        async_tcp_log_e("AsyncTCPTLS RNG init failed");
    }
    _pcb = NULL;
    _ssl_key_password = NULL;
    _have_ca_cert = false;
    _have_client_cert = false;
    _have_client_key = false;
    handshake_timeout = SSL_HANDSHAKE_TIMEOUT;
    handshake_start_time = 0;

    _ssl_rx_buf = (unsigned char *)malloc(ASYNCTCP_TLS_RX_BUF_SIZE);
    _ssl_rx_buf_capacity = _ssl_rx_buf ? ASYNCTCP_TLS_RX_BUF_SIZE : 0;
    _ssl_rx_buf_len = 0;
    _ssl_rx_pos = 0;

    _active_count++;
}

AsyncTCPTLS::~AsyncTCPTLS() {
    _deleteHandshakeCerts();

    async_tcp_log_v("~AsyncTCPTLS");

    mbedtls_ssl_free(&ssl_ctx);
    mbedtls_ssl_config_free(&ssl_conf);

    if (_ssl_key_password) {
        free((void*)_ssl_key_password);
        _ssl_key_password = NULL;
    }

    if (_ssl_rx_buf) {
        free(_ssl_rx_buf);
        _ssl_rx_buf = NULL;
    }

    _active_count--;
}

bool AsyncTCPTLS::feedRxData(const unsigned char *data, size_t len) {
    if (!_ssl_rx_buf || len == 0) return true;

    // Only compact when there's not enough room at the tail
    size_t free_at_tail = _ssl_rx_buf_capacity - _ssl_rx_buf_len;
    if (len > free_at_tail && _ssl_rx_pos > 0) {
        size_t remaining = _ssl_rx_buf_len - _ssl_rx_pos;
        if (remaining > 0) {
            memmove(_ssl_rx_buf, _ssl_rx_buf + _ssl_rx_pos, remaining);
        }
        _ssl_rx_buf_len = remaining;
        _ssl_rx_pos = 0;
        free_at_tail = _ssl_rx_buf_capacity - _ssl_rx_buf_len;
    }

    // Check hard cap — if exceeded, caller must hold the pbuf
    if (_ssl_rx_buf_len + len > ASYNCTCP_TLS_RX_BUF_MAX) {
        return false;
    }

    // Grow buffer if needed (up to cap)
    if (len > free_at_tail) {
        size_t need = _ssl_rx_buf_len + len;
        unsigned char *newbuf = (unsigned char *)realloc(_ssl_rx_buf, need);
        if (!newbuf) return false;
        _ssl_rx_buf = newbuf;
        _ssl_rx_buf_capacity = need;
    }
    memcpy(_ssl_rx_buf + _ssl_rx_buf_len, data, len);
    _ssl_rx_buf_len += len;
    return true;
}

int AsyncTCPTLS::startSSLClientInsecure(tcp_pcb *pcb, const char *host_or_ip) {
    return _startSSLClient(pcb, host_or_ip,
        NULL, 0,
        NULL, 0,
        NULL, 0,
        NULL, NULL);
}

int AsyncTCPTLS::startSSLClient(tcp_pcb *pcb, const char *host_or_ip,
        const char *pskIdent, const char *psKey) {
    return _startSSLClient(pcb, host_or_ip,
        NULL, 0,
        NULL, 0,
        NULL, 0,
        pskIdent, psKey);
}

int AsyncTCPTLS::startSSLClient(tcp_pcb *pcb, const char *host_or_ip,
        const char *rootCABuff,
        const char *cli_cert,
        const char *cli_key,
        const char *keyPassword) {
    return startSSLClient(pcb, host_or_ip,
        (const unsigned char *)rootCABuff, (rootCABuff != NULL) ? strlen(rootCABuff) + 1 : 0,
        (const unsigned char *)cli_cert, (cli_cert != NULL) ? strlen(cli_cert) + 1 : 0,
        (const unsigned char *)cli_key, (cli_key != NULL) ? strlen(cli_key) + 1 : 0,
        keyPassword);
}

int AsyncTCPTLS::startSSLClient(tcp_pcb *pcb, const char *host_or_ip,
        const unsigned char *rootCABuff, const size_t rootCABuff_len,
        const unsigned char *cli_cert, const size_t cli_cert_len,
        const unsigned char *cli_key, const size_t cli_key_len,
        const char *keyPassword) {
    return _startSSLClient(pcb, host_or_ip,
        rootCABuff, rootCABuff_len,
        cli_cert, cli_cert_len,
        cli_key, cli_key_len,
        NULL, NULL,
        keyPassword);
}

int AsyncTCPTLS::_startSSLClient(tcp_pcb *pcb, const char *host_or_ip,
        const unsigned char *rootCABuff, const size_t rootCABuff_len,
        const unsigned char *cli_cert, const size_t cli_cert_len,
        const unsigned char *cli_key, const size_t cli_key_len,
        const char *pskIdent, const char *psKey,
        const char *keyPassword) {
    int ret;

    if (!pcb) {
        return -1;
    }

    async_tcp_log_v("Setting up the SSL/TLS structure...");

    if ((ret = mbedtls_ssl_config_defaults(&ssl_conf,
                                           MBEDTLS_SSL_IS_CLIENT,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        return handle_error(ret);
    }

    // Force TLS 1.2 only
    mbedtls_ssl_conf_min_tls_version(&ssl_conf, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_max_tls_version(&ssl_conf, MBEDTLS_SSL_VERSION_TLS1_2);

    // Disable renegotiation
#if defined(MBEDTLS_SSL_RENEGOTIATION)
    mbedtls_ssl_conf_renegotiation(&ssl_conf, MBEDTLS_SSL_RENEGOTIATION_DISABLED);
#endif

    // Pin fast cipher suite — hardware-accelerated AES-GCM + SHA256 on ESP32
    static const int client_ciphersuites[] = {
        MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        0
    };
    mbedtls_ssl_conf_ciphersuites(&ssl_conf, client_ciphersuites);

    if (rootCABuff != NULL) {
        async_tcp_log_v("Loading CA cert");
        mbedtls_x509_crt_init(&ca_cert);
        mbedtls_ssl_conf_authmode(&ssl_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
        ret = mbedtls_x509_crt_parse(&ca_cert, rootCABuff, rootCABuff_len);
        _have_ca_cert = true;
        mbedtls_ssl_conf_ca_chain(&ssl_conf, &ca_cert, NULL);
        if (ret < 0) {
            _deleteHandshakeCerts();
            return handle_error(ret);
        }
    } else if (pskIdent != NULL && psKey != NULL) {
#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED) || defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
        async_tcp_log_v("Setting up PSK");
        if ((strlen(psKey) & 1) != 0 || strlen(psKey) > 2 * MBEDTLS_PSK_MAX_LEN) {
            async_tcp_log_e("pre-shared key not valid hex or too long");
            return -1;
        }
        unsigned char psk[MBEDTLS_PSK_MAX_LEN];
        size_t psk_len = strlen(psKey) / 2;
        for (size_t j = 0; j < strlen(psKey); j += 2) {
            char c = psKey[j];
            if (c >= '0' && c <= '9') c -= '0';
            else if (c >= 'A' && c <= 'F') c -= 'A' - 10;
            else if (c >= 'a' && c <= 'f') c -= 'a' - 10;
            else return -1;
            psk[j / 2] = c << 4;
            c = psKey[j + 1];
            if (c >= '0' && c <= '9') c -= '0';
            else if (c >= 'A' && c <= 'F') c -= 'A' - 10;
            else if (c >= 'a' && c <= 'f') c -= 'a' - 10;
            else return -1;
            psk[j / 2] |= c;
        }
        ret = mbedtls_ssl_conf_psk(&ssl_conf, psk, psk_len,
                (const unsigned char *)pskIdent, strlen(pskIdent));
        mbedtls_platform_zeroize(psk, sizeof(psk));
        if (ret != 0) {
            async_tcp_log_e("mbedtls_ssl_conf_psk returned %d", ret);
            return handle_error(ret);
        }
#else
        async_tcp_log_e("PSK ciphersuites not enabled in mbedTLS config");
        return -1;
#endif
    } else {
        // No CA cert, no PSK — skip server verification
        mbedtls_ssl_conf_authmode(&ssl_conf, MBEDTLS_SSL_VERIFY_NONE);
        async_tcp_log_i("WARNING: Skipping SSL Verification. INSECURE!");
    }

    if (rootCABuff != NULL && cli_cert != NULL && cli_key != NULL) {
        mbedtls_x509_crt_init(&client_cert);
        mbedtls_pk_init(&client_key);

        async_tcp_log_v("Loading CRT cert");
        ret = mbedtls_x509_crt_parse(&client_cert, cli_cert, cli_cert_len);
        _have_client_cert = true;
        if (ret < 0) {
            _deleteHandshakeCerts();
            return handle_error(ret);
        }

        async_tcp_log_v("Loading private key");
        if (_ssl_key_password) { free((void*)_ssl_key_password); _ssl_key_password = NULL; }
        _ssl_key_password = keyPassword ? strdup(keyPassword) : NULL;
        const unsigned char *pwd = (const unsigned char *)_ssl_key_password;
        size_t pwd_len = _ssl_key_password ? strlen(_ssl_key_password) : 0;
        ret = _parse_private_key(&client_key, cli_key, cli_key_len, pwd, pwd_len);
        _have_client_key = true;
        if (ret != 0) {
            _deleteHandshakeCerts();
            return handle_error(ret);
        }

        mbedtls_ssl_conf_own_cert(&ssl_conf, &client_cert, &client_key);
    }

    async_tcp_log_v("Setting hostname for TLS session...");
    if (!host_or_ip || strlen(host_or_ip) > 253) {
        _deleteHandshakeCerts();
        async_tcp_log_e("Invalid hostname (too long or NULL)");
        return -1;
    }
    if ((ret = mbedtls_ssl_set_hostname(&ssl_ctx, host_or_ip)) != 0) {
        _deleteHandshakeCerts();
        return handle_error(ret);
    }

#if ASYNCTCP_MBEDTLS_MAJOR < 4
    mbedtls_ssl_conf_rng(&ssl_conf, mbedtls_ctr_drbg_random, &drbg_ctx);
#endif

    // Reduce buffer sizes to fit ESP32 heap (requires MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
    mbedtls_ssl_conf_max_frag_len(&ssl_conf, MBEDTLS_SSL_MAX_FRAG_LEN_4096);
#endif

    if ((ret = mbedtls_ssl_setup(&ssl_ctx, &ssl_conf)) != 0) {
        _deleteHandshakeCerts();
        return handle_error(ret);
    }

    _pcb = pcb;
    // Set BIO: ctx is this context (used by both send and recv callbacks)
    mbedtls_ssl_set_bio(&ssl_ctx, this, _lwip_ssl_send, _lwip_ssl_recv, NULL);
    handshake_start_time = 0;

    return 0;
}

int AsyncTCPTLS::startSSLServer(tcp_pcb *pcb,
        const unsigned char *server_cert, size_t server_cert_len,
        const unsigned char *server_key, size_t server_key_len,
        const char *password) {
    int ret;

    if (server_cert == NULL || server_key == NULL || !pcb) {
        return -1;
    }

    if (_ssl_key_password) { free((void*)_ssl_key_password); _ssl_key_password = NULL; }
    _ssl_key_password = password ? strdup(password) : NULL;

    async_tcp_log_v("Seeding the random number generator (server)");

    async_tcp_log_v("Setting up the SSL/TLS structure (server)...");

    if ((ret = mbedtls_ssl_config_defaults(&ssl_conf,
                                           MBEDTLS_SSL_IS_SERVER,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        return handle_error(ret);
    }

    // Force TLS 1.2 only
    mbedtls_ssl_conf_min_tls_version(&ssl_conf, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_max_tls_version(&ssl_conf, MBEDTLS_SSL_VERSION_TLS1_2);

    // Disable renegotiation (only available if MBEDTLS_SSL_RENEGOTIATION is enabled)
#if defined(MBEDTLS_SSL_RENEGOTIATION)
    mbedtls_ssl_conf_renegotiation(&ssl_conf, MBEDTLS_SSL_RENEGOTIATION_DISABLED);
#endif

    // Pin fast cipher suite — hardware-accelerated AES-GCM + SHA256 on ESP32
    static const int server_ciphersuites[] = {
        MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        0
    };
    mbedtls_ssl_conf_ciphersuites(&ssl_conf, server_ciphersuites);

    // Self-signed cert — no client certificate verification
    mbedtls_ssl_conf_authmode(&ssl_conf, MBEDTLS_SSL_VERIFY_NONE);

    // Load server certificate
    mbedtls_x509_crt_init(&client_cert);

    if (server_cert_len >= 11 && memcmp(server_cert, "-----BEGIN ", 11) == 0) {
        // PEM — make a NUL-terminated copy (mbedtls_pem_read_buffer requires it)
        async_tcp_log_v("Parsing cert PEM (%u bytes)", (unsigned)server_cert_len);
        char *pem_buf = (char *)malloc(server_cert_len + 1);
        if (!pem_buf) {
            _deleteHandshakeCerts();
            return handle_error(MBEDTLS_ERR_SSL_ALLOC_FAILED);
        }
        memcpy(pem_buf, server_cert, server_cert_len);
        pem_buf[server_cert_len] = '\0';
        mbedtls_pem_context pem;
        mbedtls_pem_init(&pem);
        size_t use_len = 0;
        size_t cert_der_len = 0;
        ret = mbedtls_pem_read_buffer(&pem,
            "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----",
            (const unsigned char *)pem_buf, NULL, 0, &use_len);
        if (ret == 0) {
            const unsigned char *der_buf = mbedtls_pem_get_buffer(&pem, &cert_der_len);
            ret = mbedtls_x509_crt_parse(&client_cert, der_buf, cert_der_len);
        }
        mbedtls_pem_free(&pem);
        free(pem_buf);
    } else {
        // DER — parse directly with length
        async_tcp_log_v("Parsing cert DER (%u bytes)", (unsigned)server_cert_len);
        ret = mbedtls_x509_crt_parse(&client_cert, server_cert, server_cert_len);
    }
    _have_client_cert = true;
    if (ret < 0) {
        _deleteHandshakeCerts();
        return handle_error(ret);
    }

    // Load server private key
    mbedtls_pk_init(&client_key);

    if (server_key_len >= 11 && memcmp(server_key, "-----BEGIN ", 11) == 0) {
        // PEM — make a NUL-terminated copy
        async_tcp_log_v("Parsing key PEM (%u bytes)", (unsigned)server_key_len);
        char *pem_buf = (char *)malloc(server_key_len + 1);
        if (!pem_buf) {
            _deleteHandshakeCerts();
            return handle_error(MBEDTLS_ERR_SSL_ALLOC_FAILED);
        }
        memcpy(pem_buf, server_key, server_key_len);
        pem_buf[server_key_len] = '\0';
        mbedtls_pem_context pem;
        mbedtls_pem_init(&pem);
        size_t use_len = 0;
        size_t key_der_len = 0;
        const unsigned char *pwd = (const unsigned char *)_ssl_key_password;
        size_t pwd_len = _ssl_key_password ? strlen(_ssl_key_password) : 0;

        const char *key_header, *key_footer;
        if (strncmp(pem_buf, "-----BEGIN ENCRYPTED PRIVATE KEY-----", 37) == 0) {
            key_header = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
            key_footer = "-----END ENCRYPTED PRIVATE KEY-----";
        } else if (strncmp(pem_buf, "-----BEGIN PRIVATE KEY-----", 27) == 0) {
            key_header = "-----BEGIN PRIVATE KEY-----";
            key_footer = "-----END PRIVATE KEY-----";
        } else {
            key_header = "-----BEGIN RSA PRIVATE KEY-----";
            key_footer = "-----END RSA PRIVATE KEY-----";
        }
        ret = mbedtls_pem_read_buffer(&pem, key_header, key_footer,
            (const unsigned char *)pem_buf, pwd, pwd_len, &use_len);
        if (ret == 0) {
            const unsigned char *der_buf = mbedtls_pem_get_buffer(&pem, &key_der_len);
            ret = _parse_private_key(&client_key, der_buf, key_der_len,
                pwd, pwd_len);
        }
        mbedtls_pem_free(&pem);
        free(pem_buf);
    } else {
        // DER — parse directly with length
        async_tcp_log_v("Parsing key DER (%u bytes)", (unsigned)server_key_len);
        ret = _parse_private_key(&client_key, server_key, server_key_len,
            NULL, 0);
    }
    _have_client_key = true;
    if (ret != 0) {
        _deleteHandshakeCerts();
        return handle_error(ret);
    }

    mbedtls_ssl_conf_own_cert(&ssl_conf, &client_cert, &client_key);

#if ASYNCTCP_MBEDTLS_MAJOR < 4
    mbedtls_ssl_conf_rng(&ssl_conf, mbedtls_ctr_drbg_random, &drbg_ctx);
#endif

#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
    mbedtls_ssl_conf_max_frag_len(&ssl_conf, MBEDTLS_SSL_MAX_FRAG_LEN_4096);
#endif

    if ((ret = mbedtls_ssl_setup(&ssl_ctx, &ssl_conf)) != 0) {
        _deleteHandshakeCerts();
        return handle_error(ret);
    }

    _pcb = pcb;
    mbedtls_ssl_set_bio(&ssl_ctx, this, _lwip_ssl_send, _lwip_ssl_recv, NULL);
    handshake_start_time = 0;
    handshake_timeout = SSL_HANDSHAKE_TIMEOUT;

    return 0;
}

int AsyncTCPTLS::runSSLHandshake(void) {
    int ret, flags;

    if (!_pcb) return -1;

    if (handshake_start_time == 0) handshake_start_time = millis();
    ret = mbedtls_ssl_handshake(&ssl_ctx);
    if (ret != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            return handle_error(ret);
        }
        if ((millis() - handshake_start_time) > handshake_timeout)
            return -1;
        return ret;
    }

    async_tcp_log_d("TLS handshake done: %s / %s",
        mbedtls_ssl_get_version(&ssl_ctx), mbedtls_ssl_get_ciphersuite(&ssl_ctx));

    async_tcp_log_v("Verifying peer X.509 certificate...");

    flags = mbedtls_ssl_get_verify_result(&ssl_ctx);
    if (flags != 0) {
        char buf[512];
        memset(buf, 0, sizeof(buf));
        mbedtls_x509_crt_verify_info(buf, sizeof(buf), "  ! ", flags);
        if (strstr(buf, "skipped") != NULL) {
            async_tcp_log_v("Certificate verification was skipped (expected for self-signed server): %s", buf);
        } else {
            async_tcp_log_e("Failed to verify peer certificate! verification info: %s", buf);
            return handle_error(-1);
        }
    } else {
        async_tcp_log_v("Certificate verified.");
    }

    async_tcp_log_v("Free internal heap after TLS %u", ESP.getFreeHeap());

    return 0;
}

int AsyncTCPTLS::write(const uint8_t *data, size_t len) {
    if (!_pcb) return -1;

    int ret = mbedtls_ssl_write(&ssl_ctx, data, len);
    if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE && ret < 0) {
        return handle_error(ret);
    }
    return ret;
}

int AsyncTCPTLS::read(uint8_t *data, size_t len) {
    if (!_ssl_rx_buf || _ssl_rx_pos >= _ssl_rx_buf_len) return 0;
    size_t avail = _ssl_rx_buf_len - _ssl_rx_pos;
    size_t copy = (avail < len) ? avail : len;
    memcpy(data, _ssl_rx_buf + _ssl_rx_pos, copy);
    _ssl_rx_pos += copy;
    // Reset buffer when all consumed (TCP ack already done in _recv)
    if (_ssl_rx_pos >= _ssl_rx_buf_len) {
        _ssl_rx_buf_len = 0;
        _ssl_rx_pos = 0;
    }
    return (int)copy;
}

int AsyncTCPTLS::sslRead(uint8_t *data, size_t len) {
    if (!_pcb) return -1;
    int ret = mbedtls_ssl_read(&ssl_ctx, data, len);
    if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
        return 0;
    }
    if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
        async_tcp_log_i("SSL peer close notify");
        return 0;
    }
    if (ret == MBEDTLS_ERR_SSL_CONN_EOF) {
        return 0;
    }
    if (ret < 0) {
        async_tcp_log_e("mbedtls_ssl_read failed: -0x%04x", -ret);
        logBioState("sslRead");
        return -1;
    }
    return ret;
}

void AsyncTCPTLS::logBioState(const char *tag) const {
    async_tcp_log_e("%s: rx_buf=%u/%u pos=%u rxBufLen=%u bytes_avail=%d",
        tag, (unsigned)_ssl_rx_buf_len, (unsigned)_ssl_rx_buf_capacity,
        (unsigned)_ssl_rx_pos, (unsigned)(_ssl_rx_buf_len - _ssl_rx_pos),
        (int)mbedtls_ssl_get_bytes_avail((mbedtls_ssl_context *)&ssl_ctx));
}

void AsyncTCPTLS::sendCloseNotify(void) {
    if (!_pcb) return;
    int ret = mbedtls_ssl_close_notify(&ssl_ctx);
    if (ret != 0) {
        async_tcp_log_d("close_notify: %d", ret);
    }
}

void AsyncTCPTLS::_deleteHandshakeCerts(void) {
    if (_have_ca_cert) {
        async_tcp_log_v("Cleaning CA certificate.");
        mbedtls_ssl_conf_ca_chain(&ssl_conf, NULL, NULL);
        mbedtls_x509_crt_free(&ca_cert);
        _have_ca_cert = false;
    }
    if (_have_client_cert) {
        async_tcp_log_v("Cleaning client certificate.");
        mbedtls_ssl_conf_own_cert(&ssl_conf, NULL, NULL);
        mbedtls_x509_crt_free(&client_cert);
        _have_client_cert = false;
    }
    if (_have_client_key) {
        async_tcp_log_v("Cleaning client certificate key.");
        mbedtls_pk_free(&client_key);
        _have_client_key = false;
    }
}

#endif // ASYNC_TCP_SSL_ENABLED
// ===== end mbedTLS/ESP32 AsyncTCPTLS.cpp =====
#endif
