// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright 2016-2026 Hristo Gochkov, Mathieu Carbou, Emil Muratov, Will Miles
//
// Unified dual-stack AsyncTCP. TLS engine.
//   - ESP8266         -> BearSSL stack (AsyncTCP fork, NO_SYS lwIP)
//   - ESP32/LIBRETINY -> mbedTLS stack (AsyncTCP ESP32Async base)
// Selected at compile time via #if defined(ESP8266). Only one stack compiles per target.
#pragma once

#if defined(ESP8266)
// ===== begin BearSSL/ESP8266 AsyncTCPTLS.h (AsyncTCP) =====

// --- SSL configuration ---
// TLS support is enabled when this is set to 1. Both TLS client and server
// glue are always compiled and linked when enabled (they live in the
// separate ESP8266AsyncTCPClient.cpp / ESP8266AsyncTCPServer.cpp files,
// selected by including the matching header — the headers do not gate
// compilation).
#ifndef ASYNC_TCP_SSL_ENABLED
#define ASYNC_TCP_SSL_ENABLED 0
#endif

// Outbound TLS *client* role. BearSSL's client glue (ESP8266AsyncTCPClient.cpp)
// and the entire client crypto chain (x509 verify, client ECDHE, client RSA/EC
// suites, br_ssl_client_context) is only compiled+linked when this is 1.
//
// For a server-only TLS device (e.g. this plant serving its HTTPS config page)
// the client chain is never exercised, so defaulting this to 0 lets the linker
// --gc-sections dead-strip the whole client crypto footprint from the build.
// Projects that open outbound TLS connections (AsyncClient::connectSecure /
// setSSLContext) must define ASYNC_TCP_SSL_ENABLE_CLIENT=1.
#ifndef ASYNC_TCP_SSL_ENABLE_CLIENT
#define ASYNC_TCP_SSL_ENABLE_CLIENT 1
#endif

// TLS *server* role. The server glue (ESP8266AsyncTCPServer.cpp) and the whole
// server crypto chain (cert/private-key parsing, session cache, br_ssl_server_context)
// is only compiled+linked when this is 1.
//
// Defaults to 1 so the common server-only HTTPS device (this plant) links the
// server role out of the box. A client-only project sets ASYNC_TCP_SSL_ENABLE_SERVER=0
// (and ASYNC_TCP_SSL_ENABLE_CLIENT=1) to let --gc-sections strip the unused server
// crypto footprint.
#ifndef ASYNC_TCP_SSL_ENABLE_SERVER
#define ASYNC_TCP_SSL_ENABLE_SERVER 1
#endif

#ifndef TCP_SSL_HANDSHAKE_TIMEOUT
#define TCP_SSL_HANDSHAKE_TIMEOUT 2000
#endif

#ifndef TCP_SSL_FINGERPRINT_SIZE
#define TCP_SSL_FINGERPRINT_SIZE 20
#endif

// Inbound I/O buffer. MUST fit the largest inbound TLS record: the browser's
// ClientHello measures 1856 ciphertext + 5-byte TLS header + AEAD tag = ~1870
// on the wire. The old 1349 dropped the record tail (tcp_ssl_read overflow ->
// spurious "TLS alert [-1]" on EVERY handshake) because the on-demand growth
// machinery (ASYNC_TCP_SSL_MAX_IN_BUFFER_SIZE) is declared but not implemented.
#ifndef ASYNC_TCP_SSL_IN_BUFFER_SIZE
#define ASYNC_TCP_SSL_IN_BUFFER_SIZE 2048
#endif

// Ceiling for on-demand inbound-buffer growth. Tied to BearSSL's maximum TLS
// record: 16384 plaintext + MAX_IN_OVERHEAD(325) ciphertext + 5 header = 16714.
// Buffers start at ASYNC_TCP_SSL_IN_BUFFER_SIZE (affordable for every TLS
// connection) and are realloc'd up to this ceiling only when a large inbound
// record (e.g. a firmware upload) actually arrives, then shrunk back.
#ifndef ASYNC_TCP_SSL_MAX_IN_BUFFER_SIZE
#define ASYNC_TCP_SSL_MAX_IN_BUFFER_SIZE 16768
#endif

#ifndef ASYNC_TCP_SSL_OUT_BUFFER_SIZE
#define ASYNC_TCP_SSL_OUT_BUFFER_SIZE 1109
#endif

// App-data multi-record no-copy ring: each connection keeps this many outbound
// record slots in its slab so K TLS records can be in flight per RTT with ZERO
// per-record heap (ring bytes live in the slab; tcp_write eats only small heap
// header pbufs + pooled memp TCP_SEG/PBUF_ROM). K=2 doubles the baseline
// one-record-in-flight rate but adds +1109B/conn slab. Measured at PARKED_SLOTS=1
// with idle heap ~7.7KB, the K=2 slab (~6.3KB) + the web response buffer
// (2*TCP_MSS ~2.9KB) exceeds the serve budget mid-response: SENDREC hard-stall
// (tcp_write ERR_MEM, open window, empty queue, freeheap~1KB largest~700B).
// K=1 restores the smaller ~5.2KB slab so the serve window keeps enough free
// heap for the response buffer + LittleFS + the small per-segment pbuf headers.
// Reverted for the same reason the K>2 experiment was: big slabs starve the
// heavily-churned arena during refresh bursts.
#ifndef ASYNC_TCP_SSL_RECORD_RING_SLOTS
#define ASYNC_TCP_SSL_RECORD_RING_SLOTS 1
#endif

// One contiguous allocation backing all per-conn buffers (inbuf + K-slot
// record ring + record-reassembly accumulator). One malloc needs one big hole
//  (~5.2KB at K=1) instead of three separate allocs that each had to find a slot in a
// churned heap (a 7KB arena with a 2.7KB max hole can never serve two 2KB
// allocs at once). The admission BLOCK bar (ASYNC_TCP_SSL_SERVE_BLOCK) then
// checks for one contiguous slab rather than a fragmented set of holes.
#ifndef ASYNC_TCP_SSL_OUT_BUFFER_REGION
#define ASYNC_TCP_SSL_OUT_BUFFER_REGION \
  (ASYNC_TCP_SSL_RECORD_RING_SLOTS * ASYNC_TCP_SSL_OUT_BUFFER_SIZE)
#endif
#ifndef ASYNC_TCP_SSL_BUFFER_SLAB
#define ASYNC_TCP_SSL_BUFFER_SLAB \
  (ASYNC_TCP_SSL_IN_BUFFER_SIZE + ASYNC_TCP_SSL_OUT_BUFFER_REGION + ASYNC_TCP_SSL_IN_BUFFER_SIZE)
#endif

// Force server-side MFLN (RFC 6066 max_fragment_length). When non-zero, every
// outbound TLS record's plaintext (including the handshake Certificate flight)
// is capped at this many bytes via br_ssl_engine_new_max_frag_len(). Setting it
// below the handshake flight size will break the handshake.
#ifndef ASYNC_TCP_SSL_SERVER_MFLN
#define ASYNC_TCP_SSL_SERVER_MFLN 1024
#endif

// How long a connection may sit in a HARD SENDREC stall (open send window +
// empty pbuf queue but tcp_write still failing) before AsyncClient::_poll
// resets it. The poll runs every TCP_POLL_INTERVAL (~500ms); 5000ms gives a
// transient pool-pressure spike a generous window to clear (e.g. another
// connection being reset) before we conclude the connection is genuinely
// wedged and tear it down for a browser retry.
#ifndef ASYNC_TCP_SSL_STALL_RESET_MS
#define ASYNC_TCP_SSL_STALL_RESET_MS 5000
#endif

// How long each parked queue slot may pin its buffered RX pbufs with the live
// conn still up; past this the slot is shed so the browser can retry. Must
// comfortably exceed the time to serve the FIFO queue ahead of a parked conn
// (several assets under a burst), else legitimate queued requests are RST'd.
#ifndef ASYNC_TCP_SSL_QUEUE_IDLE_MS
#define ASYNC_TCP_SSL_QUEUE_IDLE_MS 20000
#endif

// Depth of the parked-conn queue. Under a Firefox burst the browser opens ~6
// parallel conns per host; every extra parked slot lets one more sub-resource
// survive the RST-cyclone instead of dying and retrying. 1 slot refused the
// burst beyond the single live conn (`queue busy (1/1)`), RSTing script tags
// like index.js which browsers do NOT auto-retry -> permanent NS_RESET. Parked
// conns cost a tcp_pcb (~400B, memp pool) + buffered inbound pbufs up to
// PARKED_RX_CAP, and a parked conn's request is small (~600B INREC accum in
// practice), so 4 slots absorb a full page burst at ~2-3KB heap. Slots are
// promoted FIFO one-at-a-time as the live conn frees; SERVE_HEAP still gates
// each promotion, so the pool bank never spikes beyond what the heap admits.
#ifndef ASYNC_TCP_SSL_PARKED_SLOTS
#define ASYNC_TCP_SSL_PARKED_SLOTS 4
#endif

// Max inbound bytes a PARKED conn may buffer into system heap before its excess
// is left in lwIP's recv window instead. Bounds the browser-burst heap pin: a
// parked conn's full HTTP request (~6KB) must not sit in heap pbufs for the
// whole live serve (crushes freeheap, stalls the next handshake). One TLS
// ClientHello (max ~1.9KB) is all a parked conn needs staged to resume cleanly;
// anything larger waits in the kernel on pooled pbufs.
#ifndef ASYNC_TCP_SSL_PARKED_RX_CAP
#define ASYNC_TCP_SSL_PARKED_RX_CAP 2000
#endif

// Single admission bar. With nothing live, a fresh TLS conn (or a queued
// slot promotion) is served whenever free heap clears this; below it the
// conn is refused for a browser retry. The earlier 10000 "serve bar" sat
// above the device's real idle floor (~9.9KB) and refused the page forever,
// so the bar is now the critical floor, not a comfort threshold — serving
// below 10KB works (full working set ~7.7KB + handshake transient).
#ifndef ASYNC_TCP_SSL_CRITICAL_HEAP
#define ASYNC_TCP_SSL_CRITICAL_HEAP 4096
#endif

// Serve/promote admission bar. Distinct from CRITICAL_HEAP (the read-defer
  // floor): the ctor of a server TLS conn allocs one contiguous buffer slab
  // (ASYNC_TCP_SSL_BUFFER_SLAB ~5.2KB with the K=1 record ring) plus ~450B
  // ctx/AsyncClient/small structs,
// so gating on getFreeHeap() alone lets serve attempts start with a fragmented
// heap and then fail every alloc. Two guards: HEAP (total free below = refuse)
// and BLOCK (no single >= slab-sized contiguous hole = refuse). With the
// single-live-conn parking policy, promote happens only after the previous
// conn's slab is already freed, so the pool usually shows a big reclaimed
  // hole; when the freed slab doesn't coalesce upward it sits alone at
  // slab+header  (~5190) and BLOCK (== slab size) still admits it. Conns that
// miss either bar stay queued and shed on idle instead of rattling failed
// allocs.
#ifndef ASYNC_TCP_SSL_SERVE_HEAP
#define ASYNC_TCP_SSL_SERVE_HEAP 8500
#endif
#ifndef ASYNC_TCP_SSL_SERVE_BLOCK
/* Minimum CONTIGUOUS free block to admit a serve: exactly the whole slab, the
   only per-conn big alloc. Keeping it AT the slab size (NOT slab+margin) is
   load-bearing: after a conn closes without its slab coalescing upward, the
   freed hole alone sits at slab+UMM_header  (~5190) and UMM first-fit reuses
   it in place for the NEXT ctor. A bar of slab+~200 deadlocks instead — it
   refuses EVERY subsequent conn while maxblock is at 6338 ("critical,
   refusing" spam; a multi-file page loads n-1 conns then freezes). The other
   ctor allocs (~450B AsyncClient/ctx + transient request machinery) live in
   surrounding small holes; SERVE_HEAP (8.5K total-free) guarantees enough of
   those. This bar is the CONTIGUITY guard only. */
#define ASYNC_TCP_SSL_SERVE_BLOCK ASYNC_TCP_SSL_BUFFER_SLAB
#endif

// BearSSL server-side session cache (TLS session resumption). Count and
// per-entry size of the static LRU session store; 10 x 100 B = 1KB of DRAM,
// allocated once with the server ctx. A browser reconnecting on a new
// connection with a cached session ID gets an abbreviated handshake (one
// extra RTT) instead of the full RSA/ECDHE flight, cutting handshake heap
// churn. 0 disables resumption.
#ifndef ASYNC_TCP_SSL_SESSION_CACHE_ENTRIES
#define ASYNC_TCP_SSL_SESSION_CACHE_ENTRIES 10
#endif
#ifndef ASYNC_TCP_SSL_SESSION_CACHE_ENTRY_SIZE
#define ASYNC_TCP_SSL_SESSION_CACHE_ENTRY_SIZE 100
#endif

#ifndef ASYNC_TCP_SSL_X509_MODE
// 0: secure (full cert validation)  1: insecure (skip validation)
// 2: fingerprint (SHA1 match)      3: self-signed (issuer == subject)
// 4: known key (public key match)
#define ASYNC_TCP_SSL_X509_MODE 0
#endif

const int ASYNC_TCP_SSL_MAX_FEED_LOOPS = 10;

#include <bearssl/bearssl.h>
#include <bearssl/bearssl_ssl.h>
#include <bearssl/bearssl_x509.h>

#include <vector>

// FORWARD DECLARE lwIP types to avoid including lwip/tcp.h in a public header
struct tcp_pcb;
struct pbuf;

// Opaque SSL type — only ever used as pointer
struct SSL {};  // Opaque type used by API callbacks (matches reference)

// Private-key parser comes from the ESP8266 core's built-in BearSSL (namespace
// BearSSL), included via <ESP8266WiFi.h>/<BearSSLHelpers.h> in the .cpp TU.
namespace BearSSL { class PrivateKey; }

// A wrapper to make BearSSL contexts usable as an opaque SSL context
struct BearSSL_SSL_CTX {
  // The server role owns the parsed cert chain, private key, and session
  // cache. These fields only exist when the server role is compiled in
  // (ASYNC_TCP_SSL_ENABLE_SERVER); the client role never populates them.
#if ASYNC_TCP_SSL_ENABLE_SERVER
  // We will parse the chain into a vector of C structs ourselves
  std::vector<br_x509_certificate> chain_vector;
  BearSSL::PrivateKey* pk = nullptr;

  // Shared server engine: init'ed once at ctx build, reused per connection via
  // br_ssl_server_reset() in tcp_ssl_new_server(). The single-connection gate
  // ensures no two conns share it at once. Saves ~4 KB of per-conn allocations.
  br_ssl_server_context server_ctx;

  // --- TLS session cache (session resumption) ---
  // Shared across every connection accepted by this SSL server, so a browser
  // reconnecting with the same session ID skips the expensive RSA/ECDHE
  // handshake and completes an abbreviated one (single extra RTT).
  // Initialized once in tcp_ssl_new_server_ctx(); each LRU entry is 100 B.
  br_ssl_session_cache_lru session_cache;
  unsigned char session_store[ASYNC_TCP_SSL_SESSION_CACHE_ENTRIES * ASYNC_TCP_SSL_SESSION_CACHE_ENTRY_SIZE];
#endif

  ~BearSSL_SSL_CTX();
};

// BearSSL doesn't define a true insecure decoder, so we make one ourselves
// from the simple parser.  It generates the subject hash and the SHA1
// fingerprint, only one (or none!) of which will be used to "verify" the
// certificate.  BearSSL 0.6 removed the separate issuer DN callback; in
// insecure mode we simply accept any certificate.
// Private x509 decoder state
#if ASYNC_TCP_SSL_ENABLE_CLIENT
typedef struct {
  const br_x509_class *vtable;
  bool done_cert;
  const uint8_t *match_fingerprint;
  br_sha1_context sha1_cert;
  bool allow_self_signed;
  br_sha256_context sha256_subject;
  br_sha256_context sha256_issuer;
  br_x509_decoder_context ctx;
} x509_insecure_context;
#endif

// Callback types for the BearSSL glue layer
typedef void (*tcp_ssl_data_cb_t)(void* arg, struct tcp_pcb* tcp, uint8_t* data, size_t len);
typedef void (*tcp_ssl_handshake_cb_t)(void* arg, struct tcp_pcb* tcp, SSL* ssl);
typedef void (*tcp_ssl_error_cb_t)(void* arg, struct tcp_pcb* tcp, int8_t err);

// Per-connection state for a BearSSL session.
// Shared between the core (ESP8266AsyncTCPTLS.cpp) and the role-specific
// files (ESP8266AsyncTCPClient.cpp / ESP8266AsyncTCPServer.cpp).
struct tcp_ssl_pcb {
  struct tcp_pcb* tcp;
  // Role-specific BearSSL context, heap-allocated by tcp_ssl_new_client /
  // tcp_ssl_new_server. Only the active role's context is allocated; the
  // other pointer stays null. Each context embeds its engine as its first
  // member, so br_ssl_engine_context* is always &ctx->eng.
  // The client context field only exists when the client role is compiled in;
  // a server-only build (ASYNC_TCP_SSL_ENABLE_CLIENT=0) has only sc_server so
  // the dead client crypto chain stays out of the link.
#if ASYNC_TCP_SSL_ENABLE_CLIENT
  br_ssl_client_context* sc_client;  // allocated when !is_server
  x509_insecure_context *insecure_x509;  // accept-any x509 when rootCA==NULL (owned)
#endif
#if ASYNC_TCP_SSL_ENABLE_SERVER
  br_ssl_server_context* sc_server;  // borrowed: &BearSSL_SSL_CTX::server_ctx when is_server (never owned)
#endif
  // --- SINGLE-CONTIGUOUS-BUFFER OPTIMIZATION ---
  // inbuf/outbuf/accum live in ONE slab allocation (_slab) so a per-conn
  // buffer needs a single big hole at ctor time instead of three holes.
  unsigned char* _slab;       // base of the contiguous buffer allocation
  unsigned char* inbuf;       // _slab + 0
  unsigned char* outbuf;      // _slab + ASYNC_TCP_SSL_IN_BUFFER_SIZE
  size_t inbuf_cap;           // current allocated size of the inbuf region
  size_t recvrec_accum_cap;   // current allocated size of recvrec_accum region

  // pointers to track app data currently in the inbuf and pending in the outbuf
  unsigned char* in_buf_ptr;
  unsigned char* out_buf_ptr;

  // len of app data currently in the inbuf, and len of pending data in outbuf
  size_t in_len;
  size_t out_len;

  // The accumulator region lives at _slab + IN + OUT_REGION (see alloc).
  unsigned char* recvrec_accum;
  size_t recvrec_accum_len;  // Bytes of data currently in accumulator
  size_t max_rec_len;        // largest inbound TLS record ciphertext length seen

  bool is_server;
  bool handshake_done;

  // Set when a SENDREC record was deferred because the lwIP send window / pbuf
  // queue was full (tcp_write returned ERR_MEM). Cleared once that pending
  // record is successfully transmitted. tcp_ssl_sent() only re-arms the engine
  // when this is set, so ACKs for idle connections don't spam schedule calls.
  bool sendrec_deferred;

  // --- APP-DATA MULTI-RECORD NO-COPY RING ---
  // Each emitted app-data record is copied out of BearSSL's single engine
  // outbuf into a free ring slot, then tcp_write (no-copy, TCP_WRITE_FLAG_COPY=0)
  // pins that slot until the peer ACKs while br_ssl_engine_sendrec_ack lets
  // the engine immediately build the NEXT record into outbuf. This pipelines
  // ASYNC_TCP_SSL_RECORD_RING_SLOTS records per RTT with no per-record heap.
  // Handshake records ride the SAME ring (no COPY — the ring keeps even
  // handshake flights out of the fragmented heap; no app data exists mid-
  // handshake so both slots are free for the flight). Slots free FIFO
  // in tcp_ssl_sent() as ciphertext ACKs land (the oldest pinned slot is
  // (out_ring_next - out_ring_pinned + K) % K).
  unsigned char* out_ring[ASYNC_TCP_SSL_RECORD_RING_SLOTS];      // outbuf + i*OUT_BUFFER_SIZE
  uint16_t       out_ring_len[ASYNC_TCP_SSL_RECORD_RING_SLOTS];  // ciphertext bytes in each slot
  uint8_t        out_ring_next;    // next slot to fill (write cursor)
  uint8_t        out_ring_pinned;  // slots currently referencing un-ACKed records
  uint32_t       out_ring_acked;   // CUMULATIVE ciphertext ACKed against the ring (see tcp_ssl_sent);
                                  // lwIP reports ACKed bytes per callback, but a record spanning 2
                                  // segments (1053 > MSS 536) only completes after SEVERAL ACKs each
                                  // smaller than the record, so release must compare a running total,
                                  // not the per-callback delta. Zeroed whenever the ring fully empties.

  // ---- HARD SEND STALL DETECTION ----
  // Timestamp (ms) when this connection entered a "hard" transmit stall: a
  // SENDREC record that tcp_write() could NOT transmit even though the send
  // window is open (tcp_sndbuf >= out_len) and the pbuf queue is empty
  // (tcp_sndqueuelen == 0). In that state no future ACK can arrive to re-arm
  // the deferred record (nothing is on the wire), so the defer would wedge the
  // connection (and pin its ~6KB of TLS buffers) forever. AsyncClient::_poll
  // polls tcp_ssl_is_stalled() and tears the connection down once this has
  // persisted past a timeout, so a pool-exhaustion wedge becomes a bounded
  // stall + browser retry instead of a permanent hang / device OOM.
  // 0 = not currently in a hard defer; non-zero = millis() when the hard defer
  // started. Cleared when a record is successfully transmitted (un-wedged).
  uint32_t hard_defer_start;

  // TRUE once the peer has ACKed at least one app-data record (i.e. the HTTP
  // response body has started streaming to the client). Once the body is
  // underway, a transient hard defer is recoverable (the peer IS ACKing, the
  // queue IS draining) and tearing the connection down would truncate a
  // partially-delivered response the browser cannot recover (it already has
  // Content-Length, so a reset shows as "no 200 / body incomplete"). The
  // hard-stall reset (M18) is therefore only applied while body_started==false
  // — i.e. a connection stuck with ZERO progress (handshake-wedged / first
  // record never ACKed), where reset + browser retry is the correct recovery.
  bool body_started;

  // Callbacks and arguments
  void* arg;
  tcp_ssl_data_cb_t on_data;
  tcp_ssl_handshake_cb_t on_handshake;
  tcp_ssl_error_cb_t on_error;

  SSL dummy_ssl;  // API compatibility
  struct tcp_ssl_pcb* next;

  ~tcp_ssl_pcb() {
    delete[] _slab;  // inbuf/outbuf/recvrec_accum are offsets into this one block
#if ASYNC_TCP_SSL_ENABLE_CLIENT
    delete sc_client;  // safe when null (server role)
#endif
#if ASYNC_TCP_SSL_ENABLE_SERVER
    // sc_server is borrowed (BearSSL_SSL_CTX::server_ctx) — never delete.
#endif
  }
};

// Engine accessor — dedupes the role branching used throughout the engine code.
inline br_ssl_engine_context* tcp_ssl_engine(tcp_ssl_pcb* ssl_pcb) {
#if ASYNC_TCP_SSL_ENABLE_CLIENT && ASYNC_TCP_SSL_ENABLE_SERVER
  return ssl_pcb->is_server ? &ssl_pcb->sc_server->eng : &ssl_pcb->sc_client->eng;
#elif ASYNC_TCP_SSL_ENABLE_CLIENT
  (void)ssl_pcb->is_server;  // client-only build: always the client engine
  return &ssl_pcb->sc_client->eng;
#elif ASYNC_TCP_SSL_ENABLE_SERVER
  (void)ssl_pcb->is_server;  // server-only build: always the server engine
  return &ssl_pcb->sc_server->eng;
#else
  // Degenerate: no TLS role compiled (ASYNC_TCP_SSL_ENABLED=0). tcp_ssl_engine
  // is never reachable in this configuration.
  return nullptr;
#endif
}

// Internal symbols shared between the core TU and the role-specific TUs.
// Not part of the public API — do not call from sketches.
extern tcp_ssl_pcb* tcp_ssl_pcbs;
tcp_ssl_pcb* find_ssl_pcb(struct tcp_pcb* pcb);
tcp_ssl_pcb* tcp_ssl_alloc_pcb(struct tcp_pcb* pcb, bool is_server);
void tcp_ssl_register_pcb(tcp_ssl_pcb* ssl_pcb);
void process_ssl_engine(tcp_ssl_pcb* ssl_pcb);
void schedule_ssl_engine(tcp_ssl_pcb* ssl_pcb);
void tcp_ssl_sent(struct tcp_pcb* pcb, size_t acked);
// Returns true once the connection has been in a "hard" SENDREC stall (open
// send window + empty pbuf queue but tcp_write still failing) for longer than
// stall_ms. AsyncClient::_poll uses this to bound a pool-exhaustion wedge.
bool tcp_ssl_is_stalled(struct tcp_pcb* pcb, uint32_t stall_ms);
// True while the engine still holds a TLS send record that has not reached TCP
// (buffered but deferred, or in flight referencing the no-copy outbuf). Read in
// lwIP callback context — must NOT drive BearSSL. Guards early close from
    // truncating the final record of a response.
bool tcp_ssl_tx_busy(struct tcp_pcb* pcb);

// --- Public glue API (client and server) ---
#if ASYNC_TCP_SSL_ENABLE_SERVER
BearSSL_SSL_CTX* tcp_ssl_new_server_ctx(const char* cert, const char* private_key_file,
                                const char* password);
#endif
#if ASYNC_TCP_SSL_ENABLE_CLIENT
int tcp_ssl_new_client(struct tcp_pcb* pcb, const char* host, const br_x509_class **x509ctx, BearSSL_SSL_CTX *ssl_ctx = nullptr);
#endif
#if ASYNC_TCP_SSL_ENABLE_SERVER
int tcp_ssl_new_server(struct tcp_pcb* pcb, BearSSL_SSL_CTX* ssl_ctx);
#endif
int tcp_ssl_free(struct tcp_pcb* pcb);
size_t tcp_ssl_close(struct tcp_pcb* pcb);

int tcp_ssl_write(struct tcp_pcb* pcb, const uint8_t* data, size_t len);
int tcp_ssl_read(struct tcp_pcb* pcb, struct pbuf* p);

bool tcp_ssl_has(struct tcp_pcb* pcb);
#if ASYNC_TCP_SSL_ENABLE_SERVER
uint8_t tcp_ssl_has_client();
uint8_t tcp_ssl_client_count();
uint8_t tcp_ssl_parked_count();
#endif

void tcp_ssl_arg(struct tcp_pcb* pcb, void* arg);
void tcp_ssl_data(struct tcp_pcb* pcb, tcp_ssl_data_cb_t cb);
void tcp_ssl_handshake(struct tcp_pcb* pcb, tcp_ssl_handshake_cb_t cb);
void tcp_ssl_err(struct tcp_pcb* pcb, tcp_ssl_error_cb_t cb);

const char* tcp_ssl_error_string(int err);

#if ASYNC_TCP_SSL_ENABLE_SERVER
size_t parse_certificates(const char* pem, std::vector<br_x509_certificate>& certs);
#endif

#if ASYNC_TCP_SSL_ENABLE_CLIENT
//  Set up the x509 insecure data structures for BearSSL core to use.
void br_x509_insecure_init(x509_insecure_context* ctx, bool use_fingerprint, const uint8_t* fingerprint, bool allow_self_signed);
#endif
// ===== end BearSSL/ESP8266 AsyncTCPTLS.h =====
#else
// ===== begin mbedTLS/ESP32 AsyncTCPTLS.h (AsyncTCP) =====
#pragma once

#if ASYNC_TCP_SSL_ENABLED

// --- mbedTLS version abstraction -----------------------------------------
// Mbed TLS v3 (stable Arduino core 3.x): legacy entropy + CTR-DRBG RNG.
// Mbed TLS v4 (dev core / ESP-IDF 6.0): PSA Crypto; entropy/ctr_drbg headers
// and app-supplied RNG callbacks were removed.
#include "mbedtls/build_info.h"   // defines MBEDTLS_VERSION_MAJOR on v3/v4
#ifndef MBEDTLS_VERSION_MAJOR
#define MBEDTLS_VERSION_MAJOR 3
#endif
#define ASYNCTCP_MBEDTLS_MAJOR MBEDTLS_VERSION_MAJOR
// -------------------------------------------------------------------------

#include "mbedtls/platform.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#if ASYNCTCP_MBEDTLS_MAJOR < 4
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#endif
#include "mbedtls/error.h"
#include "mbedtls/pem.h"

struct tcp_pcb;

#define ASYNCTCP_TLS_CAN_RETRY(r)   (((r) == MBEDTLS_ERR_SSL_WANT_READ) || ((r) == MBEDTLS_ERR_SSL_WANT_WRITE))
#define ASYNCTCP_TLS_EOF(r)         (((r) == MBEDTLS_ERR_SSL_CONN_EOF) || ((r) == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY))

#define ASYNCTCP_TLS_RX_BUF_SIZE    4096
#define ASYNCTCP_TLS_RX_BUF_MAX     8192

#ifndef SSL_HANDSHAKE_TIMEOUT
#define SSL_HANDSHAKE_TIMEOUT 10000
#endif

#ifndef SSL_MAX_CONNECTIONS
#define SSL_MAX_CONNECTIONS 4
#endif

class AsyncTCPTLS
{
private:
    mbedtls_ssl_context ssl_ctx;
    mbedtls_ssl_config ssl_conf;

    // Shared RNG — initialized once, serialized on async task.
    // v3: legacy entropy + CTR-DRBG. v4: PSA Crypto (no DRBG types).
#if ASYNCTCP_MBEDTLS_MAJOR < 4
    static mbedtls_ctr_drbg_context drbg_ctx;
    static mbedtls_entropy_context entropy_ctx;
#endif
    static bool _conf_initialized;

    static int _rng_init(void);
#if ASYNCTCP_MBEDTLS_MAJOR < 4
    static void _rng_seed_and_set(void);
#endif
    // Parse a PEM/DER private key. v3 supplies the legacy RNG; v4 uses PSA.
    static int _parse_private_key(mbedtls_pk_context *pk,
        const unsigned char *key, size_t keylen,
        const unsigned char *pwd, size_t pwdlen);

    // Concurrent connection tracking
    static int _active_count;

    mbedtls_x509_crt ca_cert;
    mbedtls_x509_crt client_cert;
    mbedtls_pk_context client_key;
    bool _have_ca_cert;
    bool _have_client_cert;
    bool _have_client_key;

    unsigned long handshake_timeout;
    unsigned long handshake_start_time;

    tcp_pcb *_pcb;

    // PEM password for encrypted private keys (owned copy via strdup)
    char *_ssl_key_password;

    // Per-connection encrypted data buffers for BIO callbacks
    unsigned char *_ssl_rx_buf;
    size_t _ssl_rx_buf_capacity;  // current allocation size (grows via realloc)
    size_t _ssl_rx_buf_len;
    size_t _ssl_rx_pos;

    int _startSSLClient(tcp_pcb *pcb, const char *host_or_ip,
        const unsigned char *rootCABuff, const size_t rootCABuff_len,
        const unsigned char *cli_cert, const size_t cli_cert_len,
        const unsigned char *cli_key, const size_t cli_key_len,
        const char *pskIdent, const char *psKey,
        const char *keyPassword = NULL);

    void _deleteHandshakeCerts(void);

public:
    AsyncTCPTLS(void);
    virtual ~AsyncTCPTLS();

    // Feed encrypted data from TCP into BIO buffer (returns false if buffer full)
    bool feedRxData(const unsigned char *data, size_t len);
    size_t rxBufLen() const { return _ssl_rx_buf_len - _ssl_rx_pos; }

    // Check if BIO has buffered rx data available
    bool hasRxData(void) const { return _ssl_rx_buf && (_ssl_rx_pos < _ssl_rx_buf_len); }

    // Public accessor for PCB (needed by BIO callbacks)
    tcp_pcb *pcb() const { return _pcb; }

    // Diagnostic: log BIO buffer state
    void logBioState(const char *tag) const;

    static int getActiveCount() { return _active_count; }

    int startSSLClientInsecure(tcp_pcb *pcb, const char *host_or_ip);

#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED) || defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
    int startSSLClient(tcp_pcb *pcb, const char *host_or_ip,
        const char *pskIdent, const char *psKey);
#endif

    int startSSLClient(tcp_pcb *pcb, const char *host_or_ip,
        const char *rootCABuff,
        const char *cli_cert,
        const char *cli_key,
        const char *keyPassword = NULL);

    int startSSLClient(tcp_pcb *pcb, const char *host_or_ip,
        const unsigned char *rootCABuff, const size_t rootCABuff_len,
        const unsigned char *cli_cert, const size_t cli_cert_len,
        const unsigned char *cli_key, const size_t cli_key_len,
        const char *keyPassword = NULL);

    int startSSLServer(tcp_pcb *pcb,
        const unsigned char *server_cert, size_t server_cert_len,
        const unsigned char *server_key, size_t server_key_len,
        const char *password = NULL);

    int runSSLHandshake(void);

    int write(const uint8_t *data, size_t len);

    int read(uint8_t *data, size_t len);

    // Decrypt application data via mbedtls_ssl_read (BIO pulls encrypted bytes internally)
    int sslRead(uint8_t *data, size_t len);

    // Send TLS close_notify alert and flush to TCP
    void sendCloseNotify(void);
};

#endif // ASYNC_TCP_SSL_ENABLED
// ===== end mbedTLS/ESP32 AsyncTCPTLS.h =====
#endif
