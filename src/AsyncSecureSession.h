// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright 2016-2026 Hristo Gochkov, Mathieu Carbou, Emil Muratov, Will Miles
//
// Unified dual-stack AsyncTCP. TLS engine.
//   - ESP8266         -> BearSSL stack (AsyncTCP fork, NO_SYS lwIP)
//   - ESP32/LIBRETINY -> mbedTLS stack (AsyncTCP ESP32Async base)
// Selected at compile time via #if defined(ESP8266). Only one stack compiles per target.
#pragma once

// --- TLS configuration ---
#ifndef ASYNC_TCP_SSL_ENABLED
#define ASYNC_TCP_SSL_ENABLED 0
#endif

// --- Shared TLS config (admission/park/handshake; ESP8266/ESP32).
#ifndef SSL_MAX_CONNECTIONS
#define SSL_MAX_CONNECTIONS 2
#endif

#ifndef SSL_QUEUE_IDLE_MS
#define SSL_QUEUE_IDLE_MS 20000
#endif

#ifndef SSL_PARKED_SLOTS
#define SSL_PARKED_SLOTS 6
#endif

#ifndef SSL_PARKED_RX_CAP
#define SSL_PARKED_RX_CAP 2000
#endif

#ifndef SSL_HANDSHAKE_TIMEOUT
#define SSL_HANDSHAKE_TIMEOUT 10000
#endif

#ifndef SSL_SESSION_CACHE
#define SSL_SESSION_CACHE 8
#endif

#ifndef SSL_CLIENT_MFLN
#define SSL_CLIENT_MFLN 1024
#endif

// mbedTLS serve-floor: refuse when free heap < ctor peak (~44-59KB).
// ESP8266 uses its own PARK gates.
#ifndef SSL_MBED_SERVE_FLOOR
#define SSL_MBED_SERVE_FLOOR 90000
#endif

#if defined(ESP8266)
// ===== begin BearSSL/ESP8266 (AsyncTCP) =====

// Client role. 0 for server-only (strips client crypto via --gc-sections).
#ifndef ASYNC_TCP_SSL_ENABLE_CLIENT
#define ASYNC_TCP_SSL_ENABLE_CLIENT 1
#endif

// Server role (cert parsing, session cache). Default 1 for HTTPS;
// client-only projects disable it to strip the server crypto footprint.
#ifndef ASYNC_TCP_SSL_ENABLE_SERVER
#define ASYNC_TCP_SSL_ENABLE_SERVER 1
#endif

#undef SSL_MAX_CONNECTIONS
#define SSL_MAX_CONNECTIONS 1

// ESP8266: aggressive client rx-echo cutoff (slow browser under heap pressure
// during OTA chunk handshakes gets 2s, not the shared 10s).
#undef SSL_HANDSHAKE_TIMEOUT
#define SSL_HANDSHAKE_TIMEOUT 2000

// CLIENT-role inbound record buffer. This role offers MFLN (SSL_CLIENT_MFLN),
// so the peer caps records at 1024+overhead; 2048 covers ClientHello + any
// peer that ignores MFLN.
#ifndef SSL_IN_BUFFER_SIZE
#define SSL_IN_BUFFER_SIZE 2048
#endif

// SERVER-role inbound record buffer. Browsers never send max_fragment_length
// (RFC 6066 is client-optional), so a full 16KB record would need ~17.5KB of
// slab and blow the ESP8266's ~20KB free heap mid-handshake (OOM). The OTA
// uploader is chunked instead (small POST bodies -> small TLS records), so the
// server buffer only needs to hold those small records: 4096 is enough. 4096 +
// the 1109 out-record ring = 5205B server slab, which fits the serve-time arena.
#ifndef SSL_SERVER_IN_BUFFER_SIZE
#define SSL_SERVER_IN_BUFFER_SIZE 4096
#endif

#ifndef SSL_OUT_BUFFER_SIZE
#define SSL_OUT_BUFFER_SIZE 1109
#endif

// Max lwIP pbufs queued unconsumed while the engine feeds (loop context).
// Credit-only-consumed backpressure chokes the peer's window before this.
#ifndef SSL_RX_PEND_MAX
#define SSL_RX_PEND_MAX 16
#endif

// Outbound record ring depth (K slots per conn). K=2 = +1109B/slab and
// starved serve budget under bursts; K=1 is stable.
#ifndef SSL_RECORD_RING_SLOTS
#define SSL_RECORD_RING_SLOTS 1
#endif

// Outbound ring region: K slots x record size.
#ifndef SSL_OUT_BUFFER_REGION
#define SSL_OUT_BUFFER_REGION \
  (SSL_RECORD_RING_SLOTS * SSL_OUT_BUFFER_SIZE)
#endif

// Server-role slab: record buffers for BOTH directions share ONE hole so the
// ctor needs a single contiguous alloc the SERVE_BLOCK admission bar can gate
// (this is the bar the ESP8266 arena must produce at serve time). Client conns
// allocate their own (smaller) slab at runtime.
#ifndef SSL_BUFFER_SLAB_SERVER
#define SSL_BUFFER_SLAB_SERVER \
  (SSL_SERVER_IN_BUFFER_SIZE + SSL_OUT_BUFFER_REGION)
#endif
#ifndef SSL_BUFFER_SLAB_CLIENT
#define SSL_BUFFER_SLAB_CLIENT \
  (SSL_IN_BUFFER_SIZE + SSL_OUT_BUFFER_REGION)
#endif
// Admission bar (server-side): must equal the server slab or the gate refusals
// deadlock every later conn.
#ifndef SSL_SERVE_BLOCK
#define SSL_SERVE_BLOCK SSL_BUFFER_SLAB_SERVER
#endif

// No server MFLN (RFC 6066): browsers never offer max_fragment_length, so a
// ServerHello echo is pointless and a forced cap would be ignored by the most
// common clients. Server outbound records are already limited by the 1109B
// output ring; inbound records are bounded by the server inbuf.

// Client MFLN offered outbound; keeps inbound peer records <= client inbuf
// (spelled in the shared config above; no server counterpart — see note above).

// Force-close for a serve with zero engine progress (e.g. send-pool stall).
// Too low aborts healthy conns; 20s lets lwIP recovery drain it.
#ifndef SSL_STALL_RESET_MS
#define SSL_STALL_RESET_MS 20000
#endif

// Min free heap to accept/park/promote a TLS conn; below it refuse (RST).
// Parked slots pin ~5.2KB each (4096 in + 1109 out); alloc below ~4.5K free
// crashed the device. Contiguity gated separately by SSL_SERVE_BLOCK (== the
// server slab via SSL_BUFFER_SLAB_SERVER). Keeps ~3.8K free headroom after one
// slab alloc.
#ifndef SSL_PRESSURE_PARK_FLOOR
#define SSL_PRESSURE_PARK_FLOOR (SSL_BUFFER_SLAB_SERVER + 3800)  // ≈ 9005 B
#endif

// Absolute floor below which the server refuses a conn outright (RST) instead
// of even queuing the 24B HOLD pending_pcb — at ~976B free a 24-32B malloc
// throws an unhandled C++ OOM on ESP8266. Keeps the overflow-held tier from
// crashing a conn that is otherwise surviving on heartbeat budget.
#ifndef SSL_HOLD_MIN_HEAP
#define SSL_HOLD_MIN_HEAP 2000
#endif

// Parked-conn queue depth; each slot pins ~4KB (pcb + RX pbufs). The 5.2KB
// server slab eats the arena during a serve, so 1 slot leaves room for the
// next promotion; more starve the 20KB serve floor.
#ifndef SSL_PARKED_SLOTS
#define SSL_PARKED_SLOTS 1
#endif

// Overflow-hold depth: park full (or heap under floor) -> HELD, not RST (same
// pool-only buffering as a park slot). Both queues full -> RST.
#ifndef SSL_HOLD_LIMIT
#define SSL_HOLD_LIMIT 4
#endif

// Serve/promote admission, in _accept and _promoteSlot:
//  - free heap >= PRESSURE_PARK_FLOOR (starvation guard).
//  - maxblock >= SERVE_BLOCK == server slab (ctor's ONE contiguous big alloc).
// SERVE_BLOCK must stay exactly the slab size: slab+margin (or 9000) deadlocks —
// it refuses every later conn while maxblock sits under it.

// Server-side session cache (TLS resumption). Each LRU entry = 100B static;
// resumption skips the Certificate flight. 6 entries = 600B covers Chrome's
// 6-conn parallelism without LRU thrash.
#undef SSL_SESSION_CACHE
#define SSL_SESSION_CACHE 6
  
#ifndef SSL_SESSION_CACHE_SIZE
#define SSL_SESSION_CACHE_SIZE 100
#endif

const int SSL_MAX_FEED_LOOPS = 10;

#include <bearssl/bearssl.h>
#include <bearssl/bearssl_ssl.h>
#include <bearssl/bearssl_x509.h>

#include <vector>

// FORWARD DECLARE lwIP types to avoid including lwip/tcp.h in a public header
struct tcp_pcb;
struct pbuf;

// Frees queued unconsumed RX pbufs; defined in the .cpp TU where lwIP headers
// are in scope. Called from ~tcp_ssl_pcb (inline, header-side).
void tcp_ssl_free_rx_pend(struct tcp_ssl_pcb* ssl_pcb);

// Opaque SSL type — only used as pointer
struct SSL {};

// Private-key parser lives in the core's built-in BearSSL (namespace BearSSL),
// pulled in via <ESP8266WiFi.h>/<BearSSLHelpers.h> in the .cpp TU.
namespace BearSSL { class PrivateKey; }

// Wrapper making BearSSL contexts usable as an opaque SSL context
struct BearSSL_SSL_CTX {
  // Server role owns the parsed cert chain, key, and session cache.
#if ASYNC_TCP_SSL_ENABLE_SERVER
  std::vector<br_x509_certificate> chain_vector;
  BearSSL::PrivateKey* pk = nullptr;

  // Shared server engine: init'ed once, reused per conn via
  // br_ssl_server_reset(). Single-conn gate keeps it exclusive.
  br_ssl_server_context server_ctx;

  // Session cache (resumption); shared across conns. 100B per LRU entry.
  br_ssl_session_cache_lru session_cache;
  unsigned char session_store[SSL_SESSION_CACHE * SSL_SESSION_CACHE_SIZE];
#endif

  ~BearSSL_SSL_CTX();
};

// BearSSL has no true insecure decoder; build one from the simple parser
// (BearSSL 0.6 dropped the issuer-DN callback). Accepts any server cert.
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
struct tcp_ssl_pcb {
  struct tcp_pcb* tcp;
  // Role-specific context; only the active role's is allocated (the other
  // pointer stays null). Engine embedded first, so &ctx->eng == engine.
#if ASYNC_TCP_SSL_ENABLE_CLIENT
  br_ssl_client_context* sc_client;  // allocated when !is_server
  x509_insecure_context *insecure_x509;  // accept-any x509 when rootCA==NULL (owned)
#endif
#if ASYNC_TCP_SSL_ENABLE_SERVER
  br_ssl_server_context* sc_server;  // borrowed: &BearSSL_SSL_CTX::server_ctx when is_server (never owned)
#endif
  // inbuf + outbound ring share ONE slab so the ctor needs a single big hole
  // (size depends on role; see the alloc functions).
  unsigned char* _slab;       // base of the contiguous buffer allocation
  unsigned char* inbuf;       // _slab + 0
  unsigned char* outbuf;      // _slab + role IN buffer size
  size_t inbuf_cap;           // current allocated size of the inbuf region

  // pointers to track app data currently in the inbuf and pending in the outbuf
  unsigned char* in_buf_ptr;
  unsigned char* out_buf_ptr;

  // len of app data currently in the inbuf, and len of pending data in outbuf
  size_t in_len;
  size_t out_len;

  // Direct-stream inbound queue: lwIP recv pbufs wait here (no copy, no ack)
  // until process_ssl_engine feeds them into the engine's record buffer in
  // loop() context. tcp_recved() credits only bytes fed -> natural backpressure.
  struct pbuf* rx_pend[SSL_RX_PEND_MAX];
  uint8_t  rx_pend_n;         // pbufs currently queued
  uint16_t rx_pend_head_off;  // bytes already consumed in rx_pend[0]
  size_t   max_rec_len;       // largest inbound TLS record ciphertext length seen

  bool is_server;
  bool handshake_done;

  // Set when a SENDREC record was deferred (tcp_write ERR_MEM); cleared on
  // transmit. tcp_ssl_sent() re-arms only when set, so idle ACKs don't spam.
  bool sendrec_deferred;

  // Outbound records copied into a slab ring slot; tcp_write no-copy pins it
  // until ACK, then sendrec_ack frees the engine outbuf for the NEXT record.
  // Slots free FIFO in tcp_ssl_sent() as ACKs land. Handshake rides same ring.
  unsigned char* out_ring[SSL_RECORD_RING_SLOTS];      // outbuf + i*OUT_BUFFER_SIZE
  uint16_t       out_ring_len[SSL_RECORD_RING_SLOTS];  // ciphertext bytes in each slot
  uint8_t        out_ring_next;    // next slot to fill (write cursor)
  uint8_t        out_ring_pinned;  // slots currently referencing un-ACKed records
  uint32_t       out_ring_acked;   // CUMULATIVE ciphertext ACKed (see tcp_ssl_sent);
                                  // records span 2 segments (1053 > MSS 536), so release
                                  // needs a running total, not the per-callback delta.
                                  // Zeroed when the ring fully empties.

  // Timestamp (ms) of a HARD send stall (window open, queue empty — no ACK can
  // re-arm it); AsyncClient::_poll tears the conn down past the timeout. 0 = none.
  uint32_t hard_defer_start;

  // TRUE once the peer ACKed app data (response body streaming). After that a
  // transient defer never tears the conn down — that would truncate a body the
  // browser can't recover. Resets apply only while body_started==false.
  bool body_started;

  // Callbacks and arguments
  void* arg;
  tcp_ssl_data_cb_t on_data;
  tcp_ssl_handshake_cb_t on_handshake;
  tcp_ssl_error_cb_t on_error;

  SSL dummy_ssl;  // API compatibility
  struct tcp_ssl_pcb* next;

  ~tcp_ssl_pcb() {
    tcp_ssl_free_rx_pend(this);  // return unacked lwIP pbufs before slab dies
    delete[] _slab;  // inbuf/outbuf are offsets into this one block
#if ASYNC_TCP_SSL_ENABLE_CLIENT
    delete sc_client;      // safe when null (server role)
    delete insecure_x509;  // owned; safe when null (rootCA path / alloc fail)
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
// True once a conn has been in a hard SENDREC stall longer than stall_ms.
// AsyncClient::_poll uses it to bound a pool-exhaustion wedge.
bool tcp_ssl_is_stalled(struct tcp_pcb* pcb, uint32_t stall_ms);
// True while the engine still holds a TLS record not yet in TCP (deferred, or
// in flight referencing the no-copy outbuf). lwIP-callback context — must NOT
// drive BearSSL. Guards early close from truncating the final response record.
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
// Diagnostics for the SETTLED log.
unsigned long tcp_ssl_serve_conns_total();
void tcp_ssl_shed_parked();  // flush the parked queue at the next idle tick
int tcp_ssl_live_serve_shells();  // live AsyncClient shells (leak finder)
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
// Set up the x509 insecure data structures for BearSSL core to use.
void br_x509_insecure_init(x509_insecure_context* ctx, bool use_fingerprint, const uint8_t* fingerprint, bool allow_self_signed);
#endif
// ===== end BearSSL/ESP8266 =====
#else
// ===== begin mbedTLS/ESP32 AsyncSecureSession.h (AsyncTCP) =====
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
// -------------------------------------------------------------------------

#include "mbedtls/platform.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ssl_cache.h"
#if MBEDTLS_VERSION_MAJOR < 4
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#endif
#include "mbedtls/error.h"
#include "mbedtls/pem.h"

struct tcp_pcb;
struct pbuf;

#define ASYNCTCP_TLS_CAN_RETRY(r)   (((r) == MBEDTLS_ERR_SSL_WANT_READ) || ((r) == MBEDTLS_ERR_SSL_WANT_WRITE))
#define ASYNCTCP_TLS_EOF(r)         (((r) == MBEDTLS_ERR_SSL_CONN_EOF) || ((r) == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY))

#define SSL_RX_BUF_SIZE    4096
#define SSL_RX_BUF_MAX     8192

struct pending_pcb; // park-queue item (defined in AsyncTCP.cpp); held by ctx below

class AsyncSecureSession
{
private:
    mbedtls_ssl_context ssl_ctx;
    mbedtls_ssl_config ssl_conf;

    // Shared RNG — initialized once, serialized on async task.
    // v3: legacy entropy + CTR-DRBG. v4: PSA Crypto (no DRBG types).
#if MBEDTLS_VERSION_MAJOR < 4
    static mbedtls_ctr_drbg_context drbg_ctx;
    static mbedtls_entropy_context entropy_ctx;
#endif
    static bool _conf_initialized;

    static int _rng_init(void);
#if MBEDTLS_VERSION_MAJOR < 4
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

    // Park-replay / BIO-overflow chain: encrypted bytes not yet feedable.
    // Owned by this session; acked+fed on drain. NULL when empty.
    pbuf *_pending_pbufs;

    int _startSSLClient(tcp_pcb *pcb, const char *host_or_ip,
        const unsigned char *rootCABuff, const size_t rootCABuff_len,
        const unsigned char *cli_cert, const size_t cli_cert_len,
        const unsigned char *cli_key, const size_t cli_key_len,
        const char *pskIdent, const char *psKey,
        const char *keyPassword = NULL);

    void _deleteHandshakeCerts(void);

public:
    AsyncSecureSession(void);
    virtual ~AsyncSecureSession();

    // Feed encrypted data from TCP into BIO buffer (returns false if buffer full)
    bool feedRxData(const unsigned char *data, size_t len);
    size_t feedRx(pbuf *pb);
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
        const char *password = NULL,
        mbedtls_ssl_cache_context *session_cache = NULL);

    int runSSLHandshake(void);

    int write(const uint8_t *data, size_t len);

    // Raw ciphertext drain for the mbedTLS BIO recv callback
    int read(uint8_t *data, size_t len);

    // Decrypt application data via mbedtls_ssl_read (BIO pulls encrypted bytes internally)
    int sslRead(uint8_t *data, size_t len);
};

// Server-side TLS admission state: session cache + bounded park queue. Lives
// one-per-AsyncServer (value member); only present when the server is secure.
class AsyncSecureServerCtx
{
public:
    AsyncSecureServerCtx()
    {
        mbedtls_ssl_cache_init(&cache);
        mbedtls_ssl_cache_set_max_entries(&cache, SSL_SESSION_CACHE);
        mbedtls_ssl_cache_set_timeout(&cache, 0);
    }
    ~AsyncSecureServerCtx() { mbedtls_ssl_cache_free(&cache); }
    mbedtls_ssl_cache_context *cacheContext() { return &cache; }
    int liveServeCount() const { return AsyncSecureSession::getActiveCount(); }
    AsyncSecureServerCtx(const AsyncSecureServerCtx &) = delete;
    AsyncSecureServerCtx &operator=(const AsyncSecureServerCtx &) = delete;

    mbedtls_ssl_cache_context cache;
    struct pending_pcb *pending;
    volatile int parked;
};

#endif // ASYNC_TCP_SSL_ENABLED
// ===== end mbedTLS/ESP32 AsyncSecureSession.h =====
#endif
