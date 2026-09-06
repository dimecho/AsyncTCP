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
// TLS glue is always compiled+linked when enabled; these flags gate it.
#ifndef ASYNC_TCP_SSL_ENABLED
#define ASYNC_TCP_SSL_ENABLED 0
#endif

// Outbound TLS client role. 0 for a server-only HTTPS device: --gc-sections
// strips the whole client crypto chain. Set 1 if you open connectSecure().
#ifndef ASYNC_TCP_SSL_ENABLE_CLIENT
#define ASYNC_TCP_SSL_ENABLE_CLIENT 1
#endif

// TLS server role (cert parsing, session cache, br_ssl_server_context).
// Default 1 for the common server-only HTTPS device; client-only projects
// disable it to strip the server crypto footprint.
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
// ClientHello is ~1870 on the wire; 2048 covers it (MFLN caps everything else
// at 1024+overhead).
#ifndef ASYNC_TCP_SSL_IN_BUFFER_SIZE
#define ASYNC_TCP_SSL_IN_BUFFER_SIZE 2048
#endif

// Record-reassembly accumulator: must hold one full inbound record; too small
// and the record tail drops, stalling the handshake forever. Sized to the IN
// buffer so every record that fits IN also fits here.
#ifndef ASYNC_TCP_SSL_ACCUM_BUFFER_SIZE
#define ASYNC_TCP_SSL_ACCUM_BUFFER_SIZE 2048
#endif

// Ceiling for on-demand inbound-buffer growth (largest TLS record ~16.7KB).
// Buffers start at IN_BUFFER_SIZE and grow only when a big record arrives.
#ifndef ASYNC_TCP_SSL_MAX_IN_BUFFER_SIZE
#define ASYNC_TCP_SSL_MAX_IN_BUFFER_SIZE 16768
#endif

#ifndef ASYNC_TCP_SSL_OUT_BUFFER_SIZE
#define ASYNC_TCP_SSL_OUT_BUFFER_SIZE 1109
#endif

// Outbound record ring depth (K slots per conn live in the slab). K=2 doubles
// pipelining but +1109B/slab starved this device's ~7.7K serve budget under
// bursts (SENDREC hard-stall). K=1 measured stable.
#ifndef ASYNC_TCP_SSL_RECORD_RING_SLOTS
#define ASYNC_TCP_SSL_RECORD_RING_SLOTS 1
#endif

// All per-conn buffers (inbuf + K-slot ring + accumulator) live in ONE slab so
// the ctor needs one contiguous hole, not three allocs in a churned arena. The
// SERVE_BLOCK admission bar then checks that single hole.
#ifndef ASYNC_TCP_SSL_OUT_BUFFER_REGION
#define ASYNC_TCP_SSL_OUT_BUFFER_REGION \
  (ASYNC_TCP_SSL_RECORD_RING_SLOTS * ASYNC_TCP_SSL_OUT_BUFFER_SIZE)
#endif
#ifndef ASYNC_TCP_SSL_BUFFER_SLAB
#define ASYNC_TCP_SSL_BUFFER_SLAB \
  (ASYNC_TCP_SSL_IN_BUFFER_SIZE + ASYNC_TCP_SSL_OUT_BUFFER_REGION + ASYNC_TCP_SSL_ACCUM_BUFFER_SIZE)
#endif

// Cap outbound TLS records (plaintext) via server MFLN. Must not be below the
// handshake Certificate flight size.
#ifndef ASYNC_TCP_SSL_SERVER_MFLN
#define ASYNC_TCP_SSL_SERVER_MFLN 1024
#endif

// Offer MFLN from the outbound TLS client. Browsers never offer it; a server
// that honors it also caps INBOUND records, which must stay <= accumulator.
#ifndef ASYNC_TCP_SSL_CLIENT_MFLN
#define ASYNC_TCP_SSL_CLIENT_MFLN 1024
#endif

// Force-close timeout for a serve with zero engine progress (e.g. send-pool
// stall). Too low (5s) aborts healthy conns and crashes the arena; 20s lets
// lwIP recovery drain the stall instead.
#ifndef ASYNC_TCP_SSL_STALL_RESET_MS
#define ASYNC_TCP_SSL_STALL_RESET_MS 20000
#endif

// Shed a parked slot that pins its RX pbufs this long while a live conn is up.
// Must exceed the FIFO service time of the queued conns ahead of it.
#ifndef ASYNC_TCP_SSL_QUEUE_IDLE_MS
#define ASYNC_TCP_SSL_QUEUE_IDLE_MS 20000
#endif

// Minimum FREE HEAP to accept/park/promote a TLS conn. Below it, refuse (RST):
// parked slots pin ~5.2KB each and a serve burns KBs mid-flight; a failed alloc
// at ~4.5K free crashed the device. Free heap recovers to 13-17K between bursts,
// so refusals are transient (browser retries). Contiguity is gated separately by
// ASYNC_TCP_SSL_SERVE_BLOCK (== slab size, never 9000 — that latched).
#ifndef ASYNC_TCP_SSL_PRESSURE_PARK_FLOOR
#define ASYNC_TCP_SSL_PRESSURE_PARK_FLOOR 9000
#endif

// Parked-conn queue depth. Each slot pins ~4KB (pcb + RX pbufs). 4 starved the
// busy arena and froze the UI once (measured, pre-gate-rework); 2 absorbed a
// page's parallel conns while leaving room for a queued promote. 3 = middle.
#ifndef ASYNC_TCP_SSL_PARKED_SLOTS
#define ASYNC_TCP_SSL_PARKED_SLOTS 3
#endif

// Overflow-hold depth: when the park queue is full (or free heap is under the
// floor), conns are HELD instead of RST'd — same pool-only buffering as a park
// slot, admitted even in a tight arena. When both queues are full, the conn is
// RST'd (true overload).
#ifndef ASYNC_TCP_SSL_HOLD_LIMIT
#define ASYNC_TCP_SSL_HOLD_LIMIT 4
#endif

// Max inbound bytes a PARKED conn may buffer before the excess stays in lwIP's
// recv window. Must hold a full ClientHello (~1.9KB): the promoted handshake
// needs the whole opening record staged (below it: handshake timeout).
#ifndef ASYNC_TCP_SSL_PARKED_RX_CAP
#define ASYNC_TCP_SSL_PARKED_RX_CAP 2000
#endif

// Serve/promote admission. Two guards, checked in both _accept and _promoteSlot:
//  - free heap >= PRESSURE_PARK_FLOOR: total free before ctor (starvation guard).
//  - maxblock >= SERVE_BLOCK == slab: the ctor's ONE contiguous big alloc.
// SERVE_BLOCK must stay exactly the slab size: after a conn closes without its
// slab coalescing upward, the freed hole alone sits at ~slab+header (4190) and
// reuse-in-place admits the next ctor; slab+margin (or 9000) deadlocks — it
// refuses EVERY later conn while maxblock sits under it.
#ifndef ASYNC_TCP_SSL_SERVE_BLOCK
#define ASYNC_TCP_SSL_SERVE_BLOCK ASYNC_TCP_SSL_BUFFER_SLAB
#endif

// Server-side session cache (TLS resumption). Each LRU entry = 100B static.
// Resumption skips the Certificate flight, so each serve stages fewer bytes —
// helps under parallel bursts. 2 entries = 200B.
#ifndef ASYNC_TCP_SSL_SESSION_CACHE_ENTRIES
#define ASYNC_TCP_SSL_SESSION_CACHE_ENTRIES 2
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

// Private-key parser lives in the ESP8266 core's built-in BearSSL (namespace
// BearSSL), pulled in via <ESP8266WiFi.h>/<BearSSLHelpers.h> in the .cpp TU.
namespace BearSSL { class PrivateKey; }

// Wrapper making BearSSL contexts usable as an opaque SSL context
struct BearSSL_SSL_CTX {
  // Server role owns the parsed cert chain, key, and session cache (fields
  // below; only compiled when the server role is on).
#if ASYNC_TCP_SSL_ENABLE_SERVER
  std::vector<br_x509_certificate> chain_vector;
  BearSSL::PrivateKey* pk = nullptr;

  // Shared server engine: init'ed once, reused per conn via
  // br_ssl_server_reset(). Single-conn gate keeps it exclusive.
  br_ssl_server_context server_ctx;

  // Session cache (resumption); shared across conns. 100B per LRU entry.
  br_ssl_session_cache_lru session_cache;
  unsigned char session_store[ASYNC_TCP_SSL_SESSION_CACHE_ENTRIES * ASYNC_TCP_SSL_SESSION_CACHE_ENTRY_SIZE];
#endif

  ~BearSSL_SSL_CTX();
};

// BearSSL has no true insecure decoder; build one from the simple parser. In
// insecure mode it computes the subject hash / SHA1 fingerprint and accepts
// any certificate (BearSSL 0.6 dropped the issuer-DN callback).
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
  // pointer stays null). Engine is embedded first, so &ctx->eng == engine.
#if ASYNC_TCP_SSL_ENABLE_CLIENT
  br_ssl_client_context* sc_client;  // allocated when !is_server
  x509_insecure_context *insecure_x509;  // accept-any x509 when rootCA==NULL (owned)
#endif
#if ASYNC_TCP_SSL_ENABLE_SERVER
  br_ssl_server_context* sc_server;  // borrowed: &BearSSL_SSL_CTX::server_ctx when is_server (never owned)
#endif
  // inbuf/outbuf/accum live in ONE contiguous slab so the ctor needs a single
  // big hole instead of three.
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

  // Set when a SENDREC record was deferred (tcp_write ERR_MEM in a full send
  // window/queue); cleared when it transmits. tcp_ssl_sent() re-arms the
  // engine only when set, so idle ACKs don't spam scheduling.
  bool sendrec_deferred;

  // Each outbound app-data record is copied into a ring slot in the slab, then
  // tcp_write no-copy pins it until the peer ACKs; br_ssl_engine_sendrec_ack
  // frees the engine outbuf immediately, so the NEXT record builds into it.
  // Handshake flights ride the same ring (keeps them out of heap). Slots free
  // FIFO in tcp_ssl_sent() as ciphertext ACKs land.
  unsigned char* out_ring[ASYNC_TCP_SSL_RECORD_RING_SLOTS];      // outbuf + i*OUT_BUFFER_SIZE
  uint16_t       out_ring_len[ASYNC_TCP_SSL_RECORD_RING_SLOTS];  // ciphertext bytes in each slot
  uint8_t        out_ring_next;    // next slot to fill (write cursor)
  uint8_t        out_ring_pinned;  // slots currently referencing un-ACKed records
  uint32_t       out_ring_acked;   // CUMULATIVE ciphertext ACKed against the ring (see tcp_ssl_sent);
                                  // lwIP reports ACKed bytes per callback, but a record spanning 2
                                  // segments (1053 > MSS 536) only completes after SEVERAL ACKs each
                                  // smaller than the record, so release must compare a running total,
                                  // not the per-callback delta. Zeroed whenever the ring fully empties.

  // Timestamp (ms) of a HARD send stall: SENDREC deferred while the window is
  // open and the queue empty — no ACK can ever re-arm it, so AsyncClient::_poll
  // tears the conn down once this persists past the timeout (otherwise ~6KB of
  // TLS buffers stay pinned forever). 0 = not stalled.
  uint32_t hard_defer_start;

  // TRUE once the peer ACKed at least one app-data record (response body
  // streaming). After that the conn is NOT torn down on a transient defer —
  // killing it truncates a body the browser can't recover. Resets only apply
  // while body_started==false (zero-progress / handshake-wedged conns).
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
void tcp_ssl_pcb_pressure(unsigned *active, unsigned *tw);
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
