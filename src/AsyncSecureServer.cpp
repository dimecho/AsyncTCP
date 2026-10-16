// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright 2016-2026 Hristo Gochkov, Mathieu Carbou, Emil Muratov, Will Miles
//
// Unified dual-stack AsyncTCP. TLS server.
//   - ESP8266         -> BearSSL stack (AsyncTCP fork, NO_SYS lwIP)
//   - ESP32/LIBRETINY -> mbedTLS stack (AsyncTCP ESP32Async base)
//
// AsyncSecureServer composes AsyncServer (pure-TCP accept/listen) and takes
// over the accept path with TLS admission (park/serve queue) via server hooks.
// All server-side TLS state lives here, keeping AsyncServer in AsyncTCP.cpp
// a pure transport.

#include "AsyncTCP.h"
#include "AsyncSecureSession.h"
#include "AsyncTCPLogging.h"
#include <Arduino.h>

extern "C" {
#include "lwip/tcp.h"
}
#include "AsyncTCPCoreGuard.h"
#include "AsyncTCPParkQueue.h"

#if defined(ESP8266)
// ===== begin BearSSL/ESP8266 AsyncSecureServer (AsyncTCP) =====

#if ASYNC_TCP_SSL_ENABLED && ASYNC_TCP_SSL_ENABLE_SERVER
// ESP8266 has no parked-conn queue: with SSL_MAX_CONNECTIONS=1 a parked
// ClientHello can never become a parallel serve and only pins heap/pbufs the
// live conn needs. Busy conns are refused instead (see _acceptTls). Kept as
// no-op stubs — the BearSSL glue still calls them.
uint8_t tcp_ssl_parked_count() { return 0; }
void tcp_ssl_shed_parked() {}
#endif

// All AsyncSecureServer definitions below live inside this guard; the class
// is declared in AsyncTCP.h under the same condition.
#if ASYNC_TCP_SSL_ENABLED && ASYNC_TCP_SSL_ENABLE_SERVER

// TLS server hook: owns the cert context, the parked-conn queue and the
// per-connection serve/promotion. Created by AsyncServer::beginSecure().
struct SecureServerHooks : AsyncServerHooks {
  explicit SecureServerHooks(AsyncServerImpl *srv) : _srv(srv), _ssl_ctx(NULL), _file_cb(NULL), _file_cb_arg(NULL) {}

  int8_t onAccept(AsyncServerImpl *srv, tcp_pcb *pcb, int8_t err) override;

  void beginSecure(const char *cert, const char *private_key_file, const char *password);
  void onSslFileRequest(AcSSLFileHandler cb, void *arg) {
    _file_cb = cb;
    _file_cb_arg = arg;
  }

private:
  AsyncServerImpl *_srv;
  BearSSL_SSL_CTX *_ssl_ctx;
  AcSSLFileHandler _file_cb;
  void *_file_cb_arg;

  int8_t _acceptTls(tcp_pcb *pcb);
  AsyncClient *_serveTls(tcp_pcb *pcb);
  int _cert(const char *filename, uint8_t **buf);
  static int _s_cert(void *arg, const char *filename, uint8_t **buf);
};

AsyncSecureServer::AsyncSecureServer(ip_addr_t addr, uint16_t port)
  : _tcp(addr, port) {
}

#ifdef ARDUINO
AsyncSecureServer::AsyncSecureServer(IPAddress addr, uint16_t port)
  : _tcp(addr, port) {
}
#if __has_include(<IPv6Address.h>)
AsyncSecureServer::AsyncSecureServer(IPv6Address addr, uint16_t port)
  : _tcp(addr, port) {
}
#endif
#endif

AsyncSecureServer::AsyncSecureServer(uint16_t port)
  : _tcp(port) {
}

AsyncSecureServer::~AsyncSecureServer() {
  end();
}

void AsyncSecureServer::onClient(AcConnectHandler cb, void *arg) {
  _tcp.onClient(cb, arg);
}

void AsyncSecureServer::begin() {
  _tcp.begin();
}

void AsyncSecureServer::end() {
  _tcp.end();
}

void AsyncSecureServer::setNoDelay(bool nodelay) {
  _tcp.setNoDelay(nodelay);
}

bool AsyncSecureServer::getNoDelay() const {
  return _tcp.getNoDelay();
}

uint8_t AsyncSecureServer::status() const {
  return _tcp.status();
}

void AsyncSecureServer::onSslFileRequest(AcSSLFileHandler cb, void *arg) {
  _tcp.onSslFileRequest(cb, arg);
}

void AsyncSecureServer::beginSecure(const char *cert, const char *private_key_file, const char *password) {
  _tcp.beginSecure(cert, private_key_file, password);
}

int8_t SecureServerHooks::_acceptTls(tcp_pcb *pcb) {
  // Sample max free block this accept; fresher than a cached value for the
  // fragmentation gate (slab carve / park refusal).
  size_t cachedMaxBlock = ESP.getMaxFreeBlockSize();
#if ASYNC_TCP_SSL_ENABLED && ASYNC_TCP_SSL_ENABLE_SERVER
  if (_ssl_ctx) {
    if (!hasConnectHandler(_srv)) {
      if (tcp_close(pcb) != ERR_OK) {
        tcp_abort(pcb);
      }
      return ERR_OK;
    }
    // Admission: live TLS conn + parked queue (PARKED_SLOTS). Park (not serve)
    // when slot live OR arena below serve bar, else serve. Promoted FIFO when
    // slot frees + heap clears bar; shed after idle.
    // No-live-conn below-floor park only if heap clears floor + this park's pin
    // (CAP) x (queued+1) — else refuse (RST, browser backs off). Parking below
    // that budget deadlocks promote.
    // Live conn: park while handshake in flight + heap below floor+CAP (queued
    // ClientHello robs the live handshake); body-phase parks freely. RST only
    // on live-handshake heap starvation or queue full / heap under MIN.
    unsigned accept_heap = (unsigned)ESP.getFreeHeap();
    uint8_t ssl_cnt = tcp_ssl_client_count();
    bool live_conn = ssl_cnt >= SSL_MAX_CONNECTIONS;
    // Park (never concurrently serve) whenever a live conn is up — extra
    // parallel serves breach SSL_MAX_CONNECTIONS and split the arena into
    // fragments too small to carve slabs (slow chunks). Full queue -> RST.
    bool needPark = live_conn ||
                    accept_heap < SSL_PRESSURE_FLOOR ||
                    cachedMaxBlock < SSL_SERVE_BLOCK;
    if (needPark) {
      // ESP8266: no parking — with keep-alive responses the browser reuses a
      // single connection, so extra conns are rare; parking just pinned heap.
      // Refuse (RST): the peer retries or reuses its existing TLS conn.
      async_tcp_log_d("_accept: TLS busy (live=%u heap=%u maxblock=%u), refusing conn",
                      (unsigned)ssl_cnt, accept_heap, (unsigned)cachedMaxBlock);
      tcp_abort(pcb);
      return ERR_ABRT;
    }
    _serveTls(pcb);
    return ERR_OK;
  }
#endif
  return -1;  // TLS not configured: fall through to the plain accept path
}

AsyncClient *SecureServerHooks::_serveTls(tcp_pcb *pcb) {
  // Promote a raw pcb to a live TLS AsyncClient. The session ctor allocates
  // ctx+buffers and registers the pcb, so ssl_count flips >0 inside. Returns
  // NULL (pcb closed) if allocation fails — browser simply retries.
  // Hard live-budget cap: never serve past
  // SSL_MAX_CONNECTIONS, regardless of admission path. Each serve holds a
  // ~SLAB heap alloc, so exceeding the budget splits the arena (slow chunks).
  if (tcp_ssl_client_count() >= SSL_MAX_CONNECTIONS) {
    async_tcp_log_d("_serveTls: live budget full, aborting conn");
    if (tcp_close(pcb) != ERR_OK) {
      tcp_abort(pcb);
    }
    return NULL;
  }
  AsyncClient *c = new (std::nothrow) AsyncClient(pcb);
  if (c) {
    AsyncSecureSession *ssl = new (std::nothrow) AsyncSecureSession();
    if (!ssl) {
      async_tcp_log_d("_serveTls: AsyncSecureSession alloc failed, connection aborted!");
      delete c;
      if (tcp_close(pcb) != ERR_OK) {
        tcp_abort(pcb);
      }
      return NULL;
    }
    int ret = ssl->startSSLServer(pcb, _ssl_ctx);
    if (ret != 0) {
      async_tcp_log_d("_serveTls: SSL init failed (%d), connection aborted!", ret);
      delete ssl;
      delete c;
      if (tcp_close(pcb) != ERR_OK) {
        tcp_abort(pcb);
      }
      return NULL;
    }
    SecureClientHooks *hooks = new (std::nothrow) SecureClientHooks(ssl, c->impl());
    if (!hooks) {
      async_tcp_log_d("_serveTls: SecureClientHooks alloc failed, connection aborted!");
      delete ssl;
      delete c;
      if (tcp_close(pcb) != ERR_OK) {
        tcp_abort(pcb);
      }
      return NULL;
    }
    c->setHooks(hooks);
    tcp_nagle_disable(pcb);  // flush each small TLS record immediately
    async_tcp_log_d("_serveTls: SSL connected, freeheap=%u, ssl_count=%u", (unsigned)ESP.getFreeHeap(), (unsigned)tcp_ssl_client_count());
    c->onConnect([](void *arg, AsyncClient *c) {
      SecureServerHooks *h = static_cast<SecureServerHooks *>(arg);
      if (h) {
        h->notifyClient(h->_srv, c);
      }
    }, this);
    return c;
  }
  async_tcp_log_d("_serveTls: new AsyncClient() failed, connection aborted!");
  if (tcp_close(pcb) != ERR_OK) {
    tcp_abort(pcb);
  }
  return NULL;
}

int SecureServerHooks::_cert(const char *filename, uint8_t **buf) {
  if (_file_cb) {
    return _file_cb(_file_cb_arg, filename, buf);
  }
  *buf = 0;
  return 0;
}

int SecureServerHooks::_s_cert(void *arg, const char *filename, uint8_t **buf) {
  return reinterpret_cast<SecureServerHooks *>(arg)->_cert(filename, buf);
}

// --- SecureServerHooks: TLS admission + promotion, dispatched from
// AsyncServer's accept/close paths ---

int8_t SecureServerHooks::onAccept(AsyncServerImpl *srv, tcp_pcb *pcb, int8_t err) {
  (void)srv;
  (void)err;
  // TLS conns always flush each small record immediately (overrides the plain
  // nagle handling done by AsyncServer::_accept).
  if (_ssl_ctx) {
    tcp_nagle_disable(pcb);
  }
  return _acceptTls(pcb);
}

#endif


// --- AsyncServer backward-compat TLS entry points (ESP8266) ---
// Configure + install the TLS server hooks on this plain server.
void AsyncServer::onSslFileRequest(std::function<int(void *arg, const char *filename, uint8_t **buf)> cb, void *arg) {
  if (!_impl->hooks()) {
    _impl->setHooks(new (std::nothrow) SecureServerHooks(_impl.get()));
  }
  static_cast<SecureServerHooks *>(_impl->hooks())->onSslFileRequest(cb, arg);
}

void AsyncServer::beginSecure(const char *cert, const char *private_key_file, const char *password) {
  if (!_impl->hooks()) {
    _impl->setHooks(new (std::nothrow) SecureServerHooks(_impl.get()));
  }
  static_cast<SecureServerHooks *>(_impl->hooks())->beginSecure(cert, private_key_file, password);
}

void SecureServerHooks::beginSecure(const char *cert, const char *private_key_file, const char *password) {
  if (_ssl_ctx) {
    async_tcp_log_d("beginSecure: already have ctx, skip");
    return;
  }
  _ssl_ctx = tcp_ssl_new_server_ctx(cert, private_key_file, password);
  if (_ssl_ctx) {
    async_tcp_log_d("beginSecure: ctx created OK, calling begin()");
    _srv->begin();
  } else {
    async_tcp_log_d("beginSecure: tcp_ssl_new_server_ctx returned NULL (PEM parse failed)");
  }
}

// ===== end BearSSL/ESP8266 AsyncSecureServer =====/
#else
// ===== begin mbedTLS/ESP32 AsyncSecureServer (AsyncTCP) =====
#if ASYNC_TCP_SSL_ENABLED

// TLS server hook: owns cert/key, the session cache and the parked-conn queue.
// Created by AsyncServer::beginSecure().
struct SecureServerHooks : AsyncServerHooks {
  explicit SecureServerHooks(AsyncServerImpl *srv)
      : _srv(srv), _use_ssl(false), _cert(NULL), _cert_len(0), _key(NULL), _key_len(0),
        _ssl_file_cb(NULL), _ssl_file_cb_arg(NULL), _ssl_key_password(NULL), _secureCtx() {}

  int8_t onAccept(AsyncServerImpl *srv, tcp_pcb *pcb, int8_t err) override;
  int8_t onAccepted(AsyncServerImpl *srv, AsyncClient *client) override;
  void onConnDone(AsyncServerImpl *srv, AsyncClient *client) override;

  bool beginSecure(const unsigned char *cert, size_t certLen,
      const unsigned char *key, size_t keyLen);
  bool beginSecure(const char *certPEM, const char *keyPEM);
  bool beginSecure(const char *certPEM, const char *keyPEM, const char *password);
  void setDefaultCertificate(const unsigned char *cert, size_t certLen);
  void setDefaultKey(const unsigned char *key, size_t keyLen);
  void setDefaultCertificatePEM(const char *certPEM);
  void setDefaultKeyPEM(const char *keyPEM);
  void onSslFileRequest(AcSSlFileHandler cb, void *arg) {
    _ssl_file_cb = cb;
    _ssl_file_cb_arg = arg;
  }

  static void connDoneThunk(void *arg, AsyncClient *client) {
    (void)client;
    SecureServerHooks *h = static_cast<SecureServerHooks *>(arg);
    if (h) {
      h->_promoteSlot();
    }
  }

private:
  AsyncServerImpl *_srv;
  bool _use_ssl;
  const unsigned char *_cert;
  size_t _cert_len;
  const unsigned char *_key;
  size_t _key_len;
  AcSSlFileHandler _ssl_file_cb;
  void *_ssl_file_cb_arg;
  const char *_ssl_key_password;

  // Server-side TLS admission: session cache + bounded park queue.
  AsyncSecureServerCtx _secureCtx;

  int8_t _acceptTls(tcp_pcb *pcb);
  int8_t _acceptedTls(AsyncClient *client);
  int8_t _serveTls(tcp_pcb *pcb, struct pbuf *staged);
  int8_t _s_poll(tcp_pcb *pcb);
  int8_t _s_recv(tcp_pcb *pcb, struct pbuf *pb, int8_t err);
  void _s_error(int8_t err);
  int8_t _promoteSlot(void);
  void _conn_done(AsyncClient *client);
  static err_t _s_poll_cb(void *arg, tcp_pcb *tpcb);
  static err_t _s_recv_cb(void *arg, tcp_pcb *tpcb, struct pbuf *pb, err_t err);
  static void _s_error_cb(void *arg, err_t err);
  static void _s_conn_done_cb(void *arg, AsyncClient *client);
};


AsyncSecureServer::AsyncSecureServer(ip_addr_t addr, uint16_t port)
  : _tcp(addr, port) {
}

#ifdef ARDUINO
AsyncSecureServer::AsyncSecureServer(IPAddress addr, uint16_t port)
  : _tcp(addr, port) {
}
#if __has_include(<IPv6Address.h>)
AsyncSecureServer::AsyncSecureServer(IPv6Address addr, uint16_t port)
  : _tcp(addr, port) {
}
#endif
#endif

AsyncSecureServer::AsyncSecureServer(uint16_t port)
  : _tcp(port) {
}

AsyncSecureServer::~AsyncSecureServer() {
  end();
}

void AsyncSecureServer::onClient(AcConnectHandler cb, void *arg) {
  _tcp.onClient(cb, arg);
}

void AsyncSecureServer::begin() {
  _tcp.begin();
}

void AsyncSecureServer::end() {
  _tcp.end();
}

void AsyncSecureServer::setNoDelay(bool nodelay) {
  _tcp.setNoDelay(nodelay);
}

bool AsyncSecureServer::getNoDelay() const {
  return _tcp.getNoDelay();
}

uint8_t AsyncSecureServer::status() const {
  return _tcp.status();
}

void AsyncSecureServer::onSslFileRequest(AcSSlFileHandler cb, void *arg) {
  _tcp.onSslFileRequest(cb, arg);
}

void AsyncSecureServer::beginSecure(const char *cert, const char *private_key_file, const char *password) {
  _tcp.beginSecure(cert, private_key_file, password);
}

int8_t SecureServerHooks::_acceptedTls(AsyncClient *client) {
#if ASYNC_TCP_SSL_ENABLED
  if (!(_use_ssl && _cert && _key)) {
    return -1;  // TLS not configured: fall through to the plain onClient path
  }
  if (client && client->pcb()) {
    // Admission was gated at tcp_accept time by the park queue; reaching here
    // means a live serve slot is free. Total-heap serve floor only: the ctor
    // transient is ~44-59KB, so a tight arena is refused here (browser retries)
    // instead of dying mid-build in startSSLServer.
    if ((unsigned)ESP.getFreeHeap() < SSL_MBED_SERVE_FLOOR) {
      async_tcp_log_d("_acceptedTls: freeheap=%u below serve floor, refusing TLS conn", (unsigned)ESP.getFreeHeap());
      client->abort();
      delete client;
      return ERR_ABRT;
    }
    AsyncSecureSession *ssl = new (std::nothrow) AsyncSecureSession();
    if (ssl) {
      int ret = ssl->startSSLServer(client->pcb(), &_secureCtx, _ssl_key_password);
      if (ret == 0) {
        // Wires the session callbacks into the client's app callbacks and
        // takes over the pcb data path (installs the session's own
        // recv/sent/poll/err handlers on the pcb).
        SecureClientHooks *hooks = new (std::nothrow) SecureClientHooks(ssl, client->impl());
        if (!hooks) {
          async_tcp_log_e("Failed to allocate client hooks");
          delete ssl;
          client->abort();
          delete client;
          return ERR_ABRT;
        }
        client->setHooks(hooks);
        // The session owns NO pcb callbacks: ciphertext (including the
        // parked-conn ClientHello) arrives via the client's normal recv events
        // on this async task, where hooks->onRecv drives feedRx + handshake.
        async_tcp_log_d("Server SSL context ready, handshake starts on first ClientHello");
        if (pbuf *staged = takeStaged(client->impl())) {
          async_tcp_log_d("_acceptedTls: staged feed %u bytes", (unsigned)staged->tot_len);
          feedPbuf(client->impl(), staged);
        }
      } else {
        async_tcp_log_e("startSSLServer failed: %d", ret);
        delete ssl;
        client->abort();
        delete client;
        return ERR_ABRT;
      }
    } else {
      async_tcp_log_e("Failed to allocate SSL context for server");
      client->abort();
      delete client;
      return ERR_ABRT;
    }
  }
#endif
  notifyClient(_srv, client);
  return ERR_OK;
}

#if ASYNC_TCP_SSL_ENABLED
// Runs on LwIP thread (core lock held). Admission gate: serve while live
// budget remains, else park the raw pcb and buffer the ClientHello.
int8_t SecureServerHooks::_acceptTls(tcp_pcb *pcb) {
  if (!(_use_ssl && _cert && _key)) {
    return _serveTls(pcb, NULL);
  }
  if (_secureCtx.liveServeCount() >= SSL_MAX_CONNECTIONS) {
    if (_secureCtx.parked < SSL_PARKED_SLOTS) {
      struct pending_pcb *p = park_alloc();
      p->pcb = pcb;
      p->pb = NULL;
      p->pb_len = 0;
      p->parked_ms = millis();
      p->next = NULL;
      tcp_arg(pcb, (void *)this);
      // Slow park-tick: promote is instant via _conn_done; the poll here only
      // serves idle-shed (30s), page-flush and orphan close, so 1s intervals
      // cut the event-queue pressure (and "coalescing polls" warnings) 4x.
      tcp_poll(pcb, &_s_poll_cb, 4);
      tcp_recv(pcb, &_s_recv_cb);
      tcp_err(pcb, &_s_error_cb);
      struct pending_pcb **tail = &_secureCtx.pending;
      while (*tail) tail = &(*tail)->next;
      *tail = p;
      _secureCtx.parked++;
      async_tcp_log_d("SSL conn parked (live %d, queued %d/%d)",
          _secureCtx.liveServeCount(), _secureCtx.parked, SSL_PARKED_SLOTS);
      return ERR_OK;
    }
    async_tcp_log_w("SSL admission refused (live %d, queued %d/%d)",
        _secureCtx.liveServeCount(), _secureCtx.parked, SSL_PARKED_SLOTS);
    tcp_abort(pcb);
    return ERR_ABRT;
  }
  return _serveTls(pcb, NULL);
}

// Creates the AsyncClient for an accepted pcb, hands it the staged park pbufs
// and prepends LWIP_TCP_ACCEPT. _accepted builds the SSL session and feeds staged
// bytes once the session exists. Takes pcb on success; caller frees `staged` on error.
int8_t SecureServerHooks::_serveTls(tcp_pcb *pcb, pbuf *staged) {
  AsyncClient *c = new (std::nothrow) AsyncClient(pcb);
  if (c && c->pcb()) {
    c->setNoDelay(_srv->getNoDelay());
    doPromote(c, _s_conn_done_cb, this);
    if (staged) {
      stageStaged(c->impl(), staged);
    }
    if (queueAccept(_srv, c)) {
      return ERR_OK;
    }
    async_tcp_log_e("_serveTls failed: couldn't allocate accept event");
    detachPcb(c->impl());
    tcp_abort(pcb);
    return ERR_ABRT;
  }
  if (c) {
    async_tcp_log_e("_serveTls failed: couldn't complete setup");
    delete c;
    pcb = nullptr;
    return ERR_ABRT;
  }
  async_tcp_log_e("_serveTls failed: couldn't allocate client");
  tcp_abort(pcb);
  return ERR_ABRT;
}

// ---- parked-conn lwIP callbacks (LwIP thread, core lock held) ----
err_t SecureServerHooks::_s_poll_cb(void *arg, tcp_pcb *tpcb) {
  auto h = reinterpret_cast<SecureServerHooks *>(arg);
  return (err_t)h->_s_poll(tpcb);
}

err_t SecureServerHooks::_s_recv_cb(void *arg, tcp_pcb *tpcb, pbuf *pb, err_t err) {
  auto h = reinterpret_cast<SecureServerHooks *>(arg);
  return (err_t)h->_s_recv(tpcb, pb, (int8_t)err);
}

void SecureServerHooks::_s_error_cb(void *arg, err_t err) {
  auto h = reinterpret_cast<SecureServerHooks *>(arg);
  h->_s_error((int8_t)err);
}

void SecureServerHooks::_s_conn_done_cb(void *arg, AsyncClient *client) {
  auto h = reinterpret_cast<SecureServerHooks *>(arg);
  h->_conn_done(client);
}

int8_t SecureServerHooks::_s_poll(tcp_pcb *pcb) {
  struct pending_pcb *p = _secureCtx.pending;
  while (p && p->pcb != pcb) p = p->next;
  if (!p) {
    // Genuine orphan (queue drained/popped): holding the core lock means
    // nothing else can have claimed this pcb.
    shed_parked_pcb(pcb);
    return ERR_ABRT;
  }
  // Shed if waited behind a live conn past the idle timeout.
  if ((uint32_t)(millis() - p->parked_ms) > SSL_QUEUE_IDLE_MS) {
    unlink_pending(&_secureCtx.pending, p);
    _secureCtx.parked--;
    p->pcb = NULL;
    if (p->pb) {
      pbuf_free(p->pb);
    }
    shed_parked_pcb(pcb);
    return ERR_ABRT;
  }
  // Promote the FIFO head the moment live budget allows.
  if (_secureCtx.pending == p && _secureCtx.liveServeCount() < SSL_MAX_CONNECTIONS) {
    return _promoteSlot();
  }
  return ERR_OK;
}

int8_t SecureServerHooks::_s_recv(tcp_pcb *pcb, pbuf *pb, int8_t err) {
  (void)err;
  struct pending_pcb *p = _secureCtx.pending;
  while (p && p->pcb != pcb) p = p->next;
  if (!p) {
    // Stray delivery (shed/orphan/promote in flight): we own the pbuf, drop
    // it without acking (window stays shut for the doomed conn).
    if (pb) {
      pbuf_free(pb);
    }
    return ERR_OK;
  }
  if (pb == NULL) {
    // Peer closed while parked: shed bookkeeping and close.
    unlink_pending(&_secureCtx.pending, p);
    _secureCtx.parked--;
    p->pcb = NULL;
    if (p->pb) {
      pbuf_free(p->pb);
    }
    shed_parked_pcb(pcb);
    return ERR_ABRT;
  }
  // Buffer inbound bytes. Never ack here: lwIP's window closes naturally and
  // backpressures the peer; the promoted conn acks once on feed.
  uint16_t inc = pb->tot_len;
  if ((uint32_t)p->pb_len + inc <= SSL_PARKED_RX_CAP) {
    if (p->pb) {
      pbuf_chain(p->pb, pb);
    } else {
      p->pb = pb;
    }
    p->pb_len += inc;
  } else {
    async_tcp_log_d("SSL parked conn exceeded RX cap (%u + %u > %d)", p->pb_len, inc, SSL_PARKED_RX_CAP);
    pbuf_free(pb);
  }
  return ERR_OK;
}

void SecureServerHooks::_s_error(int8_t err) {
  (void)err;
  // lwIP already freed the errored pcb(s); free bookkeeping only. Survivors
  // beyond the queue are reaped by the _s_poll orphan path.
  if (_secureCtx.pending) {
    free_queued_items(&_secureCtx.pending, &_secureCtx.parked);
  }
}

// Instant-promote trigger: called from _conn_done (async task) and the parked
// _s_poll (LwIP thread). tcp_core_guard makes pop + rebind atomic vs LwIP.
int8_t SecureServerHooks::_promoteSlot(void) {
  tcp_core_guard tcg;
  struct pending_pcb *p = _secureCtx.pending;
  if (!p) {
    return ERR_OK;
  }
  if (_secureCtx.liveServeCount() >= SSL_MAX_CONNECTIONS) {
    return ERR_OK;
  }
  _secureCtx.pending = p->next;
  _secureCtx.parked--;
  tcp_pcb *pcb = p->pcb;
  pbuf *staged = p->pb;
  p->pcb = NULL;
  p->pb = NULL;
  int8_t r = _serveTls(pcb, staged);
  if (r != ERR_OK && staged) {
    pbuf_free(staged);
  }
  return r;
}

void SecureServerHooks::_conn_done(AsyncClient *client) {
  (void)client;
  _promoteSlot();
}

// --- SecureServerHooks: TLS admission + accepted-client setup, dispatched
// from AsyncServer's accept/close paths ---

int8_t SecureServerHooks::onAccept(AsyncServerImpl *srv, tcp_pcb *pcb, int8_t err) {
  (void)srv;
  (void)err;
  return _acceptTls(pcb);
}

int8_t SecureServerHooks::onAccepted(AsyncServerImpl *srv, AsyncClient *client) {
  (void)srv;
  return _acceptedTls(client);
}

void SecureServerHooks::onConnDone(AsyncServerImpl *srv, AsyncClient *client) {
  (void)srv;
  (void)client;
  _conn_done(client);
}
#endif

#if ASYNC_TCP_SSL_ENABLED
bool SecureServerHooks::beginSecure(const unsigned char *cert, size_t certLen,
    const unsigned char *key, size_t keyLen) {
  if (cert == NULL || key == NULL) {
    async_tcp_log_e("SSL cert or key is NULL");
    return false;
  }
  _cert = cert;
  _cert_len = certLen;
  _key = key;
  _key_len = keyLen;
  // Parse cert/key ONCE here: fail fast at boot, and every accepted
  // connection then references the parsed objects (no per-conn PEM re-parse).
  if (_secureCtx.ensureParsed(cert, certLen, key, keyLen, _ssl_key_password) != 0) {
    async_tcp_log_e("SSL cert/key parse failed (PEM needs NUL-terminated +1 length)");
    return false;
  }
  _use_ssl = true;
  _srv->begin();
  return _srv->status() != 0;
}

bool SecureServerHooks::beginSecure(const char *certPEM, const char *keyPEM) {
  return beginSecure(
      (const unsigned char *)certPEM, certPEM ? strlen(certPEM) + 1 : 0,
      (const unsigned char *)keyPEM, keyPEM ? strlen(keyPEM) + 1 : 0);
}

bool SecureServerHooks::beginSecure(const char *certPEM, const char *keyPEM, const char *password) {
  _ssl_key_password = password;
  return beginSecure(certPEM, keyPEM);
}

void SecureServerHooks::setDefaultCertificate(const unsigned char *cert, size_t certLen) {
  _cert = cert;
  _cert_len = certLen;
}

void SecureServerHooks::setDefaultKey(const unsigned char *key, size_t keyLen) {
  _key = key;
  _key_len = keyLen;
}

void SecureServerHooks::setDefaultCertificatePEM(const char *certPEM) {
  _cert = (const unsigned char *)certPEM;
  _cert_len = certPEM ? strlen(certPEM) + 1 : 0;
}

void SecureServerHooks::setDefaultKeyPEM(const char *keyPEM) {
  _key = (const unsigned char *)keyPEM;
  _key_len = keyPEM ? strlen(keyPEM) + 1 : 0;
}


// --- AsyncServer backward-compat TLS entry points (ESP32) ---
void AsyncServer::onSslFileRequest(std::function<int(void *arg, uint8_t **cert, uint8_t **key)> cb, void *arg) {
  if (!_impl->hooks()) {
    _impl->setHooks(new (std::nothrow) SecureServerHooks(_impl.get()));
  }
  static_cast<SecureServerHooks *>(_impl->hooks())->onSslFileRequest(cb, arg);
}

void AsyncServer::beginSecure(const char *cert, const char *key, const char *password) {
  if (!_impl->hooks()) {
    _impl->setHooks(new (std::nothrow) SecureServerHooks(_impl.get()));
  }
  static_cast<SecureServerHooks *>(_impl->hooks())->beginSecure(cert, key, password);
}
#endif

#endif

// ===== end mbedTLS/ESP32 AsyncSecureServer =====/
#endif
