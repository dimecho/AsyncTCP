// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright 2016-2026 Hristo Gochkov, Mathieu Carbou, Emil Muratov, Will Miles
//
// Unified dual-stack AsyncTCP library.
//   - ESP8266         -> BearSSL stack (AsyncTCP fork, NO_SYS lwIP)
//   - ESP32/LIBRETINY -> mbedTLS stack (AsyncTCP ESP32Async base)
// Stacks selected per-platform below (ESP8266 = BearSSL, ESP32/LIBRETINY = mbedTLS).

#ifndef ASYNCTCP_H_
#define ASYNCTCP_H_

#include "AsyncTCPVersion.h"
#include <stdint.h>
#include <stddef.h>

#ifdef ARDUINO
#include "IPAddress.h"
#if __has_include(<IPv6Address.h>)
#include "IPv6Address.h"
#endif
#endif

#include "lwip/ip6_addr.h"
#include "lwip/ip_addr.h"
#include <functional>

#if defined(ESP32)
#include "sdkconfig.h"
extern "C" {
#include "freertos/semphr.h"
#include "lwip/pbuf.h"
}
#elif defined(LIBRETINY)
extern "C" {
#include <lwip/pbuf.h>
#include <FreeRTOS.h>
#include <semphr.h>
}
#elif defined(ESP8266)
extern "C" {
#include "lwip/pbuf.h"
}
#endif

// If core is not defined, then we are running in Arduino or PIO
#ifndef CONFIG_ASYNC_TCP_RUNNING_CORE
#define CONFIG_ASYNC_TCP_RUNNING_CORE -1  // any available core
#endif

// guard AsyncTCP task with watchdog
#ifndef CONFIG_ASYNC_TCP_USE_WDT
#define CONFIG_ASYNC_TCP_USE_WDT 1
#endif

#ifndef CONFIG_ASYNC_TCP_STACK_SIZE
#define CONFIG_ASYNC_TCP_STACK_SIZE 8192 * 2
#endif

#ifndef CONFIG_ASYNC_TCP_PRIORITY
#define CONFIG_ASYNC_TCP_PRIORITY 10
#endif

#ifndef CONFIG_ASYNC_TCP_QUEUE_SIZE
#define CONFIG_ASYNC_TCP_QUEUE_SIZE 64
#endif

#ifndef CONFIG_ASYNC_TCP_MAX_ACK_TIME
#define CONFIG_ASYNC_TCP_MAX_ACK_TIME 5000
#endif

class AsyncClient;

#define ASYNC_WRITE_FLAG_COPY 0x01  // will allocate new buffer to hold the data while sending (else will hold reference to the data given)
#define ASYNC_WRITE_FLAG_MORE 0x02  // will not send PSH flag, meaning that there should be more data to be sent before the application should react.

typedef std::function<void(void *, AsyncClient *)> AcConnectHandler;
typedef std::function<void(void *, AsyncClient *, size_t len, uint32_t time)> AcAckHandler;
typedef std::function<void(void *, AsyncClient *, int8_t error)> AcErrorHandler;
typedef std::function<void(void *, AsyncClient *, void *data, size_t len)> AcDataHandler;
typedef std::function<void(void *, AsyncClient *, struct pbuf *pb)> AcPacketHandler;
typedef std::function<void(void *, AsyncClient *, uint32_t time)> AcTimeoutHandler;

#include <memory>

struct tcp_pcb;
class AsyncTCP_detail;

struct pbuf;
class AsyncClientImpl;

class AsyncServer;


struct AsyncClientCallbackContext;
struct pending_pcb;


// Optional client TLS hooks. Unchanged interface; hook implementations now
// receive the impl (AsyncClientImpl*), where all state lives.
struct AsyncClientHooks {
  virtual ~AsyncClientHooks() {}
  virtual bool onConnected(AsyncClientImpl *c) { (void)c; return false; }
  virtual bool onRecv(AsyncClientImpl *c, struct pbuf *pb) { (void)c; (void)pb; return false; }
  virtual bool onSent(AsyncClientImpl *c, uint16_t len) { (void)c; (void)len; return false; }
  virtual bool onPoll(AsyncClientImpl *c) { (void)c; return false; }
  virtual int onWrite(AsyncClientImpl *c, const char *data, size_t size) { (void)c; (void)data; (void)size; return -1; }
  virtual void onClosing(AsyncClientImpl *c) { (void)c; }
  virtual void onError(AsyncClientImpl *c, int8_t err) { (void)c; (void)err; }

protected:
  // Helpers for hook implementations. Defined in AsyncTCP.cpp.
  void touchRx(AsyncClientImpl *c, uint32_t now);
  uint32_t lastRx(AsyncClientImpl *c) const;
  void notifyData(AsyncClientImpl *c, void *data, size_t len);
  void notifyConnect(AsyncClientImpl *c);
  void notifyError(AsyncClientImpl *c, int8_t err);
  void notifyDiscard(AsyncClientImpl *c);
  void recved(AsyncClientImpl *c, size_t len);
};

class AsyncClientImpl : public std::enable_shared_from_this<AsyncClientImpl> {
public:
  AsyncClientImpl(AsyncClient *facade, tcp_pcb *pcb = 0);
  ~AsyncClientImpl();

  bool operator==(const AsyncClientImpl &other) const;

  bool connect(ip_addr_t addr, uint16_t port);
#ifdef ARDUINO
  bool connect(const IPAddress &ip, uint16_t port);
#endif
  bool connect(const char *host, uint16_t port);
  void close();
  int8_t abort();
  bool free();
  bool canSend() const;
  size_t space() const;
  size_t add(const char *data, size_t size, uint8_t apiflags = ASYNC_WRITE_FLAG_COPY);
  bool send();
  size_t write(const char *data, size_t size, uint8_t apiflags = ASYNC_WRITE_FLAG_COPY);
  uint8_t state() const;
  bool connecting() const;
  bool connected() const;
  bool disconnecting() const;
  bool disconnected() const;
  bool freeable() const;
  uint16_t getMss() const;
  uint32_t getRxTimeout() const;
  void setRxTimeout(uint32_t timeout);
  uint32_t getAckTimeout() const;
  void setAckTimeout(uint32_t timeout);
  void setNoDelay(bool nodelay) const;
  bool getNoDelay();
  void setKeepAlive(uint32_t ms, uint8_t cnt);
  uint32_t getRemoteAddress() const;
  uint16_t getRemotePort() const;
  uint32_t getLocalAddress() const;
  uint16_t getLocalPort() const;
  ip4_addr_t getRemoteAddress4() const;
  ip4_addr_t getLocalAddress4() const;
#if LWIP_IPV6
  ip6_addr_t getRemoteAddress6() const;
  ip6_addr_t getLocalAddress6() const;
#ifdef ARDUINO
#if __has_include(<IPv6Address.h>)
  IPv6Address remoteIP6() const;
  IPv6Address localIP6() const;
#else
  IPAddress remoteIP6() const;
  IPAddress localIP6() const;
#endif
#endif
#endif
#ifdef ARDUINO
  IPAddress remoteIP() const;
  IPAddress localIP() const;
#endif
  void onConnect(AcConnectHandler cb, void *arg = 0);
  void onDisconnect(AcConnectHandler cb, void *arg = 0);
  void onAck(AcAckHandler cb, void *arg = 0);
  void onError(AcErrorHandler cb, void *arg = 0);
  void onData(AcDataHandler cb, void *arg = 0);
  void onPacket(AcPacketHandler cb, void *arg = 0);
  void onTimeout(AcTimeoutHandler cb, void *arg = 0);
  void onPoll(AcConnectHandler cb, void *arg = 0);
  void ackPacket(struct pbuf *pb);
  size_t ack(size_t len);
  void ackLater();
  const char *stateToString() const;
  int8_t _recv(tcp_pcb *pcb, struct pbuf *pb, err_t err);
  tcp_pcb *pcb() { return _pcb; }
  void setHooks(AsyncClientHooks *hooks) { _tls_client_hooks = hooks; }

private:
  friend class AsyncTCP_detail;
  friend class AsyncServer;
  friend class AsyncSecureServer;
  friend class AsyncClientHooks;
  friend class AsyncServerHooks;
  friend class AsyncSecureClient;
  friend struct SecureClientHooks;
  friend class AsyncClient;

  friend void _asynctcp_touch_rx(AsyncClientImpl *);
  friend bool _asynctcp_dns_token_current(AsyncClientImpl *, const std::shared_ptr<void> &);

  tcp_pcb *_pcb;
  AsyncClient *_facade;   // backlink; may be null once the app dropped it

  AcConnectHandler _connect_cb;
  void *_connect_cb_arg;
  AcConnectHandler _discard_cb;
  void *_discard_cb_arg;
  AcConnectHandler _server_discard_cb;  // set by AsyncServer for instant slot promote
  void *_server_discard_cb_arg;
  AcAckHandler _sent_cb;
  void *_sent_cb_arg;
  AcErrorHandler _error_cb;
  void *_error_cb_arg;
  AcDataHandler _recv_cb;
  void *_recv_cb_arg;
  AcPacketHandler _pb_cb;
  void *_pb_cb_arg;
  AcTimeoutHandler _timeout_cb;
  void *_timeout_cb_arg;
  AcConnectHandler _poll_cb;
  void *_poll_cb_arg;

  AsyncClientCallbackContext *_cb_ctx;
  uint32_t _tx_last_packet;
  uint32_t _rx_ack_len;
  uint32_t _rx_last_packet;
  uint32_t _rx_timeout;
  uint32_t _rx_last_ack;
  uint32_t _ack_timeout;
  uint16_t _connect_port;
  bool _noDelay;
  AsyncClientHooks *_tls_client_hooks;
  // Stale-DNS-answer rejection, PR124-style: every connect() by name mints a
  // fresh token; the lookup context captures it, and the answer is accepted
  // only if the identity still matches. close()/abort() drop the token.
  std::shared_ptr<void> _dns_token;
  bool _dead;            // teardown finished; queued events must not dispatch
#if ASYNC_TCP_SSL_ENABLED
  pbuf *_ssl_pending_pbufs;  // staged park-queue pbufs, fed to the session on accept
  static void _tcp_recved(tcp_pcb **pcbp, size_t len);
#endif

  int8_t _close();
  int8_t _connected(tcp_pcb *pcb, int8_t err);
  void _error(int8_t err);
  int8_t _poll(tcp_pcb *pcb);
  int8_t _sent(tcp_pcb *pcb, uint16_t len);
  int8_t _fin(tcp_pcb *pcb, err_t err);
  void _dns_found(ip_addr_t *ipaddr);
};

class AsyncClient {
public:
  AsyncClient(tcp_pcb *pcb = 0);
  ~AsyncClient();

  // Noncopyable, nonmovable: the facade is a thin handle; copy semantics
  // would fork the shared impl. (Same as before.)
  AsyncClient(const AsyncClient &) = delete;
  AsyncClient &operator=(const AsyncClient &) = delete;
  AsyncClient(AsyncClient &&) = delete;
  AsyncClient &operator=(AsyncClient &&) = delete;

  bool operator==(const AsyncClient &other) const { return _impl == other._impl; }
  bool operator!=(const AsyncClient &other) const { return !(*this == other); }

  bool connect(ip_addr_t addr, uint16_t port) { return _impl->connect(addr, port); }
#ifdef ARDUINO
  bool connect(const IPAddress &ip, uint16_t port) { return _impl->connect(ip, port); }
#if __has_include(<IPv6Address.h>)
  bool connect(const IPv6Address &ip, uint16_t port);
#endif
#endif
  bool connect(const char *host, uint16_t port) { return _impl->connect(host, port); }

  void close() { _impl->close(); }
  int8_t abort() { return _impl->abort(); }
  bool free() { return _impl->free(); }
  bool canSend() const { return _impl->canSend(); }
  size_t space() const { return _impl->space(); }
  size_t add(const char *data, size_t size, uint8_t apiflags = ASYNC_WRITE_FLAG_COPY) { return _impl->add(data, size, apiflags); }
  bool send() { return _impl->send(); }
  size_t write(const char *data, size_t size, uint8_t apiflags = ASYNC_WRITE_FLAG_COPY) { return _impl->write(data, size, apiflags); }
  size_t write(const char *data) { return data == NULL ? 0 : write(data, strlen(data)); }

  uint8_t state() const { return _impl->state(); }
  bool connecting() const { return _impl->connecting(); }
  bool connected() const { return _impl->connected(); }
  bool disconnecting() const { return _impl->disconnecting(); }
  bool disconnected() const { return _impl->disconnected(); }
  bool freeable() const { return _impl->freeable(); }
  uint16_t getMss() const { return _impl->getMss(); }
  uint32_t getRxTimeout() const { return _impl->getRxTimeout(); }
  void setRxTimeout(uint32_t timeout) { _impl->setRxTimeout(timeout); }
  uint32_t getAckTimeout() const { return _impl->getAckTimeout(); }
  void setAckTimeout(uint32_t timeout) { _impl->setAckTimeout(timeout); }
  void setNoDelay(bool nodelay) const { _impl->setNoDelay(nodelay); }
  bool getNoDelay() { return _impl->getNoDelay(); }
  void setKeepAlive(uint32_t ms, uint8_t cnt) { _impl->setKeepAlive(ms, cnt); }
  uint32_t getRemoteAddress() const { return _impl->getRemoteAddress(); }
  uint16_t getRemotePort() const { return _impl->getRemotePort(); }
  uint16_t remotePort() const { return getRemotePort(); }
  uint32_t getLocalAddress() const { return _impl->getLocalAddress(); }
  uint16_t getLocalPort() const { return _impl->getLocalPort(); }
  uint16_t localPort() const { return getLocalPort(); }
  ip4_addr_t getRemoteAddress4() const { return _impl->getRemoteAddress4(); }
  ip4_addr_t getLocalAddress4() const { return _impl->getLocalAddress4(); }
#if LWIP_IPV6
  ip6_addr_t getRemoteAddress6() const { return _impl->getRemoteAddress6(); }
  ip6_addr_t getLocalAddress6() const { return _impl->getLocalAddress6(); }
#ifdef ARDUINO
#if __has_include(<IPv6Address.h>)
  IPv6Address remoteIP6() const { return _impl->remoteIP6(); }
  IPv6Address localIP6() const { return _impl->localIP6(); }
#else
  IPAddress remoteIP6() const { return _impl->remoteIP6(); }
  IPAddress localIP6() const { return _impl->localIP6(); }
#endif
#endif
#endif
#ifdef ARDUINO
  IPAddress remoteIP() const { return _impl->remoteIP(); }
  IPAddress localIP() const { return _impl->localIP(); }
#endif

  void onConnect(AcConnectHandler cb, void *arg = 0) { _impl->onConnect(cb, arg); }
  void onDisconnect(AcConnectHandler cb, void *arg = 0) { _impl->onDisconnect(cb, arg); }
  void onAck(AcAckHandler cb, void *arg = 0) { _impl->onAck(cb, arg); }
  void onError(AcErrorHandler cb, void *arg = 0) { _impl->onError(cb, arg); }
  void onData(AcDataHandler cb, void *arg = 0) { _impl->onData(cb, arg); }
  void onPacket(AcPacketHandler cb, void *arg = 0) { _impl->onPacket(cb, arg); }
  void onTimeout(AcTimeoutHandler cb, void *arg = 0) { _impl->onTimeout(cb, arg); }
  void onPoll(AcConnectHandler cb, void *arg = 0) { _impl->onPoll(cb, arg); }

  void ackPacket(struct pbuf *pb) { _impl->ackPacket(pb); }
  size_t ack(size_t len) { return _impl->ack(len); }
  void ackLater() { _impl->ackLater(); }

  static const char *errorToString(int8_t error);
  const char *stateToString() const { return _impl->stateToString(); }

  int8_t _recv(tcp_pcb *pcb, struct pbuf *pb, err_t err) { return _impl->_recv(pcb, pb, err); }
  tcp_pcb *pcb() { return _impl->pcb(); }
  void setHooks(AsyncClientHooks *hooks) { _impl->setHooks(hooks); }
  // (internal) impl handle for the TLS server glue (SecureServerHooks)
  AsyncClientImpl *impl() { return _impl.get(); }

  [[deprecated("Use AsyncClient::close() instead")]]
  void close(bool now __attribute__((unused))) { close(); }
  [[deprecated("Use AsyncClient::close() instead")]]
  void stop() { close(); }

private:
  friend class AsyncSecureClient;
  friend class AsyncSecureServer;
  friend class AsyncServerHooks;
  std::shared_ptr<AsyncClientImpl> _impl;
};
// ============================================================================
// AsyncServer — impl + facade (same pattern as the client).
// The impl holds the listener state; queued accept events carry
// shared_ptr<AsyncServerImpl> plus the listener session epoch, so a stale
// accept (end()/destructor between accept and delivery) is dropped at
// dispatch — no purge walk, no liveness registry.
// ============================================================================
class AsyncServerImpl;
class AsyncServer;

struct AsyncServerHooks {
  virtual ~AsyncServerHooks() {}
  // Admission (LwIP thread). Return an lwIP ERR_* code if the hook handled
  // the pcb (served or parked), -1 to fall through to the plain accept path.
  virtual int8_t onAccept(AsyncServerImpl *srv, tcp_pcb *pcb, int8_t err) { (void)srv; (void)pcb; (void)err; return -1; }
  // Accepted client (async task). Return an lwIP ERR_* code if the hook
  // handled the client, -1 to fall through to the plain onClient callback.
  virtual int8_t onAccepted(AsyncServerImpl *srv, AsyncClient *client) { (void)srv; (void)client; return -1; }
  // A live connection tore down (its TLS buffers already freed) — the hook
  // may promote queued connections immediately.
  virtual void onConnDone(AsyncServerImpl *srv, AsyncClient *client) { (void)srv; (void)client; }

protected:
  // Helpers for hook implementations. Defined in AsyncTCP.cpp.
  void notifyClient(AsyncServerImpl *srv, AsyncClient *c);   // fire the app's onClient
  bool hasConnectHandler(AsyncServerImpl *srv);              // is the app's onClient callback set?
  void doPromote(AsyncClient *c, void (*thunk)(void *, AsyncClient *), void *arg);  // instant-promote hook
  struct pbuf *takeStaged(AsyncClientImpl *c);               // pop the staged park-queue pbufs
  void stageStaged(AsyncClientImpl *c, struct pbuf *staged); // stash staged park-queue pbufs
  void feedPbuf(AsyncClientImpl *c, struct pbuf *pb);        // feed a pbuf into the client's recv path
  void detachPcb(AsyncClientImpl *c);                        // null the client's pcb (pre-abort detach)
  bool queueAccept(AsyncServerImpl *srv, AsyncClient *c);
};

class AsyncServerImpl : public std::enable_shared_from_this<AsyncServerImpl> {
public:
  AsyncServerImpl(AsyncServer *facade, ip_addr_t addr, uint16_t port);
  ~AsyncServerImpl();

  void onClient(AcConnectHandler cb, void *arg);
  void setHooks(AsyncServerHooks *hooks) { _tls_server_hooks = hooks; }
  AsyncServerHooks *hooks() { return _tls_server_hooks; }
  void begin();
  void end();
  void setNoDelay(bool nodelay) { _noDelay = nodelay; }
  bool getNoDelay() const { return _noDelay; }
  uint8_t status() const;

  static bool queueAcceptEvent(AsyncServerImpl *server, AsyncClient *client, std::shared_ptr<AsyncClientImpl> impl);

private:
  friend class AsyncTCP_detail;
  friend class AsyncServer;
  friend class AsyncSecureServer;
  friend class AsyncServerHooks;

  AsyncServer *_facade;  // backlink; the facade hands accepted clients to the app

  AsyncServerHooks *_tls_server_hooks;
  uint16_t _port;
  ip_addr_t _addr;
  bool _noDelay;
  tcp_pcb *_pcb;
  AcConnectHandler _connect_cb;
  void *_connect_cb_arg;
  uint32_t _session = 0;  // listener session; bumped by begin()/end() (stale-accept guard)

  int8_t _accepted(AsyncClient *client);
};

class AsyncServer {
public:
  AsyncServer(ip_addr_t addr, uint16_t port);
#ifdef ARDUINO
  AsyncServer(IPAddress addr, uint16_t port);
#if __has_include(<IPv6Address.h>)
  AsyncServer(IPv6Address addr, uint16_t port);
#endif
#endif
  AsyncServer(uint16_t port);
  ~AsyncServer();

  void onClient(AcConnectHandler cb, void *arg) { _impl->onClient(cb, arg); }
  void setHooks(AsyncServerHooks *hooks) { _impl->setHooks(hooks); }
#if ASYNC_TCP_SSL_ENABLED
  // Backward-compat TLS entry points (SecureServerHooks glue lives in
  // AsyncSecureServer.cpp; per-stack callback signature).
#if defined(ESP8266)
  void onSslFileRequest(std::function<int(void *arg, const char *filename, uint8_t **buf)> cb, void *arg);
#else
  void onSslFileRequest(std::function<int(void *arg, uint8_t **cert, uint8_t **key)> cb, void *arg);
#endif
  void beginSecure(const char *cert, const char *private_key_file, const char *password);
#endif
  void begin() { _impl->begin(); }
  void end() { _impl->end(); }
  void setNoDelay(bool nodelay) { _impl->setNoDelay(nodelay); }
  bool getNoDelay() const { return _impl->getNoDelay(); }
  uint8_t status() const { return _impl->status(); }

private:
  friend class AsyncSecureServer;
  friend class AsyncTCP_detail;
  friend class AsyncServerHooks;
  std::shared_ptr<AsyncServerImpl> _impl;
};

// Client architecture: impl + facade.
//   AsyncClientImpl — shared_ptr-owned state + transport; the event queue,
//   lwIP callbacks and TLS hooks hold shared_ptr<AsyncClientImpl>, so a
//   queued event can never dispatch against a dead client (the registry,
//   destructor purge and friend helpers are gone).
//   AsyncClient     — thin facade; API identical to before, so AsyncWebServer
//   and application call sites are unchanged.
// ============================================================================
#include <memory>

class AsyncClientImpl;
class AsyncClient;


#include "AsyncSecureSession.h"

#if defined(ESP8266)

// TLS client: inherits AsyncClient (pure-TCP transport + the setHooks() seam)
// and adds the beginSecure() convenience. Defined in AsyncSecureClient.cpp.
#if ASYNC_TCP_SSL_ENABLED
class AsyncSecureClient : public AsyncClient {
public:
  bool beginSecure(const char *host, uint16_t port, const char *rootCA = NULL);
};
#endif
// ---------------- ESP8266 + BearSSL -------------
#if ASYNC_TCP_SSL_ENABLED
typedef std::function<int(void *arg, const char *filename, uint8_t **buf)> AcSSLFileHandler;
typedef AcSSLFileHandler AcSSlFileHandler;  // backward compat (old typo)
struct pending_pcb;
#endif


// TLS server: thin composition wrapper around AsyncServer. Installs the TLS
// server hooks (admission/serve/promotion) on the composed transport;
// implementations live in AsyncSecureServer.cpp.
#if ASYNC_TCP_SSL_ENABLED && ASYNC_TCP_SSL_ENABLE_SERVER
class AsyncSecureServer {
public:
  AsyncSecureServer(ip_addr_t addr, uint16_t port);
#ifdef ARDUINO
  AsyncSecureServer(IPAddress addr, uint16_t port);
#if __has_include(<IPv6Address.h>)
  AsyncSecureServer(IPv6Address addr, uint16_t port);
#endif
#endif
  AsyncSecureServer(uint16_t port);
~AsyncSecureServer();

  void onClient(AcConnectHandler cb, void *arg);
  void setHooks(AsyncServerHooks *hooks);
  void begin();
  void end();
  void setNoDelay(bool nodelay);
  bool getNoDelay() const;
  uint8_t status() const;

  void onSslFileRequest(AcSSLFileHandler cb, void *arg);
  void beginSecure(const char *cert, const char *private_key_file, const char *password);

private:
  AsyncServer _tcp;  // pure-TCP server
};
#endif
#else /* ESP32 */

// TLS client: inherits AsyncClient (pure-TCP transport + the setHooks() seam)
// and adds the beginSecure() convenience. Defined in AsyncSecureClient.cpp.
#if ASYNC_TCP_SSL_ENABLED
class AsyncSecureClient : public AsyncClient {
public:
  bool beginSecure(const char *host, uint16_t port, const char *rootCA = NULL,
      const char *clientCert = NULL, const char *clientKey = NULL,
      const char *keyPassword = NULL);
  bool beginSecure(const char *host, uint16_t port,
      const unsigned char *rootCA, size_t rootCALen,
      const unsigned char *clientCert = NULL, size_t clientCertLen = 0,
      const unsigned char *clientKey = NULL, size_t clientKeyLen = 0,
      const char *keyPassword = NULL);
};
#endif
// ---------------- ESP32/LIBRETINY + mbedTLS ------
#if ASYNC_TCP_SSL_ENABLED
typedef std::function<int(void *arg, uint8_t **cert, uint8_t **key)> AcSSlFileHandler;


// TLS server: thin composition wrapper around AsyncServer. Installs the TLS
// server hooks (admission/serve/promotion) on the composed transport;
// implementations live in AsyncSecureServer.cpp.
#if ASYNC_TCP_SSL_ENABLED
class AsyncSecureServer {
public:
  AsyncSecureServer(ip_addr_t addr, uint16_t port);
#ifdef ARDUINO
  AsyncSecureServer(IPAddress addr, uint16_t port);
#if __has_include(<IPv6Address.h>)
  AsyncSecureServer(IPv6Address addr, uint16_t port);
#endif
#endif
  AsyncSecureServer(uint16_t port);
~AsyncSecureServer();

  void onClient(AcConnectHandler cb, void *arg);
  void setHooks(AsyncServerHooks *hooks);
  void begin();
  void end();
  void setNoDelay(bool nodelay);
  bool getNoDelay() const;
  uint8_t status() const;

  void onSslFileRequest(AcSSlFileHandler cb, void *arg);
  void beginSecure(const char *cert, const char *key, const char *password);

private:
  AsyncServer _tcp;  // the composed pure-TCP server
};
#endif
#endif

#endif  // platform select (ESP8266 / ESP32-LIBRETINY)
#endif /* ASYNCTCP_H_ */
