// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright 2016-2026 Hristo Gochkov, Mathieu Carbou, Emil Muratov, Will Miles
//
// Unified dual-stack AsyncTCP library.
//   - ESP8266         -> BearSSL stack (AsyncTCP fork, NO_SYS lwIP)
//   - ESP32/LIBRETINY -> mbedTLS stack (AsyncTCP ESP32Async base)
// Selected at compile time via #if defined(ESP8266). Only one stack compiles per target.

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

struct tcp_pcb;
class AsyncTCP_detail;

struct pbuf;

// Optional client TLS hooks. TLS attaches to take over the data path;
struct AsyncClientHooks {
  virtual ~AsyncClientHooks() {}
  // TCP established; return true to skip the default onConnect flow
  // (e.g. onConnect fires later, on handshake completion).
  virtual bool onConnected(AsyncClient *c) { (void)c; return false; }
  // inbound data; return true if consumed (skips the plain path)
  virtual bool onRecv(AsyncClient *c, struct pbuf *pb) { (void)c; (void)pb; return false; }
  // outbound ACK; return true to skip app-level accounting (mid-handshake)
  virtual bool onSent(AsyncClient *c, uint16_t len) { (void)c; (void)len; return false; }
  // periodic tick; return true if the hook closed the connection
  virtual bool onPoll(AsyncClient *c) { (void)c; return false; }
  // TX path; return >= 0 = consumed (value = bytes accepted), -1 = plain path
  virtual int onWrite(AsyncClient *c, const char *data, size_t size) { (void)c; (void)data; (void)size; return -1; }
  // _close()/abort(): teardown while the pcb is still live
  virtual void onClosing(AsyncClient *c) { (void)c; }
  // transport RST/error: the pcb is already gone
  virtual void onError(AsyncClient *c, int8_t err) { (void)c; (void)err; }

protected:
  // Helpers for hook implementations: AsyncClientHooks is part of
  // AsyncClient, not inherited, so implementations reach
  // client internals through these. Defined in AsyncTCP.cpp.
  void touchRx(AsyncClient *c, uint32_t now);
  uint32_t lastRx(AsyncClient *c) const;
  void notifyData(AsyncClient *c, void *data, size_t len);
  void notifyConnect(AsyncClient *c);
  void notifyError(AsyncClient *c, int8_t err);
  void notifyDiscard(AsyncClient *c);
  void recved(AsyncClient *c, size_t len);  // ack consumed ciphertext to the lwIP window
};

class AsyncServer;

// Optional server TLS hooks. TLS attaches to take over handshake and the data path;
struct AsyncServerHooks {
  virtual ~AsyncServerHooks() {}
  // Admission (LwIP thread). Return an lwIP ERR_* code if the hook handled
  // the pcb (served or parked), -1 to fall through to the plain accept path.
  virtual int8_t onAccept(AsyncServer *srv, tcp_pcb *pcb, int8_t err) { (void)srv; (void)pcb; (void)err; return -1; }
  // Accepted client (async task). Return an lwIP ERR_* code if the hook
  // handled the client, -1 to fall through to the plain onClient callback.
  virtual int8_t onAccepted(AsyncServer *srv, AsyncClient *client) { (void)srv; (void)client; return -1; }
  // A live connection tore down (its TLS buffers already freed) — the hook
  // may promote queued connections immediately.
  virtual void onConnDone(AsyncServer *srv, AsyncClient *client) { (void)srv; (void)client; }

protected:
  // Helpers for hook implementations: reach AsyncServer/AsyncClient internals
  // (AsyncServerHooks is a friend of both, but friendship is not inherited).
  // Defined in AsyncTCP.cpp.
  void notifyClient(AsyncServer *srv, AsyncClient *c);                     // fire the app's onClient
  bool hasConnectHandler(AsyncServer *srv);                                 // is the app's onClient callback set?
  void doPromote(AsyncClient *c, void (*thunk)(void *, AsyncClient *), void *arg);  // set the client's instant-promote hook
  struct pbuf *takeStaged(AsyncClient *c);                                  // pop the staged park-queue pbufs
  void stageStaged(AsyncClient *c, struct pbuf *staged);                   // stash staged park-queue pbufs on the client
  void feedPbuf(AsyncClient *c, struct pbuf *pb);                          // feed a pbuf into the client's recv path
  void detachPcb(AsyncClient *c);                                            // null the client's pcb (pre-abort detach)
  bool queueAccept(AsyncServer *srv, AsyncClient *c);                    // queue the accept event for a created client
};

#include "AsyncSecureSession.h"

struct AsyncClientCallbackContext;
struct pending_pcb;

#if defined(ESP8266)
// ---------------- ESP8266 + BearSSL -------------
#if ASYNC_TCP_SSL_ENABLED
typedef std::function<int(void *arg, const char *filename, uint8_t **buf)> AcSSLFileHandler;
typedef AcSSLFileHandler AcSSlFileHandler;  // backward compat (old typo)
struct pending_pcb;
#endif

class AsyncClient {
public:
  AsyncClient(tcp_pcb *pcb = 0);
  ~AsyncClient();

  // Noncopyable
  AsyncClient(const AsyncClient &) = delete;
  AsyncClient &operator=(const AsyncClient &) = delete;

  // Nonmovable
  AsyncClient(AsyncClient &&) = delete;
  AsyncClient &operator=(AsyncClient &&) = delete;

  bool operator==(const AsyncClient &other) const;

  bool operator!=(const AsyncClient &other) const {
    return !(*this == other);
  }
  bool connect(ip_addr_t addr, uint16_t port);
#ifdef ARDUINO
  bool connect(const IPAddress &ip, uint16_t port);
#if __has_include(<IPv6Address.h>)
  bool connect(const IPv6Address &ip, uint16_t port);
#endif
#endif
  bool connect(const char *host, uint16_t port);

  /**
     * @brief close connection
     */
  void close();

  int8_t abort();
  bool free();

  // ack is not pending
  bool canSend() const;
  // TCP buffer space available
  size_t space() const;

  /**
     * @brief add data to be send (but do not send yet)
     * @note add() would call lwip's tcp_write()
        By default apiflags=ASYNC_WRITE_FLAG_COPY
        You could try to use apiflags with this flag unset to pass data by reference and avoid copy to socket buffer,
        but looks like it does not work for Arduino's lwip in ESP32/IDF at least
        it is enforced in https://github.com/espressif/esp-lwip/blob/0606eed9d8b98a797514fdf6eabb4daf1c8c8cd9/src/core/tcp_out.c#L422C5-L422C30
        if LWIP_NETIF_TX_SINGLE_PBUF is set, and it is set indeed in IDF
        https://github.com/espressif/esp-idf/blob/a0f798cfc4bbd624aab52b2c194d219e242d80c1/components/lwip/port/include/lwipopts.h#L744
     *
     * @param data
     * @param size
     * @param apiflags
     * @return size_t amount of data that has been copied
     */
  size_t add(const char *data, size_t size, uint8_t apiflags = ASYNC_WRITE_FLAG_COPY);

  /**
     * @brief send data previously add()'ed
     *
     * @return true on success
     * @return false on error
     */
  bool send();

  /**
     * @brief add and enqueue data for sending
     * @note it is same as add() + send()
     * @note only make sense when canSend() == true
     *
     * @param data
     * @param size
     * @param apiflags
     * @return size_t
     */
  size_t write(const char *data, size_t size, uint8_t apiflags = ASYNC_WRITE_FLAG_COPY);

  /**
     * @brief add and enqueue data for sending
     * @note treats data as null-terminated string
     *
     * @param data
     * @return size_t
     */
  size_t write(const char *data) {
    return data == NULL ? 0 : write(data, strlen(data));
  };

  uint8_t state() const;
  bool connecting() const;
  bool connected() const;
  bool disconnecting() const;
  bool disconnected() const;

  // disconnected or disconnecting
  bool freeable() const;

  uint16_t getMss() const;

  uint32_t getRxTimeout() const;
  // no RX data timeout for the connection in seconds
  void setRxTimeout(uint32_t timeout);

  uint32_t getAckTimeout() const;
  // no ACK timeout for the last sent packet in milliseconds
  void setAckTimeout(uint32_t timeout);

  void setNoDelay(bool nodelay) const;
  bool getNoDelay();

  void setKeepAlive(uint32_t ms, uint8_t cnt);

  uint32_t getRemoteAddress() const;
  uint16_t getRemotePort() const;
  uint16_t remotePort() const {
    return getRemotePort();
  }

  uint32_t getLocalAddress() const;
  uint16_t getLocalPort() const;
  uint16_t localPort() const {
    return getLocalPort();
  }

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

  // set callback - on successful connect
  void onConnect(AcConnectHandler cb, void *arg = 0);
  // set callback - disconnected
  void onDisconnect(AcConnectHandler cb, void *arg = 0);
  // set callback - ack received
  void onAck(AcAckHandler cb, void *arg = 0);
  // set callback - unsuccessful connect or error
  void onError(AcErrorHandler cb, void *arg = 0);
  // set callback - data received (called if onPacket is not used)
  void onData(AcDataHandler cb, void *arg = 0);
  // set callback - data received
  // !!! You MUST call ackPacket() or free the pbuf yourself to prevent memory leaks
  void onPacket(AcPacketHandler cb, void *arg = 0);
  // set callback - ack timeout
  void onTimeout(AcTimeoutHandler cb, void *arg = 0);
  // set callback - every 125ms when connected
  void onPoll(AcConnectHandler cb, void *arg = 0);

  // ack pbuf from onPacket
  void ackPacket(struct pbuf *pb);
  // ack data that you have not acked using the method below
  size_t ack(size_t len);
  // will not ack the current packet. Call from onData
  void ackLater();

  static const char *errorToString(int8_t error);
  const char *stateToString() const;

  int8_t _recv(tcp_pcb *pcb, pbuf *pb, err_t err);
  tcp_pcb *pcb() {
    return _pcb;
  }

  // Attach optional lifecycle hooks (TLS, or any other protocol layer).
  // See AsyncClientHooks.
  void setHooks(AsyncClientHooks *hooks);

protected:
  friend class AsyncTCP_detail;
  friend class AsyncServer;
  friend class AsyncSecureServer;
  friend class AsyncClientHooks;
  friend class AsyncServerHooks;

  tcp_pcb *_pcb;

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
  AsyncClientHooks *_tls_client_hooks;
#if ASYNC_TCP_SSL_ENABLED
  pbuf *_ssl_pending_pbufs;  // staged park-queue pbufs, fed to the session on accept
  // (internal) Thread-safe deferred ACK (tcpip_api_call). Defined in AsyncTCP.cpp.
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

// TLS client: inherits AsyncClient (pure-TCP transport + the setHooks() seam)
// and adds the beginSecure() convenience. Defined in AsyncSecureClient.cpp.
#if ASYNC_TCP_SSL_ENABLED
class AsyncSecureClient : public AsyncClient {
public:
  bool beginSecure(const char *host, uint16_t port, const char *rootCA = NULL);
};
#endif

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
  void onClient(AcConnectHandler cb, void *arg);
  void setHooks(AsyncServerHooks *hooks);
#if ASYNC_TCP_SSL_ENABLED
  // Backward-compat TLS entry points: configure + install the TLS server
  // hooks on this plain server. Implementations in AsyncSecureServer.cpp.
  void onSslFileRequest(AcSSlFileHandler cb, void *arg);
  void beginSecure(const char *cert, const char *private_key_file, const char *password);
#endif
  void begin();
  void end();
  void setNoDelay(bool nodelay);
  bool getNoDelay() const;
  uint8_t status() const;

public:
  // (internal) Queue the LWIP_TCP_ACCEPT event for a freshly accepted client.
  // Defined in AsyncTCP.cpp, which owns the event queue.
  static bool queueAcceptEvent(AsyncClient *client, void *server);

protected:
  friend class AsyncTCP_detail;
  friend class AsyncServerHooks;

  AsyncServerHooks *_tls_server_hooks;

  uint16_t _port;
  ip_addr_t _addr;
  bool _noDelay;
  tcp_pcb *_pcb;
  AcConnectHandler _connect_cb;
  void *_connect_cb_arg;

  // Accept a connection and create its AsyncClient. Pure TCP; server hooks
  // may take over admission (park/serve queue).
  int8_t _accept(tcp_pcb *newpcb, int8_t err);
  int8_t _accepted(AsyncClient *client);
};

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
// ---------------- ESP32/LIBRETINY + mbedTLS ------
#if ASYNC_TCP_SSL_ENABLED
typedef std::function<int(void *arg, uint8_t **cert, uint8_t **key)> AcSSlFileHandler;
#endif
class AsyncClient {
public:
  AsyncClient(tcp_pcb *pcb = 0);
  ~AsyncClient();

  // Noncopyable
  AsyncClient(const AsyncClient &) = delete;
  AsyncClient &operator=(const AsyncClient &) = delete;

  // Nonmovable
  AsyncClient(AsyncClient &&) = delete;
  AsyncClient &operator=(AsyncClient &&) = delete;

  bool operator==(const AsyncClient &other) const;

  bool operator!=(const AsyncClient &other) const {
    return !(*this == other);
  }
  bool connect(ip_addr_t addr, uint16_t port);
#ifdef ARDUINO
  bool connect(const IPAddress &ip, uint16_t port);
#if __has_include(<IPv6Address.h>)
  bool connect(const IPv6Address &ip, uint16_t port);
#endif
#endif
  bool connect(const char *host, uint16_t port);

  /**
     * @brief close connection
     *
     * @param now - ignored
     */
  [[deprecated("Use AsyncClient::close() instead")]]
  void close(bool now __attribute__((unused))) {
    close();
  }
  [[deprecated("Use AsyncClient::close() instead")]]
  void stop() {
    close();
  };

  /**
     * @brief close connection
     */
  void close();

  int8_t abort();
  bool free();

  // ack is not pending
  bool canSend() const;
  // TCP buffer space available
  size_t space() const;

  /**
     * @brief add data to be send (but do not send yet)
     * @note add() would call lwip's tcp_write()
        By default apiflags=ASYNC_WRITE_FLAG_COPY
        You could try to use apiflags with this flag unset to pass data by reference and avoid copy to socket buffer,
        but looks like it does not work for Arduino's lwip in ESP32/IDF at least
        it is enforced in https://github.com/espressif/esp-lwip/blob/0606eed9d8b98a797514fdf6eabb4daf1c8c8cd9/src/core/tcp_out.c#L422C5-L422C30
        if LWIP_NETIF_TX_SINGLE_PBUF is set, and it is set indeed in IDF
        https://github.com/espressif/esp-idf/blob/a0f798cfc4bbd624aab52b2c194d219e242d80c1/components/lwip/port/include/lwipopts.h#L744
     *
     * @param data
     * @param size
     * @param apiflags
     * @return size_t amount of data that has been copied
     */
  size_t add(const char *data, size_t size, uint8_t apiflags = ASYNC_WRITE_FLAG_COPY);

  /**
     * @brief send data previously add()'ed
     *
     * @return true on success
     * @return false on error
     */
  bool send();

  /**
     * @brief add and enqueue data for sending
     * @note it is same as add() + send()
     * @note only make sense when canSend() == true
     *
     * @param data
     * @param size
     * @param apiflags
     * @return size_t
     */
  size_t write(const char *data, size_t size, uint8_t apiflags = ASYNC_WRITE_FLAG_COPY);

  /**
     * @brief add and enqueue data for sending
     * @note treats data as null-terminated string
     *
     * @param data
     * @return size_t
     */
  size_t write(const char *data) {
    return data == NULL ? 0 : write(data, strlen(data));
  };

  uint8_t state() const;
  bool connecting() const;
  bool connected() const;
  bool disconnecting() const;
  bool disconnected() const;

  // disconnected or disconnecting
  bool freeable() const;

  uint16_t getMss() const;

  uint32_t getRxTimeout() const;
  // no RX data timeout for the connection in seconds
  void setRxTimeout(uint32_t timeout);

  uint32_t getAckTimeout() const;
  // no ACK timeout for the last sent packet in milliseconds
  void setAckTimeout(uint32_t timeout);

  void setNoDelay(bool nodelay) const;
  bool getNoDelay();

  void setKeepAlive(uint32_t ms, uint8_t cnt);

  uint32_t getRemoteAddress() const;
  uint16_t getRemotePort() const;
  uint16_t remotePort() const {
    return getRemotePort();
  }

  uint32_t getLocalAddress() const;
  uint16_t getLocalPort() const;
  uint16_t localPort() const {
    return getLocalPort();
  }

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

  // set callback - on successful connect
  void onConnect(AcConnectHandler cb, void *arg = 0);
  // set callback - disconnected
  void onDisconnect(AcConnectHandler cb, void *arg = 0);
  // set callback - ack received
  void onAck(AcAckHandler cb, void *arg = 0);
  // set callback - unsuccessful connect or error
  void onError(AcErrorHandler cb, void *arg = 0);
  // set callback - data received (called if onPacket is not used)
  void onData(AcDataHandler cb, void *arg = 0);
  // set callback - data received
  // !!! You MUST call ackPacket() or free the pbuf yourself to prevent memory leaks
  void onPacket(AcPacketHandler cb, void *arg = 0);
  // set callback - ack timeout
  void onTimeout(AcTimeoutHandler cb, void *arg = 0);
  // set callback - every 125ms when connected
  void onPoll(AcConnectHandler cb, void *arg = 0);

  // ack pbuf from onPacket
  void ackPacket(struct pbuf *pb);
  // ack data that you have not acked using the method below
  size_t ack(size_t len);
  // will not ack the current packet. Call from onData
  void ackLater();

  static const char *errorToString(int8_t error);
  const char *stateToString() const;

  int8_t _recv(tcp_pcb *pcb, pbuf *pb, err_t err);
  tcp_pcb *pcb() {
    return _pcb;
  }

#if ASYNC_TCP_SSL_ENABLED
  // Attach optional lifecycle hooks (TLS, or any other protocol layer).
  // See AsyncClientHooks.
  void setHooks(AsyncClientHooks *hooks);
#endif

protected:
  friend class AsyncTCP_detail;
  friend class AsyncServer;
  friend class AsyncSecureServer;
  friend class AsyncClientHooks;
  friend class AsyncServerHooks;

  tcp_pcb *_pcb;

  AcConnectHandler _connect_cb;
  void *_connect_cb_arg;
  AcConnectHandler _discard_cb;
  void *_discard_cb_arg;
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
  AsyncClientHooks *_tls_client_hooks;
  AcConnectHandler _server_discard_cb;  // set by AsyncServer for instant slot promote
  void *_server_discard_cb_arg;
#if ASYNC_TCP_SSL_ENABLED
  pbuf *_ssl_pending_pbufs;  // staged park-queue pbufs, fed to the session on accept
  // (internal) Thread-safe deferred ACK (tcpip_api_call). Defined in AsyncTCP.cpp.
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
  void onClient(AcConnectHandler cb, void *arg);
  void setHooks(AsyncServerHooks *hooks);
#if ASYNC_TCP_SSL_ENABLED
  // Backward-compat TLS entry points: configure + install the TLS server
  // hooks on this plain server. Implementations in AsyncSecureServer.cpp.
  void onSslFileRequest(AcSSlFileHandler cb, void *arg);
  void beginSecure(const char *cert, const char *private_key_file, const char *password);
#endif
  void begin();
  void end();
  void setNoDelay(bool nodelay);
  bool getNoDelay() const;
  uint8_t status() const;

public:
  // (internal) Queue the LWIP_TCP_ACCEPT event for a freshly accepted client.
  // Defined in AsyncTCP.cpp, which owns the event queue.
  static bool queueAcceptEvent(AsyncClient *client, void *server);

protected:
  friend class AsyncTCP_detail;
  friend class AsyncServerHooks;

  AsyncServerHooks *_tls_server_hooks;

  uint16_t _port;
  ip_addr_t _addr;
  bool _noDelay;
  tcp_pcb *_pcb;
  AcConnectHandler _connect_cb;
  void *_connect_cb_arg;

  // Accept a connection and create its AsyncClient. Pure TCP; server hooks
  // may take over admission (park/serve queue).
  int8_t _accept(tcp_pcb *newpcb, int8_t err);
  int8_t _accepted(AsyncClient *client);
};

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

#endif /* ASYNCTCP_H_ */
