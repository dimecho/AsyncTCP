// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright 2016-2026 Hristo Gochkov, Mathieu Carbou, Emil Muratov, Will Miles
//
// Unified dual-stack AsyncTCP. TLS client.
//   - ESP8266         -> BearSSL stack (AsyncTCP fork, NO_SYS lwIP)
//   - ESP32/LIBRETINY -> mbedTLS stack (AsyncTCP ESP32Async base)
//
// AsyncSecureClient inherits AsyncClient (pure-TCP transport + the
// setHooks() extension point) and adds the beginSecure() convenience. All
// client TLS entry logic lives here, keeping AsyncClient in AsyncTCP.cpp
// a pure transport. The session engine lives in AsyncSecureSession.cpp.

#include "AsyncTCP.h"
#include "AsyncSecureSession.h"
#include "AsyncTCPLogging.h"
#include <Arduino.h>  // millis() (hooks liveness/timeout bookkeeping)

extern "C" {
#include "lwip/tcp.h"
}

#if ASYNC_TCP_SSL_ENABLED

#if defined(ESP8266)
bool AsyncSecureClient::beginSecure(const char *host, uint16_t port, const char *rootCA) {
#else
bool AsyncSecureClient::beginSecure(const char *host, uint16_t port, const char *rootCA,
    const char *clientCert, const char *clientKey, const char *keyPassword) {
#endif
  if (pcb()) {
    async_tcp_log_d("already connected");
    return false;
  }
  AsyncSecureSession *session = new (std::nothrow) AsyncSecureSession();
  if (!session) {
    return false;
  }
#if defined(ESP8266)
  (void)rootCA;  // BearSSL client: no server-cert verification
  session->setClientCredentials(host, NULL);
#else
  session->setClientCredentials(host,
      (const unsigned char *)rootCA, (rootCA != NULL) ? strlen(rootCA) + 1 : 0,
      (const unsigned char *)clientCert, (clientCert != NULL) ? strlen(clientCert) + 1 : 0,
      (const unsigned char *)clientKey, (clientKey != NULL) ? strlen(clientKey) + 1 : 0,
      keyPassword);
#endif
  SecureClientHooks *hooks = new (std::nothrow) SecureClientHooks(session, this);
  if (!hooks) {
    delete session;
    return false;
  }
  setHooks(hooks);
  return connect(host, port);
}

#ifndef ESP8266
bool AsyncSecureClient::beginSecure(const char *host, uint16_t port,
    const unsigned char *rootCA, size_t rootCALen,
    const unsigned char *clientCert, size_t clientCertLen,
    const unsigned char *clientKey, size_t clientKeyLen,
    const char *keyPassword) {
  if (pcb()) {
    async_tcp_log_d("already connected");
    return false;
  }
  AsyncSecureSession *session = new (std::nothrow) AsyncSecureSession();
  if (!session) {
    return false;
  }
  session->setClientCredentials(host, rootCA, rootCALen, clientCert, clientCertLen,
      clientKey, clientKeyLen, keyPassword);
  SecureClientHooks *hooks = new (std::nothrow) SecureClientHooks(session, this);
  if (!hooks) {
    delete session;
    return false;
  }
  setHooks(hooks);
  return connect(host, port);
}
#endif // !ESP8266

// --- SecureClientHooks: the session-driven data path, connected to the client
// lifecycle by AsyncClient::setHooks() ---

SecureClientHooks::SecureClientHooks(AsyncSecureSession *s, AsyncClient *c) : sess(s), client(c) {
  // Route the session's callbacks into this client's app callbacks. The
  // onConnect/onData/onError the app registers on the AsyncClient fire from
  // here (the server path's onConnect fires on handshake completion,
  // mirroring the original _s_handshake behavior).
#ifdef ESP8266
  sess->onData([](void *arg, uint8_t *data, size_t len) {
    SecureClientHooks *h = static_cast<SecureClientHooks *>(arg);
    if (h && h->client) {
      h->notifyData(h->client, data, len);
    }
  }, this);
  sess->onHandshake([](void *arg) {
    SecureClientHooks *h = static_cast<SecureClientHooks *>(arg);
    if (h && h->client) {
      h->notifyConnect(h->client);
    }
  }, this);
  sess->onError([](void *arg, int8_t err) {
    SecureClientHooks *h = static_cast<SecureClientHooks *>(arg);
    if (!h || !h->client) {
      return;
    }
    // err + 64: BearSSL alert codes, mapped like the original _ssl_error().
    h->notifyError(h->client, err + 64);
    // Tear down while the pcb is still live (safe re-entry: close()
    // releases the session state, not the object).
    h->client->close();
  }, this);
#else
  // Handshake completion → app onConnect. runSSLHandshake() only runs on the
  // async task (hooks onRecv / server accepted path), so this fires there.
  sess->onHandshake([](void *arg) {
    SecureClientHooks *h = static_cast<SecureClientHooks *>(arg);
    if (h && h->client) {
      h->notifyConnect(h->client);
    }
  }, this);
#endif
}

bool SecureClientHooks::onConnected(AsyncClient *c) {
  // Start the handshake from the stored credentials. onConnect fires from the
  // session's onHandshake callback when the handshake completes.
  if (sess->startClient(c->pcb()) != 0) {
#ifdef ESP8266
    // BearSSL setup failed: tear down (original did not fire onError here).
    c->close();
#else
    // mbedtls setup failed: mirror the original startSSLClient failure path.
    notifyError(c, -60);
    c->close();
#endif
    return true;
  }
  return true;
}

#ifdef ESP8266
bool SecureClientHooks::onRecv(AsyncClient *c, struct pbuf *pb) {
  if (pb == NULL) {
    // Peer FIN: close the TLS connection (close_notify exchange) — mirror
    // the reference; the plain path uses lwIP's own fin handling instead.
    async_tcp_log_d("_recv: pb == NULL! Closing...");
    c->close();
    return true;
  }
  int read_bytes = sess->feedRx(pb);
  if (read_bytes < 0) {
    if (read_bytes != BR_ALERT_CLOSE_NOTIFY) {
      async_tcp_log_d("_recv SSL error: [%d] %s", read_bytes, tcp_ssl_error_string(read_bytes));
      c->close();
    }
  } else {
    // Inbound TLS ciphertext = progress: refresh watchdog timer.
    touchRx(c, millis());
  }
  return true;
}

bool SecureClientHooks::onSent(AsyncClient *c, uint16_t len) {
  // TLS-layer ACK handling must run for EVERY ciphertext ACK, INCLUDING
  // mid-handshake: handshake flight records ride the same no-copy ring as
  // app data, and their slots only free here.
  sess->sentAck(len);
  if (!sess->handshakeDone()) {
    // ACK during handshake = progress: refresh watchdog timer.
    touchRx(c, millis());
    return true;  // skip app-level accounting until the handshake completes
  }
  return false;
}

bool SecureClientHooks::onPoll(AsyncClient *c) {
  struct tcp_pcb *pcb = c->pcb();
  if (!pcb) {
    return false;
  }
  uint32_t now = millis();
  // SSL Handshake Timeout — a stuck half-open handshake holds KBs of TLS
  // buffers; a dead conn can't be recovered by TCP retransmit, so abort early
  // and let the peer retry.
  if (!sess->handshakeDone() && (now - lastRx(c)) >= SSL_HANDSHAKE_TIMEOUT) {
    async_tcp_log_d("SSL handshake timeout %d", pcb->state);
    c->close();
    return true;
  }
  // Poll retry: no ACK to account for, just re-arm deferred records
  // (tcp_ssl_sent is idempotent unless the engine is in SENDREC).
  sess->sentAck(0);

  // Safety net: if the schedule_function pool was full, pump the engine
  // directly from the poll (process_ssl_engine skips QUEUED engines).
  sess->pump();

  // Bounded hard-stall recovery: a SENDREC record with an open send window
  // and an empty pbuf queue has nothing on the wire — no ACK will ever
  // un-wedge it. Tear down past the stall timeout so the peer retries.
  if (sess->isStalled(SSL_STALL_RESET_MS)) {
    async_tcp_log_d("SSL hard SENDREC stall, resetting connection");
    c->close();
    return true;
  }
  // Silent-live teardown (browser stop/abort recovery): a conn gone fully
  // idle — no inbound data, nothing unacked on the wire, send window drained
  // — has nothing more to deliver; free it after the stall window so a parked
  // refresh conn promotes instead of waiting on a wedged conn.
  if (sess->handshakeDone() &&
      (now - lastRx(c)) >= SSL_STALL_RESET_MS &&
      !sess->txBusy() && tcp_sndbuf(pcb) != 0) {
    async_tcp_log_d("SSL conn idle (browser abort?), closing to free slot, sndbuf=%u space=%u", (unsigned)tcp_sndbuf(pcb), (unsigned)c->space());
    c->close();
    return true;
  }
  return false;
}

int SecureClientHooks::onWrite(AsyncClient *c, const char *data, size_t size) {
  // TLS: encrypt via the session (tcp_ssl_write on the fork's TLS-aware lwIP)
  size_t room = c->space();
  size_t will_send = (room < size) ? room : size;
  int sent = sess->write((uint8_t *)data, will_send);
  if (sent < 0) {
    c->close();
    return 0;
  }
  return sent;
}
#else  // ESP32
// Runs on the async task (AsyncClient's pcb recv handler queues the pbuf as a
// normal event). All TLS work — ciphertext buffer, handshake, plaintext
// delivery — happens here and ONLY here, so the BIO buffer is single-threaded.
bool SecureClientHooks::onRecv(AsyncClient *c, struct pbuf *pb) {
  touchRx(c, millis());  // inbound ciphertext = liveness
  if (!pb) {
    return true;
  }
  size_t fed = sess->feedRx(pb);  // surplus stays in session (unacked → window backpressure)
  if (fed) {
    recved(c, fed);
  }
  if (!sess->handshakeDone()) {
    int ret = sess->runSSLHandshake();
    if (ret != 0 && !ASYNCTCP_TLS_CAN_RETRY(ret)) {
      notifyError(c, -60);
      c->close();
    }
    return true;
  }
  uint8_t buf[1024];
  int n;
  while ((n = sess->sslRead(buf, sizeof(buf))) > 0) {
    notifyData(c, buf, n);
    if (!c->pcb()) {
      return true;  // app closed the conn in onData
    }
  }
  if (n < 0 && c->pcb()) {
    notifyError(c, -60);
    c->close();
    return true;
  }
  // Second pass: drain ciphertext that overflowed the BIO buffer above.
  fed = sess->feedRx(NULL);
  if (fed) {
    recved(c, fed);
    while ((n = sess->sslRead(buf, sizeof(buf))) > 0) {
      notifyData(c, buf, n);
      if (!c->pcb()) {
        return true;
      }
    }
  }
  return true;
}

bool SecureClientHooks::onSent(AsyncClient *c, uint16_t len) {
  (void)c;
  (void)len;
  return false;  // app-level ACK accounting applies to TLS too
}

bool SecureClientHooks::onPoll(AsyncClient *c) {
  // Handshake timeout: a wedge here pins the TLS slab; abort so peer retries.
  if (!sess->handshakeDone() && sess->handshakeTimeoutElapsed()) {
    notifyError(c, -61);
    c->close();
    return true;
  }
  return false;
}

int SecureClientHooks::onWrite(AsyncClient *c, const char *data, size_t size) {
  (void)c;
  if (!sess->handshakeDone()) {
    return -1;
  }
  // SSL: encrypt via mbedtls, which calls BIO send -> tcp_write
  int ret = sess->write((const uint8_t *)data, size);
  if (ret > 0) {
    return ret;
  }
  return 0;
}
#endif // ESP8266

void SecureClientHooks::onClosing(AsyncClient *c) {
  (void)c;
  // Release TLS state while the pcb is still live: flush pending records and
  // return the session slab.
  sess->close();
}

void SecureClientHooks::onError(AsyncClient *c, int8_t err) {
  (void)c;
  (void)err;
  // Transport RST: the pcb is already gone; release the session (the fork's
  // tcp_ssl_close/free are no-ops for already-freed pcbs).
  sess->close();
}

#endif // ASYNC_TCP_SSL_ENABLED