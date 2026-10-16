// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright 2016-2026 Hristo Gochkov, Mathieu Carbou, Emil Muratov, Will Miles
//
// Unified dual-stack AsyncTCP. Core TCP.
//   - ESP8266         -> BearSSL stack (AsyncTCP fork, NO_SYS lwIP)
//   - ESP32/LIBRETINY -> mbedTLS stack (AsyncTCP ESP32Async base)
// Selected at compile time via #if defined(ESP8266). Only one stack compiles per target.

#include "AsyncTCP.h"
#include "AsyncSecureSession.h"
#include "AsyncTCPLogging.h"
#include "AsyncTCPSimpleIntrusiveList.h"



/**
 * Non-ESP32 specific configurations
 */
#if defined(LIBRETINY) || defined(ESP8266)
#include <Arduino.h>
// LibreTiny does not support IDF - disable code that expects it to be available
#define ESP_IDF_VERSION_MAJOR (0)
// xTaskCreatePinnedToCore is not available, force single-core operation
#define CONFIG_FREERTOS_UNICORE 1
// ESP watchdog is not available
#undef CONFIG_ASYNC_TCP_USE_WDT
#define CONFIG_ASYNC_TCP_USE_WDT 0
#endif  // LIBRETINY || ESP8266

#ifdef ESP8266
#include <Schedule.h>
typedef err_t esp_err_t;
#define ESP_OK 0
#define ESP_FAIL -1
#endif

/**
 * ESP32 Arduino specific configurations
 */
#if defined(ARDUINO) && !defined(LIBRETINY) && !defined(ESP8266)
#include <Arduino.h>
#include <esp_idf_version.h>
#if (ESP_IDF_VERSION_MAJOR >= 5)
#include <NetworkInterface.h>
#endif  // ESP_IDF_VERSION_MAJOR
#endif  // ARDUINO

/**
 * ESP-IDF specific configurations
 */
#if !defined(LIBRETINY) && !defined(ARDUINO)
#include "esp_timer.h"
static unsigned long millis() {
  return (unsigned long)(esp_timer_get_time() / 1000ULL);
}
static unsigned long micros() {
  return static_cast<unsigned long>(esp_timer_get_time());
}
#endif  // !LIBRETINY && !ARDUINO

extern "C" {
#include "lwip/dns.h"
#include "lwip/err.h"
#include "lwip/inet.h"
#include "lwip/opt.h"
#include "lwip/tcp.h"
#include "lwip/tcpip.h"
}

// Required for:
// https://github.com/espressif/arduino-esp32/blob/3.0.3/libraries/Network/src/NetworkInterface.cpp#L37-L47

#if CONFIG_ASYNC_TCP_USE_WDT
#include "esp_task_wdt.h"
#define ASYNC_TCP_MAX_TASK_SLEEP (pdMS_TO_TICKS(1000 * CONFIG_ESP_TASK_WDT_TIMEOUT_S) / 4)
#else
#define ASYNC_TCP_MAX_TASK_SLEEP portMAX_DELAY
#endif

#include "AsyncTCPCoreGuard.h"

/*
  TCP poll interval is specified in terms of the TCP coarse timer interval, which is called twice a second
  https://github.com/espressif/esp-lwip/blob/2acf959a2bb559313cd2bf9306c24612ba3d0e19/src/core/tcp.c#L1895
*/
#ifndef CONFIG_ASYNC_TCP_POLL_TIMER
#define CONFIG_ASYNC_TCP_POLL_TIMER 1
#endif

/* Callback context */
struct AsyncClientCallbackContext {
  AsyncClientCallbackContext *next = nullptr;
  bool client_is_valid = true;
  bool ack_later = false;
  u16_t ack_len = 0;  // lwip's size_t
};

/*
 * TCP/IP Event Task
 * */

typedef enum {
  LWIP_TCP_SENT,
  LWIP_TCP_RECV,
  LWIP_TCP_FIN,
  LWIP_TCP_ERROR,
  LWIP_TCP_POLL,
  LWIP_TCP_ACCEPT,
  LWIP_TCP_CONNECTED,
  LWIP_TCP_DNS
} lwip_tcp_event_t;

struct lwip_tcp_event_packet_t {
  lwip_tcp_event_packet_t *next;
  lwip_tcp_event_t event;
  std::shared_ptr<AsyncClientImpl> impl;  // keeps the client alive for dispatch
  AsyncClient *client;                    // ACCEPT events only: the delivered facade
  std::shared_ptr<AsyncServerImpl> accept_server;  // ACCEPT: pins the listener for dispatch
  uint32_t accept_epoch = 0;                       // ACCEPT: listener session (stale guard)
  union {
    struct {
      tcp_pcb *pcb;
      int8_t err;
    } connected;
    struct {
      int8_t err;
    } error;
    struct {
      tcp_pcb *pcb;
      uint16_t len;
    } sent;
    struct {
      tcp_pcb *pcb;
      pbuf *pb;
      int8_t err;
    } recv;
    struct {
      tcp_pcb *pcb;
      int8_t err;
    } fin;
    struct {
      tcp_pcb *pcb;
    } poll;
    struct {
      ip_addr_t addr;
    } dns;
  };
  // DNS-event payload (outside the union: shared_ptr is non-trivial). The
  // token is the one minted by the connect() that started this lookup — a
  // pointer-identity check against the client's current token rejects
  // answers from superseded or cancelled dials.
  std::shared_ptr<void> dns_token;

  inline lwip_tcp_event_packet_t(lwip_tcp_event_t _event, std::shared_ptr<AsyncClientImpl> _impl) : next(nullptr), event(_event), impl(std::move(_impl)), client(nullptr){};
  inline lwip_tcp_event_packet_t(lwip_tcp_event_t _event, AsyncClient *_client) : next(nullptr), event(_event), client(_client){};
  inline lwip_tcp_event_packet_t(lwip_tcp_event_t _event, AsyncClient *_client, std::shared_ptr<AsyncServerImpl> srv) : next(nullptr), event(_event), client(_client), accept_server(std::move(srv)){};

};

// Detail class for interacting with AsyncClient internals, but without exposing the API
class AsyncTCP_detail {
public:
  // Helper functions
  static void __attribute__((visibility("internal"))) handle_async_event(lwip_tcp_event_packet_t *event);

  // LwIP TCP event callbacks that (will) require privileged access
  static err_t __attribute__((visibility("internal"))) tcp_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *pb, err_t err);
  static err_t __attribute__((visibility("internal"))) tcp_sent(void *arg, struct tcp_pcb *pcb, uint16_t len);
  static void __attribute__((visibility("internal"))) tcp_error(void *arg, err_t err);
  static err_t __attribute__((visibility("internal"))) tcp_poll(void *arg, struct tcp_pcb *pcb);
  static err_t __attribute__((visibility("internal"))) tcp_accept(void *arg, tcp_pcb *pcb, err_t err);
};

// Random number generator for poll event coalescing
static uint32_t _xor_shift_state = 31;  // any nonzero seed will do
static uint32_t _xor_shift_next() {
  uint32_t x = _xor_shift_state;
  x ^= x << 13;
  x ^= x >> 17;
  x ^= x << 5;
  return _xor_shift_state = x;
}


// The global queue
static SimpleIntrusiveList<lwip_tcp_event_packet_t> _async_queue;

// Queued events carry shared_ptr<AsyncClientImpl> / shared_ptr<AsyncServerImpl>,
// so no liveness registry is needed. A stale accept (listener ended between
// accept and delivery) is rejected at dispatch via the listener session epoch.
void _asynctcp_touch_rx(AsyncClientImpl *c) { c->_rx_last_packet = millis(); }
bool _asynctcp_dns_token_current(AsyncClientImpl *c, const std::shared_ptr<void> &token) { return c->_dns_token == token; }

// Outbound DNS lookup context: lwIP may answer after the client object is
// gone or has moved on to another dial; the token rejects superseded answers
// (PR124-style identity check).
namespace {
struct dns_lookup_ctx_t {
  std::shared_ptr<AsyncClientImpl> client;  // keeps the impl alive across the lookup
  std::shared_ptr<void> token;              // the dial's token; compared at the answer
};
}

static void _free_event(lwip_tcp_event_packet_t *evpkt) {
  if ((evpkt->event == LWIP_TCP_RECV) && (evpkt->recv.pb != nullptr)) {
    pbuf_free(evpkt->recv.pb);
  }
  delete evpkt;
}


// Guard class for the global queue

#if defined(ARDUINO) && !defined(ESP8266)
namespace {
static SemaphoreHandle_t _async_queue_mutex = nullptr;

class queue_mutex_guard {
  bool holds_mutex;

public:
  // Tolerate a mutex that was never created (the guard runs in paths that can
  // precede _start_async_task(); taking a NULL semaphore handle would crash).
  inline queue_mutex_guard() : holds_mutex(_async_queue_mutex && xSemaphoreTake(_async_queue_mutex, portMAX_DELAY)){};
  inline ~queue_mutex_guard() {
    if (holds_mutex) {
      xSemaphoreGive(_async_queue_mutex);
    }
  };
  inline explicit operator bool() const {
    return holds_mutex;
  };
};

static TaskHandle_t _async_service_task_handle = NULL;
}  // anonymous namespace


static inline void _send_async_event(lwip_tcp_event_packet_t *e) {
  if (e == nullptr) {
    return;
  }
  _async_queue.push_back(e);
  xTaskNotifyGive(_async_service_task_handle);
}

static inline void _prepend_async_event(lwip_tcp_event_packet_t *e) {
  if (e == nullptr) {
    return;
  }
  _async_queue.push_front(e);
  xTaskNotifyGive(_async_service_task_handle);
}
#else

namespace {
  // No-op guard class
  class queue_mutex_guard {} __attribute__((unused));
}  // anonymous namespace

static void _process_async_event();

static inline void _send_async_event(lwip_tcp_event_packet_t *e) {
  if (e == nullptr) {
    return;
  }
  _async_queue.push_back(e);
  if (_async_queue.size() == 1) {
    schedule_function(_process_async_event);
  }
}

static inline void _prepend_async_event(lwip_tcp_event_packet_t *e) {
  if (e == nullptr) {
    return;
  }
  _async_queue.push_front(e);
  if (_async_queue.size() == 1) {
    schedule_function(_process_async_event);
  }
}
#endif

static inline lwip_tcp_event_packet_t *_get_async_event() {
  queue_mutex_guard guard;
  while (1) {
    lwip_tcp_event_packet_t *e = _async_queue.pop_front();

    if ((!e) || (e->event != LWIP_TCP_POLL)) {
      return e;
    }

    /*
      Let's try to coalesce two (or more) consecutive poll events into one
      this usually happens with poor implemented user-callbacks that are runs too long and makes poll events to stack in the queue
      if consecutive user callback for a same connection runs longer that poll time then it will fill the queue with events until it deadlocks.
      This is a workaround to mitigate such poor designs and won't let other events/connections to starve the task time.
      It won't be effective if user would run multiple simultaneous long running callbacks due to message interleaving.
      todo: implement some kind of fair dequeuing or (better) simply punish user for a bad designed callbacks by resetting hog connections
    */
    for (lwip_tcp_event_packet_t *next_pkt = _async_queue.begin(); next_pkt && (next_pkt->impl == e->impl) && (next_pkt->event == LWIP_TCP_POLL);
         next_pkt = _async_queue.begin()) {
      // if the next event that will come is a poll event for the same connection, we can discard it and continue
      _free_event(_async_queue.pop_front());
      async_tcp_log_d("coalescing polls, network congestion or async callbacks might be too slow!");
    }

    /*
      now we have to decide if to proceed with poll callback handler or discard it?
      poor designed apps using asynctcp without proper dataflow control could flood the queue with interleaved pool/ack events.
      I.e. on each poll app would try to generate more data to send, which in turn results in additional ack event triggering chain effect
      for long connections. Or poll callback could take long time starving other connections. Anyway our goal is to keep the queue length
      grows under control (if possible) and poll events are the safest to discard.
      Let's discard poll events processing using linear-increasing probability curve when queue size grows over 3/4
      Poll events are periodic and connection could get another chance next time
    */
    if (_async_queue.size() > (_xor_shift_next() % CONFIG_ASYNC_TCP_QUEUE_SIZE / 4 + CONFIG_ASYNC_TCP_QUEUE_SIZE * 3 / 4)) {
      _free_event(e);
      async_tcp_log_d("discarding poll due to queue congestion");
      continue;
    }

    return e;
  }
}

// If LwIP is configured with mutex support, wrap all calls with tcpip_api_call() to ensure that the LwIP core is locked during the call.
static size_t _remove_events_for_client(AsyncClientImpl *client) {
  lwip_tcp_event_packet_t *removed_event_chain;
  {
    queue_mutex_guard guard;
    removed_event_chain = _async_queue.remove_if([=](lwip_tcp_event_packet_t &pkt) {
      return pkt.impl.get() == client;
    });
  }

  size_t count = 0;
  while (removed_event_chain) {
    ++count;
    auto t = removed_event_chain;
    removed_event_chain = t->next;
    _free_event(t);
  }
  return count;
};


void AsyncTCP_detail::handle_async_event(lwip_tcp_event_packet_t *e) {
  if (e->impl == nullptr && e->client == nullptr) {
    // do nothing when arg is NULL
    // ets_printf("event arg == NULL: 0x%08x\n", e->recv.pcb);
  } else if (e->event == LWIP_TCP_RECV) {
    // ets_printf("-R: 0x%08x\n", e->recv.pcb);
    if (!e->impl->_dead) {
      e->impl->_recv(e->recv.pcb, e->recv.pb, e->recv.err);
    }
    e->recv.pb = nullptr;  // given to client
  } else if (e->event == LWIP_TCP_FIN) {
    // ets_printf("-F: 0x%08x\n", e->fin.pcb);
    if (!e->impl->_dead) {
      e->impl->_fin(e->fin.pcb, e->fin.err);
    }
  } else if (e->event == LWIP_TCP_SENT) {
    // ets_printf("-S: 0x%08x\n", e->sent.pcb);
    if (!e->impl->_dead) {
      e->impl->_sent(e->sent.pcb, e->sent.len);
    }
  } else if (e->event == LWIP_TCP_POLL) {
    // ets_printf("-P: 0x%08x\n", e->poll.pcb);
    if (!e->impl->_dead) {
      e->impl->_poll(e->poll.pcb);
    }
  } else if (e->event == LWIP_TCP_ERROR) {
    // ets_printf("-E: 0x%08x %d\n", e->impl.get(), e->error.err);
    if (!e->impl->_dead) {
      e->impl->_error(e->error.err);
    }
  } else if (e->event == LWIP_TCP_CONNECTED) {
    // ets_printf("C: 0x%08x 0x%08x %d\n", e->impl.get(), e->connected.pcb, e->connected.err);
    if (!e->impl->_dead) {
      e->impl->_connected(e->connected.pcb, e->connected.err);
    }
  } else if (e->event == LWIP_TCP_ACCEPT) {
    // ets_printf("A: 0x%08x 0x%08x\n", e->accept.server.get(), e->client);
    // Stale-accept guard: drop connections from a listener that was ended
    // (or re-begun) between accept and delivery. No purge walk needed —
    // the shared_ptr keeps the listener object itself valid either way.
    if (e->accept_server && e->accept_server->_session == e->accept_epoch) {
      e->accept_server->_accepted(e->client);
    } else if (e->client) {
      e->client->abort();
      delete e->client;  // listener gone/stale: don't leak the client
      e->client = nullptr;
    }
  } else if (e->event == LWIP_TCP_DNS) {
    // ets_printf("D: 0x%08x %s = %s\n", e->impl.get(), e->dns.name, ipaddr_ntoa(&e->dns.addr));
    // Drop stale answers (client reconnected to something else since).
    if (!e->impl->_dead && e->impl->_dns_token == e->dns_token) {
      e->impl->_dns_found(&e->dns.addr);
    }
  }
  _free_event(e);
}

#if defined(ARDUINO) && !defined(ESP8266)
static void _async_service_task(void *pvParameters) {
  async_tcp_log_d("Task 'async_tcp' started on core %d", static_cast<int>(xPortGetCoreID()));
#if CONFIG_ASYNC_TCP_USE_WDT
  if (esp_task_wdt_add(NULL) != ESP_OK) {
    async_tcp_log_w("Failed to add async task to WDT");
  }
#endif
  for (;;) {
    while (auto packet = _get_async_event()) {
      async_tcp_log_elapsed("handle_async_event", AsyncTCP_detail::handle_async_event(packet));
#if CONFIG_ASYNC_TCP_USE_WDT
      esp_task_wdt_reset();
#endif
    }
    // queue is empty
    // DEBUG_PRINTF("Async task waiting 0x%08",(intptr_t)_async_queue_head);
    ulTaskNotifyTake(pdTRUE, ASYNC_TCP_MAX_TASK_SLEEP);
    // DEBUG_PRINTF("Async task woke = %d 0x%08x",q, (intptr_t)_async_queue_head);
#if CONFIG_ASYNC_TCP_USE_WDT
    esp_task_wdt_reset();
#endif
  }
#if CONFIG_ASYNC_TCP_USE_WDT
  esp_task_wdt_delete(NULL);
#endif
  vTaskDelete(NULL);
  _async_service_task_handle = NULL;
}

/*
static void _stop_async_task(){
    if(_async_service_task_handle){
        vTaskDelete(_async_service_task_handle);
        _async_service_task_handle = NULL;
    }
}
*/

static bool customTaskCreateUniversal(
  TaskFunction_t pxTaskCode, const char *const pcName, const uint32_t usStackDepth, void *const pvParameters, UBaseType_t uxPriority,
  TaskHandle_t *const pxCreatedTask, const BaseType_t xCoreID
) {
#ifndef CONFIG_FREERTOS_UNICORE
  if (xCoreID >= 0 && xCoreID < 2) {
    return xTaskCreatePinnedToCore(pxTaskCode, pcName, usStackDepth, pvParameters, uxPriority, pxCreatedTask, xCoreID);
  } else {
#endif
    return xTaskCreate(pxTaskCode, pcName, usStackDepth, pvParameters, uxPriority, pxCreatedTask);
#ifndef CONFIG_FREERTOS_UNICORE
  }
#endif
}

static bool _start_async_task() {
  if (!_async_queue_mutex) {
    _async_queue_mutex = xSemaphoreCreateMutex();
    if (!_async_queue_mutex) {
      return false;
    }
  }

  if (!_async_service_task_handle) {
    customTaskCreateUniversal(
      _async_service_task, "async_tcp", CONFIG_ASYNC_TCP_STACK_SIZE, NULL, CONFIG_ASYNC_TCP_PRIORITY, &_async_service_task_handle, CONFIG_ASYNC_TCP_RUNNING_CORE
    );
    if (!_async_service_task_handle) {
      return false;
    }
  }
  return true;
}
#else

static void _process_async_event() {
  auto packet = _get_async_event();
  if (packet) {
    async_tcp_log_elapsed("handle_async_event", AsyncTCP_detail::handle_async_event(packet));
  }
  if (_async_queue.size() > 0) {
    schedule_function(_process_async_event);
  }
}

static inline bool _start_async_task() {
  return true;
}

#endif


/*
 * LwIP Callbacks
 * */

static void _bind_tcp_callbacks(tcp_pcb *pcb, AsyncClientImpl *client) {
  tcp_arg(pcb, client);
  tcp_recv(pcb, &AsyncTCP_detail::tcp_recv);
  tcp_sent(pcb, &AsyncTCP_detail::tcp_sent);
  tcp_err(pcb, &AsyncTCP_detail::tcp_error);
  tcp_poll(pcb, &AsyncTCP_detail::tcp_poll, CONFIG_ASYNC_TCP_POLL_TIMER);
}

static void _reset_tcp_callbacks(tcp_pcb *pcb, AsyncClientImpl *client) {
  tcp_arg(pcb, NULL);
  tcp_sent(pcb, NULL);
  tcp_recv(pcb, NULL);
  tcp_err(pcb, NULL);
  tcp_poll(pcb, NULL, 0);
  if (client) {
    _remove_events_for_client(client);
  }
}

static err_t _tcp_connected(void *arg, tcp_pcb *pcb, err_t err) {
  // ets_printf("+C: 0x%08x\n", pcb);
  AsyncClientImpl *client = reinterpret_cast<AsyncClientImpl *>(arg);
  _asynctcp_touch_rx(client);  // stamp RX liveness in lwIP context
  lwip_tcp_event_packet_t *e = new (std::nothrow) lwip_tcp_event_packet_t{LWIP_TCP_CONNECTED, client->shared_from_this()};
  if (!e) {
    async_tcp_log_e("Failed to allocate event packet");
    return ERR_MEM;
  }
  e->connected.pcb = pcb;
  e->connected.err = err;
  queue_mutex_guard guard;
  _send_async_event(e);
  return ERR_OK;
}

err_t AsyncTCP_detail::tcp_poll(void *arg, struct tcp_pcb *pcb) {
  // throttle polling events queueing when event queue is getting filled up, let it handle _onack's
  {
    queue_mutex_guard guard;
    // async_tcp_log_d("qs:%u", _async_queue.size());
    if (_async_queue.size() > (_xor_shift_next() % CONFIG_ASYNC_TCP_QUEUE_SIZE / 2 + CONFIG_ASYNC_TCP_QUEUE_SIZE / 4)) {
      async_tcp_log_d("throttling");
      return ERR_OK;
    }
  }

  // ets_printf("+P: 0x%08x\n", pcb);
  AsyncClientImpl *client = reinterpret_cast<AsyncClientImpl *>(arg);
  lwip_tcp_event_packet_t *e = new (std::nothrow) lwip_tcp_event_packet_t{LWIP_TCP_POLL, client->shared_from_this()};
  if (!e) {
    async_tcp_log_e("Failed to allocate event packet");
    return ERR_MEM;
  }
  e->poll.pcb = pcb;

  queue_mutex_guard guard;
  _send_async_event(e);
  return ERR_OK;
}

err_t AsyncTCP_detail::tcp_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *pb, err_t err) {
  AsyncClientImpl *client = reinterpret_cast<AsyncClientImpl *>(arg);
  // Stamp RX liveness in lwIP context: event-queue lag must
  // not make a just-arrived packet look stale to the rx/ack timeout logic.
  client->_rx_last_packet = millis();
  lwip_tcp_event_packet_t *e = new (std::nothrow) lwip_tcp_event_packet_t{LWIP_TCP_RECV, client->shared_from_this()};
  if (!e) {
    async_tcp_log_e("Failed to allocate event packet");
    return ERR_MEM;
  }
  if (pb) {
    // ets_printf("+R: 0x%08x\n", pcb);
    e->recv.pcb = pcb;
    e->recv.pb = pb;
    e->recv.err = err;
  } else {
    // ets_printf("+F: 0x%08x\n", pcb);
    e->event = LWIP_TCP_FIN;
    e->fin.pcb = pcb;
    e->fin.err = err;
  }

  queue_mutex_guard guard;
  _send_async_event(e);
  return ERR_OK;
}

err_t AsyncTCP_detail::tcp_sent(void *arg, struct tcp_pcb *pcb, uint16_t len) {
  // ets_printf("+S: 0x%08x\n", pcb);
  AsyncClientImpl *client = reinterpret_cast<AsyncClientImpl *>(arg);
  lwip_tcp_event_packet_t *e = new (std::nothrow) lwip_tcp_event_packet_t{LWIP_TCP_SENT, client->shared_from_this()};
  if (!e) {
    async_tcp_log_e("Failed to allocate event packet");
    return ERR_MEM;
  }
  e->sent.pcb = pcb;
  e->sent.len = len;

  queue_mutex_guard guard;
  _send_async_event(e);
  return ERR_OK;
}

void AsyncTCP_detail::tcp_error(void *arg, err_t err) {
  // ets_printf("+E: 0x%08x\n", arg);
  AsyncClientImpl *client = reinterpret_cast<AsyncClientImpl *>(arg);
  if (client && client->_pcb) {
    // The pcb has already been freed by LwIP; do not attempt to clear the callbacks!
    if (client->_tls_client_hooks) {
      client->_tls_client_hooks->onError(client, err);
    }
    _remove_events_for_client(client);
    client->_pcb = nullptr;
  }

  // enqueue event to be processed in the async task for the user callback
  lwip_tcp_event_packet_t *e = new (std::nothrow) lwip_tcp_event_packet_t{LWIP_TCP_ERROR, client->shared_from_this()};
  if (!e) {
    async_tcp_log_e("Failed to allocate event packet");
    return;
  }
  e->error.err = err;

  queue_mutex_guard guard;
  _send_async_event(e);
}

static void _tcp_dns_found(const char *name, ip_addr_t *ipaddr, void *arg) {
  dns_lookup_ctx_t *ctx = reinterpret_cast<dns_lookup_ctx_t *>(arg);
  std::shared_ptr<AsyncClientImpl> client = ctx->client;
  std::shared_ptr<void> token = ctx->token;
  delete ctx;

  // Drop superseded dials (lwIP can't cancel an in-flight query). Liveness is
  // guaranteed by the shared_ptr; the token identity rejects answers for a
  // dial the client has moved on from or cancelled.
  {
    queue_mutex_guard guard;
    if (!_asynctcp_dns_token_current(client.get(), token)) {
      return;
    }
    lwip_tcp_event_packet_t *e = new (std::nothrow) lwip_tcp_event_packet_t{LWIP_TCP_DNS, client};
    if (!e) {
      async_tcp_log_e("Failed to allocate event packet");
      return;
    }
    e->dns_token = token;
    if (ipaddr) {
      memcpy(&e->dns.addr, ipaddr, sizeof(ip_addr_t));
    } else {
      memset(&e->dns.addr, 0, sizeof(e->dns.addr));
    }
    _send_async_event(e);
  }
}

/*
 * TCP/IP API Call wrappers
 *
 * Handles TCPIP core locking and ensures that the AsyncClient is not destroyed while the call is in progress.
 * */

#include "lwip/priv/tcpip_priv.h"

// If LwIP is configured with mutex support, wrap all calls with tcpip_api_call() to ensure that the LwIP core is locked during the call.

// Direct-call fast path: tcpip_api_call() posts to the tcpip task's mbox and
// blocks waiting for completion. If the CALLER already holds the core lock
// (i.e. we are running inside an lwIP callback on the tcpip thread, or on any
// thread that took LOCK_TCPIP_CORE()), that wait can never be satisfied ->
// self-deadlock of the tcpip task (whole network stack wedges: no ping, no
// accepts, no WDT). In that context the raw lwIP calls are safe because the
// core lock is already ours. AsyncClientImpl::close() racing a TLS FIN is the
// prime example.
static inline bool _tcp_core_lock_held_by_us(void) {
#ifdef CONFIG_LWIP_TCPIP_CORE_LOCKING
  return sys_thread_tcpip(LWIP_CORE_LOCK_QUERY_HOLDER);
#else
  // No core locking: raw lwIP calls are legal from callback context anyway.
  return false;
#endif
}
#if !NO_SYS
typedef struct {
  struct tcpip_api_call_data call;
  tcp_pcb **pcb;
  int8_t err;
  union {
    AsyncClientImpl *close;
    struct {
      const char *data;
      size_t size;
      uint8_t apiflags;
    } write;
    size_t received;
    struct {
      ip_addr_t *addr;
      uint16_t port;
      tcp_connected_fn cb;
    } connect;
    struct {
      ip_addr_t *addr;
      uint16_t port;
    } bind;
    uint8_t backlog;
  };
} tcp_api_call_t;

static err_t _tcp_output_api(struct tcpip_api_call_data *api_call_msg) {
  tcp_api_call_t *msg = (tcp_api_call_t *)api_call_msg;
  msg->err = ERR_CONN;
  if (*msg->pcb) {
    msg->err = tcp_output(*msg->pcb);
  }
  return msg->err;
}

static esp_err_t _tcp_output(tcp_pcb **pcb) {
  if (!pcb || !*pcb) {
    return ERR_CONN;
  }
  tcp_api_call_t msg;
  msg.pcb = pcb;
  if (_tcp_core_lock_held_by_us()) {
    return _tcp_output_api((struct tcpip_api_call_data *)&msg);
  }
  tcpip_api_call(_tcp_output_api, (struct tcpip_api_call_data *)&msg);
  return msg.err;
}

static err_t _tcp_write_api(struct tcpip_api_call_data *api_call_msg) {
  tcp_api_call_t *msg = (tcp_api_call_t *)api_call_msg;
  msg->err = ERR_CONN;
  if (*msg->pcb) {
    msg->err = tcp_write(*msg->pcb, msg->write.data, msg->write.size, msg->write.apiflags);
  }
  return msg->err;
}

static esp_err_t _tcp_write(tcp_pcb **pcb, const char *data, size_t size, uint8_t apiflags) {
  if (!pcb || !*pcb) {
    return ERR_CONN;
  }
  tcp_api_call_t msg;
  msg.pcb = pcb;
  msg.write.data = data;
  msg.write.size = size;
  msg.write.apiflags = apiflags;
  if (_tcp_core_lock_held_by_us()) {
    return _tcp_write_api((struct tcpip_api_call_data *)&msg);
  }
  tcpip_api_call(_tcp_write_api, (struct tcpip_api_call_data *)&msg);
  return msg.err;
}

static err_t _tcp_recved_api(struct tcpip_api_call_data *api_call_msg) {
  tcp_api_call_t *msg = (tcp_api_call_t *)api_call_msg;
  msg->err = ERR_CONN;
  if (*msg->pcb) {
    msg->err = 0;
    tcp_recved(*msg->pcb, msg->received);
  }
  return msg->err;
}

static esp_err_t _tcp_recved(tcp_pcb **pcb, size_t len) {
  if (!pcb || !*pcb) {
    return ERR_CONN;
  }
  tcp_api_call_t msg;
  msg.pcb = pcb;
  msg.received = len;
  if (_tcp_core_lock_held_by_us()) {
    return _tcp_recved_api((struct tcpip_api_call_data *)&msg);
  }
  tcpip_api_call(_tcp_recved_api, (struct tcpip_api_call_data *)&msg);
  return msg.err;
}

static err_t _tcp_close_api(struct tcpip_api_call_data *api_call_msg) {
  // Unlike the other calls, this is not a direct wrapper of the LwIP function;
  // we perform the AsyncClient teardown interlocked safely with the LwIP task.

  // As a postcondition, the queue must not have any events referencing
  // the AsyncClient in api_call_msg->close.  This is because it is possible for
  // an error event to have been queued, clearing the pcb*, but after the async
  // thread has committed to closing/destructing the AsyncClient object.

  tcp_api_call_t *msg = (tcp_api_call_t *)api_call_msg;
  msg->err = ERR_CONN;
  if (*msg->pcb) {
    tcp_pcb *pcb = *msg->pcb;
    _reset_tcp_callbacks(pcb, msg->close);
    if (tcp_close(pcb) != ERR_OK) {
      // We do not permit failure here: abandon the pcb anyways.
      tcp_abort(pcb);
    }
    msg->err = ERR_OK;
    *msg->pcb = nullptr;  // PCB is now the property of LwIP
  } else {
    // Ensure there is not an error event queued for this client
    if (_remove_events_for_client(msg->close)) {
      msg->err = ERR_OK;  // dispose needs to be run
    }
  }
  return msg->err;
}

static esp_err_t _tcp_close(tcp_pcb **pcb, AsyncClientImpl *client) {
  tcp_api_call_t msg;
  msg.pcb = pcb;
  msg.close = client;
  if (_tcp_core_lock_held_by_us()) {
    async_tcp_log_d("_tcp_close: direct path (core lock held)");
    return _tcp_close_api((struct tcpip_api_call_data *)&msg);
  }
  tcpip_api_call(_tcp_close_api, (struct tcpip_api_call_data *)&msg);
  return msg.err;
}

static err_t _tcp_abort_api(struct tcpip_api_call_data *api_call_msg) {
  // Like close(), we must ensure that the queue is cleared of any events referencing the AsyncClient.
  // ERR_ABRT: the pcb was aborted.
  // ERR_OK:   the pcb was already gone, but a queued error event was purged, so the
  //           caller must still run the discard callback (dispose needs to run).
  // ERR_CONN: nothing to do (pcb already null and no queued events).
  tcp_api_call_t *msg = (tcp_api_call_t *)api_call_msg;
  if (*msg->pcb) {
    _reset_tcp_callbacks(*msg->pcb, msg->close);
    tcp_abort(*msg->pcb);
    *msg->pcb = nullptr;  // PCB is now the property of LwIP
    msg->err = ERR_ABRT;
  } else {
    // Ensure there is not an error event queued for this client
    msg->err = _remove_events_for_client(msg->close) ? ERR_OK : ERR_CONN;
  }
  return msg->err;
}

static esp_err_t _tcp_abort(tcp_pcb **pcb, AsyncClientImpl *client) {
  if (!pcb || !*pcb) {
    return ERR_CONN;
  }
  tcp_api_call_t msg;
  msg.pcb = pcb;
  msg.close = client;
  if (_tcp_core_lock_held_by_us()) {
    return _tcp_abort_api((struct tcpip_api_call_data *)&msg);
  }
  tcpip_api_call(_tcp_abort_api, (struct tcpip_api_call_data *)&msg);
  return msg.err;
}

static err_t _tcp_connect_api(struct tcpip_api_call_data *api_call_msg) {
  tcp_api_call_t *msg = (tcp_api_call_t *)api_call_msg;
  msg->err = tcp_connect(*msg->pcb, msg->connect.addr, msg->connect.port, msg->connect.cb);
  return msg->err;
}

static esp_err_t _tcp_connect(tcp_pcb *pcb, ip_addr_t *addr, uint16_t port, tcp_connected_fn cb) {
  if (!pcb) {
    return ESP_FAIL;
  }
  tcp_api_call_t msg;
  msg.pcb = &pcb;  // cannot be invalidated by LwIP at this point
  msg.connect.addr = addr;
  msg.connect.port = port;
  msg.connect.cb = cb;
  tcpip_api_call(_tcp_connect_api, (struct tcpip_api_call_data *)&msg);
  return msg.err;
}

static err_t _tcp_bind_api(struct tcpip_api_call_data *api_call_msg) {
  tcp_api_call_t *msg = (tcp_api_call_t *)api_call_msg;
  tcp_pcb *pcb = *msg->pcb;
  msg->err = tcp_bind(pcb, msg->bind.addr, msg->bind.port);
  if (msg->err != ERR_OK) {
    // Close the pcb on behalf of the server without an extra round-trip through the LwIP lock
    if (tcp_close(pcb) != ERR_OK) {
      tcp_abort(pcb);
    }
    *msg->pcb = nullptr;  // PCB is now owned by LwIP
  }
  return msg->err;
}

static esp_err_t _tcp_bind(tcp_pcb **pcb, ip_addr_t *addr, uint16_t port) {
  if (!pcb || !*pcb) {
    return ESP_FAIL;
  }
  tcp_api_call_t msg;
  msg.pcb = pcb;
  msg.bind.addr = addr;
  msg.bind.port = port;
  tcpip_api_call(_tcp_bind_api, (struct tcpip_api_call_data *)&msg);
  return msg.err;
}

static err_t _tcp_listen_api(struct tcpip_api_call_data *api_call_msg) {
  tcp_api_call_t *msg = (tcp_api_call_t *)api_call_msg;
  msg->err = 0;
  *msg->pcb = tcp_listen_with_backlog(*msg->pcb, msg->backlog);
  return msg->err;
}

static tcp_pcb *_tcp_listen_with_backlog(tcp_pcb *pcb, uint8_t backlog) {
  if (!pcb) {
    return NULL;
  }
  tcp_api_call_t msg;
  msg.pcb = &pcb;
  msg.backlog = backlog ? backlog : 0xFF;
  tcpip_api_call(_tcp_listen_api, (struct tcpip_api_call_data *)&msg);
  return pcb;
}

#else

static esp_err_t _tcp_output(tcp_pcb **pcb) {
  if (!pcb || !*pcb) {
    return ERR_CONN;
  }
  return tcp_output(*pcb);
}

static esp_err_t _tcp_write(tcp_pcb **pcb, const char *data, size_t size, uint8_t apiflags) {
  if (!pcb || !*pcb) {
    return ERR_CONN;
  }
  return tcp_write(*pcb, data, size, apiflags);
}

static esp_err_t _tcp_recved(tcp_pcb **pcb, size_t len) {
  if (!pcb || !*pcb) {
    return ERR_CONN;
  }
  tcp_recved(*pcb, len); 
  return ERR_OK;
}

static esp_err_t _tcp_close(tcp_pcb **pcb, AsyncClientImpl *client) {
  // Unlike the other calls, this is not a direct wrapper of the LwIP function;
  // we perform the AsyncClient teardown interlocked safely with the LwIP task.

  // As a postcondition, the queue must not have any events referencing
  // the AsyncClient in api_call_msg->close.  This is because it is possible for
  // an error event to have been queued, clearing the pcb*, but after the async
  // thread has committed to closing/destructing the AsyncClient object.

  if (*pcb) {
    tcp_pcb *lpcb = *pcb;
    _reset_tcp_callbacks(lpcb, client);
    if (tcp_close(lpcb) != ERR_OK) {
      // We do not permit failure here: abandon the pcb anyways.
      tcp_abort(lpcb);
    }
    *pcb = nullptr;  // PCB is now the property of LwIP
    return ERR_OK;
  } else {
    // Ensure there is not an error event queued for this client
    if (_remove_events_for_client(client)) {
      return ERR_OK;
    }
  }
  return ERR_CONN;
}

static esp_err_t _tcp_abort(tcp_pcb **pcb, AsyncClientImpl *client) {
  // Like close(), we must ensure that the queue is cleared of any events referencing the AsyncClient.
  // ERR_ABRT: the pcb was aborted.
  // ERR_OK:   the pcb was already gone, but a queued error event was purged, so the
  //           caller must still run the discard callback (dispose needs to run).
  // ERR_CONN: nothing to do (pcb already null and no queued events).
  if (!pcb) {
    return ERR_CONN;
  }
  if (*pcb) {
    _reset_tcp_callbacks(*pcb, client);
    tcp_abort(*pcb);
    *pcb = nullptr;  // PCB is now the property of LwIP
    return ERR_ABRT;
  } else {
    // Ensure there is not an error event queued for this client
    return _remove_events_for_client(client) ? ERR_OK : ERR_CONN;
  }
}

static esp_err_t _tcp_connect(tcp_pcb *pcb, ip_addr_t *addr, uint16_t port, tcp_connected_fn cb) {
  if (!pcb) {
    return ESP_FAIL;
  }
  return tcp_connect(pcb, addr, port, cb);
}

static esp_err_t _tcp_bind(tcp_pcb **pcb, ip_addr_t *addr, uint16_t port) {
  if (!pcb || !*pcb) {
    return ESP_FAIL;
  }
  err_t err = tcp_bind(*pcb, addr, port);
  if (err != ERR_OK) {
    // Close the pcb on behalf of the server without an extra round-trip through the LwIP lock
    if (tcp_close(*pcb) != ERR_OK) {
      tcp_abort(*pcb);
    }
    *pcb = nullptr;  // PCB is now owned by LwIP
  }
  return err;
}

static tcp_pcb *_tcp_listen_with_backlog(tcp_pcb *pcb, uint8_t backlog) {
  if (!pcb) {
    return NULL;
  }
  return tcp_listen_with_backlog(pcb, backlog ? backlog : 0xFF);
}

#endif

// Thread-safe deferred ACK for bytes fed outside the normal recv path
// (parked-conn staged pbufs). Used by AsyncSecureServer.
void AsyncClientImpl::_tcp_recved(tcp_pcb **pcbp, size_t len) {
  ::_tcp_recved(pcbp, len);
}


/*
  Async TCP Client
 */

AsyncClientImpl::AsyncClientImpl(AsyncClient *facade, tcp_pcb *pcb)
  : _pcb(nullptr), _facade(facade),
    _connect_cb(0), _connect_cb_arg(0), _discard_cb(0), _discard_cb_arg(0), _server_discard_cb(0), _server_discard_cb_arg(0), _sent_cb(0), _sent_cb_arg(0), _error_cb(0), _error_cb_arg(0), _recv_cb(0),
    _recv_cb_arg(0), _pb_cb(0), _pb_cb_arg(0), _timeout_cb(0), _timeout_cb_arg(0), _poll_cb(0), _poll_cb_arg(0), _cb_ctx(nullptr), _tx_last_packet(0),
    _rx_ack_len(0), _rx_timeout(0), _rx_last_ack(0), _ack_timeout(CONFIG_ASYNC_TCP_MAX_ACK_TIME), _connect_port(0), _noDelay(false), _tls_client_hooks(nullptr), _dns_token(nullptr), _dead(false)
#if ASYNC_TCP_SSL_ENABLED
    , _ssl_pending_pbufs(nullptr)
#endif
    {
  _pcb = pcb;
  if (_pcb) {
    _rx_last_packet = millis();
    _bind_tcp_callbacks(_pcb, this);
  }
}

// Queued events hold shared_ptr — the impl outlives the facade, so the
// destructor needs no event purge and no liveness registry.
AsyncClientImpl::~AsyncClientImpl() {
  _dead = true;
  if (_tls_client_hooks) {
    delete _tls_client_hooks;
    _tls_client_hooks = nullptr;
  }
  if (_pcb) {
    _close();
  }
  for (AsyncClientCallbackContext *ctx = _cb_ctx; ctx != nullptr; ctx = ctx->next) {
    ctx->client_is_valid = false;
  }
}

// ---- facade lifecycle ----
AsyncClient::AsyncClient(tcp_pcb *pcb) : _impl(new AsyncClientImpl(this, pcb)) {}
AsyncClient::~AsyncClient() {
  if (_impl) {
    _impl->_facade = nullptr;
    _impl->close();  // app dropped the handle: tear the transport down (old semantics)
  }
}

/*
 * Operators
 * */

bool AsyncClientImpl::operator==(const AsyncClientImpl &other) const {
  return _pcb == other._pcb;
}

/*
 * Callback Setters
 * */

void AsyncClientImpl::onConnect(AcConnectHandler cb, void *arg) {
  _connect_cb = cb;
  _connect_cb_arg = arg;
}

void AsyncClientImpl::onDisconnect(AcConnectHandler cb, void *arg) {
  _discard_cb = cb;
  _discard_cb_arg = arg;
}

void AsyncClientImpl::onAck(AcAckHandler cb, void *arg) {
  _sent_cb = cb;
  _sent_cb_arg = arg;
}

void AsyncClientImpl::onError(AcErrorHandler cb, void *arg) {
  _error_cb = cb;
  _error_cb_arg = arg;
}

void AsyncClientImpl::onData(AcDataHandler cb, void *arg) {
  _recv_cb = cb;
  _recv_cb_arg = arg;
}

void AsyncClientImpl::onPacket(AcPacketHandler cb, void *arg) {
  _pb_cb = cb;
  _pb_cb_arg = arg;
}

void AsyncClientImpl::onTimeout(AcTimeoutHandler cb, void *arg) {
  _timeout_cb = cb;
  _timeout_cb_arg = arg;
}

void AsyncClientImpl::onPoll(AcConnectHandler cb, void *arg) {
  _poll_cb = cb;
  _poll_cb_arg = arg;
}

/*
 * Main Public Methods
 * */

bool AsyncClientImpl::connect(ip_addr_t addr, uint16_t port) {
  _dns_token.reset();  // lookup resolved (or direct dial): no longer pending
  if (_pcb) {
    async_tcp_log_d("already connected, state %d", _pcb->state);
    return false;
  }
  if (!_start_async_task()) {
    async_tcp_log_e("failed to start task");
    return false;
  }

  tcp_pcb *pcb;
  {
    tcp_core_guard tcg;
#if LWIP_IPV4 && LWIP_IPV6
    pcb = tcp_new_ip_type(addr.type);
#else
    pcb = tcp_new_ip_type(IPADDR_TYPE_V4);
#endif
    if (!pcb) {
      async_tcp_log_e("pcb == NULL");
      return false;
    }
    _bind_tcp_callbacks(pcb, this);
  }

  esp_err_t err = _tcp_connect(pcb, &addr, port, (tcp_connected_fn)&_tcp_connected);
  if (err != ESP_OK) {
    // Dial failed: don't hand back a dangling pcb (each leaked pcb holds a
    // local socket until reboot — common when WiFi drops and the app retries).
    tcp_core_guard tcg;
    _reset_tcp_callbacks(pcb, this);
    tcp_abort(pcb);
    return false;
  }
  return true;
}

#ifdef ARDUINO
bool AsyncClientImpl::connect(const IPAddress &ip, uint16_t port) {
  ip_addr_t addr;
#if ESP_IDF_VERSION_MAJOR < 5
#if LWIP_IPV4 && LWIP_IPV6
  // if both IPv4 and IPv6 are enabled, ip_addr_t has a union field and the address type
  addr.u_addr.ip4.addr = ip;
  addr.type = IPADDR_TYPE_V4;
#else
  addr.addr = ip;
#endif
#else
  ip.to_ip_addr_t(&addr);
#endif

  return connect(addr, port);
}
#endif

#if LWIP_IPV6 && ESP_IDF_VERSION_MAJOR < 5
bool AsyncClientImpl::connect(const IPv6Address &ip, uint16_t port) {
  auto ipaddr = static_cast<const uint32_t *>(ip);
  ip_addr_t addr = IPADDR6_INIT(ipaddr[0], ipaddr[1], ipaddr[2], ipaddr[3]);

  return connect(addr, port);
}
#endif

bool AsyncClientImpl::connect(const char *host, uint16_t port) {
  ip_addr_t addr;

  if (!_start_async_task()) {
    async_tcp_log_e("failed to start task");
    return false;
  }

  err_t err;
  {
    tcp_core_guard tcg;
    // A fresh token per dial: any older in-flight lookup's answer now fails
    // the identity check (PR124-style _dns_token).
    _dns_token = std::make_shared<char>();
    dns_lookup_ctx_t *ctx = new (std::nothrow) dns_lookup_ctx_t{shared_from_this(), _dns_token};
    if (!ctx) {
      return false;
    }
    err = dns_gethostbyname(host, &addr, (dns_found_callback)&_tcp_dns_found, ctx);
    if (err != ERR_INPROGRESS) {
      delete ctx;  // no callback will carry it
    }
  }

  if (err == ERR_OK) {
#if ESP_IDF_VERSION_MAJOR < 5
#if LWIP_IPV6
    if (addr.type == IPADDR_TYPE_V6) {
      return connect(IPv6Address(addr.u_addr.ip6.addr), port);
    }
    return connect(IPAddress(addr.u_addr.ip4.addr), port);
#else
    return connect(IPAddress(addr.addr), port);
#endif
#else
    return connect(addr, port);
#endif
  } else if (err == ERR_INPROGRESS) {
    _connect_port = port;
    return true;
  }
  async_tcp_log_d("error: %d", err);
  return false;
}

void AsyncClientImpl::close() {
  _dns_token.reset();  // cancel semantics: any in-flight lookup's answer is dropped
  if (_pcb) {
    // If we're in an onData callback, add the final packet size to the ack count
    // before closing the connection.
    size_t pending = _rx_ack_len;
    _rx_ack_len = 0;
    for (AsyncClientCallbackContext *ctx = _cb_ctx; ctx != nullptr; ctx = ctx->next) {
      pending += ctx->ack_len;
    }
    if (pending) {
      _tcp_recved(&_pcb, pending);
    }
  }
  _close();
}

int8_t AsyncClientImpl::abort() {
  _dns_token.reset();  // see close()
  if (_tls_client_hooks && _pcb) {
    // TLS teardown while the pcb is still live: flush pending records and
    // return the session slab before the abort.
    _tls_client_hooks->onClosing(this);
  }
  int8_t err = _tcp_abort(&_pcb, this);
  // _pcb is now NULL
  // LwIP invokes the error callback when abort is issued; preserve this semantic.
  // This will also trigger the dispose callback.
  // If the pcb was previously invalidated by some other queued error, we've discarded that value; so we always send ERR_ABRT.
  if (err != ERR_CONN) {
    _error(ERR_ABRT);
  }
  return err;
}

size_t AsyncClientImpl::space() const {
  // CLOSE_WAIT: peer sent FIN but we may still have data to send
  if ((_pcb != NULL) && (_pcb->state == ESTABLISHED || _pcb->state == CLOSE_WAIT)) {
    // Read the send buffer under the core lock — it is updated
    // by the tcpip thread (ACK processing) while we read it from the async
    // task. Holder-aware: no re-lock when already on the tcpip thread.
    tcp_core_guard tcg;
    return tcp_sndbuf(_pcb);
  }
  return 0;
}

size_t AsyncClientImpl::add(const char *data, size_t size, uint8_t apiflags) {
  if (!_pcb || size == 0 || data == NULL) {
    return 0;
  }
  size_t room = space();
  if (!room) {
    return 0;
  }
  size_t will_send = (room < size) ? room : size;
  if (_tls_client_hooks) {
    int n = _tls_client_hooks->onWrite(this, data, size);
    if (n >= 0) {
      return n;
    }
  }
  int8_t err = ERR_OK;
  err = _tcp_write(&_pcb, data, will_send, apiflags);
  if (err != ERR_OK) {
    return 0;
  }
  return will_send;
}

bool AsyncClientImpl::send() {
  auto backup = _tx_last_packet;
  _tx_last_packet = millis();
  if (_tcp_output(&_pcb) == ERR_OK) {
    return true;
  }
  _tx_last_packet = backup;
  return false;
}

size_t AsyncClientImpl::ack(size_t len) {
  if (len > _rx_ack_len) {
    len = _rx_ack_len;
  }
  if (len) {
    _tcp_recved(&_pcb, len);
  }
  _rx_ack_len -= len;
  return len;
}

void AsyncClientImpl::ackPacket(struct pbuf *pb) {
  if (!pb) {
    return;
  }
  _tcp_recved(&_pcb, pb->len);
  pbuf_free(pb);
}

void AsyncClientImpl::ackLater() {
  // Nested callbacks only occur when abort() is called during an onData or
  // onPacket callback; mark every active context so all layers ack later.
  for (AsyncClientCallbackContext *ctx = _cb_ctx; ctx != nullptr; ctx = ctx->next) {
    ctx->ack_later = true;
  }
}

/*
 * Main Private Methods
 * */

int8_t AsyncClientImpl::_close() {
  // ets_printf("X: 0x%08x\n", (uint32_t)this);
  if (_tls_client_hooks && _pcb) {
    // TLS teardown MUST happen while _pcb is still live: flush any pending
    // plaintext/close_notify records into the send queue and return the TLS
    // slab to the heap. _tcp_close() below nulls _pcb and FINs the socket;
    // doing this the other way round drops the un-transmitted tail (truncated
    // responses) and leaks the session.
    _tls_client_hooks->onClosing(this);
  }
  int8_t err = _tcp_close(&_pcb, this);
  // _pcb is now NULL
  if ((err == ERR_OK) && _discard_cb) {
    // _pcb was closed here
    async_tcp_log_elapsed("onDisconnect", _discard_cb(_discard_cb_arg, _facade));
  }
  // Fires _server_discard_cb (AsyncServer's instant-slot-promote hook) on the
  // graceful-close path, matching _error() above. Without it a live conn that
  // closes normally never triggers _conn_done/_promoteSlot, so a parked conn
  // waits for the next 4s _poll tick instead of promoting immediately.
  if ((err == ERR_OK) && _server_discard_cb) {
    _server_discard_cb(_server_discard_cb_arg, _facade);
  }
  return err;
}

/*
 * Private Callbacks
 * */

int8_t AsyncClientImpl::_connected(tcp_pcb *pcb, int8_t err) {
  _pcb = reinterpret_cast<tcp_pcb *>(pcb);
  if (_pcb) {
    _rx_last_packet = millis();
  }
  _tx_last_packet = 0;
  _rx_last_ack = 0;
  if (_tls_client_hooks && _tls_client_hooks->onConnected(this)) {
    return ERR_OK;
  }
  if (_connect_cb) {
    async_tcp_log_elapsed("onConnect", _connect_cb(_connect_cb_arg, _facade));
  }
  return ERR_OK;
}

// Disable the "dangling pointer" warning for these calls with newer GCCs
// We store a pointer to a stack local AsyncClientCallbackContext in the AsyncClient object over the context of the function
// call to track if the object was destroyed.  If so, we do not reset the pointer, which GCC identifies as a possible
// dangling reference case.  It is not - the reference was destroyed along with the AsyncClient object.
#if defined(__GNUC__) && !defined(__clang__) && (__GNUC__ >= 12)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdangling-pointer"
#endif

void AsyncClientImpl::_error(int8_t err) {
  AsyncClientCallbackContext ctx;
  ctx.next = _cb_ctx;
  _cb_ctx = &ctx;
  if (_error_cb) {
    async_tcp_log_elapsed("onError", _error_cb(_error_cb_arg, _facade, err));
  }
  // Early exit if the error callback destructed our object.
  // Discard callback is already destroyed, so we cannot call it; so just return.
  if (!ctx.client_is_valid) {
    return;
  }
  // Since we no longer need it, release the callback context before calling discard
  // so we don't have to check client_is_valid again before clearing it.
  _cb_ctx = ctx.next;
  if (_discard_cb) {
    async_tcp_log_elapsed("onDisconnect", _discard_cb(_discard_cb_arg, _facade));
  }
#if ASYNC_TCP_SSL_ENABLED
  if (_server_discard_cb) {
    _server_discard_cb(_server_discard_cb_arg, _facade);
  }
#endif
}

int8_t AsyncClientImpl::_recv(tcp_pcb *pcb, pbuf *pb, err_t err) {
  AsyncClientCallbackContext ctx;
  if (_tls_client_hooks && _tls_client_hooks->onRecv(this, pb)) {
    return ERR_OK;
  }
  ctx.next = _cb_ctx;
  _cb_ctx = &ctx;
  while (pb != NULL) {
    _rx_last_packet = millis();
    // Grab the next pbuf.  We hand it to the user callback, then ack it if needed.
    pbuf *b = pb;
    pb = pb->next;
    b->next = NULL;
    b->tot_len = b->len;  // detached from chain: tot_len is this pbuf only
    ctx.ack_later = false;
    if (_pb_cb) {
      async_tcp_log_elapsed("onPacket", _pb_cb(_pb_cb_arg, _facade, b));
      // Break if object was destructed or pcb closed
      if ((!ctx.client_is_valid) || (!_pcb)) {
        break;
      }
    } else {
      ctx.ack_len = b->len;
      if (_recv_cb && _facade) {
        async_tcp_log_elapsed("onData", _recv_cb(_recv_cb_arg, _facade, b->payload, b->len));
      }
      pbuf_free(b);
      // Break if object was destructed or pcb closed (and thus we do not need to ack the data)
      if ((!ctx.client_is_valid) || (!_pcb)) {
        break;
      }
      if (ctx.ack_later == false) {
        _tcp_recved(&_pcb, ctx.ack_len);
      } else {
        _rx_ack_len += ctx.ack_len;
      }
      ctx.ack_len = 0;
    }
  }
  if (pb) {
    pbuf_free(pb);  // Release any un-processed pbufs if the client was invalidated during callbacks
  }
  if (ctx.client_is_valid) {
    _cb_ctx = ctx.next;
  }
  return ERR_OK;
}

#if defined(__GNUC__) && !defined(__clang__) && (__GNUC__ >= 12)
#pragma GCC diagnostic pop
#endif

int8_t AsyncClientImpl::_fin(tcp_pcb *pcb, err_t err) {
  // Entry guard: a FIN raced with close/abort — don't close twice.
  if (!_pcb) {
    return ERR_OK;
  }
  close();
  return ERR_OK;
}

int8_t AsyncClientImpl::_sent(tcp_pcb *pcb, uint16_t len) {
  // Entry guard: ACK dispatched after teardown.
  if (!_pcb) {
    return ERR_OK;
  }
  if (_tls_client_hooks && _tls_client_hooks->onSent(this, len)) {
    return ERR_OK;
  }
  _rx_last_ack = _rx_last_packet = millis();
  if (_sent_cb) {
    async_tcp_log_elapsed("onAck", _sent_cb(_sent_cb_arg, _facade, len, (_rx_last_packet - _tx_last_packet)));
  }
  return ERR_OK;
}

int8_t AsyncClientImpl::_poll(tcp_pcb *pcb) {
  if (!_pcb) {
    // async_tcp_log_d("pcb is NULL");
    return ERR_OK;
  }
  if (pcb != _pcb) {
    async_tcp_log_d("0x%08" PRIx32 " != 0x%08" PRIx32, (uint32_t)pcb, (uint32_t)_pcb);
    return ERR_OK;
  }

  uint32_t now = millis();

  // ACK Timeout
  if (_ack_timeout) {
    const uint32_t one_day = 86400000;
    bool last_tx_is_after_last_ack = (_rx_last_ack - _tx_last_packet + one_day) < one_day;
    if (last_tx_is_after_last_ack && (now - _tx_last_packet) >= _ack_timeout) {
      async_tcp_log_d("ack timeout %d", pcb->state);
      if (_timeout_cb) {
        async_tcp_log_elapsed("onTimeout", _timeout_cb(_timeout_cb_arg, _facade, (now - _tx_last_packet)));
        return ERR_OK;  // do not call poll callback
      }
      // No timeout callback configured: fall through to poll
    }
  }
  // RX Timeout
  if (_rx_timeout && (now - _rx_last_packet) >= (_rx_timeout * 1000)) {
    async_tcp_log_d("rx timeout %d", pcb->state);
    _close();
    return ERR_OK;
  }
  if (_tls_client_hooks && _tls_client_hooks->onPoll(this)) {
    return ERR_OK;
  }
  // Everything is fine
  if (_poll_cb) {
    async_tcp_log_elapsed("onPoll", _poll_cb(_poll_cb_arg, _facade));
  }
  return ERR_OK;
}

void AsyncClientImpl::_dns_found(ip_addr_t *ipaddr) {
  _dns_token.reset();  // lookup finished (either way): no longer pending
  // A failed/empty lookup must NOT dial the zero address (used to fall into
  // connect(0.0.0.0) and, before the connect-failure cleanup, leak the pcb).
  if (ipaddr && !ip_addr_isany(ipaddr)) {
    connect(*ipaddr, _connect_port);
  } else {
    _error(-55);
  }
}

/*
 * Public Helper Methods
 * */

bool AsyncClientImpl::free() {
  if (!_pcb) {
    return true;
  }
  if (_pcb->state == CLOSED || _pcb->state > ESTABLISHED) {
    return true;
  }
  return false;
}

size_t AsyncClientImpl::write(const char *data, size_t size, uint8_t apiflags) {
  size_t will_send = add(data, size, apiflags);
  if (!will_send || !send()) {
    return 0;
  }
  return will_send;
}

void AsyncClientImpl::setRxTimeout(uint32_t timeout) {
  _rx_timeout = timeout;
}

uint32_t AsyncClientImpl::getRxTimeout() const {
  return _rx_timeout;
}

uint32_t AsyncClientImpl::getAckTimeout() const {
  return _ack_timeout;
}

void AsyncClientImpl::setAckTimeout(uint32_t timeout) {
  _ack_timeout = timeout;
}

void AsyncClientImpl::setNoDelay(bool nodelay) const {
  if (!_pcb) {
    return;
  }
  if (nodelay) {
    tcp_nagle_disable(_pcb);
  } else {
    tcp_nagle_enable(_pcb);
  }
}

bool AsyncClientImpl::getNoDelay() {
  if (!_pcb) {
    return false;
  }
  return tcp_nagle_disabled(_pcb);
}

void AsyncClientImpl::setKeepAlive(uint32_t ms, uint8_t cnt) {
  if (ms != 0) {
    _pcb->so_options |= SOF_KEEPALIVE;  // Turn on TCP Keepalive for the given pcb
    // Set the time between keepalive messages in milli-seconds
    _pcb->keep_idle = ms;
    _pcb->keep_intvl = ms;
    _pcb->keep_cnt = cnt;  // The number of unanswered probes required to force closure of the socket
  } else {
    _pcb->so_options &= ~SOF_KEEPALIVE;  // Turn off TCP Keepalive for the given pcb
  }
}

uint16_t AsyncClientImpl::getMss() const {
  if (!_pcb) {
    return 0;
  }
  return tcp_mss(_pcb);
}

uint32_t AsyncClientImpl::getRemoteAddress() const {
  if (!_pcb) {
    return 0;
  }
#if LWIP_IPV4 && LWIP_IPV6
  return _pcb->remote_ip.u_addr.ip4.addr;
#else
  return _pcb->remote_ip.addr;
#endif
}

#if LWIP_IPV6
ip6_addr_t AsyncClientImpl::getRemoteAddress6() const {
  if (_pcb && _pcb->remote_ip.type == IPADDR_TYPE_V6) {
    return _pcb->remote_ip.u_addr.ip6;
  } else {
    ip6_addr_t nulladdr;
    ip6_addr_set_zero(&nulladdr);
    return nulladdr;
  }
}

ip6_addr_t AsyncClientImpl::getLocalAddress6() const {
  if (_pcb && _pcb->local_ip.type == IPADDR_TYPE_V6) {
    return _pcb->local_ip.u_addr.ip6;
  } else {
    ip6_addr_t nulladdr;
    ip6_addr_set_zero(&nulladdr);
    return nulladdr;
  }
}
#ifdef ARDUINO
#if ESP_IDF_VERSION_MAJOR < 5
IPv6Address AsyncClientImpl::remoteIP6() const {
  return IPv6Address(getRemoteAddress6().addr);
}

IPv6Address AsyncClientImpl::localIP6() const {
  return IPv6Address(getLocalAddress6().addr);
}
#else
IPAddress AsyncClientImpl::remoteIP6() const {
  if (!_pcb) {
    return IPAddress(IPType::IPv6);
  }
  IPAddress ip;
  ip.from_ip_addr_t(&(_pcb->remote_ip));
  return ip;
}

IPAddress AsyncClientImpl::localIP6() const {
  if (!_pcb) {
    return IPAddress(IPType::IPv6);
  }
  IPAddress ip;
  ip.from_ip_addr_t(&(_pcb->local_ip));
  return ip;
}
#endif
#endif
#endif

uint16_t AsyncClientImpl::getRemotePort() const {
  if (!_pcb) {
    return 0;
  }
  return _pcb->remote_port;
}

uint32_t AsyncClientImpl::getLocalAddress() const {
  if (!_pcb) {
    return 0;
  }
#if LWIP_IPV4 && LWIP_IPV6
  return _pcb->local_ip.u_addr.ip4.addr;
#else
  return _pcb->local_ip.addr;
#endif
}

uint16_t AsyncClientImpl::getLocalPort() const {
  if (!_pcb) {
    return 0;
  }
  return _pcb->local_port;
}

ip4_addr_t AsyncClientImpl::getRemoteAddress4() const {
#if LWIP_IPV4 && LWIP_IPV6
  if (_pcb && _pcb->remote_ip.type == IPADDR_TYPE_V4) {
    return _pcb->remote_ip.u_addr.ip4;
  }
#else
  if (_pcb) {
    return _pcb->remote_ip;
  }
#endif
  else {
    ip4_addr_t nulladdr;
    ip4_addr_set_zero(&nulladdr);
    return nulladdr;
  }
}

ip4_addr_t AsyncClientImpl::getLocalAddress4() const {
#if LWIP_IPV4 && LWIP_IPV6
  if (_pcb && _pcb->local_ip.type == IPADDR_TYPE_V4) {
    return _pcb->local_ip.u_addr.ip4;
  }
#else
  if (_pcb) {
    return _pcb->local_ip;
  }
#endif
  else {
    ip4_addr_t nulladdr;
    ip4_addr_set_zero(&nulladdr);
    return nulladdr;
  }
}

#ifdef ARDUINO
IPAddress AsyncClientImpl::remoteIP() const {
#if ESP_IDF_VERSION_MAJOR < 5
  return IPAddress(getRemoteAddress());
#else
  if (!_pcb) {
    return IPAddress();
  }
  IPAddress ip;
  ip.from_ip_addr_t(&(_pcb->remote_ip));
  return ip;
#endif
}

IPAddress AsyncClientImpl::localIP() const {
#if ESP_IDF_VERSION_MAJOR < 5
  return IPAddress(getLocalAddress());
#else
  if (!_pcb) {
    return IPAddress();
  }
  IPAddress ip;
  ip.from_ip_addr_t(&(_pcb->local_ip));
  return ip;
#endif
}
#endif

uint8_t AsyncClientImpl::state() const {
  if (!_pcb) {
    return 0;
  }
  return _pcb->state;
}

bool AsyncClientImpl::connected() const {
  if (!_pcb) {
    return false;
  }
  return _pcb->state == ESTABLISHED;
}

bool AsyncClientImpl::connecting() const {
  // A name lookup in flight counts as connecting (PR124 87e6c268): the pcb is
  // only adopted after the answer arrives, so the pcb-only check would
  // misreport a resolving dial as idle.
  if (_dns_token) {
    return true;  // resolving the hostname
  }
  if (!_pcb) {
    return false;
  }
  return _pcb->state > CLOSED && _pcb->state < ESTABLISHED;
}

bool AsyncClientImpl::disconnecting() const {
  if (!_pcb) {
    return false;
  }
  return _pcb->state > ESTABLISHED && _pcb->state < TIME_WAIT;
}

bool AsyncClientImpl::disconnected() const {
  if (_dns_token) {
    return false;  // resolving the hostname
  }
  if (!_pcb) {
    return true;
  }
  return _pcb->state == CLOSED || _pcb->state == TIME_WAIT;
}

bool AsyncClientImpl::freeable() const {
  if (_dns_token) {
    return false;  // resolving the hostname: not freeable yet
  }
  if (!_pcb) {
    return true;
  }
  return _pcb->state == CLOSED || _pcb->state > ESTABLISHED;
}

bool AsyncClientImpl::canSend() const {
  return space() > 0;
}

const char *AsyncClient::errorToString(int8_t error) {
  switch (error) {
    case ERR_OK:         return "OK";
    case ERR_MEM:        return "Out of memory error";
    case ERR_BUF:        return "Buffer error";
    case ERR_TIMEOUT:    return "Timeout";
    case ERR_RTE:        return "Routing problem";
    case ERR_INPROGRESS: return "Operation in progress";
    case ERR_VAL:        return "Illegal value";
    case ERR_WOULDBLOCK: return "Operation would block";
    case ERR_USE:        return "Address in use";
    case ERR_ALREADY:    return "Already connecting";
    case ERR_ISCONN:     return "Already connected";
    case ERR_CONN:       return "Not connected";
    case ERR_IF:         return "Low-level netif error";
    case ERR_ABRT:       return "Connection aborted";
    case ERR_RST:        return "Connection reset";
    case ERR_CLSD:       return "Connection closed";
    case ERR_ARG:        return "Illegal argument";
    case -55:            return "DNS failed";
    default:             return "UNKNOWN";
  }
}

const char *AsyncClientImpl::stateToString() const {
  switch (state()) {
    case 0:  return "Closed";
    case 1:  return "Listen";
    case 2:  return "SYN Sent";
    case 3:  return "SYN Received";
    case 4:  return "Established";
    case 5:  return "FIN Wait 1";
    case 6:  return "FIN Wait 2";
    case 7:  return "Close Wait";
    case 8:  return "Closing";
    case 9:  return "Last ACK";
    case 10: return "Time Wait";
    default: return "UNKNOWN";
  }
}

/*
  Async TCP Server
 */

AsyncServerImpl::AsyncServerImpl(AsyncServer *facade, ip_addr_t addr, uint16_t port)
  : _facade(facade), _tls_server_hooks(nullptr), _port(port), _addr(addr), _noDelay(false), _pcb(nullptr), _connect_cb(nullptr), _connect_cb_arg(nullptr), _session(0) {}

#ifdef ARDUINO
AsyncServer::AsyncServer(IPAddress addr, uint16_t port) {
  ip_addr_t a;
  memset(&a, 0, sizeof(a));
#if ESP_IDF_VERSION_MAJOR < 5
#if LWIP_IPV4 && LWIP_IPV6
  a.type = IPADDR_TYPE_V4;
  a.u_addr.ip4.addr = addr;
#else
  a.addr = addr;
#endif
#else
  addr.to_ip_addr_t(&a);
#endif
  _impl.reset(new AsyncServerImpl(this, a, port));
}
#if ESP_IDF_VERSION_MAJOR < 5 && __has_include(<IPv6Address.h>) && LWIP_IPV6
AsyncServer::AsyncServer(IPv6Address addr, uint16_t port) {
  auto ipaddr = static_cast<const uint32_t *>(addr);
  ip_addr_t a = IPADDR6_INIT(ipaddr[0], ipaddr[1], ipaddr[2], ipaddr[3]);
  _impl.reset(new AsyncServerImpl(this, a, port));
}
#endif
#endif

AsyncServer::AsyncServer(uint16_t port) {
  ip_addr_t a;
  memset(&a, 0, sizeof(a));
#if LWIP_IPV4 && LWIP_IPV6
  a.type = IPADDR_TYPE_ANY;
  a.u_addr.ip4.addr = INADDR_ANY;
#else
  a.addr = INADDR_ANY;
#endif
  _impl.reset(new AsyncServerImpl(this, a, port));
}

AsyncServer::AsyncServer(ip_addr_t addr, uint16_t port) {
  _impl.reset(new AsyncServerImpl(this, addr, port));
}

AsyncServer::~AsyncServer() {
  if (_impl) {
    _impl->end();  // old semantics: destroying the server closes the listener
  }
}

void AsyncServerImpl::onClient(AcConnectHandler cb, void *arg) {
  _connect_cb = cb;
  _connect_cb_arg = arg;
}

void AsyncServerImpl::begin() {
  if (_pcb) {
    return;
  }

  if (!_start_async_task()) {
    async_tcp_log_e("failed to start task");
    return;
  }
  int8_t err;
  {
    tcp_core_guard tcg;
#if LWIP_IPV4 && LWIP_IPV6
    _pcb = tcp_new_ip_type(_addr.type);
#else
    _pcb = tcp_new_ip_type(IPADDR_TYPE_ANY);
#endif
  }
  if (!_pcb) {
    async_tcp_log_e("_pcb == NULL");
    return;
  }

  err = _tcp_bind(&_pcb, &_addr, _port);

  if (err != ERR_OK) {
    // pcb was closed by _tcp_bind
    async_tcp_log_e("bind error: %d", err);
    return;
  }

  static uint8_t backlog = 5;
  tcp_pcb *listen_pcb = _tcp_listen_with_backlog(_pcb, backlog);
  if (!listen_pcb) {
    // Bind+listen must unwind as one transaction: release the bound pcb or
    // the (closed) connection keeps the port held forever.
    async_tcp_log_e("listen_pcb == NULL");
    if (_pcb) {
      tcp_core_guard tcg;
      if (tcp_close(_pcb) != ERR_OK) {
        tcp_abort(_pcb);
      }
      _pcb = NULL;
    }
    return;
  }
  _pcb = listen_pcb;
  tcp_core_guard tcg;
  ++_session;  // new listening session: queued accepts from the old one go stale
  tcp_arg(_pcb, (void *)this);
  tcp_accept(_pcb, &AsyncTCP_detail::tcp_accept);
}

void AsyncServerImpl::end() {
  tcp_core_guard tcg;
  ++_session;  // invalidate any queued accept from this listener
  if (_pcb) {
    tcp_arg(_pcb, NULL);
    tcp_accept(_pcb, NULL);
    if (tcp_close(_pcb) != ERR_OK) {
      tcp_abort(_pcb);
    }
    _pcb = NULL;
  }
  // No purge walk needed: queued accept events carry shared_ptr<impl> and the
  // session epoch — dispatch drops them.
}

// runs on LwIP thread
err_t AsyncTCP_detail::tcp_accept(void *arg, tcp_pcb *pcb, err_t err) {
  if (!pcb) {
    async_tcp_log_e("_accept failed: pcb is NULL");
    return ERR_ABRT;
  }
  auto server = reinterpret_cast<AsyncServerImpl *>(arg);
#if ASYNC_TCP_SSL_ENABLED
  // TLS admission hook (park/serve queue, nagle, serve floors). Returns -1 to
  // fall through to the plain accept below (hook present but not configured).
  if (server->_tls_server_hooks) {
    int8_t r = server->_tls_server_hooks->onAccept(server, pcb, (int8_t)err);
    if (r != -1) {
      return (err_t)r;
    }
  }
#endif
  if (server->_connect_cb) {
    AsyncClient *c = new (std::nothrow) AsyncClient(pcb);
    if (c && c->pcb()) {
      c->setNoDelay(server->_noDelay);

      lwip_tcp_event_packet_t *e = new (std::nothrow) lwip_tcp_event_packet_t{LWIP_TCP_ACCEPT, c, server->shared_from_this()};
      if (e) {
        e->accept_epoch = server->_session;

        queue_mutex_guard guard;
        _prepend_async_event(e);
        return ERR_OK;  // success
      }

      // Couldn't allocate accept event
      // We can't let the client object call in to close, as we're on the LWIP thread; it could deadlock trying to RPC to itself
      c->impl()->_pcb = nullptr;  // detach before abort (no RPC from lwIP thread)
      tcp_abort(pcb);
      async_tcp_log_e("_accept failed: couldn't accept client");
      return ERR_ABRT;
    }
    if (c) {
      // Couldn't complete setup
      // pcb has already been aborted
      delete c;
      pcb = nullptr;
      async_tcp_log_e("_accept failed: couldn't complete setup");
      return ERR_ABRT;
    }
    async_tcp_log_e("_accept failed: couldn't allocate client");
  } else {
    async_tcp_log_e("_accept failed: no onConnect callback");
  }
  tcp_abort(pcb);
  return ERR_OK;
}

int8_t AsyncServerImpl::_accepted(AsyncClient *client) {
  if (_tls_server_hooks) {
    int8_t r = _tls_server_hooks->onAccepted(this, client);
    if (r != -1) {
      return r;
    }
  }
  if (_connect_cb) {
    async_tcp_log_elapsed("onClient", _connect_cb(_connect_cb_arg, client));
  }
  return ERR_OK;
}

uint8_t AsyncServerImpl::status() const {
  if (!_pcb) {
    return 0;
  }
  return _pcb->state;
}
bool AsyncServerImpl::queueAcceptEvent(AsyncServerImpl *server, AsyncClient *client, std::shared_ptr<AsyncClientImpl> impl) {
  lwip_tcp_event_packet_t *e = new (std::nothrow) lwip_tcp_event_packet_t{LWIP_TCP_ACCEPT, client};
  if (e) {
    e->accept_server = server->shared_from_this();  // pins the listener for dispatch
    e->accept_epoch = server->_session;

    queue_mutex_guard guard;
    _prepend_async_event(e);
    return true;
  }
  return false;
}

AsyncServerImpl::~AsyncServerImpl() {
  end();
}

bool AsyncServerHooks::queueAccept(AsyncServerImpl *srv, AsyncClient *c) {
  if (!srv || !c || !c->impl()) {
    return false;
  }
  return AsyncServerImpl::queueAcceptEvent(srv, c, c->impl()->shared_from_this());
}

// AsyncClientHooks helpers (defined once for both stacks; AsyncClient
// is complete at this point).
void AsyncClientHooks::touchRx(AsyncClientImpl *c, uint32_t now) {
  c->_rx_last_packet = now;
}

uint32_t AsyncClientHooks::lastRx(AsyncClientImpl *c) const {
  return c->_rx_last_packet;
}

void AsyncClientHooks::notifyData(AsyncClientImpl *c, void *data, size_t len) {
  // App onData fires here, synchronously. Callers must be on the async task
  // (TLS plaintext drain in hooks onRecv, ESP8266 schedule loop) — never from
  // an lwIP callback, where app writes would deadlock tcpip_api_call.
  if (c->_recv_cb && c->_facade) {
    async_tcp_log_elapsed("onData", c->_recv_cb(c->_recv_cb_arg, c->_facade, data, len));
  }
}

void AsyncClientHooks::recved(AsyncClientImpl *c, size_t len) {
  if (c && len) {
    c->_tcp_recved(&c->_pcb, len);
  }
}

void AsyncClientHooks::notifyConnect(AsyncClientImpl *c) {
  if (c->_connect_cb && c->_facade) {
    async_tcp_log_elapsed("onConnect", c->_connect_cb(c->_connect_cb_arg, c->_facade));
  }
}

void AsyncClientHooks::notifyError(AsyncClientImpl *c, int8_t err) {
  if (c->_error_cb && c->_facade) {
    c->_error_cb(c->_error_cb_arg, c->_facade, err);
  }
}

// --- AsyncServerHooks helpers (reaches AsyncServer/AsyncClient internals) ---
void AsyncServerHooks::notifyClient(AsyncServerImpl *srv, AsyncClient *c) {
  if (srv && srv->_connect_cb) {
    async_tcp_log_elapsed("onClient", srv->_connect_cb(srv->_connect_cb_arg, c));
  }
}

bool AsyncServerHooks::hasConnectHandler(AsyncServerImpl *srv) {
  return srv && srv->_connect_cb;
}

void AsyncServerHooks::doPromote(AsyncClient *c, void (*thunk)(void *, AsyncClient *), void *arg) {
  if (!c || !c->_impl) {
    return;
  }
  c->_impl->_server_discard_cb = thunk;
  c->_impl->_server_discard_cb_arg = arg;
}

struct pbuf *AsyncServerHooks::takeStaged(AsyncClientImpl *c) {
#if ASYNC_TCP_SSL_ENABLED
  if (!c || !c->_ssl_pending_pbufs) {
    return nullptr;
  }
  struct pbuf *staged = c->_ssl_pending_pbufs;
  c->_ssl_pending_pbufs = NULL;
  return staged;
#else
  (void)c;
  return nullptr;
#endif
}

void AsyncServerHooks::stageStaged(AsyncClientImpl *c, struct pbuf *staged) {
#if ASYNC_TCP_SSL_ENABLED
  if (c) {
    c->_ssl_pending_pbufs = staged;
  }
#else
  (void)c;
  (void)staged;
#endif
}

void AsyncServerHooks::feedPbuf(AsyncClientImpl *c, struct pbuf *pb) {
  if (c && c->pcb()) {
    c->_recv(c->pcb(), pb, 0);
  }
}

void AsyncServerHooks::detachPcb(AsyncClientImpl *c) {
  if (c) {
    c->_pcb = nullptr;
  }
}

