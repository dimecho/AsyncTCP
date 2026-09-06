// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright 2016-2026 Hristo Gochkov, Mathieu Carbou, Emil Muratov, Will Miles
//
// Unified dual-stack AsyncTCP. Core TCP.
//   - ESP8266         -> BearSSL stack (AsyncTCP fork, NO_SYS lwIP)
//   - ESP32/LIBRETINY -> mbedTLS stack (AsyncTCP ESP32Async base)
// Selected at compile time via #if defined(ESP8266). Only one stack compiles per target.
#if defined(ESP8266)
// ===== begin BearSSL/ESP8266 AsyncTCP.cpp (AsyncTCP) =====
// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright 2016-2026 Hristo Gochkov, Mathieu Carbou, Emil Muratov, Will Miles

#include "AsyncTCP.h"
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

#if ASYNC_TCP_SSL_ENABLED && ASYNC_TCP_SSL_ENABLE_SERVER
// Number of TLS conns parked in the bounded queue (ASYNC_TCP_SSL_PARKED_SLOTS
// slots, FIFO over the pending_pcb list).
static volatile int s_async_parked_tls = 0;
// Overflow-hold queue depth (ASYNC_TCP_SSL_HOLD_LIMIT, FIFO over _held).
static volatile int s_async_held_tls = 0;

uint8_t tcp_ssl_parked_count() {
  return (uint8_t)(s_async_parked_tls + s_async_held_tls);
}

// Page-finished flush request. SETTLED (last TLS conn drained) raises this;
// AsyncServer::_poll drains the whole parked queue on its next tick. Parked
// raw pcbs pin the PREVIOUS page's pre-connect/retry pbuf chains and can hold
// free heap below the admission bar; flushing them at page-finish lets the
// arena coalesce before the NEXT refresh burst (instead of waiting out the
// 20s idle shed).
static volatile bool s_shed_requested = false;

void tcp_ssl_shed_parked() {
  s_shed_requested = true;
}

// Total TLS server conns ever created (across all bursts) — SETTLED log uses
// this to correlate the idle-heap floor with the number of conns served.
static volatile unsigned long s_serve_conns_total = 0;

unsigned long tcp_ssl_serve_conns_total() {
  return s_serve_conns_total;
}

// Live AsyncClient shells created by the SSL serve path that have NOT been
// deleted yet. SETTLED prints this: a value that climbs across bursts while
// free heap ratchets down isolates per-serve object leaks (web-server request
// objects vs our AsyncClient vs lwIP). Incremented in _serveTls on ctor
// success, decremented in ~AsyncClient (timestamped when the object actually
// frees), so a persistent count >0 after drain = leaked shells.
static int s_live_serve_clients = 0;

int tcp_ssl_live_serve_shells() {
  return s_live_serve_clients;
}
#endif

#if CONFIG_ASYNC_TCP_USE_WDT
// Required for:
// https://github.com/espressif/arduino-esp32/blob/3.0.3/libraries/Network/src/NetworkInterface.cpp#L37-L47
#include "esp_task_wdt.h"
#define ASYNC_TCP_MAX_TASK_SLEEP (pdMS_TO_TICKS(1000 * CONFIG_ESP_TASK_WDT_TIMEOUT_S) / 4)
#else
#define ASYNC_TCP_MAX_TASK_SLEEP portMAX_DELAY
#endif

#define async_tcp_log_elapsed(tag, statement)                          \
  {                                                                    \
    [[maybe_unused]]                                                   \
    const uint32_t s_time = micros();                                  \
    statement;                                                         \
    async_tcp_log_v("%s took %" PRIu32 " us", tag, micros() - s_time); \
  }

// https://github.com/espressif/arduino-esp32/issues/10526
namespace {
#ifdef CONFIG_LWIP_TCPIP_CORE_LOCKING
struct tcp_core_guard {
  bool do_lock;
  inline tcp_core_guard() : do_lock(!sys_thread_tcpip(LWIP_CORE_LOCK_QUERY_HOLDER)) {
    if (do_lock) {
      LOCK_TCPIP_CORE();
    }
  }
  inline ~tcp_core_guard() {
    if (do_lock) {
      UNLOCK_TCPIP_CORE();
    }
  }
  tcp_core_guard(const tcp_core_guard &) = delete;
  tcp_core_guard(tcp_core_guard &&) = delete;
  tcp_core_guard &operator=(const tcp_core_guard &) = delete;
  tcp_core_guard &operator=(tcp_core_guard &&) = delete;
} __attribute__((unused));
#else   // CONFIG_LWIP_TCPIP_CORE_LOCKING
struct tcp_core_guard {
} __attribute__((unused));
#endif  // CONFIG_LWIP_TCPIP_CORE_LOCKING
}  // anonymous namespace

/*
  TCP poll interval is specified in terms of the TCP coarse timer interval, which is called twice a second
  https://github.com/espressif/esp-lwip/blob/2acf959a2bb559313cd2bf9306c24612ba3d0e19/src/core/tcp.c#L1895
*/
#ifndef CONFIG_ASYNC_TCP_POLL_TIMER
#define CONFIG_ASYNC_TCP_POLL_TIMER 1
#endif

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
  AsyncClient *client;
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
      AsyncServer *server;
    } accept;
    struct {
      const char *name;
      ip_addr_t addr;
    } dns;
  };

  inline lwip_tcp_event_packet_t(lwip_tcp_event_t _event, AsyncClient *_client) : next(nullptr), event(_event), client(_client){};
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

static void _free_event(lwip_tcp_event_packet_t *evpkt) {
  if ((evpkt->event == LWIP_TCP_RECV) && (evpkt->recv.pb != nullptr)) {
    pbuf_free(evpkt->recv.pb);
  }
  delete evpkt;
}


// Guard class for the global queue

#if defined(FREERTOS)
namespace {
static SemaphoreHandle_t _async_queue_mutex = nullptr;

class queue_mutex_guard {
  bool holds_mutex;

public:
  inline queue_mutex_guard() : holds_mutex(xSemaphoreTake(_async_queue_mutex, portMAX_DELAY)){};
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
    for (lwip_tcp_event_packet_t *next_pkt = _async_queue.begin(); next_pkt && (next_pkt->client == e->client) && (next_pkt->event == LWIP_TCP_POLL);
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

static size_t _remove_events_for_client(AsyncClient *client) {
  lwip_tcp_event_packet_t *removed_event_chain;
  {
    queue_mutex_guard guard;
    removed_event_chain = _async_queue.remove_if([=](lwip_tcp_event_packet_t &pkt) {
      return pkt.client == client;
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
  if (e->client == NULL) {
    // do nothing when arg is NULL
    // ets_printf("event arg == NULL: 0x%08x\n", e->recv.pcb);
  } else if (e->event == LWIP_TCP_RECV) {
    // ets_printf("-R: 0x%08x\n", e->recv.pcb);
    e->client->_recv(e->recv.pcb, e->recv.pb, e->recv.err);
    e->recv.pb = nullptr;  // given to client
  } else if (e->event == LWIP_TCP_FIN) {
    // ets_printf("-F: 0x%08x\n", e->fin.pcb);
    e->client->_fin(e->fin.pcb, e->fin.err);
  } else if (e->event == LWIP_TCP_SENT) {
    // ets_printf("-S: 0x%08x\n", e->sent.pcb);
    e->client->_sent(e->sent.pcb, e->sent.len);
  } else if (e->event == LWIP_TCP_POLL) {
    // ets_printf("-P: 0x%08x\n", e->poll.pcb);
    e->client->_poll(e->poll.pcb);
  } else if (e->event == LWIP_TCP_ERROR) {
    // ets_printf("-E: 0x%08x %d\n", e->client, e->error.err);
    e->client->_error(e->error.err);
  } else if (e->event == LWIP_TCP_CONNECTED) {
    // ets_printf("C: 0x%08x 0x%08x %d\n", e->client, e->connected.pcb, e->connected.err);
    e->client->_connected(e->connected.pcb, e->connected.err);
  } else if (e->event == LWIP_TCP_ACCEPT) {
    // ets_printf("A: 0x%08x 0x%08x\n", e->client, e->accept.client);
    e->accept.server->_accepted(e->client);
  } else if (e->event == LWIP_TCP_DNS) {
    // ets_printf("D: 0x%08x %s = %s\n", e->client, e->dns.name, ipaddr_ntoa(&e->dns.addr));
    e->client->_dns_found(&e->dns.addr);
  }
  _free_event(e);
}

#ifdef FREERTOS
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

static void _bind_tcp_callbacks(tcp_pcb *pcb, AsyncClient *client) {
  tcp_arg(pcb, client);
  tcp_recv(pcb, &AsyncTCP_detail::tcp_recv);
  tcp_sent(pcb, &AsyncTCP_detail::tcp_sent);
  tcp_err(pcb, &AsyncTCP_detail::tcp_error);
  tcp_poll(pcb, &AsyncTCP_detail::tcp_poll, CONFIG_ASYNC_TCP_POLL_TIMER);
}

static void _reset_tcp_callbacks(tcp_pcb *pcb, AsyncClient *client) {
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
  AsyncClient *client = reinterpret_cast<AsyncClient *>(arg);
  lwip_tcp_event_packet_t *e = new (std::nothrow) lwip_tcp_event_packet_t{LWIP_TCP_CONNECTED, client};
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
  AsyncClient *client = reinterpret_cast<AsyncClient *>(arg);
  lwip_tcp_event_packet_t *e = new (std::nothrow) lwip_tcp_event_packet_t{LWIP_TCP_POLL, client};
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
  AsyncClient *client = reinterpret_cast<AsyncClient *>(arg);
  lwip_tcp_event_packet_t *e = new (std::nothrow) lwip_tcp_event_packet_t{LWIP_TCP_RECV, client};
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
  AsyncClient *client = reinterpret_cast<AsyncClient *>(arg);
  lwip_tcp_event_packet_t *e = new (std::nothrow) lwip_tcp_event_packet_t{LWIP_TCP_SENT, client};
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
  AsyncClient *client = reinterpret_cast<AsyncClient *>(arg);
  if (client && client->_pcb) {
    // The pcb has already been freed by LwIP; do not attempt to clear the callbacks!
    _remove_events_for_client(client);
    client->_pcb = nullptr;
  }

  // enqueue event to be processed in the async task for the user callback
  lwip_tcp_event_packet_t *e = new (std::nothrow) lwip_tcp_event_packet_t{LWIP_TCP_ERROR, client};
  if (!e) {
    async_tcp_log_e("Failed to allocate event packet");
    return;
  }
  e->error.err = err;

  queue_mutex_guard guard;
  _send_async_event(e);
}

static void _tcp_dns_found(const char *name, ip_addr_t *ipaddr, void *arg) {
  // ets_printf("+DNS: name=%s ipaddr=0x%08x arg=%x\n", name, ipaddr, arg);
  auto client = reinterpret_cast<AsyncClient *>(arg);

  lwip_tcp_event_packet_t *e = new (std::nothrow) lwip_tcp_event_packet_t{LWIP_TCP_DNS, client};
  if (!e) {
    async_tcp_log_e("Failed to allocate event packet");
    return;
  }

  e->dns.name = name;
  if (ipaddr) {
    memcpy(&e->dns.addr, ipaddr, sizeof(ip_addr_t));
  } else {
    memset(&e->dns.addr, 0, sizeof(e->dns.addr));
  }

  queue_mutex_guard guard;
  _send_async_event(e);
}

/*
 * TCP/IP API Ccll wrappers
 *
 * Handles TCPIP core locking and ensures that the AsyncClient is not destroyed while the call is in progress.
 * */

#include "lwip/priv/tcpip_priv.h"

// If LwIP is configured with mutex support, wrap all calls with tcpip_api_call() to ensure that the LwIP core is locked during the call.
#ifndef NO_SYS
typedef struct {
  struct tcpip_api_call_data call;
  tcp_pcb **pcb;
  int8_t err;
  union {
    AsyncClient *close;
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

static esp_err_t _tcp_close(tcp_pcb **pcb, AsyncClient *client) {
  tcp_api_call_t msg;
  msg.pcb = pcb;
  msg.close = client;
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

static esp_err_t _tcp_abort(tcp_pcb **pcb, AsyncClient *client) {
  if (!pcb || !*pcb) {
    return ERR_CONN;
  }
  tcp_api_call_t msg;
  msg.pcb = pcb;
  msg.close = client;
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

static esp_err_t _tcp_close(tcp_pcb **pcb, AsyncClient *client) {
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

static esp_err_t _tcp_abort(tcp_pcb **pcb, AsyncClient *client) {
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

/*
  Async TCP Client
 */

AsyncClient::AsyncClient(tcp_pcb *pcb)
  : _connect_cb(0), _connect_cb_arg(0), _discard_cb(0), _discard_cb_arg(0), _server_discard_cb(0), _server_discard_cb_arg(0), _sent_cb(0), _sent_cb_arg(0), _error_cb(0), _error_cb_arg(0), _recv_cb(0),
    _recv_cb_arg(0), _pb_cb(0), _pb_cb_arg(0), _timeout_cb(0), _timeout_cb_arg(0), _poll_cb(0), _poll_cb_arg(0), _ack_pcb(true), _closing(false),
#if ASYNC_TCP_SSL_ENABLED
    _pcb_secure(false), _handshake_done(true), _client_ssl_ctx(NULL),
#endif
    _tx_last_packet(0), _tx_unacked_len(0),
    _rx_timeout(0), _rx_last_ack(0), _ack_timeout(CONFIG_ASYNC_TCP_MAX_ACK_TIME), _connect_port(0) {
  _pcb = pcb;
  if (_pcb) {
    _rx_last_packet = millis();
    _bind_tcp_callbacks(_pcb, this);
  }
}

#if ASYNC_TCP_SSL_ENABLED
AsyncClient::AsyncClient(tcp_pcb *pcb, BearSSL_SSL_CTX *ssl_ctx)
  : _connect_cb(0), _connect_cb_arg(0), _discard_cb(0), _discard_cb_arg(0), _server_discard_cb(0), _server_discard_cb_arg(0), _sent_cb(0), _sent_cb_arg(0), _error_cb(0), _error_cb_arg(0), _recv_cb(0),
    _recv_cb_arg(0), _pb_cb(0), _pb_cb_arg(0), _timeout_cb(0), _timeout_cb_arg(0), _poll_cb(0), _poll_cb_arg(0), _ack_pcb(true), _closing(false),
    _pcb_secure(false), _handshake_done(true), _client_ssl_ctx(NULL),
    _tx_last_packet(0), _tx_unacked_len(0),
    _rx_timeout(0), _rx_last_ack(0), _ack_timeout(CONFIG_ASYNC_TCP_MAX_ACK_TIME), _connect_port(0) {
  _pcb = pcb;
  if (_pcb) {
    _rx_last_packet = millis();
    _bind_tcp_callbacks(_pcb, this);
#if ASYNC_TCP_SSL_ENABLE_SERVER
    if (tcp_ssl_new_server(_pcb, ssl_ctx) < 0) {
      _close();
      return;
    }
    tcp_ssl_arg(_pcb, this);
    tcp_ssl_data(_pcb, &_s_data);
    tcp_ssl_handshake(_pcb, &_s_handshake);
    tcp_ssl_err(_pcb, &_s_ssl_error);

    _pcb_secure = true;
    _handshake_done = false;
#else
    // Server role compiled out: a TLS-accepted connection has no server
    // glue, so close it out.
    _close();
    return;
#endif
  }
}
#endif

AsyncClient::~AsyncClient() {
#if ASYNC_TCP_SSL_ENABLED
  // The shellCLOSE probe + live-shell decrement MUST live in this (ESP8266)
  // dtor — the copy in the ESP32 mbedTLS section never compiles here. Without
  // the decrement, SETTLED's `shells` only ever climbs (tautology, read as a
  // leak in an earlier session). With both, shells reveals the truth: 0 by the
  // next SETTLED = AsyncClient freed on teardown, arena stable.
  if (s_live_serve_clients) {
    s_live_serve_clients--;
  }
  if (_server_discard_cb) {
    async_tcp_log_d("shellCLOSE: live shells=%d", s_live_serve_clients);
  }
#endif
  if (_pcb) {
    _close();
  }
}

/*
 * Operators
 * */

bool AsyncClient::operator==(const AsyncClient &other) const {
  return _pcb == other._pcb;
}

/*
 * Callback Setters
 * */

void AsyncClient::onConnect(AcConnectHandler cb, void *arg) {
  _connect_cb = cb;
  _connect_cb_arg = arg;
}

void AsyncClient::onDisconnect(AcConnectHandler cb, void *arg) {
  _discard_cb = cb;
  _discard_cb_arg = arg;
}

void AsyncClient::onAck(AcAckHandler cb, void *arg) {
  _sent_cb = cb;
  _sent_cb_arg = arg;
}

void AsyncClient::onError(AcErrorHandler cb, void *arg) {
  _error_cb = cb;
  _error_cb_arg = arg;
}

void AsyncClient::onData(AcDataHandler cb, void *arg) {
  _recv_cb = cb;
  _recv_cb_arg = arg;
}

void AsyncClient::onPacket(AcPacketHandler cb, void *arg) {
  _pb_cb = cb;
  _pb_cb_arg = arg;
}

void AsyncClient::onTimeout(AcTimeoutHandler cb, void *arg) {
  _timeout_cb = cb;
  _timeout_cb_arg = arg;
}

void AsyncClient::onPoll(AcConnectHandler cb, void *arg) {
  _poll_cb = cb;
  _poll_cb_arg = arg;
}

/*
 * Main Public Methods
 * */

bool AsyncClient::connect(ip_addr_t addr, uint16_t port, bool secure) {
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
#if ASYNC_TCP_SSL_ENABLED
    _pcb_secure = secure;
    _handshake_done = !secure;
#endif
  }

  esp_err_t err = _tcp_connect(pcb, &addr, port, (tcp_connected_fn)&_tcp_connected);
  return err == ESP_OK;
}

#ifdef ARDUINO
bool AsyncClient::connect(const IPAddress &ip, uint16_t port, bool secure) {
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

  return connect(addr, port, secure);
}
#endif

#if LWIP_IPV6 && ESP_IDF_VERSION_MAJOR < 5
bool AsyncClient::connect(const IPv6Address &ip, uint16_t port, bool secure) {
  auto ipaddr = static_cast<const uint32_t *>(ip);
  ip_addr_t addr = IPADDR6_INIT(ipaddr[0], ipaddr[1], ipaddr[2], ipaddr[3]);

  return connect(addr, port, secure);
}
#endif

bool AsyncClient::connect(const char *host, uint16_t port, bool secure) {
  ip_addr_t addr;

  if (!_start_async_task()) {
    async_tcp_log_e("failed to start task");
    return false;
  }

  err_t err;
  {
    tcp_core_guard tcg;
    err = dns_gethostbyname(host, &addr, (dns_found_callback)&_tcp_dns_found, this);
  }

  if (err == ERR_OK) {
#if ESP_IDF_VERSION_MAJOR < 5
#if LWIP_IPV6
    if (addr.type == IPADDR_TYPE_V6) {
      return connect(IPv6Address(addr.u_addr.ip6.addr), port, secure);
    }
    return connect(IPAddress(addr.u_addr.ip4.addr), port, secure);
#else
    return connect(IPAddress(addr.addr), port, secure);
#endif
#else
    return connect(addr, port, secure);
#endif
  } else if (err == ERR_INPROGRESS) {
#if ASYNC_TCP_SSL_ENABLED
    _pcb_secure = secure;
    _handshake_done = !secure;
#endif
    _connect_port = port;
    return true;
  }
  async_tcp_log_d("error: %d", err);
  return false;
}

// Plain-TCP wrappers. connect() always uses an unencrypted transport; TLS
// connects go through beginSecure() (ASYNC_TCP_SSL_ENABLED builds) which maps
// onto the same 3-arg connect() helper with secure=true.
bool AsyncClient::connect(ip_addr_t addr, uint16_t port) {
  return connect(addr, port, false);
}

#ifdef ARDUINO
bool AsyncClient::connect(const IPAddress &ip, uint16_t port) {
  return connect(ip, port, false);
}
#if __has_include(<IPv6Address.h>)
bool AsyncClient::connect(const IPv6Address &ip, uint16_t port) {
  return connect(ip, port, false);
}
#endif
#endif

bool AsyncClient::connect(const char *host, uint16_t port) {
  return connect(host, port, false);
}

#if ASYNC_TCP_SSL_ENABLED
bool AsyncClient::beginSecure(const char *host, uint16_t port, const char *rootCA) {
  (void)rootCA;  // no server-cert verification (mirrors mbedTLS beginSecure(host, port, NULL))
  _pcb_secure = true;
  _handshake_done = false;
  return connect(host, port, true);
}
#endif

#if ASYNC_TCP_SSL_ENABLED
bool AsyncClient::startTLS(const char *host) {
#if ASYNC_TCP_SSL_ENABLE_CLIENT
  if (!_pcb || _pcb_secure || !connected()) {
    return false;
  }
  // Flipping _pcb_secure BEFORE binding the engine (matching _connected(),
  // where _pcb_secure is already true) ensures any data routed during the
  // engine bind / handshake kickoff goes through the SSL path as intended.
  _pcb_secure = true;
  _handshake_done = false;
  if (tcp_ssl_new_client(_pcb, host ? host : "", NULL, _client_ssl_ctx) < 0) {
    _close();
    return false;
  }
  tcp_ssl_arg(_pcb, this);
  tcp_ssl_data(_pcb, &_s_data);
  tcp_ssl_handshake(_pcb, &_s_handshake);
  tcp_ssl_err(_pcb, &_s_ssl_error);
  return true;
#else
  // Client role compiled out (server-only build): no STARTTLS upgrade support.
  (void)host;
  return false;
#endif
}
#endif

void AsyncClient::close() {
  if (_pcb) {
    _tcp_recved(&_pcb, _rx_ack_len);
  }
  _close();
}

int8_t AsyncClient::abort() {
#if ASYNC_TCP_SSL_ENABLED
  if (_pcb_secure && _pcb) {
    tcp_ssl_free(_pcb);
  }
#endif
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

size_t AsyncClient::space() const {
  if ((_pcb != NULL) && (_pcb->state == ESTABLISHED)) {
#if ASYNC_TCP_SSL_ENABLED
    if (_handshake_done) {
      uint16_t s = tcp_sndbuf(_pcb);
      if (_pcb_secure) {
        if (s >= 128)  // safe approach
          return s - 128;
        return 0;
      }
      return s;
    }
    return 0;
#else
    return tcp_sndbuf(_pcb);
#endif
  }
  return 0;
}

size_t AsyncClient::add(const char *data, size_t size, uint8_t apiflags) {
  if (!_pcb || size == 0 || data == NULL) {
    return 0;
  }
  size_t room = space();
  if (!room) {
    return 0;
  }
#if ASYNC_TCP_SSL_ENABLED
  if (_pcb_secure) {
    int sent = tcp_ssl_write(_pcb, (uint8_t *)data, size);
    if (sent >= 0) {
      _tx_unacked_len += sent;
      return sent;
    }
    _close();
    return 0;
  }
#endif
  size_t will_send = (room < size) ? room : size;
  int8_t err = ERR_OK;
  err = _tcp_write(&_pcb, data, will_send, apiflags);
  if (err != ERR_OK) {
    return 0;
  }
#if ASYNC_TCP_SSL_ENABLED
  _tx_unacked_len += will_send;
#endif
  return will_send;
}

bool AsyncClient::send() {
#if ASYNC_TCP_SSL_ENABLED
  if (_pcb_secure) {
    return true;
  }
#endif
  auto backup = _tx_last_packet;
  _tx_last_packet = millis();
  if (_tcp_output(&_pcb) == ERR_OK) {
    return true;
  }
  _tx_last_packet = backup;
  return false;
}

size_t AsyncClient::ack(size_t len) {
  if (len > _rx_ack_len) {
    len = _rx_ack_len;
  }
  if (len) {
    _tcp_recved(&_pcb, len);
  }
  _rx_ack_len -= len;
  return len;
}

void AsyncClient::ackPacket(struct pbuf *pb) {
  if (!pb) {
    return;
  }
  _tcp_recved(&_pcb, pb->len);
  pbuf_free(pb);
}

/*
 * Main Private Methods
 * */

int8_t AsyncClient::_close() {
  // Claim the teardown with the _closing flag: lwIP callbacks (_recv/_error)
  // can fire synchronously inside tcp_ssl_close()/tcp_ssl_free()/tcp_close()
  // and re-enter _close() on the same pcb; _closing makes those entry points
  // bail. _pcb stays non-NULL until _tcp_close() nulls it.
  if (_closing || !_pcb) {
    return ERR_OK;
  }
  _closing = true;
  tcp_pcb *pcb = _pcb;
#if ASYNC_TCP_SSL_ENABLED
  // Leak probe: the web server's request self-destructs ONLY on its
  // onDisconnect (_discard_cb). Zero onDisconnect prints + zero shellCLOSE =
  // the web request+AsyncClient pair leaks per conn. This line shows whether
  // teardown reaches _close at all and whether the web hook is still wired.
  async_tcp_log_d("serveClose: discard=%d server_discard=%d pcb=%p",
                  (int)(bool)_discard_cb, (int)(bool)_server_discard_cb, (void *)pcb);
#endif
#if ASYNC_TCP_SSL_ENABLED
  if (_pcb_secure) {
    // A hard SENDREC stall means tcp_write() cannot allocate (memp TCP_SEG /
    // heap exhausted) — the graceful close_notify transmit below would also
    // fail (ERR_MEM) and merely add latency while the TLS buffers stay pinned.
    // In that exact state skip close_notify and tear the connection down
    // immediately so its TLS buffers are returned to the heap. Graceful close
    // is preserved for every healthy connection.
    // ORDER MATTERS: abort the pcb FIRST — lwIP synchronously purges its
    // queued send segments (which may reference the slab) — THEN free the TLS
    // buffers. Freeing the slab while lwIP still drains its queue is a UAF:
    // the next marshal copies from / chain-manipulates freed slabs, corrupting
    // the arena (observed: force-close at free 5896 left the allocator stuck
    // at 10528 with a lingering conn -> permanent admission-refusal latch).
    if (tcp_ssl_is_stalled(pcb, ASYNC_TCP_SSL_STALL_RESET_MS)) {
      async_tcp_log_d("_close: skipping graceful close_notify (hard stall), resetting TCP + freeing TLS buffers immediately.\n");
      tcp_abort(pcb);
      tcp_ssl_free(pcb);
      _pcb = NULL;
      _pcb_secure = false;
      _closing = false;
      if (_discard_cb) {
        async_tcp_log_elapsed("onDisconnect", _discard_cb(_discard_cb_arg, this));
      }
      if (_server_discard_cb) {
        _server_discard_cb(_server_discard_cb_arg, this);
      }
      return ERR_OK;
    } else {
      tcp_ssl_close(pcb);  // graceful TLS shutdown: emit close_notify before FIN (best effort)
      tcp_ssl_free(pcb);
    }
  }
#endif
  int8_t err = _tcp_close(&_pcb, this);
  // _pcb is now NULL
  _closing = false;
  if ((err == ERR_OK) && _discard_cb) {
    // _pcb was closed here
    async_tcp_log_elapsed("onDisconnect", _discard_cb(_discard_cb_arg, this));
  }
  if (_server_discard_cb) {
    _server_discard_cb(_server_discard_cb_arg, this);
  }
  return err;
}

/*
 * Private Callbacks
 * */

int8_t AsyncClient::_connected(tcp_pcb *pcb, int8_t err __attribute__((unused))) {
  _pcb = reinterpret_cast<tcp_pcb *>(pcb);
  if (_pcb) {
    _rx_last_packet = millis();
  }
  _tx_last_packet = 0;
  _rx_last_ack = 0;
#if ASYNC_TCP_SSL_ENABLED
  if (_pcb_secure) {
#if ASYNC_TCP_SSL_ENABLE_CLIENT
    if (tcp_ssl_new_client(_pcb, "", NULL, _client_ssl_ctx) < 0) {
      _close();
      return ERR_OK;
    }
#else
    // Client role compiled out (server-only build): a secure *outbound*
    // connect has no support, so close it out.
    _close();
    return ERR_OK;
#endif
    tcp_ssl_arg(_pcb, this);
    tcp_ssl_data(_pcb, &_s_data);
    tcp_ssl_handshake(_pcb, &_s_handshake);
    tcp_ssl_err(_pcb, &_s_ssl_error);
    return ERR_OK;
  }
#endif
  if (_connect_cb) {
    async_tcp_log_elapsed("onConnect", _connect_cb(_connect_cb_arg, this));
  }
  return ERR_OK;
}

void AsyncClient::_error(int8_t err) {
  if (_pcb) {
#if ASYNC_TCP_SSL_ENABLED
    if (_pcb_secure) {
      tcp_ssl_free(_pcb);
    }
#endif
    _pcb = NULL;
  }
  if (_error_cb) {
    async_tcp_log_elapsed("onError", _error_cb(_error_cb_arg, this, err));
  }
  if (_discard_cb) {
    async_tcp_log_elapsed("onDisconnect", _discard_cb(_discard_cb_arg, this));
  }
  if (_server_discard_cb) {
    _server_discard_cb(_server_discard_cb_arg, this);
  }
}

#if ASYNC_TCP_SSL_ENABLED
void AsyncClient::_ssl_error(int8_t err) {
  // A deferred SSL error can fire after teardown already nulled _pcb / freed
  // the ssl_pcb. close() would re-enter _close() on freed state, so bail.
  if (!_pcb)
    return;
  if (_error_cb)
    _error_cb(_error_cb_arg, this, err + 64);
  // The BearSSL engine reached CLOSED (peer close_notify, TLS alert, or engine
  // error) without an app-initiated _close(). process_ssl_engine() routes this
  // here via on_error. If we don't tear down now, the tcp_ssl_pcb (in+out+
  // accum buffers ~6KB) leaks. _close() frees it (guarded by find_ssl_pcb
  // returning -1 for already-freed pcbs).
  close();
}

void AsyncClient::_s_data(void *arg, struct tcp_pcb *tcp, uint8_t *data, size_t len) {
  (void)tcp;
  AsyncClient *c = reinterpret_cast<AsyncClient *>(arg);
  if (c->_recv_cb)
    c->_recv_cb(c->_recv_cb_arg, c, data, len);
}

void AsyncClient::_s_handshake(void *arg, struct tcp_pcb *tcp, SSL *ssl) {
  (void)tcp;
  (void)ssl;
  AsyncClient *c = reinterpret_cast<AsyncClient *>(arg);
  c->_handshake_done = true;
  if (c->_connect_cb)
    c->_connect_cb(c->_connect_cb_arg, c);
}

void AsyncClient::_s_ssl_error(void *arg, struct tcp_pcb *tcp, int8_t err) {
  (void)tcp;
  reinterpret_cast<AsyncClient *>(arg)->_ssl_error(err);
}
#endif

// In LwIP Thread
int8_t AsyncClient::_lwip_fin(tcp_pcb *pcb, int8_t err __attribute__((unused))) {
  if (!_pcb || pcb != _pcb) {
    async_tcp_log_d("0x%08" PRIx32 " != 0x%08" PRIx32, (uint32_t)pcb, (uint32_t)_pcb);
    return ERR_OK;
  }
  _reset_tcp_callbacks(_pcb, this);
  if (tcp_close(_pcb) != ERR_OK) {
    tcp_abort(_pcb);
  }
  _pcb = NULL;
  return ERR_OK;
}

// In Async Thread
int8_t AsyncClient::_fin(tcp_pcb *pcb __attribute__((unused)), int8_t err __attribute__((unused))) {
  close();
  return ERR_OK;
}

int8_t AsyncClient::_sent(tcp_pcb *pcb __attribute__((unused)), uint16_t len) {
#if ASYNC_TCP_SSL_ENABLED
  if (_pcb_secure) {
    // TLS-layer ACK handling must run for EVERY ciphertext ACK, INCLUDING
    // mid-handshake: handshake flight records ride the same no-copy ring as
    // app data, and their slots only free here (tcp_ssl_sent releases FIFO and
    // re-arms the engine).
    tcp_ssl_sent(_pcb, len);
    if (!_handshake_done)
      return ERR_OK;  // skip app-level accounting until the handshake completes
    _tx_unacked_len -= _tx_unacked_len > len ? len : _tx_unacked_len;
  }
#endif
  _rx_last_ack = _rx_last_packet = millis();
  if (_sent_cb) {
    async_tcp_log_elapsed("onAck", _sent_cb(_sent_cb_arg, this, len, (_rx_last_packet - _tx_last_packet)));
  }
  return ERR_OK;
}

int8_t AsyncClient::_recv(tcp_pcb *pcb __attribute__((unused)), pbuf *pb, int8_t err __attribute__((unused))) {
  // A teardown is in flight for this client (close/abort running on the lwIP
  // pcb). Late synchronous callbacks would resurrect _pcb and tear the pcb
  // down twice -> use-after-free. Bail so the claiming _close() owns it.
  if (_closing) {
    return ERR_OK;
  }
#if ASYNC_TCP_SSL_ENABLED
  if (_pcb_secure) {
    if (pb == NULL) {
      // Peer FIN: close the TLS connection (close_notify exchange) — mirror
      // the reference; the plain path uses lwIP's own fin handling instead.
      async_tcp_log_d("_recv: pb == NULL! Closing...");
      _close();
      return ERR_OK;
    }
    int read_bytes = tcp_ssl_read(pcb, pb);
    if (read_bytes < 0) {
      if (read_bytes != BR_ALERT_CLOSE_NOTIFY) {
        async_tcp_log_d("_recv SSL error: [%d] %s", read_bytes, tcp_ssl_error_string(read_bytes));
        _close();
      }
    }
    return ERR_OK;
  }
#endif
  while (pb != NULL) {
    _rx_last_packet = millis();
    // we should not ack before we assimilate the data
    _ack_pcb = true;
    pbuf *b = pb;
    pb = b->next;
    b->next = NULL;
    if (_pb_cb) {
      async_tcp_log_elapsed("onPacket", _pb_cb(_pb_cb_arg, this, b));
    } else {
      if (_recv_cb) {
        async_tcp_log_elapsed("onData", _recv_cb(_recv_cb_arg, this, b->payload, b->len));
      }
      if (!_ack_pcb) {
        _rx_ack_len += b->len;
      } else if (_pcb) {
        _tcp_recved(&_pcb, b->len);
      }
      pbuf_free(b);
    }
  }
  return ERR_OK;
}

int8_t AsyncClient::_poll(tcp_pcb *pcb) {
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
        async_tcp_log_elapsed("onTimeout", _timeout_cb(_timeout_cb_arg, this, (now - _tx_last_packet)));
      }
      return ERR_OK;
    }
  }
  // RX Timeout
  if (_rx_timeout && (now - _rx_last_packet) >= (_rx_timeout * 1000)) {
    async_tcp_log_d("rx timeout %d", pcb->state);
    _close();
    return ERR_OK;
  }
#if ASYNC_TCP_SSL_ENABLED
  // SSL Handshake Timeout — 6s; the admission gates (free >= 9K, maxblock >=
  // slab) mean the flight usually fits, but a momentary fragmented dip can
  // defer the record for a while. A stuck half-open handshake holds ~5.4KB of
  // TLS buffers, so
  // still bound it.
  if (_pcb_secure && !_handshake_done && (now - _rx_last_packet) >= 6000) {
    async_tcp_log_d("SSL handshake timeout %d", pcb->state);
    _close();
    return ERR_OK;
  }

  // Deferred-record retry. A SENDREC record that couldn't be written is retried
  // on the next ACK (_sent). But when it is the LAST outstanding record there is
  // no future ACK to wake it. lwIP polls this callback every TCP_POLL_INTERVAL
  // regardless of traffic, so re-arm the engine here too; tcp_ssl_sent() is
  // idempotent (no-op unless sendrec_deferred is set and engine is in SENDREC).
  if (_pcb_secure && _handshake_done) {
    tcp_ssl_sent(pcb, 0);  // poll retry: no ACK to account for, just re-arm
    // Bounded hard-stall recovery. A SENDREC record that tcp_write() cannot
    // transmit even with an open send window and an empty pbuf queue has
    // nothing on the wire, so no ACK will ever un-wedge it — it would pin this
    // connection (and its ~6KB of TLS buffers) forever. If it has persisted
    // past the stall timeout, tear the connection down so the browser retries
    // on a fresh connection.
    if (tcp_ssl_is_stalled(pcb, ASYNC_TCP_SSL_STALL_RESET_MS)) {
      async_tcp_log_d("SSL hard SENDREC stall >%ums, resetting connection", (unsigned)ASYNC_TCP_SSL_STALL_RESET_MS);
      _close();
      return ERR_OK;
    }
    // Silent-live teardown (browser stop/abort recovery). A force-"stop" in the
    // browser usually abandons the socket (RST) or simply stops reading; it
    // does not always deliver the FIN that _recv()'s pb==NULL path closes on.
    // When such a conn goes fully idle — no inbound data, nothing unacked on
    // the wire, send window drained — it has nothing more to deliver or wait
    // for, yet its TLS buffers (and this slot) stay pinned forever. Free it
    // after the stall window so a parked refresh conn promotes instead of
    // waiting on a wedged connection. Benign for the normal case: a finished
    // page is idle and the next nav opens a fresh socket anyway.
    if ((now - _rx_last_packet) >= ASYNC_TCP_SSL_STALL_RESET_MS &&
        _tx_unacked_len == 0 && tcp_sndbuf(pcb) != 0) {
      async_tcp_log_d("SSL conn idle >%ums (browser abort?), closing to free slot", (unsigned)ASYNC_TCP_SSL_STALL_RESET_MS);
      _close();
      return ERR_OK;
    }
  }
#endif
  // Everything is fine
  if (_poll_cb) {
    async_tcp_log_elapsed("onPoll", _poll_cb(_poll_cb_arg, this));
  }
  return ERR_OK;
}

void AsyncClient::_dns_found(ip_addr_t *ipaddr) {
  if (ipaddr) {
#if ASYNC_TCP_SSL_ENABLED
    connect(*ipaddr, _connect_port, _pcb_secure);
#else
    connect(*ipaddr, _connect_port);
#endif
  } else {
    if (_error_cb) {
      async_tcp_log_elapsed("onError", _error_cb(_error_cb_arg, this, -55));
    }
    if (_discard_cb) {
      async_tcp_log_elapsed("onDisconnect", _discard_cb(_discard_cb_arg, this));
    }
  }
}

/*
 * Public Helper Methods
 * */

bool AsyncClient::free() {
  if (!_pcb) {
    return true;
  }
  if (_pcb->state == CLOSED || _pcb->state > ESTABLISHED) {
    return true;
  }
  return false;
}

size_t AsyncClient::write(const char *data, size_t size, uint8_t apiflags) {
  size_t will_send = add(data, size, apiflags);
  if (!will_send || !send()) {
    return 0;
  }
  return will_send;
}

void AsyncClient::setRxTimeout(uint32_t timeout) {
  _rx_timeout = timeout;
}

uint32_t AsyncClient::getRxTimeout() const {
  return _rx_timeout;
}

uint32_t AsyncClient::getAckTimeout() const {
  return _ack_timeout;
}

void AsyncClient::setAckTimeout(uint32_t timeout) {
  _ack_timeout = timeout;
}

void AsyncClient::setNoDelay(bool nodelay) const {
  if (!_pcb) {
    return;
  }
  if (nodelay) {
    tcp_nagle_disable(_pcb);
  } else {
    tcp_nagle_enable(_pcb);
  }
}

bool AsyncClient::getNoDelay() {
  if (!_pcb) {
    return false;
  }
  return tcp_nagle_disabled(_pcb);
}

void AsyncClient::setKeepAlive(uint32_t ms, uint8_t cnt) {
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

uint16_t AsyncClient::getMss() const {
  if (!_pcb) {
    return 0;
  }
  return tcp_mss(_pcb);
}

uint32_t AsyncClient::getRemoteAddress() const {
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
ip6_addr_t AsyncClient::getRemoteAddress6() const {
  if (_pcb && _pcb->remote_ip.type == IPADDR_TYPE_V6) {
    return _pcb->remote_ip.u_addr.ip6;
  } else {
    ip6_addr_t nulladdr;
    ip6_addr_set_zero(&nulladdr);
    return nulladdr;
  }
}

ip6_addr_t AsyncClient::getLocalAddress6() const {
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
IPv6Address AsyncClient::remoteIP6() const {
  return IPv6Address(getRemoteAddress6().addr);
}

IPv6Address AsyncClient::localIP6() const {
  return IPv6Address(getLocalAddress6().addr);
}
#else
IPAddress AsyncClient::remoteIP6() const {
  if (!_pcb) {
    return IPAddress(IPType::IPv6);
  }
  IPAddress ip;
  ip.from_ip_addr_t(&(_pcb->remote_ip));
  return ip;
}

IPAddress AsyncClient::localIP6() const {
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

uint16_t AsyncClient::getRemotePort() const {
  if (!_pcb) {
    return 0;
  }
  return _pcb->remote_port;
}

uint32_t AsyncClient::getLocalAddress() const {
  if (!_pcb) {
    return 0;
  }
#if LWIP_IPV4 && LWIP_IPV6
  return _pcb->local_ip.u_addr.ip4.addr;
#else
  return _pcb->local_ip.addr;
#endif
}

uint16_t AsyncClient::getLocalPort() const {
  if (!_pcb) {
    return 0;
  }
  return _pcb->local_port;
}

ip4_addr_t AsyncClient::getRemoteAddress4() const {
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

ip4_addr_t AsyncClient::getLocalAddress4() const {
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
IPAddress AsyncClient::remoteIP() const {
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

IPAddress AsyncClient::localIP() const {
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

uint8_t AsyncClient::state() const {
  if (!_pcb) {
    return 0;
  }
  return _pcb->state;
}

bool AsyncClient::connected() const {
  if (!_pcb) {
    return false;
  }
  return _pcb->state == ESTABLISHED;
}

bool AsyncClient::connecting() const {
  if (!_pcb) {
    return false;
  }
  return _pcb->state > CLOSED && _pcb->state < ESTABLISHED;
}

bool AsyncClient::disconnecting() const {
  if (!_pcb) {
    return false;
  }
  return _pcb->state > ESTABLISHED && _pcb->state < TIME_WAIT;
}

bool AsyncClient::disconnected() const {
  if (!_pcb) {
    return true;
  }
  return _pcb->state == CLOSED || _pcb->state == TIME_WAIT;
}

bool AsyncClient::freeable() const {
  if (!_pcb) {
    return true;
  }
  return _pcb->state == CLOSED || _pcb->state > ESTABLISHED;
}

bool AsyncClient::canSend() const {
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
    case ERR_ALREADY:    return "Already connected";
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

const char *AsyncClient::stateToString() const {
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

AsyncServer::AsyncServer(ip_addr_t addr, uint16_t port)
  : _port(port), _addr(addr), _noDelay(false), _pcb(nullptr), _connect_cb(nullptr), _connect_cb_arg(nullptr)
#if ASYNC_TCP_SSL_ENABLED
    , _pending(NULL), _held(NULL), _ssl_ctx(NULL), _file_cb(NULL), _file_cb_arg(NULL)
#endif
{
}

#ifdef ARDUINO
AsyncServer::AsyncServer(IPAddress addr, uint16_t port) : _port(port), _noDelay(false), _pcb(0), _connect_cb(0), _connect_cb_arg(0)
#if ASYNC_TCP_SSL_ENABLED
                                                          , _pending(NULL), _held(NULL), _ssl_ctx(NULL), _file_cb(NULL), _file_cb_arg(NULL)
#endif
{
#if ESP_IDF_VERSION_MAJOR < 5
#if LWIP_IPV4 && LWIP_IPV6
  _addr.type = IPADDR_TYPE_V4;
  _addr.u_addr.ip4.addr = addr;
#else
  _addr.addr = addr;
#endif
#else
  addr.to_ip_addr_t(&_addr);
#endif
}
#if ESP_IDF_VERSION_MAJOR < 5 && __has_include(<IPv6Address.h>) && LWIP_IPV6
AsyncServer::AsyncServer(IPv6Address addr, uint16_t port) : _port(port), _noDelay(false), _pcb(0), _connect_cb(0), _connect_cb_arg(0)
#if ASYNC_TCP_SSL_ENABLED
                                                           , _pending(NULL), _held(NULL), _ssl_ctx(NULL), _file_cb(NULL), _file_cb_arg(NULL)
#endif
{
#if LWIP_IPV4 && LWIP_IPV6
  _addr.type = IPADDR_TYPE_V6;
#endif
  auto ipaddr = static_cast<const uint32_t *>(addr);
  _addr = IPADDR6_INIT(ipaddr[0], ipaddr[1], ipaddr[2], ipaddr[3]);
}
#endif
#endif

AsyncServer::AsyncServer(uint16_t port) : _port(port), _noDelay(false), _pcb(0), _connect_cb(0), _connect_cb_arg(0)
#if ASYNC_TCP_SSL_ENABLED
                                          , _pending(NULL), _held(NULL), _ssl_ctx(NULL), _file_cb(NULL), _file_cb_arg(NULL)
#endif
{
#if LWIP_IPV4 && LWIP_IPV6
  _addr.type = IPADDR_TYPE_ANY;
  _addr.u_addr.ip4.addr = INADDR_ANY;
#else
  _addr.addr = INADDR_ANY;
#endif
}

AsyncServer::~AsyncServer() {
  end();
}

void AsyncServer::onClient(AcConnectHandler cb, void *arg) {
  _connect_cb = cb;
  _connect_cb_arg = arg;
}

#if ASYNC_TCP_SSL_ENABLED
void AsyncServer::onSslFileRequest(AcSSLFileHandler cb, void *arg) {
  _file_cb = cb;
  _file_cb_arg = arg;
}

void AsyncServer::beginSecure(const char *cert, const char *private_key_file, const char *password) {
  if (_ssl_ctx) {
    async_tcp_log_d("beginSecure: already have ctx, skip");
    return;
  }
  _ssl_ctx = tcp_ssl_new_server_ctx(cert, private_key_file, password);
  if (_ssl_ctx) {
    async_tcp_log_d("beginSecure: ctx created OK, calling begin()");
    begin();
  } else {
    async_tcp_log_d("beginSecure: tcp_ssl_new_server_ctx returned NULL (PEM parse failed)");
  }
}
#endif

void AsyncServer::begin() {
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
  _pcb = _tcp_listen_with_backlog(_pcb, backlog);
  if (!_pcb) {
    async_tcp_log_e("listen_pcb == NULL");
    return;
  }
  tcp_core_guard tcg;
  tcp_arg(_pcb, (void *)this);
  tcp_accept(_pcb, &AsyncTCP_detail::tcp_accept);
}

struct pending_pcb {
  tcp_pcb *pcb;
  pbuf *pb;
  uint16_t pb_len;  // total plaintext buffered in pb (chained); cap bounds heap used
  uint32_t parked_ms;  // ms this conn was parked waiting to be served
  struct pending_pcb *next;
};

// Unlinks `p` from the singly-linked tracked/queued list pointed to by
// *headptr, fixing the head, middle and tail cases. Safe for p == head and
// p anywhere in the chain.
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

// Frees a whole queued list's bookkeeping (pbufs + items) WITHOUT touching the
// pcbs — used by _error (lwIP already freed the errored pcb) and end().
static void free_queued_items(struct pending_pcb **list, volatile int *count) {
  while (*list) {
    struct pending_pcb *p = *list;
    *list = p->next;
    if (p->pb) {
      pbuf_free(p->pb);
    }
    (*count)--;
    free(p);
  }
}

// Sheds a whole queued list: nulls callbacks, aborts each pcb (RST) and frees
// bookkeeping. Used by the SETTLED arena flush.
static int abort_queued_items(struct pending_pcb **list, volatile int *count) {
  int n = 0;
  while (*list) {
    struct pending_pcb *p = *list;
    *list = p->next;
    tcp_pcb *spcb = p->pcb;
    if (p->pb) {
      pbuf_free(p->pb);
    }
    (*count)--;
    if (spcb) {
      tcp_arg(spcb, NULL);
      tcp_recv(spcb, NULL);
      tcp_poll(spcb, NULL, 0);
      tcp_err(spcb, NULL);
      tcp_abort(spcb);
    }
    free(p);
    n++;
  }
  return n;
}

void AsyncServer::end() {
  if (_pcb) {
    tcp_core_guard tcg;
    tcp_arg(_pcb, NULL);
    tcp_accept(_pcb, NULL);
    if (tcp_close(_pcb) != ERR_OK) {
      tcp_abort(_pcb);
    }
    _pcb = NULL;
  }
#if ASYNC_TCP_SSL_ENABLED && ASYNC_TCP_SSL_ENABLE_SERVER
  if (_ssl_ctx) {
    delete _ssl_ctx;
    _ssl_ctx = NULL;
    // Drain the queued lists (raw pcbs + possibly-buffered request pbufs)
    // to return their memory at teardown.
    free_queued_items(&_pending, &s_async_parked_tls);
    free_queued_items(&_held, &s_async_held_tls);
  }
#endif
}

// runs on LwIP thread
err_t AsyncTCP_detail::tcp_accept(void *arg, tcp_pcb *pcb, err_t err __attribute__((unused))) {
  if (!pcb) {
    async_tcp_log_e("_accept failed: pcb is NULL");
    return ERR_ABRT;
  }
  auto server = reinterpret_cast<AsyncServer *>(arg);
#if ASYNC_TCP_SSL_ENABLED
  if (server->_ssl_ctx) {
    return server->_accept(pcb, err);
  }
#endif
  if (server->_connect_cb) {
    AsyncClient *c = new (std::nothrow) AsyncClient(pcb);
    if (c && c->pcb()) {
      c->setNoDelay(server->_noDelay);

      lwip_tcp_event_packet_t *e = new (std::nothrow) lwip_tcp_event_packet_t{LWIP_TCP_ACCEPT, c};
      if (e) {
        e->accept.server = server;

        queue_mutex_guard guard;
        _prepend_async_event(e);
        return ERR_OK;  // success
      }

      // Couldn't allocate accept event
      // We can't let the client object call in to close, as we're on the LWIP thread; it could deadlock trying to RPC to itself
      c->_pcb = nullptr;
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

int8_t AsyncServer::_accepted(AsyncClient *client) {
  if (_connect_cb) {
    async_tcp_log_elapsed("onClient", _connect_cb(_connect_cb_arg, client));
  }
  return ERR_OK;
}

/*
 * Server-side TLS: accept admission, park/promote queue and slot driver.
 * Ported from ESP8266AsyncTCP (reference: ESP8266AsyncTCP.cpp:1157-1668).
 */

int8_t AsyncServer::_accept(tcp_pcb *pcb, int8_t err) {
  if (NULL == pcb || ERR_OK != err) {
    return ERR_OK;
  }
  if (_noDelay
#if ASYNC_TCP_SSL_ENABLED
      || _ssl_ctx
#endif
  ) {
    tcp_nagle_disable(pcb);
  } else {
    tcp_nagle_enable(pcb);
  }
#if ASYNC_TCP_SSL_ENABLED && ASYNC_TCP_SSL_ENABLE_SERVER
  if (_ssl_ctx) {
    if (!_connect_cb) {
      if (tcp_close(pcb) != ERR_OK) {
        tcp_abort(pcb);
      }
      return ERR_OK;
    }
    // Admission: ONE live TLS conn + staged park queue (PARKED_SLOTS) +
    // overflow hold queue (HOLD_LIMIT). While a conn is active, extra conns are
    // queued as raw pcbs (NO SSL buffers yet) and promoted FIFO the moment the
    // slot frees and heap clears the bar (free >= 9K && maxblock >= slab size),
    // so a conn never ctors into a churned arena mid-close. Queue slots are
    // shed after ASYNC_TCP_SSL_QUEUE_IDLE_MS if never promoted.
    if (tcp_ssl_client_count() > 0) {
      // Pressure-aware parking: while the live conn is serving, prefer the
      // staged park queue only when free heap >= floor (a staged slot pins
      // ~5.2KB of pbuf/ClientHello that a struggling live conn may need for its
      // next record). Under the floor, or when the park queue is full, the
      // conn falls to the overflow-hold tier instead of being RST'd — same
      // pool-only buffering, no heap, bounded by HOLD_LIMIT.
      struct pending_pcb *new_item = NULL;
      if (s_async_parked_tls < ASYNC_TCP_SSL_PARKED_SLOTS &&
          (unsigned)ESP.getFreeHeap() >= ASYNC_TCP_SSL_PRESSURE_PARK_FLOOR) {
        new_item = (struct pending_pcb *)malloc(sizeof(struct pending_pcb));
        if (new_item) {
          new_item->pcb = pcb;
          new_item->pb = NULL;
          new_item->pb_len = 0;
          new_item->parked_ms = millis();
          new_item->next = NULL;
          tcp_arg(pcb, this);
          tcp_poll(pcb, &_s_poll, 1);
          tcp_recv(pcb, &_s_recv);
          tcp_err(pcb, &_s_error);
          // Append at the tail so _promoteSlot lifts in arrival order (FIFO).
          if (!_pending) {
            _pending = new_item;
          } else {
            struct pending_pcb *tail = _pending;
            while (tail->next) {
              tail = tail->next;
            }
            tail->next = new_item;
          }
          s_async_parked_tls++;
          async_tcp_log_d("_accept: live conn, queued new conn (queued=%u/%d)", s_async_parked_tls, ASYNC_TCP_SSL_PARKED_SLOTS);
          return ERR_OK;
        }
      }
      // Wedged-staged or park full -> overflow-held tier: same buffering as a
      // park slot (pool pbufs only; no heap beyond the 24B pending_pcb) but
      // admitted even when free heap < floor, so a tight arena never RSTs a
      // newcomer. Costs only pooled pbufs — bounded by HOLD_LIMIT.
      if (!new_item && s_async_held_tls < ASYNC_TCP_SSL_HOLD_LIMIT) {
        new_item = (struct pending_pcb *)malloc(sizeof(struct pending_pcb));
        if (new_item) {
          new_item->pcb = pcb;
          new_item->pb = NULL;
          new_item->pb_len = 0;
          new_item->parked_ms = millis();
          new_item->next = NULL;
          tcp_arg(pcb, this);
          tcp_poll(pcb, &_s_poll, 1);
          tcp_recv(pcb, &_s_recv);
          tcp_err(pcb, &_s_error);
          if (!_held) {
            _held = new_item;
          } else {
            struct pending_pcb *tail = _held;
            while (tail->next) {
              tail = tail->next;
            }
            tail->next = new_item;
          }
          s_async_held_tls++;
          async_tcp_log_d("_accept: live conn, held overflow conn (held=%u/%d)", s_async_held_tls, ASYNC_TCP_SSL_HOLD_LIMIT);
          return ERR_OK;
        }
      }
      // Genuinely overloaded (staged+held both full) — RST; browser retry backs
      // off instead of instantly re-parking.
      async_tcp_log_d("_accept: queue busy (queued=%u/%d held=%u/%d), refusing TLS conn", s_async_parked_tls, ASYNC_TCP_SSL_PARKED_SLOTS, s_async_held_tls, ASYNC_TCP_SSL_HOLD_LIMIT);
      tcp_abort(pcb);
      return ERR_ABRT;
    }
    if ((unsigned)ESP.getFreeHeap() < ASYNC_TCP_SSL_PRESSURE_PARK_FLOOR ||
        (unsigned)ESP.getMaxFreeBlockSize() < ASYNC_TCP_SSL_SERVE_BLOCK) {
      // Serve gate, two checks:
      //  - free heap >= 9000: don't start a serve that runs the arena to its
      //    crash point mid-flight (1072B alloc fail at ~4.5K = exception 29).
      //  - maxblock >= slab (4506): the ctor needs one contiguous slab; a
      //    fragmented arena below this aborts the conn and that asset's
      //    retries keep missing -> intermittent "some .js not loading".
      // Slab-sized does NOT latch (the old 9000-contiguity gate did): after a
      // conn closes, its freed slab is reused in place, so the hole always
      // exists even fully fragmented. Never raise to slab+margin — that
      // deadlocks (freed in-place hole ~4190 < slab+margin forever).
      unsigned active = 0, tw = 0;
      tcp_ssl_pcb_pressure(&active, &tw);
      async_tcp_log_d("_accept: freeheap=%u maxblock=%u below serve floor, refusing TLS conn (active=%u tw=%u)", (unsigned)ESP.getFreeHeap(), (unsigned)ESP.getMaxFreeBlockSize(), active, tw);
      tcp_abort(pcb);
      return ERR_ABRT;
    }
    _serveTls(pcb);
    return ERR_OK;
  }
#endif
  // Plain fallback: AsyncTCP_detail::tcp_accept only routes here when
  // server->_ssl_ctx; direct callers can still use this path.
  if (!_connect_cb) {
    if (tcp_close(pcb) != ERR_OK) {
      tcp_abort(pcb);
    }
    return ERR_OK;
  }
  AsyncClient *c = new (std::nothrow) AsyncClient(pcb);
  if (c) {
    _connect_cb(_connect_cb_arg, c);
    return ERR_OK;
  }
  if (tcp_close(pcb) != ERR_OK) {
    tcp_abort(pcb);
    return ERR_ABRT;
  }
  return ERR_OK;
}

#if ASYNC_TCP_SSL_ENABLED && ASYNC_TCP_SSL_ENABLE_SERVER
AsyncClient *AsyncServer::_serveTls(tcp_pcb *pcb) {
  // Promote a raw pcb to a live TLS AsyncClient. The ctor allocates
  // ctx+buffers and registers the pcb, so ssl_count flips >0 inside. Returns
  // NULL (pcb closed) if allocation fails — browser simply retries.
  AsyncClient *c = new (std::nothrow) AsyncClient(pcb, _ssl_ctx);
  if (c) {
    s_live_serve_clients++;
    s_serve_conns_total++;
    if (!c->_pcb) {
      // Ctor could not init the TLS engine (heap allocation failed) and
      // already closed the pcb. Drop the empty shell — this both avoids a
      // crash (a live-looking client wired to a closed pcb) and stops a
      // per-conn RAM leak — and let the browser retry.
      async_tcp_log_d("_serveTls: AsyncClient TLS init failed, connection aborted!");
      delete c;
      return NULL;
    }
    tcp_nagle_disable(pcb);  // flush each small TLS record immediately
    async_tcp_log_d("_serveTls: SSL connected, freeheap=%u, ssl_count=%u", (unsigned)ESP.getFreeHeap(), (unsigned)tcp_ssl_client_count());
    c->onConnect([this](void *arg, AsyncClient *c) {
      (void)arg;
      _connect_cb(_connect_cb_arg, c);
    }, this);
    // Instant slot promote: when this live conn tears down (its TLS buffers
    // already freed), promote any queued conn right away instead of waiting
    // for the next _poll tick. AsyncClient::_close()/_error() fire
    // _server_discard_cb at teardown.
    c->_server_discard_cb = _s_conn_done;
    c->_server_discard_cb_arg = this;
    return c;
  }
  async_tcp_log_d("_serveTls: new AsyncClient() failed, connection aborted!");
  if (tcp_close(pcb) != ERR_OK) {
    tcp_abort(pcb);
  }
  return NULL;
}

int AsyncServer::_cert(const char *filename, uint8_t **buf) {
  if (_file_cb) {
    return _file_cb(_file_cb_arg, filename, buf);
  }
  *buf = 0;
  return 0;
}

int AsyncServer::_s_cert(void *arg, const char *filename, uint8_t **buf) {
  return reinterpret_cast<AsyncServer *>(arg)->_cert(filename, buf);
}

int8_t AsyncServer::_poll(tcp_pcb *pcb) {
  // Queue driver for the queued conns (staged park + overflow hold). Promotes
  // the head (staged FIFO first, then held) the moment the live conn is gone
  // and heap clears the bar; sheds any slot that sat queued past idle.
  struct pending_pcb *p = _pending;
  bool in_held = false;
  while (p && p->pcb != pcb) {
    p = p->next;
  }
  if (!p) {
    p = _held;
    in_held = true;
    while (p && p->pcb != pcb) {
      p = p->next;
    }
  }
  if (!p) {
    // Orphaned pcb: a peer-error on another slot cleared both queues, but
    // this pcb survived. Walked by our poll tick — close it so the tcp_pcb
    // isn't leaked (lwIP leaves callbacks set, so we must null them first).
    tcp_arg(pcb, NULL);
    tcp_recv(pcb, NULL);
    tcp_poll(pcb, NULL, 0);
    tcp_err(pcb, NULL);
    // RST (abort), not graceful close: this pcb never served a byte, and a
    // graceful close would park it in lwIP TIME_WAIT for 2*MSL with its pbuf
    // bank. Nothing queued to protect, so RST is correct.
    tcp_abort(pcb);
    return ERR_ABRT;
  }

  bool is_head = (in_held ? (p == _held) : (p == _pending));
  // Page-finished flush: a SETTLED drain (count hit 0) requested we shed the
  // whole queue so the arena coalesces before the next refresh burst. Queued
  // pcbs are retry-able (browser reconnects), so RST'ing them is safe.
  if (tcp_ssl_client_count() == 0 && s_shed_requested) {
    s_shed_requested = false;
    int shed = abort_queued_items(&_pending, &s_async_parked_tls) +
               abort_queued_items(&_held, &s_async_held_tls);
    async_tcp_log_d("_poll: shed %d queued (arena flush after page done), freeheap=%u, maxblock=%u",
                    shed, (unsigned)ESP.getFreeHeap(), (unsigned)ESP.getMaxFreeBlockSize());
    // Our pcb was in the drained set (every queued pcb is drained) — abort.
    return ERR_ABRT;
  }
  if (is_head && tcp_ssl_client_count() == 0) {
    return _promoteSlot();
  }

  // Slot queued past idle timeout -> live conn wedged; shed so pcb+pbufs
  // return to the heap and the browser retries on a fresh connection.
  if ((uint32_t)(millis() - p->parked_ms) < ASYNC_TCP_SSL_QUEUE_IDLE_MS) {
    return ERR_OK;
  }
  unlink_pending(in_held ? &_held : &_pending, p);
  if (in_held) {
    s_async_held_tls--;
  } else {
    s_async_parked_tls--;
  }
  async_tcp_log_d("_poll: shedding queued conn (held=%d, parked=%ums, freeheap=%u, maxblock=%u)", in_held ? 1 : 0, (unsigned)(millis() - p->parked_ms), (unsigned)ESP.getFreeHeap(), (unsigned)ESP.getMaxFreeBlockSize());
  if (p->pb) {
    pbuf_free(p->pb);
    p->pb = NULL;
  }
  tcp_arg(pcb, NULL);
  tcp_recv(pcb, NULL);
  tcp_poll(pcb, NULL, 0);
  tcp_err(pcb, NULL);
  free(p);
  // RST (abort) not graceful close — see orphan path above.
  tcp_abort(pcb);
  return ERR_ABRT;
}

int8_t AsyncServer::_recv(struct tcp_pcb *pcb, struct pbuf *pb, int8_t err) {
  (void)err;
  struct pending_pcb *p = _pending;
  while (p && p->pcb != pcb) {
    p = p->next;
  }
  if (!p) {
    if (pb) {
      pbuf_free(pb);
    }
    return ERR_OK;
  }

  if (!pb) {
    // Peer closed the queued connection before it was served — release it.
    // Null callbacks BEFORE aborting so tcp_abort's synchronous err callback
    // cannot re-enter _error() on this pcb and double-drain the queue.
    tcp_arg(pcb, NULL);
    tcp_recv(pcb, NULL);
    tcp_poll(pcb, NULL, 0);
    tcp_err(pcb, NULL);
    unlink_pending(&_pending, p);
    if (p->pb) {
      pbuf_free(p->pb);
    }
    s_async_parked_tls--;
    free(p);
    // RST (abort) not graceful close — peer is already gone.
    tcp_abort(pcb);
    return ERR_ABRT;
  } else {
    // Buffer request bytes; _poll feeds them to the promoted conn.
    // BROWSER-BURST CAP: a parked conn's inbound HTTP request must NOT be
    // bulk-buffered into system heap. We buffer only a small prefix
    // (ClientHello + request head) so a reason can resume it, and once the
    // cap is hit we STOP consuming: the pbuf is left in lwIP's recv window
    // (we don't tcp_recved it), so the bulk of the request parks in the
    // kernel on pooled pbufs, not heap.
    uint16_t inc = pb ? pb->tot_len : 0;
    if (p->pb_len + inc <= ASYNC_TCP_SSL_PARKED_RX_CAP) {
      if (p->pb) {
        pbuf_chain(p->pb, pb);
      } else {
        p->pb = pb;
      }
      p->pb_len += inc;
    } else {
      // Cap reached: hold this pbuf back in lwIP's window (do not free, do not
      // ack) so further bytes park in the kernel, not our heap.
      return ERR_OK;
    }
  }
  return ERR_OK;
}

void AsyncServer::_error(int8_t err) {
  (void)err;
  // Peer reset/errored a queued raw pcb before promotion; lwIP already freed
  // that pcb (tcp_err carries no pcb), so release only our bookkeeping.
  // With a multi-slot queue we can't tell WHICH pcb errored — clear both
  // queues. Any queued pcb that survived its peer's teardown is orphaned and
  // gets shed+closed by _poll on its next 1s tick, so nothing leaks.
  free_queued_items(&_pending, &s_async_parked_tls);
  free_queued_items(&_held, &s_async_held_tls);
}

int8_t AsyncServer::_promoteSlot() {
  // Lifts the queued raw PCB at the head to a live AsyncClient: staged park
  // slots first (their ClientHello is already buffered -> fastest handshake),
  // otherwise the held-overflow head. Runs whenever the live conn is gone
  // (TLS buffers freed, ssl_count==0) — either from _poll's tick or instantly
  // from _conn_done. No heap bar below the serving floor: _serveTls is
  // allocation-gated (nothrow fails cleanly, pcb aborted, retried), but a
  // serve burns several KB mid-flight, so below PRESSURE_PARK_FLOOR we keep
  // the slot queued and retry on the next tick — the arena recovers to its
  // floor after each conn frees its TLS buffers.
  if (tcp_ssl_client_count() != 0) {
    return ERR_OK;
  }
  struct pending_pcb **list = (s_async_parked_tls > 0) ? &_pending : &_held;
  if (!*list) {
    return ERR_OK;
  }
#if ASYNC_TCP_SSL_ENABLED && ASYNC_TCP_SSL_ENABLE_SERVER
  // Same serve gate as _accept: free heap >= 9000 AND maxblock >= slab.
  // Slab-sized doesn't latch (freed slabs reuse in place); raising it to 9000
  // or slab+margin deadlocks. Below it, keep queued, retry next tick.
  if ((unsigned)ESP.getFreeHeap() < ASYNC_TCP_SSL_PRESSURE_PARK_FLOOR ||
      (unsigned)ESP.getMaxFreeBlockSize() < ASYNC_TCP_SSL_SERVE_BLOCK) {
    async_tcp_log_d("_promoteSlot: freeheap=%u maxblock=%u below serve floor, keeping slot queued", (unsigned)ESP.getFreeHeap(), (unsigned)ESP.getMaxFreeBlockSize());
    return ERR_OK;
  }
#endif
  bool was_held = (list == &_held);
  struct pending_pcb *p = *list;
  tcp_pcb *pcb = p->pcb;
  *list = p->next;  // next queued conn slides into the head
  if (was_held) {
    s_async_held_tls--;
  } else {
    s_async_parked_tls--;
  }
  AsyncClient *c = _serveTls(pcb);
  err_t err = ERR_OK;
  if (c) {
    // Feed the request-header pbufs that arrived while queued straight into
    // the now-live client (ClientHello sits at the head) — staged and held
    // conns alike.
    if (p->pb) {
      c->_recv(pcb, p->pb, 0);
    }
  } else {
    if (p->pb) {
      pbuf_free(p->pb);
    }
  }
  free(p);
  return err;
}

void AsyncServer::_conn_done(AsyncClient *client) {
  (void)client;
  // Live conn tore down (its TLS buffers already freed) — promote the queued
  // conn immediately instead of waiting for the next _poll tick.
  _promoteSlot();
}

err_t AsyncServer::_s_poll(void *arg, struct tcp_pcb *pcb) {
  return reinterpret_cast<AsyncServer *>(arg)->_poll(pcb);
}

err_t AsyncServer::_s_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *pb, err_t err) {
  return reinterpret_cast<AsyncServer *>(arg)->_recv(pcb, pb, err);
}

void AsyncServer::_s_error(void *arg, err_t err) {
  if (!arg) {
    return;
  }
  reinterpret_cast<AsyncServer *>(arg)->_error(err);
}

void AsyncServer::_s_conn_done(void *arg, AsyncClient *client) {
  if (!arg) {
    return;
  }
  reinterpret_cast<AsyncServer *>(arg)->_conn_done(client);
}
#endif

void AsyncServer::setNoDelay(bool nodelay) {
  _noDelay = nodelay;
}

bool AsyncServer::getNoDelay() const {
  return _noDelay;
}

uint8_t AsyncServer::status() const {
  if (!_pcb) {
    return 0;
  }
  return _pcb->state;
}
// ===== end BearSSL/ESP8266 AsyncTCP.cpp =====
#else
// ===== begin mbedTLS/ESP32 AsyncTCP.cpp (AsyncTCP) =====
// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright 2016-2026 Hristo Gochkov, Mathieu Carbou, Emil Muratov, Will Miles

#include "AsyncTCP.h"
#include "AsyncTCPLogging.h"
#include "AsyncTCPSimpleIntrusiveList.h"

// The mbedTLS stack (ESP32/LibreTiny/IDF) always runs under FreeRTOS, so the
// async event dispatch must use the task path. 'FREERTOS' is not defined by
// the ESP32 Arduino core (nor by ESP8266/LibreTiny), so without this define
// the queue dispatcher below would fall through to the ESP8266-only
// schedule_function() branch and fail to compile on ESP32.
#ifndef FREERTOS
#define FREERTOS
#endif

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

#if CONFIG_ASYNC_TCP_USE_WDT
// Required for:
// https://github.com/espressif/arduino-esp32/blob/3.0.3/libraries/Network/src/NetworkInterface.cpp#L37-L47
#include "esp_task_wdt.h"
#define ASYNC_TCP_MAX_TASK_SLEEP (pdMS_TO_TICKS(1000 * CONFIG_ESP_TASK_WDT_TIMEOUT_S) / 4)
#else
#define ASYNC_TCP_MAX_TASK_SLEEP portMAX_DELAY
#endif

#define async_tcp_log_elapsed(tag, statement)                          \
  {                                                                    \
    [[maybe_unused]]                                                   \
    const uint32_t s_time = micros();                                  \
    statement;                                                         \
    async_tcp_log_v("%s took %" PRIu32 " us", tag, micros() - s_time); \
  }

// https://github.com/espressif/arduino-esp32/issues/10526
namespace {
#ifdef CONFIG_LWIP_TCPIP_CORE_LOCKING
struct tcp_core_guard {
  bool do_lock;
  inline tcp_core_guard() : do_lock(!sys_thread_tcpip(LWIP_CORE_LOCK_QUERY_HOLDER)) {
    if (do_lock) {
      LOCK_TCPIP_CORE();
    }
  }
  inline ~tcp_core_guard() {
    if (do_lock) {
      UNLOCK_TCPIP_CORE();
    }
  }
  tcp_core_guard(const tcp_core_guard &) = delete;
  tcp_core_guard(tcp_core_guard &&) = delete;
  tcp_core_guard &operator=(const tcp_core_guard &) = delete;
  tcp_core_guard &operator=(tcp_core_guard &&) = delete;
} __attribute__((unused));
#else   // CONFIG_LWIP_TCPIP_CORE_LOCKING
struct tcp_core_guard {
} __attribute__((unused));
#endif  // CONFIG_LWIP_TCPIP_CORE_LOCKING
}  // anonymous namespace

/*
  TCP poll interval is specified in terms of the TCP coarse timer interval, which is called twice a second
  https://github.com/espressif/esp-lwip/blob/2acf959a2bb559313cd2bf9306c24612ba3d0e19/src/core/tcp.c#L1895
*/
#ifndef CONFIG_ASYNC_TCP_POLL_TIMER
#define CONFIG_ASYNC_TCP_POLL_TIMER 1
#endif

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
  AsyncClient *client;
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
      AsyncServer *server;
    } accept;
    struct {
      const char *name;
      ip_addr_t addr;
    } dns;
  };

  inline lwip_tcp_event_packet_t(lwip_tcp_event_t _event, AsyncClient *_client) : next(nullptr), event(_event), client(_client){};
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

static void _free_event(lwip_tcp_event_packet_t *evpkt) {
  if ((evpkt->event == LWIP_TCP_RECV) && (evpkt->recv.pb != nullptr)) {
    pbuf_free(evpkt->recv.pb);
  }
  delete evpkt;
}


// Guard class for the global queue

#if defined(FREERTOS)
namespace {
static SemaphoreHandle_t _async_queue_mutex = nullptr;

class queue_mutex_guard {
  bool holds_mutex;

public:
  inline queue_mutex_guard() : holds_mutex(xSemaphoreTake(_async_queue_mutex, portMAX_DELAY)){};
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
    for (lwip_tcp_event_packet_t *next_pkt = _async_queue.begin(); next_pkt && (next_pkt->client == e->client) && (next_pkt->event == LWIP_TCP_POLL);
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

static size_t _remove_events_for_client(AsyncClient *client) {
  lwip_tcp_event_packet_t *removed_event_chain;
  {
    queue_mutex_guard guard;
    removed_event_chain = _async_queue.remove_if([=](lwip_tcp_event_packet_t &pkt) {
      return pkt.client == client;
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
  if (e->client == NULL) {
    // do nothing when arg is NULL
    // ets_printf("event arg == NULL: 0x%08x\n", e->recv.pcb);
  } else if (e->event == LWIP_TCP_RECV) {
    // ets_printf("-R: 0x%08x\n", e->recv.pcb);
    e->client->_recv(e->recv.pcb, e->recv.pb, e->recv.err);
    e->recv.pb = nullptr;  // given to client
  } else if (e->event == LWIP_TCP_FIN) {
    // ets_printf("-F: 0x%08x\n", e->fin.pcb);
    e->client->_fin(e->fin.pcb, e->fin.err);
  } else if (e->event == LWIP_TCP_SENT) {
    // ets_printf("-S: 0x%08x\n", e->sent.pcb);
    e->client->_sent(e->sent.pcb, e->sent.len);
  } else if (e->event == LWIP_TCP_POLL) {
    // ets_printf("-P: 0x%08x\n", e->poll.pcb);
    e->client->_poll(e->poll.pcb);
  } else if (e->event == LWIP_TCP_ERROR) {
    // ets_printf("-E: 0x%08x %d\n", e->client, e->error.err);
    e->client->_error(e->error.err);
  } else if (e->event == LWIP_TCP_CONNECTED) {
    // ets_printf("C: 0x%08x 0x%08x %d\n", e->client, e->connected.pcb, e->connected.err);
    e->client->_connected(e->connected.pcb, e->connected.err);
  } else if (e->event == LWIP_TCP_ACCEPT) {
    // ets_printf("A: 0x%08x 0x%08x\n", e->client, e->accept.client);
    e->accept.server->_accepted(e->client);
  } else if (e->event == LWIP_TCP_DNS) {
    // ets_printf("D: 0x%08x %s = %s\n", e->client, e->dns.name, ipaddr_ntoa(&e->dns.addr));
    e->client->_dns_found(&e->dns.addr);
  }
  _free_event(e);
}

#ifdef FREERTOS
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

static void _bind_tcp_callbacks(tcp_pcb *pcb, AsyncClient *client) {
  tcp_arg(pcb, client);
  tcp_recv(pcb, &AsyncTCP_detail::tcp_recv);
  tcp_sent(pcb, &AsyncTCP_detail::tcp_sent);
  tcp_err(pcb, &AsyncTCP_detail::tcp_error);
  tcp_poll(pcb, &AsyncTCP_detail::tcp_poll, CONFIG_ASYNC_TCP_POLL_TIMER);
}

static void _reset_tcp_callbacks(tcp_pcb *pcb, AsyncClient *client) {
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
  AsyncClient *client = reinterpret_cast<AsyncClient *>(arg);
  lwip_tcp_event_packet_t *e = new (std::nothrow) lwip_tcp_event_packet_t{LWIP_TCP_CONNECTED, client};
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
  AsyncClient *client = reinterpret_cast<AsyncClient *>(arg);
  lwip_tcp_event_packet_t *e = new (std::nothrow) lwip_tcp_event_packet_t{LWIP_TCP_POLL, client};
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
  AsyncClient *client = reinterpret_cast<AsyncClient *>(arg);
  lwip_tcp_event_packet_t *e = new (std::nothrow) lwip_tcp_event_packet_t{LWIP_TCP_RECV, client};
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
  AsyncClient *client = reinterpret_cast<AsyncClient *>(arg);
  lwip_tcp_event_packet_t *e = new (std::nothrow) lwip_tcp_event_packet_t{LWIP_TCP_SENT, client};
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
  AsyncClient *client = reinterpret_cast<AsyncClient *>(arg);
  if (client && client->_pcb) {
    // The pcb has already been freed by LwIP; do not attempt to clear the callbacks!
    _remove_events_for_client(client);
    client->_pcb = nullptr;
  }

  // enqueue event to be processed in the async task for the user callback
  lwip_tcp_event_packet_t *e = new (std::nothrow) lwip_tcp_event_packet_t{LWIP_TCP_ERROR, client};
  if (!e) {
    async_tcp_log_e("Failed to allocate event packet");
    return;
  }
  e->error.err = err;

  queue_mutex_guard guard;
  _send_async_event(e);
}

static void _tcp_dns_found(const char *name, ip_addr_t *ipaddr, void *arg) {
  // ets_printf("+DNS: name=%s ipaddr=0x%08x arg=%x\n", name, ipaddr, arg);
  auto client = reinterpret_cast<AsyncClient *>(arg);

  lwip_tcp_event_packet_t *e = new (std::nothrow) lwip_tcp_event_packet_t{LWIP_TCP_DNS, client};
  if (!e) {
    async_tcp_log_e("Failed to allocate event packet");
    return;
  }

  e->dns.name = name;
  if (ipaddr) {
    memcpy(&e->dns.addr, ipaddr, sizeof(ip_addr_t));
  } else {
    memset(&e->dns.addr, 0, sizeof(e->dns.addr));
  }

  queue_mutex_guard guard;
  _send_async_event(e);
}

/*
 * TCP/IP API Ccll wrappers
 *
 * Handles TCPIP core locking and ensures that the AsyncClient is not destroyed while the call is in progress.
 * */

#include "lwip/priv/tcpip_priv.h"

// If LwIP is configured with mutex support, wrap all calls with tcpip_api_call() to ensure that the LwIP core is locked during the call.
#ifndef NO_SYS
typedef struct {
  struct tcpip_api_call_data call;
  tcp_pcb **pcb;
  int8_t err;
  union {
    AsyncClient *close;
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

static esp_err_t _tcp_close(tcp_pcb **pcb, AsyncClient *client) {
  tcp_api_call_t msg;
  msg.pcb = pcb;
  msg.close = client;
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

static esp_err_t _tcp_abort(tcp_pcb **pcb, AsyncClient *client) {
  if (!pcb || !*pcb) {
    return ERR_CONN;
  }
  tcp_api_call_t msg;
  msg.pcb = pcb;
  msg.close = client;
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

static esp_err_t _tcp_close(tcp_pcb **pcb, AsyncClient *client) {
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

static esp_err_t _tcp_abort(tcp_pcb **pcb, AsyncClient *client) {
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

/*
  Async TCP Client
 */

AsyncClient::AsyncClient(tcp_pcb *pcb)
  : _connect_cb(0), _connect_cb_arg(0), _discard_cb(0), _discard_cb_arg(0), _sent_cb(0), _sent_cb_arg(0), _error_cb(0), _error_cb_arg(0), _recv_cb(0),
    _recv_cb_arg(0), _pb_cb(0), _pb_cb_arg(0), _timeout_cb(0), _timeout_cb_arg(0), _poll_cb(0), _poll_cb_arg(0), _ack_pcb(true), _tx_last_packet(0),
    _rx_timeout(0), _rx_last_ack(0), _ack_timeout(CONFIG_ASYNC_TCP_MAX_ACK_TIME), _connect_port(0) {
  _pcb = pcb;
#if ASYNC_TCP_SSL_ENABLED
  _ssl_ctx = 0;
  _ssl_handshake_done = false;
  _ssl_timeout = SSL_HANDSHAKE_TIMEOUT;
  _ssl_ca_cert = 0;
  _ssl_ca_cert_len = 0;
  _ssl_client_cert = 0;
  _ssl_client_cert_len = 0;
  _ssl_client_key = 0;
  _ssl_client_key_len = 0;
  _ssl_key_password = NULL;
  _ssl_pending_pbufs = NULL;
#endif
  if (_pcb) {
    _rx_last_packet = millis();
    _bind_tcp_callbacks(_pcb, this);
  }
}

AsyncClient::~AsyncClient() {
#if ASYNC_TCP_SSL_ENABLED
  if (_ssl_pending_pbufs) {
    pbuf_free(_ssl_pending_pbufs);
    _ssl_pending_pbufs = NULL;
  }
  if (_ssl_ctx) {
    delete _ssl_ctx;
    _ssl_ctx = 0;
  }
  if (_ssl_key_password) { ::free((void*)_ssl_key_password); _ssl_key_password = NULL; }
#endif
  if (_pcb) {
    _close();
  }
}

#if ASYNC_TCP_SSL_ENABLED
void AsyncClient::_clearSSLParams(void) {
  _ssl_host = "";
  _ssl_ca_cert = NULL;
  _ssl_ca_cert_len = 0;
  _ssl_client_cert = NULL;
  _ssl_client_cert_len = 0;
  _ssl_client_key = NULL;
  _ssl_client_key_len = 0;
  if (_ssl_key_password) { ::free((void*)_ssl_key_password); _ssl_key_password = NULL; }
}

bool AsyncClient::beginSecure(const char *host, uint16_t port, const char *rootCA,
    const char *clientCert, const char *clientKey, const char *keyPassword) {
  return beginSecure(host, port,
      (const unsigned char *)rootCA, (rootCA != NULL) ? strlen(rootCA) + 1 : 0,
      (const unsigned char *)clientCert, (clientCert != NULL) ? strlen(clientCert) + 1 : 0,
      (const unsigned char *)clientKey, (clientKey != NULL) ? strlen(clientKey) + 1 : 0,
      keyPassword);
}

bool AsyncClient::beginSecure(const char *host, uint16_t port,
    const unsigned char *rootCA, size_t rootCALen,
    const unsigned char *clientCert, size_t clientCertLen,
    const unsigned char *clientKey, size_t clientKeyLen,
    const char *keyPassword) {
  if (_ssl_ctx) {
    async_tcp_log_d("already have SSL context");
    return false;
  }
  // Store SSL parameters — handshake will run in _connected() after TCP completes
  _ssl_host = String(host);
  _ssl_ca_cert = rootCA;
  _ssl_ca_cert_len = rootCALen;
  _ssl_client_cert = clientCert;
  _ssl_client_cert_len = clientCertLen;
  _ssl_client_key = clientKey;
  _ssl_client_key_len = clientKeyLen;
  if (_ssl_key_password) { ::free((void*)_ssl_key_password); _ssl_key_password = NULL; }
  _ssl_key_password = keyPassword ? strdup(keyPassword) : NULL;
  return connect(host, port);
}

void AsyncClient::feedSSLRxData(const unsigned char *data, size_t len) {
  if (_ssl_ctx) {
    _ssl_ctx->feedRxData(data, len);
  }
}

bool AsyncClient::hasSSLRxData() const {
  if (_ssl_ctx) {
    return _ssl_ctx->hasRxData();
  }
  return false;
}

int AsyncClient::sslRead(uint8_t *data, size_t len) {
  if (_ssl_ctx) {
    return _ssl_ctx->sslRead(data, len);
  }
  return -1;
}

int AsyncClient::sslWrite(const uint8_t *data, size_t len) {
  if (_ssl_ctx) {
    return _ssl_ctx->write(data, len);
  }
  return -1;
}

int AsyncClient::runSSLHandshake() {
  if (_ssl_ctx) {
    return _ssl_ctx->runSSLHandshake();
  }
  return -1;
}
#endif

/*
 * Operators
 * */

bool AsyncClient::operator==(const AsyncClient &other) const {
  return _pcb == other._pcb;
}

/*
 * Callback Setters
 * */

void AsyncClient::onConnect(AcConnectHandler cb, void *arg) {
  _connect_cb = cb;
  _connect_cb_arg = arg;
}

void AsyncClient::onDisconnect(AcConnectHandler cb, void *arg) {
  _discard_cb = cb;
  _discard_cb_arg = arg;
}

void AsyncClient::onAck(AcAckHandler cb, void *arg) {
  _sent_cb = cb;
  _sent_cb_arg = arg;
}

void AsyncClient::onError(AcErrorHandler cb, void *arg) {
  _error_cb = cb;
  _error_cb_arg = arg;
}

void AsyncClient::onData(AcDataHandler cb, void *arg) {
  _recv_cb = cb;
  _recv_cb_arg = arg;
}

void AsyncClient::onPacket(AcPacketHandler cb, void *arg) {
  _pb_cb = cb;
  _pb_cb_arg = arg;
}

void AsyncClient::onTimeout(AcTimeoutHandler cb, void *arg) {
  _timeout_cb = cb;
  _timeout_cb_arg = arg;
}

void AsyncClient::onPoll(AcConnectHandler cb, void *arg) {
  _poll_cb = cb;
  _poll_cb_arg = arg;
}

/*
 * Main Public Methods
 * */

bool AsyncClient::connect(ip_addr_t addr, uint16_t port) {
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
  return err == ESP_OK;
}

#ifdef ARDUINO
bool AsyncClient::connect(const IPAddress &ip, uint16_t port) {
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
bool AsyncClient::connect(const IPv6Address &ip, uint16_t port) {
  auto ipaddr = static_cast<const uint32_t *>(ip);
  ip_addr_t addr = IPADDR6_INIT(ipaddr[0], ipaddr[1], ipaddr[2], ipaddr[3]);

  return connect(addr, port);
}
#endif

bool AsyncClient::connect(const char *host, uint16_t port) {
  ip_addr_t addr;

  if (!_start_async_task()) {
    async_tcp_log_e("failed to start task");
    return false;
  }

  err_t err;
  {
    tcp_core_guard tcg;
    err = dns_gethostbyname(host, &addr, (dns_found_callback)&_tcp_dns_found, this);
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

void AsyncClient::close() {
  if (_pcb) {
    _tcp_recved(&_pcb, _rx_ack_len);
  }
  _close();
}

int8_t AsyncClient::abort() {
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

size_t AsyncClient::space() const {
  if ((_pcb != NULL) && (_pcb->state == ESTABLISHED)) {
    return tcp_sndbuf(_pcb);
  }
  return 0;
}

size_t AsyncClient::add(const char *data, size_t size, uint8_t apiflags) {
  if (!_pcb || size == 0 || data == NULL) {
    return 0;
  }
#if ASYNC_TCP_SSL_ENABLED
  if (_ssl_ctx && _ssl_handshake_done) {
    // SSL: encrypt via mbedtls, which calls BIO send -> tcp_write
    int ret = _ssl_ctx->write((const uint8_t *)data, size);
    if (ret > 0) {
      return (size_t)ret;
    }
    return 0;
  }
#endif
  size_t room = space();
  if (!room) {
    return 0;
  }
  size_t will_send = (room < size) ? room : size;
  int8_t err = ERR_OK;
  err = _tcp_write(&_pcb, data, will_send, apiflags);
  if (err != ERR_OK) {
    return 0;
  }
  return will_send;
}

bool AsyncClient::send() {
  auto backup = _tx_last_packet;
  _tx_last_packet = millis();
  if (_tcp_output(&_pcb) == ERR_OK) {
    return true;
  }
  _tx_last_packet = backup;
  return false;
}

size_t AsyncClient::ack(size_t len) {
  if (len > _rx_ack_len) {
    len = _rx_ack_len;
  }
  if (len) {
    _tcp_recved(&_pcb, len);
  }
  _rx_ack_len -= len;
  return len;
}

void AsyncClient::ackPacket(struct pbuf *pb) {
  if (!pb) {
    return;
  }
  _tcp_recved(&_pcb, pb->len);
  pbuf_free(pb);
}

/*
 * Main Private Methods
 * */

int8_t AsyncClient::_close() {
  // ets_printf("X: 0x%08x\n", (uint32_t)this);
  int8_t err = _tcp_close(&_pcb, this);
  // _pcb is now NULL
  if ((err == ERR_OK) && _discard_cb) {
    // _pcb was closed here
    async_tcp_log_elapsed("onDisconnect", _discard_cb(_discard_cb_arg, this));
  }
  return err;
}

/*
 * Private Callbacks
 * */

int8_t AsyncClient::_connected(tcp_pcb *pcb, int8_t err __attribute__((unused))) {
  _pcb = reinterpret_cast<tcp_pcb *>(pcb);
  if (_pcb) {
    _rx_last_packet = millis();
  }
  _tx_last_packet = 0;
  _rx_last_ack = 0;

#if ASYNC_TCP_SSL_ENABLED
  if (_ssl_host.length() > 0 && !_ssl_ctx) {
    // Create SSL context and start handshake
    _ssl_ctx = new (std::nothrow) AsyncTCPTLS();
    if (!_ssl_ctx) {
      async_tcp_log_e("failed to allocate SSL context");
      if (_error_cb) {
        _error_cb(_error_cb_arg, this, -60);
      }
      if (_discard_cb) {
        _discard_cb(_discard_cb_arg, this);
      }
      return ERR_ABRT;
    }
    int ret;
    if (_ssl_ca_cert == NULL) {
      ret = _ssl_ctx->startSSLClientInsecure(_pcb, _ssl_host.c_str());
    } else {
      ret = _ssl_ctx->startSSLClient(_pcb, _ssl_host.c_str(),
          _ssl_ca_cert, _ssl_ca_cert_len,
          _ssl_client_cert, _ssl_client_cert_len,
          _ssl_client_key, _ssl_client_key_len,
          _ssl_key_password);
    }
    if (ret != 0) {
      async_tcp_log_e("startSSLClient failed: %d", ret);
      delete _ssl_ctx;
      _ssl_ctx = 0;
      _clearSSLParams();
      if (_error_cb) {
        _error_cb(_error_cb_arg, this, -60);
      }
      if (_discard_cb) {
        _discard_cb(_discard_cb_arg, this);
      }
      return ERR_ABRT;
    }
  }

  if (_ssl_ctx) {
    int ret = _ssl_ctx->runSSLHandshake();
    if (ret != 0) {
      if (ret < 0 && ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
        async_tcp_log_e("SSL handshake failed: %d", ret);
        _ssl_ctx->logBioState("handshake_poll");
        _clearSSLParams();
        if (_error_cb) {
          _error_cb(_error_cb_arg, this, -60);
        }
        if (_discard_cb) {
          _discard_cb(_discard_cb_arg, this);
        }
        return ERR_ABRT;
      }
    } else {
      _ssl_handshake_done = true;
      async_tcp_log_d("SSL handshake completed (from _connected)");
    }
  }
#endif

  if (_connect_cb) {
    async_tcp_log_elapsed("onConnect", _connect_cb(_connect_cb_arg, this));
  }
  return ERR_OK;
}

void AsyncClient::_error(int8_t err) {
  if (_error_cb) {
    async_tcp_log_elapsed("onError", _error_cb(_error_cb_arg, this, err));
  }
  if (_discard_cb) {
    async_tcp_log_elapsed("onDisconnect", _discard_cb(_discard_cb_arg, this));
  }
}

// In LwIP Thread
int8_t AsyncClient::_lwip_fin(tcp_pcb *pcb, int8_t err __attribute__((unused))) {
  if (!_pcb || pcb != _pcb) {
    async_tcp_log_d("0x%08" PRIx32 " != 0x%08" PRIx32, (uint32_t)pcb, (uint32_t)_pcb);
    return ERR_OK;
  }
  _reset_tcp_callbacks(_pcb, this);
  if (tcp_close(_pcb) != ERR_OK) {
    tcp_abort(_pcb);
  }
  _pcb = NULL;
  return ERR_OK;
}

// In Async Thread
int8_t AsyncClient::_fin(tcp_pcb *pcb __attribute__((unused)), int8_t err __attribute__((unused))) {
  close();
  return ERR_OK;
}

int8_t AsyncClient::_sent(tcp_pcb *pcb __attribute__((unused)), uint16_t len) {
  _rx_last_ack = _rx_last_packet = millis();
  if (_sent_cb) {
    async_tcp_log_elapsed("onAck", _sent_cb(_sent_cb_arg, this, len, (_rx_last_packet - _tx_last_packet)));
  }
  return ERR_OK;
}

int8_t AsyncClient::_recv(tcp_pcb *pcb __attribute__((unused)), pbuf *pb, int8_t err __attribute__((unused))) {
#if ASYNC_TCP_SSL_ENABLED
  if (_ssl_ctx && !_ssl_handshake_done) {
    // During handshake: buffer encrypted data, ack full pbuf size to TCP
    // (LwIP requires exact ack — pbufs already removed from receive queue)
    size_t total_recved = 0;
    while (pb != NULL) {
      _rx_last_packet = millis();
      if (!_ssl_ctx->feedRxData((const unsigned char *)pb->payload, pb->len)) {
        // BIO buffer full — hold remaining pbufs without acking
        // LwIP backpressures naturally via TCP window
        if (_ssl_pending_pbufs) {
          pbuf_chain(_ssl_pending_pbufs, pb);
        } else {
          _ssl_pending_pbufs = pb;
        }
        break;
      }
      pbuf *b = pb;
      pb = b->next;
      b->next = NULL;
      total_recved += b->len;
      pbuf_free(b);
    }
    if (total_recved > 0 && _pcb) {
      _tcp_recved(&_pcb, total_recved);
    }
    // Try to continue handshake
    int ret = _ssl_ctx->runSSLHandshake();
    if (ret == 0) {
      _ssl_handshake_done = true;
      async_tcp_log_d("SSL handshake completed (from _recv)");
      if (_connect_cb) {
        async_tcp_log_elapsed("onConnect", _connect_cb(_connect_cb_arg, this));
      }
    } else if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
      // Still in progress, wait for more data
    } else {
      async_tcp_log_e("SSL handshake failed in _recv: %d", ret);
      _ssl_ctx->logBioState("handshake");
      _clearSSLParams();
      if (_error_cb) {
        _error_cb(_error_cb_arg, this, -60);
      }
      if (_discard_cb) {
        _discard_cb(_discard_cb_arg, this);
      }
    }
    return ERR_OK;
  }

  if (_ssl_ctx && _ssl_handshake_done) {
    // SSL established: buffer encrypted data, ack full pbuf size to TCP
    size_t total_recved = 0;
    while (pb != NULL) {
      _rx_last_packet = millis();
      if (!_ssl_ctx->feedRxData((const unsigned char *)pb->payload, pb->len)) {
        // BIO buffer full — hold remaining pbufs without acking
        if (_ssl_pending_pbufs) {
          pbuf_chain(_ssl_pending_pbufs, pb);
        } else {
          _ssl_pending_pbufs = pb;
        }
        break;
      }
      pbuf *b = pb;
      pb = b->next;
      b->next = NULL;
      total_recved += b->len;
      pbuf_free(b);
    }
    if (total_recved > 0 && _pcb) {
      _tcp_recved(&_pcb, total_recved);
    }
    // Drain decrypted plaintext from mbedTLS
    uint8_t buf[1024];
    int n;
    while ((n = _ssl_ctx->sslRead(buf, sizeof(buf))) > 0) {
      if (_recv_cb) {
        async_tcp_log_elapsed("onData", _recv_cb(_recv_cb_arg, this, (char *)buf, n));
      }
    }
    return ERR_OK;
  }
#endif
  while (pb != NULL) {
    _rx_last_packet = millis();
    // we should not ack before we assimilate the data
    _ack_pcb = true;
    pbuf *b = pb;
    pb = b->next;
    b->next = NULL;
    if (_pb_cb) {
      async_tcp_log_elapsed("onPacket", _pb_cb(_pb_cb_arg, this, b));
    } else {
      if (_recv_cb) {
        async_tcp_log_elapsed("onData", _recv_cb(_recv_cb_arg, this, b->payload, b->len));
      }
      if (!_ack_pcb) {
        _rx_ack_len += b->len;
      } else if (_pcb) {
        _tcp_recved(&_pcb, b->len);
      }
      pbuf_free(b);
    }
  }
  return ERR_OK;
}

int8_t AsyncClient::_poll(tcp_pcb *pcb) {
  if (!_pcb) {
    // async_tcp_log_d("pcb is NULL");
    return ERR_OK;
  }
  if (pcb != _pcb) {
    async_tcp_log_d("0x%08" PRIx32 " != 0x%08" PRIx32, (uint32_t)pcb, (uint32_t)_pcb);
    return ERR_OK;
  }

  uint32_t now = millis();
#if ASYNC_TCP_SSL_ENABLED
  if (_ssl_ctx && !_ssl_handshake_done) {
    if ((now - _rx_last_packet) > _ssl_timeout) {
      async_tcp_log_e("SSL handshake timeout");
      if (_error_cb) {
        _error_cb(_error_cb_arg, this, -61);
      }
      _close();
      return ERR_OK;
    }
    int ret = _ssl_ctx->runSSLHandshake();
    if (ret == 0) {
      _ssl_handshake_done = true;
      async_tcp_log_d("SSL handshake completed (from _poll)");
      if (_connect_cb) {
        async_tcp_log_elapsed("onConnect", _connect_cb(_connect_cb_arg, this));
      }
    } else if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
      async_tcp_log_e("SSL handshake failed in _poll: %d", ret);
      if (_error_cb) {
        _error_cb(_error_cb_arg, this, -60);
      }
      _close();
    }
    return ERR_OK;
  }

  // Process pending SSL pbufs — drain BIO buffer first to make room
  if (_ssl_pending_pbufs && _ssl_ctx && _ssl_handshake_done) {
    uint8_t buf[1024];
    int n;
    while ((n = _ssl_ctx->sslRead(buf, sizeof(buf))) > 0) {
      if (_recv_cb) {
        async_tcp_log_elapsed("onData", _recv_cb(_recv_cb_arg, this, (char *)buf, n));
      }
    }
    // Try to feed held pbufs now that BIO buffer has drained
    pbuf *pb = _ssl_pending_pbufs;
    _ssl_pending_pbufs = NULL;
    size_t total_recved = 0;
    while (pb != NULL) {
      _rx_last_packet = millis();
      if (!_ssl_ctx->feedRxData((const unsigned char *)pb->payload, pb->len)) {
        if (_ssl_pending_pbufs) {
          pbuf_chain(_ssl_pending_pbufs, pb);
        } else {
          _ssl_pending_pbufs = pb;
        }
        break;
      }
      pbuf *b = pb;
      pb = b->next;
      b->next = NULL;
      total_recved += b->len;
      pbuf_free(b);
    }
    if (total_recved > 0 && _pcb) {
      _tcp_recved(&_pcb, total_recved);
    }
    // Drain decrypted plaintext again after feeding held pbufs
    while ((n = _ssl_ctx->sslRead(buf, sizeof(buf))) > 0) {
      if (_recv_cb) {
        async_tcp_log_elapsed("onData", _recv_cb(_recv_cb_arg, this, (char *)buf, n));
      }
    }
    return ERR_OK;
  }
#endif



  // ACK Timeout
  if (_ack_timeout) {
    const uint32_t one_day = 86400000;
    bool last_tx_is_after_last_ack = (_rx_last_ack - _tx_last_packet + one_day) < one_day;
    if (last_tx_is_after_last_ack && (now - _tx_last_packet) >= _ack_timeout) {
      async_tcp_log_d("ack timeout %d", pcb->state);
      if (_timeout_cb) {
        async_tcp_log_elapsed("onTimeout", _timeout_cb(_timeout_cb_arg, this, (now - _tx_last_packet)));
      }
      return ERR_OK;
    }
  }
  // RX Timeout
  if (_rx_timeout && (now - _rx_last_packet) >= (_rx_timeout * 1000)) {
    async_tcp_log_d("rx timeout %d", pcb->state);
    _close();
    return ERR_OK;
  }
  // Everything is fine
  if (_poll_cb) {
    async_tcp_log_elapsed("onPoll", _poll_cb(_poll_cb_arg, this));
  }
  return ERR_OK;
}

void AsyncClient::_dns_found(ip_addr_t *ipaddr) {
  if (ipaddr) {
    connect(*ipaddr, _connect_port);
  } else {
    if (_error_cb) {
      async_tcp_log_elapsed("onError", _error_cb(_error_cb_arg, this, -55));
    }
    if (_discard_cb) {
      async_tcp_log_elapsed("onDisconnect", _discard_cb(_discard_cb_arg, this));
    }
  }
}

/*
 * Public Helper Methods
 * */

bool AsyncClient::free() {
  if (!_pcb) {
    return true;
  }
  if (_pcb->state == CLOSED || _pcb->state > ESTABLISHED) {
    return true;
  }
  return false;
}

size_t AsyncClient::write(const char *data, size_t size, uint8_t apiflags) {
  size_t will_send = add(data, size, apiflags);
  if (!will_send || !send()) {
    return 0;
  }
  return will_send;
}

void AsyncClient::setRxTimeout(uint32_t timeout) {
  _rx_timeout = timeout;
}

uint32_t AsyncClient::getRxTimeout() const {
  return _rx_timeout;
}

uint32_t AsyncClient::getAckTimeout() const {
  return _ack_timeout;
}

void AsyncClient::setAckTimeout(uint32_t timeout) {
  _ack_timeout = timeout;
}

void AsyncClient::setNoDelay(bool nodelay) const {
  if (!_pcb) {
    return;
  }
  if (nodelay) {
    tcp_nagle_disable(_pcb);
  } else {
    tcp_nagle_enable(_pcb);
  }
}

bool AsyncClient::getNoDelay() {
  if (!_pcb) {
    return false;
  }
  return tcp_nagle_disabled(_pcb);
}

void AsyncClient::setKeepAlive(uint32_t ms, uint8_t cnt) {
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

uint16_t AsyncClient::getMss() const {
  if (!_pcb) {
    return 0;
  }
  return tcp_mss(_pcb);
}

uint32_t AsyncClient::getRemoteAddress() const {
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
ip6_addr_t AsyncClient::getRemoteAddress6() const {
  if (_pcb && _pcb->remote_ip.type == IPADDR_TYPE_V6) {
    return _pcb->remote_ip.u_addr.ip6;
  } else {
    ip6_addr_t nulladdr;
    ip6_addr_set_zero(&nulladdr);
    return nulladdr;
  }
}

ip6_addr_t AsyncClient::getLocalAddress6() const {
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
IPv6Address AsyncClient::remoteIP6() const {
  return IPv6Address(getRemoteAddress6().addr);
}

IPv6Address AsyncClient::localIP6() const {
  return IPv6Address(getLocalAddress6().addr);
}
#else
IPAddress AsyncClient::remoteIP6() const {
  if (!_pcb) {
    return IPAddress(IPType::IPv6);
  }
  IPAddress ip;
  ip.from_ip_addr_t(&(_pcb->remote_ip));
  return ip;
}

IPAddress AsyncClient::localIP6() const {
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

uint16_t AsyncClient::getRemotePort() const {
  if (!_pcb) {
    return 0;
  }
  return _pcb->remote_port;
}

uint32_t AsyncClient::getLocalAddress() const {
  if (!_pcb) {
    return 0;
  }
#if LWIP_IPV4 && LWIP_IPV6
  return _pcb->local_ip.u_addr.ip4.addr;
#else
  return _pcb->local_ip.addr;
#endif
}

uint16_t AsyncClient::getLocalPort() const {
  if (!_pcb) {
    return 0;
  }
  return _pcb->local_port;
}

ip4_addr_t AsyncClient::getRemoteAddress4() const {
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

ip4_addr_t AsyncClient::getLocalAddress4() const {
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
IPAddress AsyncClient::remoteIP() const {
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

IPAddress AsyncClient::localIP() const {
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

uint8_t AsyncClient::state() const {
  if (!_pcb) {
    return 0;
  }
  return _pcb->state;
}

bool AsyncClient::connected() const {
  if (!_pcb) {
    return false;
  }
  return _pcb->state == ESTABLISHED;
}

bool AsyncClient::connecting() const {
  if (!_pcb) {
    return false;
  }
  return _pcb->state > CLOSED && _pcb->state < ESTABLISHED;
}

bool AsyncClient::disconnecting() const {
  if (!_pcb) {
    return false;
  }
  return _pcb->state > ESTABLISHED && _pcb->state < TIME_WAIT;
}

bool AsyncClient::disconnected() const {
  if (!_pcb) {
    return true;
  }
  return _pcb->state == CLOSED || _pcb->state == TIME_WAIT;
}

bool AsyncClient::freeable() const {
  if (!_pcb) {
    return true;
  }
  return _pcb->state == CLOSED || _pcb->state > ESTABLISHED;
}

bool AsyncClient::canSend() const {
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
    case ERR_ALREADY:    return "Already connected";
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

const char *AsyncClient::stateToString() const {
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

AsyncServer::AsyncServer(ip_addr_t addr, uint16_t port)
  : _port(port), _addr(addr), _noDelay(false), _pcb(nullptr), _connect_cb(nullptr), _connect_cb_arg(nullptr)
#if ASYNC_TCP_SSL_ENABLED
    , _use_ssl(false), _cert(nullptr), _cert_len(0), _key(nullptr), _key_len(0), _ssl_file_cb(nullptr), _ssl_file_cb_arg(nullptr), _ssl_key_password(nullptr)
#endif
    {}

#ifdef ARDUINO
AsyncServer::AsyncServer(IPAddress addr, uint16_t port) : _port(port), _noDelay(false), _pcb(0), _connect_cb(0), _connect_cb_arg(0)
#if ASYNC_TCP_SSL_ENABLED
  , _use_ssl(false), _cert(0), _cert_len(0), _key(0), _key_len(0), _ssl_file_cb(0), _ssl_file_cb_arg(0), _ssl_key_password(0)
#endif
{
#if ESP_IDF_VERSION_MAJOR < 5
#if LWIP_IPV4 && LWIP_IPV6
  _addr.type = IPADDR_TYPE_V4;
  _addr.u_addr.ip4.addr = addr;
#else
  _addr.addr = addr;
#endif
#else
  addr.to_ip_addr_t(&_addr);
#endif
}
#if ESP_IDF_VERSION_MAJOR < 5 && __has_include(<IPv6Address.h>) && LWIP_IPV6
AsyncServer::AsyncServer(IPv6Address addr, uint16_t port) : _port(port), _noDelay(false), _pcb(0), _connect_cb(0), _connect_cb_arg(0)
#if ASYNC_TCP_SSL_ENABLED
  , _use_ssl(false), _cert(0), _cert_len(0), _key(0), _key_len(0), _ssl_file_cb(0), _ssl_file_cb_arg(0), _ssl_key_password(0)
#endif
{
#if LWIP_IPV4 && LWIP_IPV6
  _addr.type = IPADDR_TYPE_V6;
#endif
  auto ipaddr = static_cast<const uint32_t *>(addr);
  _addr = IPADDR6_INIT(ipaddr[0], ipaddr[1], ipaddr[2], ipaddr[3]);
}
#endif
#endif

AsyncServer::AsyncServer(uint16_t port) : _port(port), _noDelay(false), _pcb(0), _connect_cb(0), _connect_cb_arg(0)
#if ASYNC_TCP_SSL_ENABLED
  , _use_ssl(false), _cert(0), _cert_len(0), _key(0), _key_len(0), _ssl_file_cb(0), _ssl_file_cb_arg(0), _ssl_key_password(0)
#endif
{
#if LWIP_IPV4 && LWIP_IPV6
  _addr.type = IPADDR_TYPE_ANY;
  _addr.u_addr.ip4.addr = INADDR_ANY;
#else
  _addr.addr = INADDR_ANY;
#endif
}

AsyncServer::~AsyncServer() {
  end();
}

void AsyncServer::onClient(AcConnectHandler cb, void *arg) {
  _connect_cb = cb;
  _connect_cb_arg = arg;
}

void AsyncServer::begin() {
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
  _pcb = _tcp_listen_with_backlog(_pcb, backlog);
  if (!_pcb) {
    async_tcp_log_e("listen_pcb == NULL");
    return;
  }
  tcp_core_guard tcg;
  tcp_arg(_pcb, (void *)this);
  tcp_accept(_pcb, &AsyncTCP_detail::tcp_accept);
}

void AsyncServer::end() {
  if (_pcb) {
    tcp_core_guard tcg;
    tcp_arg(_pcb, NULL);
    tcp_accept(_pcb, NULL);
    if (tcp_close(_pcb) != ERR_OK) {
      tcp_abort(_pcb);
    }
    _pcb = NULL;
  }
}

// runs on LwIP thread
err_t AsyncTCP_detail::tcp_accept(void *arg, tcp_pcb *pcb, err_t err __attribute__((unused))) {
  if (!pcb) {
    async_tcp_log_e("_accept failed: pcb is NULL");
    return ERR_ABRT;
  }
  auto server = reinterpret_cast<AsyncServer *>(arg);
  if (server->_connect_cb) {
    AsyncClient *c = new (std::nothrow) AsyncClient(pcb);
    if (c && c->pcb()) {
      c->setNoDelay(server->_noDelay);

      lwip_tcp_event_packet_t *e = new (std::nothrow) lwip_tcp_event_packet_t{LWIP_TCP_ACCEPT, c};
      if (e) {
        e->accept.server = server;

        queue_mutex_guard guard;
        _prepend_async_event(e);
        return ERR_OK;  // success
      }

      // Couldn't allocate accept event
      // We can't let the client object call in to close, as we're on the LWIP thread; it could deadlock trying to RPC to itself
      c->_pcb = nullptr;
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

int8_t AsyncServer::_accepted(AsyncClient *client) {
#if ASYNC_TCP_SSL_ENABLED
  if (_use_ssl && _cert && _key && client && client->pcb()) {
    if (AsyncTCPTLS::getActiveCount() >= SSL_MAX_CONNECTIONS) {
      async_tcp_log_e("SSL connection limit reached (%d/%d)", AsyncTCPTLS::getActiveCount(), SSL_MAX_CONNECTIONS);
      client->abort();
      delete client;
      return ERR_ABRT;
    }
    if (ESP.getFreeHeap() < 10000) {
      async_tcp_log_e("SSL rejected: low heap (%u bytes)", ESP.getFreeHeap());
      client->abort();
      delete client;
      return ERR_ABRT;
    }
    AsyncTCPTLS *ssl = new (std::nothrow) AsyncTCPTLS();
    if (ssl) {
      int ret = ssl->startSSLServer(client->pcb(), _cert, _cert_len, _key, _key_len, _ssl_key_password);
      if (ret == 0) {
        client->_ssl_ctx = ssl;
        async_tcp_log_d("Server SSL context ready, handshake will start on first poll");
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
  if (_connect_cb) {
    async_tcp_log_elapsed("onClient", _connect_cb(_connect_cb_arg, client));
  }
  return ERR_OK;
}

#if ASYNC_TCP_SSL_ENABLED
bool AsyncServer::beginSecure(const unsigned char *cert, size_t certLen,
    const unsigned char *key, size_t keyLen) {
  if (cert == NULL || key == NULL) {
    async_tcp_log_e("SSL cert or key is NULL");
    return false;
  }
  _cert = cert;
  _cert_len = certLen;
  _key = key;
  _key_len = keyLen;
  _use_ssl = true;
  begin();
  return _pcb != NULL;
}

bool AsyncServer::beginSecure(const char *certPEM, const char *keyPEM) {
  return beginSecure(
      (const unsigned char *)certPEM, certPEM ? strlen(certPEM) + 1 : 0,
      (const unsigned char *)keyPEM, keyPEM ? strlen(keyPEM) + 1 : 0);
}

bool AsyncServer::beginSecure(const char *certPEM, const char *keyPEM, const char *password) {
  _ssl_key_password = password;
  return beginSecure(certPEM, keyPEM);
}

void AsyncServer::setDefaultCertificate(const unsigned char *cert, size_t certLen) {
  _cert = cert;
  _cert_len = certLen;
}

void AsyncServer::setDefaultKey(const unsigned char *key, size_t keyLen) {
  _key = key;
  _key_len = keyLen;
}

void AsyncServer::setDefaultCertificatePEM(const char *certPEM) {
  _cert = (const unsigned char *)certPEM;
  _cert_len = certPEM ? strlen(certPEM) + 1 : 0;
}

void AsyncServer::setDefaultKeyPEM(const char *keyPEM) {
  _key = (const unsigned char *)keyPEM;
  _key_len = keyPEM ? strlen(keyPEM) + 1 : 0;
}

void AsyncServer::onSslFileRequest(AcSSlFileHandler cb, void *arg) {
  _ssl_file_cb = cb;
  _ssl_file_cb_arg = arg;
}
#endif

void AsyncServer::setNoDelay(bool nodelay) {
  _noDelay = nodelay;
}

bool AsyncServer::getNoDelay() const {
  return _noDelay;
}

uint8_t AsyncServer::status() const {
  if (!_pcb) {
    return 0;
  }
  return _pcb->state;
}
// ===== end mbedTLS/ESP32 AsyncTCP.cpp =====
#endif
