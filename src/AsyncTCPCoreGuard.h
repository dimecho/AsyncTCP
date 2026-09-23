// SPDX-License-Identifier: LGPL-3.0-or-later
//
// Internal: RAII guard for the lwIP core lock (CONFIG_LWIP_TCPIP_CORE_LOCKING).
// Shared by the TUs that need to serialize pcb access against the LwIP task
// (AsyncSecureServer). MUST be included after the stack's lwIP headers.
#pragma once

extern "C" {
#include "lwip/opt.h"
#include "lwip/tcp.h"
#include "lwip/tcpip.h"
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
