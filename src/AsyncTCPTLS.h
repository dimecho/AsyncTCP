#pragma once

#if ASYNC_TCP_SSL_ENABLED

#include "mbedtls/platform.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/pem.h"
#include "mbedtls/sha256.h"
#include "mbedtls/oid.h"

struct tcp_pcb;

#define ASYNCTCP_TLS_CAN_RETRY(r)   (((r) == MBEDTLS_ERR_SSL_WANT_READ) || ((r) == MBEDTLS_ERR_SSL_WANT_WRITE))
#define ASYNCTCP_TLS_EOF(r)         (((r) == MBEDTLS_ERR_SSL_CONN_EOF) || ((r) == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY))

#define ASYNCTCP_TLS_RX_BUF_SIZE    4096
#define ASYNCTCP_TLS_TX_BUF_SIZE    4096

class AsyncTCPTLS
{
private:
    mbedtls_ssl_context ssl_ctx;
    mbedtls_ssl_config ssl_conf;
    mbedtls_ctr_drbg_context drbg_ctx;
    mbedtls_entropy_context entropy_ctx;

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
    size_t _ssl_rx_buf_len;
    size_t _ssl_rx_pos;
    size_t _ssl_rx_total;  // total bytes buffered, for tcp_recved()

    unsigned char *_ssl_tx_buf;
    size_t _ssl_tx_buf_len;
    size_t _ssl_tx_pos;

    bool _output_pending;  // tcp_write queued, tcp_output deferred

    int _startSSLClient(tcp_pcb *pcb, const char *host_or_ip,
        const unsigned char *rootCABuff, const size_t rootCABuff_len,
        const unsigned char *cli_cert, const size_t cli_cert_len,
        const unsigned char *cli_key, const size_t cli_key_len,
        const char *pskIdent, const char *psKey,
        bool insecure);

    void _deleteHandshakeCerts(void);
    static void _clear_DER_cache(void);

public:
    AsyncTCPTLS(void);
    virtual ~AsyncTCPTLS();

    // Feed encrypted data from TCP into BIO buffer
    void feedRxData(const unsigned char *data, size_t len);

    // Flush BIO tx buffer to TCP (returns bytes flushed, 0 if nothing to flush)
    size_t flushTxData(void);

    // Check if BIO has buffered rx data available
    bool hasRxData(void) const { return _ssl_rx_buf && (_ssl_rx_pos < _ssl_rx_buf_len); }

    // Public accessor for PCB (needed by BIO callbacks)
    tcp_pcb *pcb() const { return _pcb; }
    void setOutputPending(bool v) { _output_pending = v; }

    int startSSLClientInsecure(tcp_pcb *pcb, const char *host_or_ip);

    int startSSLClient(tcp_pcb *pcb, const char *host_or_ip,
        const char *pskIdent, const char *psKey);

    int startSSLClient(tcp_pcb *pcb, const char *host_or_ip,
        const char *rootCABuff,
        const char *cli_cert,
        const char *cli_key);

    int startSSLClient(tcp_pcb *pcb, const char *host_or_ip,
        const unsigned char *rootCABuff, const size_t rootCABuff_len,
        const unsigned char *cli_cert, const size_t cli_cert_len,
        const unsigned char *cli_key, const size_t cli_key_len);

    int startSSLServer(tcp_pcb *pcb,
        const unsigned char *server_cert, size_t server_cert_len,
        const unsigned char *server_key, size_t server_key_len,
        const char *password = NULL);

    int runSSLHandshake(void);

    int write(const uint8_t *data, size_t len);

    int read(uint8_t *data, size_t len);

    // Decrypt application data via mbedtls_ssl_read (BIO pulls encrypted bytes internally)
    int sslRead(uint8_t *data, size_t len);

    // Flush deferred tcp_output (called after mbedtls_ssl_handshake/write/read completes)
    void flushOutput(void);
};

#endif // ASYNC_TCP_SSL_ENABLED
