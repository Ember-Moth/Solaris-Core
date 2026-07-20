#ifndef ANYTLS_TLS_UV_H
#define ANYTLS_TLS_UV_H

#include <stddef.h>
#include <stdint.h>

#include <uv.h>

#include "aproxy/dns.h"
#include "aproxy/reality.h"
#include "aproxy/socket_protect.h"
#include "aproxy/tls.h"

typedef struct anytls_tls_client anytls_tls_client_t;

typedef void (*anytls_tls_ready_cb)(anytls_tls_client_t *tls,
                                    int status,
                                    void *user_data);

typedef void (*anytls_tls_data_cb)(anytls_tls_client_t *tls,
                                   const uint8_t *data,
                                   size_t len,
                                   void *user_data);

typedef void (*anytls_tls_close_cb)(anytls_tls_client_t *tls,
                                    int status,
                                    void *user_data);

typedef struct anytls_tls_client_config {
    uv_loop_t *loop;
    const char *host;
    const char *port;
    const char *sni;
    /* Borrowed; it must outlive this TLS client and pending resolution. */
    aproxy_dns_resolver_t *resolver;
    /* Optional shared context; retained by the TLS client. */
    aproxy_tls_context_t *context;
    /* Comma-separated ALPN protocols, in preference order. */
    const char *alpn;
    aproxy_ech_config_t ech;
    /* Zeroed means ordinary TLS. Copied into SSL during construction. */
    aproxy_reality_config_t reality;
    /* Zero selects APROXY_DEFAULT_STREAM_PENDING_BYTES. */
    size_t max_pending_bytes;
    aproxy_socket_protector_t socket_protector;
    int insecure_skip_verify;
    anytls_tls_ready_cb on_ready;
    anytls_tls_data_cb on_data;
    anytls_tls_close_cb on_close;
    void *user_data;
} anytls_tls_client_config_t;

int anytls_tls_client_new(const anytls_tls_client_config_t *config,
                          anytls_tls_client_t **out);

void anytls_tls_client_free(anytls_tls_client_t *tls);

int anytls_tls_client_connect(anytls_tls_client_t *tls);

int anytls_tls_client_write(anytls_tls_client_t *tls,
                            const uint8_t *data,
                            size_t len);

/* Queues bytes directly on the TCP stream after earlier TLS records. */
int anytls_tls_client_write_raw(anytls_tls_client_t *tls,
                                const uint8_t *data,
                                size_t len);

/* Switches only the receive direction from TLS records to raw TCP bytes. */
int anytls_tls_client_enable_raw_read(anytls_tls_client_t *tls);

int anytls_tls_client_alpn_is(const anytls_tls_client_t *tls,
                              const char *protocol);

void anytls_tls_client_close(anytls_tls_client_t *tls);

#endif
