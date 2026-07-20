#ifndef ANYTLS_CLIENT_H
#define ANYTLS_CLIENT_H

#include <stddef.h>
#include <stdint.h>

#include <uv.h>

#include "anytls/error.h"
#include "anytls/padding.h"
#include "anytls/socksaddr.h"
#include "aproxy/dns.h"
#include "aproxy/reality.h"
#include "aproxy/socket_protect.h"
#include "aproxy/tls.h"

typedef struct anytls_client anytls_client_t;
typedef struct anytls_stream anytls_stream_t;

typedef void (*anytls_client_ready_cb)(anytls_client_t *client,
                                       int status,
                                       void *user_data);

typedef void (*anytls_client_close_cb)(anytls_client_t *client,
                                       int status,
                                       void *user_data);

typedef void (*anytls_stream_data_cb)(anytls_stream_t *stream,
                                      const uint8_t *data,
                                      size_t len,
                                      void *user_data);

typedef void (*anytls_stream_event_cb)(anytls_stream_t *stream,
                                       int status,
                                       void *user_data);

typedef struct anytls_client_config {
    uv_loop_t *loop;
    const char *server_host;
    const char *server_port;
    const char *sni;
    const char *password;
    /* Comma-separated ALPN protocols, in preference order. */
    const char *alpn;
    aproxy_ech_config_t ech;
    int insecure_skip_verify;
    aproxy_reality_config_t reality;
    /* Borrowed; it must outlive this client. */
    aproxy_dns_resolver_t *resolver;
    /* Optional shared context; retained by the client. */
    aproxy_tls_context_t *tls_context;
    /*
     * Star-Node/sing-anytls compatible active heartbeat knobs.
     * interval == 0 uses the protocol default, interval < 0 disables active
     * heartbeat, timeout <= 0 uses the protocol default.
     */
    int64_t heartbeat_interval_ms;
    int64_t heartbeat_timeout_ms;
    size_t max_pending_bytes;
    aproxy_socket_protector_t socket_protector;
    anytls_padding_store_t *padding_store;
    anytls_client_ready_cb on_ready;
    anytls_client_close_cb on_close;
    void *user_data;
} anytls_client_config_t;

int anytls_client_new(const anytls_client_config_t *config,
                      anytls_client_t **out);

void anytls_client_free(anytls_client_t *client);

int anytls_client_connect(anytls_client_t *client);

void anytls_client_close(anytls_client_t *client);

int anytls_client_open_stream(anytls_client_t *client,
                              const anytls_socksaddr_t *destination,
                              anytls_stream_data_cb on_data,
                              anytls_stream_event_cb on_open,
                              anytls_stream_event_cb on_close,
                              void *user_data,
                              anytls_stream_t **out);

int anytls_stream_write(anytls_stream_t *stream,
                        const uint8_t *data,
                        size_t len);

int anytls_stream_close(anytls_stream_t *stream);

uint32_t anytls_stream_id(const anytls_stream_t *stream);

#endif
