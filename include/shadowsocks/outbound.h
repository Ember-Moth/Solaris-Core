#ifndef SHADOWSOCKS_OUTBOUND_H
#define SHADOWSOCKS_OUTBOUND_H

#include <stddef.h>
#include <stdint.h>

#include <uv.h>

#include "aproxy/dns.h"
#include "aproxy/outbound.h"
#include "aproxy/socket_protect.h"

typedef struct shadowsocks_outbound_config {
    uv_loop_t *loop;
    const char *tag;
    const char *server_host;
    const char *server_port;
    const char *method;
    const char *password;
    aproxy_dns_resolver_t *resolver;
    size_t read_buffer_size;
    size_t max_pending_bytes;
    /* Native UDP by default; UoT version zero selects version 2. */
    aproxy_outbound_udp_transport_t udp_transport;
    uint8_t uot_version;
    aproxy_socket_protector_t socket_protector;
} shadowsocks_outbound_config_t;

int shadowsocks_outbound_new(const shadowsocks_outbound_config_t *config,
                             aproxy_outbound_t **out);

#endif
