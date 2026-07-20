#ifndef VLESS_OUTBOUND_H
#define VLESS_OUTBOUND_H

#include <stddef.h>

#include <uv.h>

#include "aproxy/dns.h"
#include "aproxy/outbound.h"
#include "aproxy/reality.h"
#include "aproxy/socket_protect.h"
#include "aproxy/xhttp.h"

typedef struct vless_outbound_config {
    uv_loop_t *loop;
    const char *tag;
    const char *server_host;
    const char *server_port;
    const char *uuid;
    const char *flow;
    const char *encryption;
    int tls_enabled;
    const char *sni;
    /* Raw TCP only. XHTTP enforces the ALPN required by its HTTP version. */
    const char *alpn;
    aproxy_ech_config_t ech;
    int insecure_skip_verify;
    aproxy_reality_config_t reality;
    aproxy_dns_resolver_t *resolver;
    size_t read_buffer_size;
    size_t max_pending_bytes;
    const aproxy_xhttp_config_t *xhttp;
    aproxy_socket_protector_t socket_protector;
} vless_outbound_config_t;

int vless_outbound_new(const vless_outbound_config_t *config,
                       aproxy_outbound_t **out);

#endif
