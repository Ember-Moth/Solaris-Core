#ifndef APROXY_DIRECT_OUTBOUND_H
#define APROXY_DIRECT_OUTBOUND_H

#include <stddef.h>

#include <uv.h>

#include "aproxy/dns.h"
#include "aproxy/outbound.h"
#include "aproxy/socket_protect.h"

typedef struct aproxy_direct_outbound_config {
    uv_loop_t *loop;
    const char *tag;
    aproxy_dns_resolver_t *resolver;
    size_t read_buffer_size;
    size_t max_pending_bytes;
    aproxy_socket_protector_t socket_protector;
} aproxy_direct_outbound_config_t;

int aproxy_direct_outbound_new(const aproxy_direct_outbound_config_t *config,
                               aproxy_outbound_t **out);

#endif
