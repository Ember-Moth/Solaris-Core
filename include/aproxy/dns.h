#ifndef APROXY_DNS_H
#define APROXY_DNS_H

#include <stddef.h>
#include <stdint.h>

#include <uv.h>

#include "aproxy/address.h"
#include "aproxy/error.h"

typedef struct aproxy_dns_resolver aproxy_dns_resolver_t;

#define APROXY_DNS_DEFAULT_MAX_PENDING_REQUESTS 1024u
#define APROXY_DNS_DEFAULT_MAX_WAITERS_PER_REQUEST 256u

/* addresses is only valid for the duration of the callback. */
typedef void (*aproxy_dns_result_cb)(aproxy_dns_resolver_t *resolver,
                                     int status,
                                     const aproxy_addr_t *addresses,
                                     size_t count,
                                     void *user_data);

typedef struct aproxy_dns_libuv_config {
    uv_loop_t *loop;
    size_t max_cache_entries;
    uint64_t cache_ttl_ms;
    uint64_t negative_cache_ttl_ms;
    /* Zero selects APROXY_DNS_DEFAULT_MAX_PENDING_REQUESTS. */
    size_t max_pending_requests;
    /* Zero selects APROXY_DNS_DEFAULT_MAX_WAITERS_PER_REQUEST. */
    size_t max_waiters_per_request;
} aproxy_dns_libuv_config_t;

typedef struct aproxy_dns_resolver_vtable {
    int (*resolve)(void *impl,
                   const char *host,
                   uint16_t port,
                   aproxy_dns_result_cb cb,
                   void *user_data);
    void (*free)(void *impl);
} aproxy_dns_resolver_vtable_t;

struct aproxy_dns_resolver {
    const aproxy_dns_resolver_vtable_t *vtable;
    void *impl;
};

int aproxy_dns_resolve(aproxy_dns_resolver_t *resolver,
                       const char *host,
                       uint16_t port,
                       aproxy_dns_result_cb cb,
                       void *user_data);

int aproxy_dns_resolver_new_libuv(const aproxy_dns_libuv_config_t *config,
                                  aproxy_dns_resolver_t **out);

void aproxy_dns_resolver_free(aproxy_dns_resolver_t *resolver);

#endif
