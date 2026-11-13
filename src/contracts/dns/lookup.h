#ifndef SOLARIS_DNS_LOOKUP_H
#define SOLARIS_DNS_LOOKUP_H

#include "dns/system/resolver.h"

enum {
    SOLARIS_DNS_ROUTE_TARGET = 1,
    SOLARIS_DNS_DIRECT_TARGET = 2,
    SOLARIS_DNS_PROXY_SERVER = 3,
    SOLARIS_DNS_BOOTSTRAP = 4,
    SOLARIS_DNS_CLIENT_QUERY = 5
};
typedef struct solaris_dns_lookup_view {
    uint32_t role;
    uint64_t config_revision, resolver_revision, network_revision, selection_revision;
} solaris_dns_lookup_view_t;

/* Immutable hooks, copied by callers. Context outlives all accepted requests.
 * Start/cancel run on the requesting owner; callbacks return there, deferred
 * exactly once including cancellation. Rejection owns nothing and leaves
 * request NULL. The request expires on callback return; cancel does not omit
 * that callback. Addresses are borrowed, numeric, and bounded by
 * SOLARIS_RESOLVER_MAX_ADDRESSES. The absolute deadline covers the full dial.
 * NETWORK_CHANGED/CANCELLED/CLOSED/ACCESS are terminal, not cache misses. */
typedef struct solaris_dns_lookup {
    void *context;
    solaris_status_t (*start)(void *context, solaris_executor_t *owner,
        const solaris_dns_lookup_view_t *view, const solaris_address_t *target,
        uint64_t deadline_ns, solaris_resolve_fn callback, void *user, void **request);
    void (*cancel)(void *context, void *request);
} solaris_dns_lookup_t;

static inline int solaris_dns_lookup_terminal(solaris_status_t status)
{
    return status == SOLARIS_ECANCELLED || status == SOLARIS_ECLOSED ||
           status == SOLARIS_EACCESS || status == SOLARIS_ENETWORK_CHANGED;
}
#endif
