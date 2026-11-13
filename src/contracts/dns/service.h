#ifndef SOLARIS_DNS_SERVICE_H
#define SOLARIS_DNS_SERVICE_H

#include "contracts/dns/cache.h"
#include "contracts/dns/exchange.h"
#include "contracts/dns/hosts.h"

#define SOLARIS_DNS_ROLE_COUNT 5u
#define SOLARIS_DNS_MAX_UPSTREAMS 16u
typedef struct solaris_dns_service solaris_dns_service_t;
typedef struct solaris_dns_resolver_view solaris_dns_resolver_view_t;
typedef struct solaris_dns_binding solaris_dns_binding_t;
typedef struct solaris_dns_request solaris_dns_request_t;
typedef struct solaris_dns_upstream {
    uint64_t id;
    solaris_address_t address; /* Numeric, nonzero port. */
    uint32_t transport; /* SOLARIS_DNS_TRANSPORT_UDP or TCP. */
} solaris_dns_upstream_t;
typedef struct solaris_dns_role_options {
    uint64_t policy_id, upstream_set_id;
    const solaris_dns_upstream_t *upstreams;
    size_t upstream_count;
} solaris_dns_role_options_t;
typedef struct solaris_dns_resolver_view_options {
    uint64_t resolver_revision, network_revision;
    const solaris_hosts_t *hosts;
    uint32_t wire_use_hosts, ipv6, prefer_ipv6, ipv6_wait_ms;
    uint64_t query_timeout_ms;
    uint32_t allow_stale, allow_system_lookup;
    /* allow_system_lookup defaults to 0. Only the address adapter may use OS
     * resolution after a hosts miss with no explicit upstream. Never for wire
     * queries, and never enabled by strict TUN configuration. */
    /* Index is lookup.h role - 1. An empty role has no network upstream.
     * First version uses ordered transport-error failover. A DNS response,
     * including negative/error RCODE, is not transport failover. No DoH/DoT,
     * implicit public DNS, proxy policy, parallel racing or fallback filtering.
     * Set/list/order changes require a new resolver revision. */
    solaris_dns_role_options_t role[SOLARIS_DNS_ROLE_COUNT];
} solaris_dns_resolver_view_options_t;
void solaris_dns_resolver_view_options_init(solaris_dns_resolver_view_options_t *options);
/* Pure, bounded construction; copies upstream arrays and retains hosts. No
 * I/O or executor affinity. View references may cross owner boundaries. */
solaris_status_t solaris_dns_resolver_view_create(solaris_budget_t *budget,
    const solaris_dns_resolver_view_options_t *options, solaris_dns_resolver_view_t **out);
void solaris_dns_resolver_view_retain(const solaris_dns_resolver_view_t *view);
void solaris_dns_resolver_view_release(const solaris_dns_resolver_view_t *view);

typedef struct solaris_dns_service_options {
    solaris_executor_t *owner; /* First implementation: engine worker 0. */
    solaris_budget_t *budget;
    solaris_scope_t *parent_scope; /* Optional same-owner rejected-create fence. */
    uint64_t initial_network_revision;
    size_t inflight_limit, waiter_limit, waiters_per_query;
    solaris_dns_cache_options_t cache;
    solaris_dialer_options_t dialer;
    /* Optional paired thread-safe hooks for dialer.policy_context. Retained
     * through service I/O close, not through inert external binding lifetime.
     * Other borrowed dialer contexts must likewise outlive on_close. */
    void (*policy_context_retain)(void *context);
    void (*policy_context_release)(void *context);
    void *context;
    void (*on_close)(void *context);
} solaris_dns_service_options_t;
void solaris_dns_service_options_init(solaris_dns_service_options_t *options);
/* Owner-only activation. Rejection sets *out=NULL with no on_close; the parent
 * scope fences any already-created asynchronous cleanup. Successful close
 * waits for transports, refreshes, requester callbacks and their final ACKs.
 * Engine stop also closes the service. External refs keep only an inert handle
 * after on_close; they never delay I/O close or executor quiescence. */
solaris_status_t solaris_dns_service_create(const solaris_dns_service_options_t *options,
    solaris_dns_service_t **out);
void solaris_dns_service_retain(solaris_dns_service_t *service);
void solaris_dns_service_release(solaris_dns_service_t *service);
solaris_status_t solaris_dns_service_close(solaris_dns_service_t *service);
/* Owner-only, strictly increasing nonzero physical-network revision. Revokes
 * old-network groups/cache/results, including success queued to another owner. */
solaris_status_t solaris_dns_service_invalidate_network(solaris_dns_service_t *service,
    uint64_t network_revision);

/* Inert thread-safe binding; no I/O. Pins service handle + immutable view.
 * Request view resolver/network revisions must match this binding; config and
 * selection revisions come from the flow's captured publication. */
solaris_status_t solaris_dns_binding_create(solaris_dns_service_t *service,
    const solaris_dns_resolver_view_t *view, solaris_dns_binding_t **out);
void solaris_dns_binding_retain(solaris_dns_binding_t *binding);
void solaris_dns_binding_release(solaris_dns_binding_t *binding);
solaris_dns_lookup_t solaris_dns_binding_lookup(solaris_dns_binding_t *binding);

enum { SOLARIS_DNS_SOURCE_HOSTS = 1, SOLARIS_DNS_SOURCE_CACHE = 2, SOLARIS_DNS_SOURCE_UPSTREAM = 3 };
typedef struct solaris_dns_service_result {
    solaris_status_t status;
    const solaris_dns_wire_t *response; /* Borrowed until done returns; retainable. */
    solaris_dns_lookup_view_t view;
    uint64_t upstream_id;
    uint32_t source, stale;
} solaris_dns_service_result_t;
typedef void (*solaris_dns_service_fn)(void *context, solaris_dns_request_t *request,
    const solaris_dns_service_result_t *result);
typedef struct solaris_dns_query_options {
    solaris_executor_t *owner; /* Requesting owner, same non-NULL engine context. */
    solaris_scope_t *parent_scope; /* Optional same-owner request/cleanup fence. */
    solaris_dns_lookup_view_t view;
    uint64_t deadline_ns;
    uint32_t address_lookup; /* Internal lookup adapter: hosts always enabled. */
} solaris_dns_query_options_t;
/* Caller-owner start/cancel. Query retained on acceptance, never consumed.
 * Deadline is absolute in the shared engine monotonic domain. Same-owner hits
 * are also deferred. Acceptance guarantees exactly one done, including cancel;
 * rejection has no callback. Request expires when done returns. A cancelled
 * waiter cannot cancel peers; the last waiter cancels/drains its exchange.
 * Data admission is bounded. Preallocated result/cancel/ACK nodes remain usable
 * after ordinary executor admission closes. No callbacks under service lock.
 * Wire use-hosts is view-controlled; address lookup always consults hosts.
 * Binary/opaque upstream replies may be forwarded unchanged in layout. Hosts
 * alias rewriting that requires relocating opaque RDATA is explicitly ENOTSUP.
 * No implicit Fake-IP/DoH support is exposed by this initial service. */
solaris_status_t solaris_dns_service_query(solaris_dns_binding_t *binding,
    const solaris_dns_query_options_t *options, const solaris_dns_wire_t *query,
    solaris_dns_service_fn done, void *context, solaris_dns_request_t **out);
solaris_status_t solaris_dns_request_cancel(solaris_dns_request_t *request);

#endif
