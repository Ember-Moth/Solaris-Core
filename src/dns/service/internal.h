#ifndef SOLARIS_DNS_SERVICE_INTERNAL_H
#define SOLARIS_DNS_SERVICE_INTERNAL_H
#include "contracts/dns/service.h"
#include <stdatomic.h>

struct solaris_dns_resolver_view {
    atomic_size_t references;
    solaris_dns_resolver_view_options_t options;
    solaris_dns_upstream_t upstreams[SOLARIS_DNS_ROLE_COUNT][SOLARIS_DNS_MAX_UPSTREAMS];
};
struct solaris_dns_binding {
    atomic_size_t references;
    solaris_dns_service_t *service;
    const solaris_dns_resolver_view_t *view;
};
solaris_budget_t *solaris_dns_service_budget(solaris_dns_service_t *service);
/* Tracks an entire address lookup (including requester-local OS cleanup) in
 * the service's shutdown barrier. Finish after its user callback returns. */
solaris_status_t solaris_dns_activity_start(solaris_dns_binding_t *binding,
    const solaris_dns_query_options_t *options, void (*cancel)(void *, solaris_status_t),
    void *context, solaris_dns_request_t **out);
solaris_status_t solaris_dns_activity_status(solaris_dns_request_t *request);
void solaris_dns_activity_finish(solaris_dns_request_t *request);
solaris_status_t solaris_dns_lookup_start(void *context, solaris_executor_t *owner,
    const solaris_dns_lookup_view_t *view, const solaris_address_t *target,
    uint64_t deadline_ns, solaris_resolve_fn callback, void *user, void **request);
void solaris_dns_lookup_cancel(void *context, void *request);
#endif
