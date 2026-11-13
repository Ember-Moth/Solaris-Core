#include "dns/service/internal.h"
#include <string.h>

void solaris_dns_resolver_view_options_init(solaris_dns_resolver_view_options_t *o)
{
    if (!o) return;
    memset(o, 0, sizeof(*o)); o->wire_use_hosts = 1u; o->ipv6_wait_ms = 100u;
    o->query_timeout_ms = 5000u; o->allow_stale = 1u;
}
solaris_status_t solaris_dns_resolver_view_create(solaris_budget_t *budget,
    const solaris_dns_resolver_view_options_t *o, solaris_dns_resolver_view_t **out)
{
    if (!out) return SOLARIS_EINVAL;
    *out = NULL;
    if (!budget || !o || !o->resolver_revision || !o->network_revision ||
        o->wire_use_hosts > 1u || o->ipv6 > 1u || o->prefer_ipv6 > 1u || o->allow_stale > 1u || o->allow_system_lookup > 1u ||
        o->ipv6_wait_ms > 60000u || !o->query_timeout_ms || o->query_timeout_ms > 3600000u) return SOLARIS_EINVAL;
    for (size_t r = 0; r < SOLARIS_DNS_ROLE_COUNT; r++) {
        const solaris_dns_role_options_t *role = &o->role[r];
        if (role->upstream_count > SOLARIS_DNS_MAX_UPSTREAMS ||
            (role->upstream_count && (!role->upstreams || !role->upstream_set_id))) return SOLARIS_EINVAL;
        for (size_t i = 0; i < role->upstream_count; i++) {
            const solaris_dns_upstream_t *u = &role->upstreams[i];
            if (!u->id || !u->address.port || u->address.host[0] ||
                (u->address.family != SOLARIS_ADDRESS_IPV4 && u->address.family != SOLARIS_ADDRESS_IPV6) ||
                (u->transport != SOLARIS_DNS_TRANSPORT_UDP && u->transport != SOLARIS_DNS_TRANSPORT_TCP)) return SOLARIS_EINVAL;
            for (size_t j = 0; j < i; j++) if (role->upstreams[j].id == u->id) return SOLARIS_EINVAL;
        }
    }
    solaris_dns_resolver_view_t *v = solaris_memory_allocate(budget, sizeof(*v));
    if (!v) return SOLARIS_ENOMEM;
    memset(v, 0, sizeof(*v)); atomic_init(&v->references, 1u); v->options = *o;
    if (o->hosts) solaris_hosts_retain(o->hosts);
    for (size_t r = 0; r < SOLARIS_DNS_ROLE_COUNT; r++) {
        if (o->role[r].upstream_count) memcpy(v->upstreams[r], o->role[r].upstreams,
            o->role[r].upstream_count * sizeof(*v->upstreams[r]));
        v->options.role[r].upstreams = v->upstreams[r];
    }
    *out = v; return SOLARIS_OK;
}
void solaris_dns_resolver_view_retain(const solaris_dns_resolver_view_t *v)
{ if (v) (void)atomic_fetch_add_explicit(&((solaris_dns_resolver_view_t *)v)->references, 1u, memory_order_relaxed); }
void solaris_dns_resolver_view_release(const solaris_dns_resolver_view_t *v)
{
    if (v && atomic_fetch_sub_explicit(&((solaris_dns_resolver_view_t *)v)->references, 1u, memory_order_acq_rel) == 1u) {
        solaris_hosts_release(v->options.hosts); solaris_memory_free((void *)v);
    }
}
solaris_status_t solaris_dns_binding_create(solaris_dns_service_t *service,
    const solaris_dns_resolver_view_t *view, solaris_dns_binding_t **out)
{
    if (!out) return SOLARIS_EINVAL;
    *out = NULL;
    if (!service || !view) return SOLARIS_EINVAL;
    solaris_dns_binding_t *b = solaris_memory_allocate(solaris_dns_service_budget(service), sizeof(*b));
    if (!b) return SOLARIS_ENOMEM;
    atomic_init(&b->references, 1u); b->service = service; b->view = view;
    solaris_dns_service_retain(service); solaris_dns_resolver_view_retain(view); *out = b; return SOLARIS_OK;
}
void solaris_dns_binding_retain(solaris_dns_binding_t *b)
{ if (b) (void)atomic_fetch_add_explicit(&b->references, 1u, memory_order_relaxed); }
void solaris_dns_binding_release(solaris_dns_binding_t *b)
{
    if (b && atomic_fetch_sub_explicit(&b->references, 1u, memory_order_acq_rel) == 1u) {
        solaris_dns_resolver_view_release(b->view); solaris_dns_service_release(b->service); solaris_memory_free(b);
    }
}
solaris_dns_lookup_t solaris_dns_binding_lookup(solaris_dns_binding_t *b)
{ return (solaris_dns_lookup_t){b, solaris_dns_lookup_start, solaris_dns_lookup_cancel}; }
