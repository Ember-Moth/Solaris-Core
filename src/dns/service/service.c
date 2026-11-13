#include "dns/service/internal.h"
#include <assert.h>
#include <string.h>
#include <uv.h>

typedef struct dns_group dns_group_t;
struct solaris_dns_request {
    solaris_scope_t scope;
    solaris_scope_t *parent;
    solaris_deferred_t pump;
    solaris_deadline_t *deadline;
    solaris_dns_binding_t *binding;
    solaris_dns_query_options_t options;
    const solaris_dns_wire_t *query;
    const solaris_dns_wire_t *work_query;
    solaris_dns_wire_t *response;
    solaris_dns_service_fn done;
    void (*manual_cancel)(void *, solaris_status_t);
    void *context;
    struct solaris_dns_request *next, *group_next;
    dns_group_t *group; /* Service-owner only. */
    solaris_dns_service_result_t result;
    solaris_status_t cancel_status;
    int accepted, begun, cancel_handled, ready, scheduled, delivering, client_done, acked, finalizing, alias;
    int manual, manual_notified, manual_finished;
};
struct dns_group {
    solaris_scope_t scope;
    solaris_dns_service_t *service;
    const solaris_dns_resolver_view_t *view;
    const solaris_dns_wire_t *query;
    const solaris_dns_wire_t *response;
    solaris_dns_lookup_view_t identity;
    solaris_dns_cache_key_t key;
    solaris_dns_exchange_t *exchange;
    dns_group_t *next;
    solaris_dns_request_t *waiters;
    size_t waiter_count, next_upstream;
    uint64_t deadline, upstream_id;
    solaris_status_t status;
    int keyed, refresh, settled;
};
struct solaris_dns_service {
    atomic_size_t references;
    solaris_scope_t scope;
    solaris_scope_t *parent;
    solaris_deferred_t pump;
    uv_mutex_t mutex;
    solaris_dns_service_options_t options;
    void *engine_context;
    solaris_dns_cache_t *cache;
    solaris_dns_request_t *requests;
    dns_group_t *groups;
    size_t request_count, group_count;
    uint64_t network_revision;
    int scheduled, closing, closed, finalizing, accepted, policy_retained;
};

static void service_pump(void *context);
static void request_pump(void *context);
static void group_settle(dns_group_t *g, solaris_status_t status);
static void group_next(dns_group_t *g);
static void schedule_service_locked(solaris_dns_service_t *s)
{
    if (s->scheduled || s->finalizing || s->closed) return;
    s->scheduled = 1; solaris_status_t rc = solaris_executor_defer(s->options.owner, &s->pump);
    assert(rc == SOLARIS_OK); (void)rc;
}
static void schedule_request_locked(solaris_dns_request_t *r)
{
    if (r->scheduled || r->finalizing) return;
    r->scheduled = 1; solaris_status_t rc = solaris_executor_defer(r->options.owner, &r->pump);
    assert(rc == SOLARIS_OK); (void)rc;
}
solaris_budget_t *solaris_dns_service_budget(solaris_dns_service_t *s) { return s->options.budget; }
void solaris_dns_service_retain(solaris_dns_service_t *s)
{ if (s) (void)atomic_fetch_add_explicit(&s->references, 1u, memory_order_relaxed); }
void solaris_dns_service_release(solaris_dns_service_t *s)
{
    if (s && atomic_fetch_sub_explicit(&s->references, 1u, memory_order_acq_rel) == 1u) {
        assert(s->closed); uv_mutex_destroy(&s->mutex); solaris_memory_free(s);
    }
}
static void service_cancelled(void *context)
{
    solaris_dns_service_t *s = context;
    uv_mutex_lock(&s->mutex); s->closing = 1;
    for (solaris_dns_request_t *r = s->requests; r; r = r->next)
        if (!r->cancel_status) r->cancel_status = SOLARIS_ECANCELLED;
    schedule_service_locked(s); uv_mutex_unlock(&s->mutex);
    for (dns_group_t *g = s->groups; g; g = g->next) group_settle(g, SOLARIS_ECANCELLED);
}
static void service_done(void *context)
{
    solaris_dns_service_t *s = context;
    assert(!s->groups && !s->requests && !s->scheduled);
    if (s->cache) { (void)solaris_dns_cache_destroy(s->cache); s->cache = NULL; }
    if (s->policy_retained) s->options.policy_context_release(s->options.dialer.policy_context);
    uv_mutex_lock(&s->mutex); s->closed = 1; uv_mutex_unlock(&s->mutex);
    if (s->accepted) s->options.on_close(s->options.context);
    solaris_scope_t *parent = s->parent;
    solaris_dns_service_release(s);
    if (parent) solaris_scope_release(parent);
}
void solaris_dns_service_options_init(solaris_dns_service_options_t *o)
{
    if (!o) return;
    memset(o, 0, sizeof(*o)); o->inflight_limit = 256u; o->waiter_limit = 4096u; o->waiters_per_query = 64u;
    solaris_dns_cache_options_init(&o->cache); solaris_dialer_options_init(&o->dialer);
}
solaris_status_t solaris_dns_service_create(const solaris_dns_service_options_t *o, solaris_dns_service_t **out)
{
    if (!out) return SOLARIS_EINVAL;
    *out = NULL;
    if (!o || !o->owner || !o->budget || !o->on_close || !o->initial_network_revision ||
        !o->inflight_limit || o->inflight_limit > 4096u || !o->waiter_limit || o->waiter_limit > 65536u ||
        !o->waiters_per_query || o->waiters_per_query > 1024u ||
        ((o->policy_context_retain == NULL) != (o->policy_context_release == NULL))) return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(o->owner)) return SOLARIS_ETHREAD;
    if (!solaris_executor_context(o->owner) || (o->parent_scope &&
        (o->parent_scope->owner != o->owner || o->parent_scope->cancelled || o->parent_scope->finishing))) return SOLARIS_EINVAL;
    solaris_dns_service_t *s = solaris_memory_allocate(o->budget, sizeof(*s)); if (!s) return SOLARIS_ENOMEM;
    memset(s, 0, sizeof(*s)); atomic_init(&s->references, 1u); s->options = *o;
    s->network_revision = o->initial_network_revision; s->engine_context = solaris_executor_context(o->owner);
    s->pump = (solaris_deferred_t){.run = service_pump, .context = s};
    if (uv_mutex_init(&s->mutex)) { solaris_memory_free(s); return SOLARIS_EIO; }
    solaris_status_t rc = solaris_scope_init(&s->scope, o->owner, service_cancelled, service_done, s);
    if (rc != SOLARIS_OK) { uv_mutex_destroy(&s->mutex); solaris_memory_free(s); return rc; }
    solaris_scope_retain(&s->scope); /* Drain guard, released by final service pump. */
    s->parent = o->parent_scope; if (s->parent) solaris_scope_retain(s->parent);
    solaris_dns_cache_options_t cache = o->cache; cache.owner = o->owner; cache.budget = o->budget;
    rc = solaris_dns_cache_create(&cache, &s->cache);
    if (rc != SOLARIS_OK) { solaris_scope_cancel(&s->scope); return rc; }
    if (o->policy_context_retain) { o->policy_context_retain(o->dialer.policy_context); s->policy_retained = 1; }
    s->accepted = 1; solaris_dns_service_retain(s); *out = s; return SOLARIS_OK;
}
solaris_status_t solaris_dns_service_close(solaris_dns_service_t *s)
{
    if (!s) return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(s->options.owner)) return SOLARIS_ETHREAD;
    if (!s->closed) solaris_scope_cancel(&s->scope);
    return SOLARIS_OK;
}
solaris_status_t solaris_dns_service_invalidate_network(solaris_dns_service_t *s, uint64_t revision)
{
    if (!s || !revision) return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(s->options.owner)) return SOLARIS_ETHREAD;
    uv_mutex_lock(&s->mutex);
    if (s->closing || s->closed) { uv_mutex_unlock(&s->mutex); return SOLARIS_ECLOSED; }
    if (revision <= s->network_revision) { uv_mutex_unlock(&s->mutex); return SOLARIS_EINVAL; }
    s->network_revision = revision;
    for (solaris_dns_request_t *r = s->requests; r; r = r->next)
        if (r->options.view.network_revision != revision && !solaris_dns_lookup_terminal(r->cancel_status)) r->cancel_status = SOLARIS_ENETWORK_CHANGED;
    schedule_service_locked(s); uv_mutex_unlock(&s->mutex);
    (void)solaris_dns_cache_flush(s->cache, 0u, 0u, 0u, NULL);
    for (dns_group_t *g = s->groups; g; g = g->next) if (g->identity.network_revision != revision) group_settle(g, SOLARIS_ENETWORK_CHANGED);
    return SOLARIS_OK;
}
static void request_done(void *context)
{
    solaris_dns_request_t *r = context;
    assert(!r->deadline && !r->scheduled && (!r->accepted || (r->client_done && r->acked)));
    solaris_scope_t *parent = r->parent;
    solaris_dns_wire_release(r->query); solaris_dns_wire_release(r->work_query); solaris_dns_wire_release(r->response);
    solaris_dns_binding_release(r->binding); solaris_memory_free(r);
    if (parent) solaris_scope_release(parent);
}
static void request_cancelled(void *context)
{
    solaris_dns_request_t *r = context; solaris_dns_service_t *s = r->binding->service;
    if (r->deadline) solaris_deadline_cancel(r->deadline);
    uv_mutex_lock(&s->mutex);
    if (r->accepted && !r->client_done && !r->delivering) {
        if (!r->cancel_status) r->cancel_status = SOLARIS_ECANCELLED;
        schedule_service_locked(s);
    }
    uv_mutex_unlock(&s->mutex);
}
static void request_deadline(void *context, solaris_status_t status)
{
    solaris_dns_request_t *r = context; solaris_dns_service_t *s = r->binding->service; r->deadline = NULL;
    uv_mutex_lock(&s->mutex);
    if (status == SOLARIS_OK && !r->cancel_status && !r->delivering) r->cancel_status = SOLARIS_ETIMEDOUT;
    if (r->ready || r->manual_finished) schedule_request_locked(r); else schedule_service_locked(s);
    uv_mutex_unlock(&s->mutex);
    if (status == SOLARIS_OK) solaris_scope_cancel(&r->scope);
    solaris_scope_release(&r->scope);
}
solaris_status_t solaris_dns_request_cancel(solaris_dns_request_t *r)
{
    if (!r) return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(r->options.owner)) return SOLARIS_ETHREAD;
    solaris_dns_service_t *s = r->binding->service; uv_mutex_lock(&s->mutex);
    int done = r->delivering || r->client_done;
    if (!done && !r->cancel_status) r->cancel_status = SOLARIS_ECANCELLED;
    uv_mutex_unlock(&s->mutex);
    if (done) return SOLARIS_ECLOSED;
    solaris_scope_cancel(&r->scope); return SOLARIS_OK;
}
static void request_pump(void *context)
{
    solaris_dns_request_t *r = context; solaris_dns_service_t *s = r->binding->service;
    uv_mutex_lock(&s->mutex); r->scheduled = 0;
    int notify_manual = r->manual && r->ready && !r->manual_notified && !r->manual_finished;
    if (notify_manual) r->manual_notified = 1;
    int deliver = !r->manual && r->ready && !r->client_done && !r->delivering;
    uv_mutex_unlock(&s->mutex);
    if (notify_manual) r->manual_cancel(r->context, solaris_dns_activity_status(r));
    if (r->manual && r->manual_finished && !r->deadline) {
        uv_mutex_lock(&s->mutex);
        if (!r->client_done) { r->client_done = 1; schedule_service_locked(s); }
        uv_mutex_unlock(&s->mutex);
    }
    if (deliver && r->deadline) { solaris_deadline_cancel(r->deadline); return; }
    if (deliver) {
        uv_mutex_lock(&s->mutex); r->delivering = 1;
        if (solaris_dns_lookup_terminal(r->cancel_status)) r->result.status = r->cancel_status;
        else if (s->closing || !solaris_executor_accepting(r->options.owner)) r->result.status = SOLARIS_ECANCELLED;
        else if (r->options.view.network_revision != s->network_revision) r->result.status = SOLARIS_ENETWORK_CHANGED;
        else if (r->cancel_status) r->result.status = r->cancel_status;
        else if (solaris_executor_now_ns(r->options.owner) >= r->options.deadline_ns) r->result.status = SOLARIS_ETIMEDOUT;
        r->result.response = r->result.status == SOLARIS_OK ? r->response : NULL;
        uv_mutex_unlock(&s->mutex);
        r->done(r->context, r, &r->result);
        solaris_dns_wire_release(r->response); r->response = NULL;
        uv_mutex_lock(&s->mutex); r->client_done = 1; r->delivering = 0; schedule_service_locked(s); uv_mutex_unlock(&s->mutex);
    }
    uv_mutex_lock(&s->mutex); int finish = r->acked && !r->finalizing && !r->scheduled;
    if (finish) r->finalizing = 1;
    uv_mutex_unlock(&s->mutex);
    if (finish) { solaris_scope_cancel(&r->scope); solaris_scope_release(&r->scope); }
}
static solaris_status_t start_request(solaris_dns_binding_t *binding,
    const solaris_dns_query_options_t *o, const solaris_dns_wire_t *query,
    solaris_dns_service_fn done, void (*manual_cancel)(void *, solaris_status_t), void *context, solaris_dns_request_t **out)
{
    if (!out) return SOLARIS_EINVAL;
    *out = NULL;
    if (!binding || !o || !o->owner || ((!query || !done) && !manual_cancel) || !o->deadline_ns || o->address_lookup > 1u ||
        o->view.role < 1u || o->view.role > SOLARIS_DNS_ROLE_COUNT ||
        o->view.resolver_revision != binding->view->options.resolver_revision ||
        o->view.network_revision != binding->view->options.network_revision ||
        (query && (solaris_dns_wire_header(query)->flags & SOLARIS_DNS_QR))) return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(o->owner)) return SOLARIS_ETHREAD;
    solaris_dns_service_t *s = binding->service;
    if (!solaris_executor_context(o->owner) || solaris_executor_context(o->owner) != s->engine_context ||
        (o->parent_scope && (o->parent_scope->owner != o->owner || o->parent_scope->cancelled || o->parent_scope->finishing))) return SOLARIS_EINVAL;
    uint64_t now = solaris_executor_now_ns(o->owner); if (now >= o->deadline_ns) return SOLARIS_ETIMEDOUT;
    uv_mutex_lock(&s->mutex);
    solaris_status_t rc = s->closing || s->closed ? SOLARIS_ECLOSED :
        s->network_revision != o->view.network_revision ? SOLARIS_ENETWORK_CHANGED : SOLARIS_OK;
    uv_mutex_unlock(&s->mutex); if (rc != SOLARIS_OK) return rc;
    solaris_dns_request_t *r = solaris_memory_allocate(s->options.budget, sizeof(*r)); if (!r) return SOLARIS_ENOMEM;
    memset(r, 0, sizeof(*r)); r->binding = binding; r->options = *o; r->query = query; r->done = done; r->context = context;
    r->manual = manual_cancel != NULL; r->manual_cancel = manual_cancel;
    r->result.view = o->view; r->pump = (solaris_deferred_t){.run = request_pump, .context = r};
    solaris_dns_binding_retain(binding); solaris_dns_wire_retain(query);
    rc = solaris_scope_init(&r->scope, o->owner, request_cancelled, request_done, r);
    if (rc != SOLARIS_OK) { solaris_dns_binding_release(binding); solaris_dns_wire_release(query); solaris_memory_free(r); return rc; }
    solaris_scope_retain(&r->scope); r->parent = o->parent_scope; if (r->parent) solaris_scope_retain(r->parent);
    uv_mutex_lock(&s->mutex);
    rc = s->closing || s->closed ? SOLARIS_ECLOSED : s->network_revision != o->view.network_revision ? SOLARIS_ENETWORK_CHANGED :
        s->request_count == s->options.waiter_limit ? SOLARIS_EAGAIN : SOLARIS_OK;
    if (rc == SOLARIS_OK) {
        r->accepted = 1; r->next = s->requests; s->requests = r; s->request_count++; schedule_service_locked(s);
    }
    uv_mutex_unlock(&s->mutex);
    if (rc != SOLARIS_OK) { r->finalizing = 1; solaris_scope_cancel(&r->scope); solaris_scope_release(&r->scope); return rc; }
    uint64_t delay = (o->deadline_ns - now - 1u) / UINT64_C(1000000) + 1u;
    rc = solaris_deadline_start(o->owner, delay, request_deadline, r, &r->deadline);
    if (rc == SOLARIS_OK) solaris_scope_retain(&r->scope);
    else {
        uv_mutex_lock(&s->mutex); if (!r->cancel_status) r->cancel_status = rc; schedule_service_locked(s); uv_mutex_unlock(&s->mutex);
        solaris_scope_cancel(&r->scope);
    }
    *out = r; return SOLARIS_OK;
}
solaris_status_t solaris_dns_service_query(solaris_dns_binding_t *binding,
    const solaris_dns_query_options_t *o, const solaris_dns_wire_t *query,
    solaris_dns_service_fn done, void *context, solaris_dns_request_t **out)
{ return start_request(binding, o, query, done, NULL, context, out); }
solaris_status_t solaris_dns_activity_start(solaris_dns_binding_t *binding,
    const solaris_dns_query_options_t *o, void (*cancel)(void *, solaris_status_t), void *context, solaris_dns_request_t **out)
{ return start_request(binding, o, NULL, NULL, cancel, context, out); }
solaris_status_t solaris_dns_activity_status(solaris_dns_request_t *r)
{
    solaris_dns_service_t *s = r->binding->service; uv_mutex_lock(&s->mutex);
    solaris_status_t status = solaris_dns_lookup_terminal(r->cancel_status) ? r->cancel_status :
        s->closing || !solaris_executor_accepting(r->options.owner) ? SOLARIS_ECANCELLED :
        r->options.view.network_revision != s->network_revision ? SOLARIS_ENETWORK_CHANGED :
        r->cancel_status ? r->cancel_status : solaris_executor_now_ns(r->options.owner) >= r->options.deadline_ns ? SOLARIS_ETIMEDOUT : SOLARIS_OK;
    uv_mutex_unlock(&s->mutex); return status;
}
void solaris_dns_activity_finish(solaris_dns_request_t *r)
{
    assert(r->manual && solaris_executor_is_owner(r->options.owner));
    solaris_dns_service_t *s = r->binding->service;
    uv_mutex_lock(&s->mutex); r->manual_finished = 1; schedule_request_locked(r); uv_mutex_unlock(&s->mutex);
    if (r->deadline) solaris_deadline_cancel(r->deadline);
}
static void ready(solaris_dns_request_t *r, solaris_status_t status, solaris_dns_wire_t *response,
    uint32_t source, uint32_t stale, uint64_t upstream)
{
    solaris_dns_service_t *s = r->binding->service;
    uv_mutex_lock(&s->mutex); assert(!r->ready && !r->group);
    r->ready = 1; r->response = response; r->result.status = status; r->result.source = source;
    r->result.stale = stale; r->result.upstream_id = upstream;
    schedule_request_locked(r); uv_mutex_unlock(&s->mutex);
}
static solaris_status_t parse_buffer(solaris_dns_service_t *s, solaris_buffer_t *buffer, solaris_dns_wire_t **out)
{
    solaris_dns_wire_limits_t limits; solaris_dns_wire_limits_init(&limits); limits.records = SOLARIS_DNS_MAX_RECORDS;
    solaris_status_t rc = solaris_dns_wire_parse(s->options.budget, solaris_buffer_data(buffer), solaris_buffer_length(buffer), &limits, out, NULL);
    solaris_buffer_release(buffer); return rc;
}
static solaris_status_t render(solaris_dns_request_t *r, const solaris_dns_wire_t *answer, solaris_dns_wire_t **out)
{
    *out = NULL; solaris_dns_service_t *s = r->binding->service;
    const solaris_dns_question_t *q = solaris_dns_wire_question(r->query);
    const solaris_dns_header_t *h = solaris_dns_wire_header(answer);
    if (r->alias) {
        size_t count = solaris_dns_wire_record_count(answer), used = 1u;
        if (count >= SOLARIS_DNS_MAX_RECORDS) return SOLARIS_EOVERFLOW;
        solaris_dns_record_t *records = solaris_memory_allocate(s->options.budget, (count + 1u) * sizeof(*records));
        if (!records) return SOLARIS_ENOMEM;
        memset(&records[0], 0, sizeof(*records)); records[0].name = q->name; records[0].type = SOLARIS_DNS_CNAME;
        records[0].class_code = SOLARIS_DNS_IN; records[0].ttl = 10u; records[0].kind = SOLARIS_DNS_RDATA_NAME;
        records[0].value.target = solaris_dns_wire_question(r->work_query)->name;
        for (size_t i = 0; i < count; i++) {
            const solaris_dns_record_t *record = solaris_dns_wire_record(answer, i);
            if (record->kind != SOLARIS_DNS_RDATA_OPT) records[used++] = *record;
        }
        solaris_buffer_t *buffer = NULL;
        solaris_status_t rc = solaris_dns_wire_make_response(s->options.budget, r->query,
            (uint16_t)(h->flags & (SOLARIS_DNS_AA | SOLARIS_DNS_RA | SOLARIS_DNS_TC)), h->rcode, records, used, &buffer);
        solaris_memory_free(records); return rc == SOLARIS_OK ? parse_buffer(s, buffer, out) : rc;
    }
    const solaris_dns_question_t *original = solaris_dns_wire_question(answer);
    if (!solaris_dns_name_equal(&q->name, &original->name) || q->type != original->type || q->class_code != original->class_code) return SOLARIS_EINVAL;
    if (h->id == solaris_dns_wire_header(r->query)->id && !memcmp(q->name.bytes, original->name.bytes, q->name.length)) {
        solaris_dns_wire_retain(answer); *out = (solaris_dns_wire_t *)answer; return SOLARIS_OK;
    }
    /* Case-only question replacement preserves all offsets, including opaque
     * RDATA compression pointers. No names or records are relocated. */
    const solaris_buffer_t *input = solaris_dns_wire_buffer(answer); solaris_buffer_t *copy;
    solaris_status_t rc = solaris_buffer_allocate(s->options.budget, solaris_buffer_length(input), &copy);
    if (rc != SOLARIS_OK) return rc;
    uint8_t *bytes = solaris_buffer_mutable_data(copy); memcpy(bytes, solaris_buffer_data(input), solaris_buffer_length(input));
    uint16_t id = solaris_dns_wire_header(r->query)->id; bytes[0] = (uint8_t)(id >> 8); bytes[1] = (uint8_t)id;
    memcpy(bytes + 12, q->name.bytes, q->name.length);
    (void)solaris_buffer_set_length(copy, solaris_buffer_length(input)); solaris_buffer_publish(copy); return parse_buffer(s, copy, out);
}
static int text_name(const solaris_dns_name_t *name, char out[254])
{
    size_t p = 0, n = 0;
    while (p < name->length && name->bytes[p]) {
        size_t label = name->bytes[p++]; if (n && n < 253u) out[n++] = '.';
        if (n + label > 253u) return 0;
        for (size_t i = 0; i < label; i++) { uint8_t c = name->bytes[p++]; if (c < 0x21u || c > 0x7eu || c == '.' || c == '\\') return 0; out[n++] = (char)c; }
    }
    out[n] = 0; return n != 0u;
}
static solaris_status_t hosts(solaris_dns_request_t *r, solaris_dns_wire_t **response, int *handled)
{
    *response = NULL; *handled = 0;
    const solaris_dns_resolver_view_options_t *v = &r->binding->view->options;
    const solaris_dns_question_t *q = solaris_dns_wire_question(r->query);
    if (!v->hosts || (!v->wire_use_hosts && !r->options.address_lookup) || q->class_code != SOLARIS_DNS_IN ||
        (q->type != SOLARIS_DNS_A && q->type != SOLARIS_DNS_AAAA && q->type != SOLARIS_DNS_CNAME)) return SOLARIS_OK;
    char name[254]; if (!text_name(&q->name, name)) return SOLARIS_OK;
    solaris_hosts_result_t found;
    solaris_status_t rc = solaris_hosts_lookup(v->hosts, name, q->type == SOLARIS_DNS_A ? 4u : q->type == SOLARIS_DNS_AAAA ? 6u : 0u, &found);
    if (rc != SOLARIS_OK || !found.matched) return SOLARIS_OK;
    if (q->type == SOLARIS_DNS_CNAME && !found.first_alias[0]) return SOLARIS_OK;
    if (q->type != SOLARIS_DNS_CNAME && found.kind == SOLARIS_HOSTS_ALIAS) {
        solaris_dns_question_t target = *q; rc = solaris_dns_name_from_text(found.terminal_name, &target.name);
        if (rc != SOLARIS_OK) return rc;
        solaris_buffer_t *buffer;
        rc = solaris_dns_wire_make_query(r->binding->service->options.budget, solaris_dns_wire_header(r->query)->id,
            solaris_dns_wire_header(r->query)->flags, &target, solaris_dns_wire_edns(r->query), &buffer);
        if (rc != SOLARIS_OK) return rc;
        solaris_dns_wire_t *work; rc = parse_buffer(r->binding->service, buffer, &work);
        if (rc == SOLARIS_OK) { r->work_query = work; r->alias = 1; }
        return rc;
    }
    solaris_dns_record_t records[SOLARIS_HOSTS_MAX_ADDRESSES]; memset(records, 0, sizeof(records));
    size_t count = q->type == SOLARIS_DNS_CNAME ? 1u : found.address_count;
    for (size_t i = 0; i < count; i++) {
        records[i].name = q->name; records[i].type = q->type; records[i].class_code = SOLARIS_DNS_IN; records[i].ttl = 10u;
        records[i].kind = q->type == SOLARIS_DNS_CNAME ? SOLARIS_DNS_RDATA_NAME : SOLARIS_DNS_RDATA_ADDRESS;
        if (q->type == SOLARIS_DNS_CNAME) {
            rc = solaris_dns_name_from_text(found.first_alias, &records[i].value.target); if (rc != SOLARIS_OK) return rc;
        } else memcpy(records[i].value.address, found.addresses[i].ip, q->type == SOLARIS_DNS_A ? 4u : 16u);
    }
    solaris_buffer_t *buffer; *handled = 1;
    rc = solaris_dns_wire_make_response(r->binding->service->options.budget, r->query,
        SOLARIS_DNS_AA | SOLARIS_DNS_RA, 0u, records, count, &buffer);
    return rc == SOLARIS_OK ? parse_buffer(r->binding->service, buffer, response) : rc;
}
static void group_cancelled(void *context)
{
    dns_group_t *g = context;
    if (!g->settled) { g->settled = 1; g->status = SOLARIS_ECANCELLED; }
    if (g->exchange) (void)solaris_dns_exchange_cancel(g->exchange);
}
static void group_settle(dns_group_t *g, solaris_status_t status)
{
    if (g->settled) return;
    g->settled = 1; g->status = status; solaris_scope_cancel(&g->scope);
}
static void group_done(void *context)
{
    dns_group_t *g = context; solaris_dns_service_t *s = g->service; assert(!g->exchange);
    uv_mutex_lock(&s->mutex);
    if (s->closing) g->status = SOLARIS_ECANCELLED;
    else if (g->identity.network_revision != s->network_revision) g->status = SOLARIS_ENETWORK_CHANGED;
    uv_mutex_unlock(&s->mutex);
    if (g->status == SOLARIS_OK && g->keyed) {
        solaris_dns_cache_put_result_t ignored; (void)solaris_dns_cache_put(s->cache, &g->key, g->query, g->response, &ignored);
    }
    solaris_dns_request_t *r = g->waiters;
    while (r) {
        solaris_dns_request_t *next = r->group_next; r->group = NULL; r->group_next = NULL;
        solaris_dns_wire_t *response = NULL;
        uv_mutex_lock(&s->mutex); solaris_status_t status = r->cancel_status ? r->cancel_status : g->status; uv_mutex_unlock(&s->mutex);
        if (status == SOLARIS_OK) status = render(r, g->response, &response);
        ready(r, status, response, SOLARIS_DNS_SOURCE_UPSTREAM, 0u, g->upstream_id); r = next;
    }
    dns_group_t **cursor = &s->groups; while (*cursor != g) cursor = &(*cursor)->next;
    *cursor = g->next; s->group_count--;
    solaris_dns_resolver_view_release(g->view); solaris_dns_wire_release(g->query); solaris_dns_wire_release(g->response);
    solaris_memory_free(g);
    uv_mutex_lock(&s->mutex); schedule_service_locked(s); uv_mutex_unlock(&s->mutex);
    solaris_scope_release(&s->scope);
}
static void exchanged(void *context, solaris_dns_exchange_t *exchange, const solaris_dns_exchange_result_t *result)
{
    dns_group_t *g = context; (void)exchange; g->exchange = NULL;
    if (g->settled) return;
    if (result->status == SOLARIS_OK) { g->response = result->response; solaris_dns_wire_retain(g->response); group_settle(g, SOLARIS_OK); return; }
    if (!solaris_dns_lookup_terminal(result->status) &&
        g->next_upstream < g->view->options.role[g->identity.role - 1u].upstream_count &&
        solaris_executor_now_ns(g->scope.owner) < g->deadline) group_next(g);
    else group_settle(g, result->status);
}
static void group_next(dns_group_t *g)
{
    const solaris_dns_role_options_t *role = &g->view->options.role[g->identity.role - 1u];
    solaris_status_t status = SOLARIS_ENOTSUP;
    while (!g->settled && g->next_upstream < role->upstream_count) {
        const solaris_dns_upstream_t *u = &role->upstreams[g->next_upstream++]; g->upstream_id = u->id;
        solaris_dns_exchange_options_t o; solaris_dns_exchange_options_init(&o);
        o.upstream = u->address; o.transport = u->transport; o.deadline_ns = g->deadline; o.view = g->identity;
        o.dialer = g->service->options.dialer; o.parent_scope = &g->scope; o.dialer.parent_scope = NULL;
        status = solaris_dns_exchange_start(g->scope.owner, g->query, &o, exchanged, g, &g->exchange);
        if (status == SOLARIS_OK) return;
        if (solaris_dns_lookup_terminal(status) || solaris_executor_now_ns(g->scope.owner) >= g->deadline) break;
    }
    group_settle(g, status);
}
static dns_group_t *find_group(solaris_dns_service_t *s, const solaris_dns_cache_key_t *key)
{
    for (dns_group_t *g = s->groups; g; g = g->next)
        if (!g->settled && g->keyed && solaris_dns_cache_key_equal(&g->key, key)) return g;
    return NULL;
}
static solaris_status_t group_create(solaris_dns_request_t *r, const solaris_dns_cache_key_t *key,
    int keyed, int refresh, dns_group_t **out)
{
    *out = NULL; solaris_dns_service_t *s = r->binding->service;
    if (s->group_count == s->options.inflight_limit) return SOLARIS_EAGAIN;
    if (!r->binding->view->options.role[r->options.view.role - 1u].upstream_count) return SOLARIS_ENOTSUP;
    uint64_t now = solaris_executor_now_ns(s->options.owner), duration = r->binding->view->options.query_timeout_ms * UINT64_C(1000000);
    if (now > UINT64_MAX - duration) return SOLARIS_EOVERFLOW;
    dns_group_t *g = solaris_memory_allocate(s->options.budget, sizeof(*g)); if (!g) return SOLARIS_ENOMEM;
    memset(g, 0, sizeof(*g)); g->service = s; g->view = r->binding->view; g->query = r->work_query;
    g->identity = r->options.view; g->keyed = keyed; if (keyed) g->key = *key;
    g->refresh = refresh; g->deadline = now + duration;
    solaris_status_t rc = solaris_scope_init(&g->scope, s->options.owner, group_cancelled, group_done, g);
    if (rc != SOLARIS_OK) { solaris_memory_free(g); return rc; }
    solaris_scope_retain(&s->scope); solaris_dns_resolver_view_retain(g->view); solaris_dns_wire_retain(g->query);
    g->next = s->groups; s->groups = g; s->group_count++; *out = g; return SOLARIS_OK;
}
static void begin_request(solaris_dns_request_t *r)
{
    solaris_dns_service_t *s = r->binding->service;
    uv_mutex_lock(&s->mutex);
    solaris_status_t status = r->cancel_status ? r->cancel_status : s->closing ? SOLARIS_ECANCELLED :
        r->options.view.network_revision != s->network_revision ? SOLARIS_ENETWORK_CHANGED : SOLARIS_OK;
    uv_mutex_unlock(&s->mutex);
    if (status != SOLARIS_OK) { ready(r, status, NULL, 0u, 0u, 0u); return; }
    if (r->manual) return;
    solaris_dns_wire_t *response; int handled;
    status = hosts(r, &response, &handled);
    if (status != SOLARIS_OK || handled) { ready(r, status, response, SOLARIS_DNS_SOURCE_HOSTS, 0u, 0u); return; }
    if (!r->work_query) { r->work_query = r->query; solaris_dns_wire_retain(r->work_query); }
    const solaris_dns_role_options_t *role = &r->binding->view->options.role[r->options.view.role - 1u];
    solaris_dns_cache_key_t key;
    int keyed = solaris_dns_cache_key_make(&r->options.view, role->policy_id, role->upstream_set_id, r->work_query, &key) == SOLARIS_OK;
    if (keyed) {
        solaris_dns_cache_hit_t hit;
        if (solaris_dns_cache_get(s->cache, &key, r->work_query, (int)r->binding->view->options.allow_stale, &hit) == SOLARIS_OK && hit.found) {
            solaris_dns_wire_t *cached = NULL; status = parse_buffer(s, hit.wire, &cached);
            if (status == SOLARIS_OK) { status = render(r, cached, &response); solaris_dns_wire_release(cached); }
            if (hit.needs_refresh && !find_group(s, &key)) {
                dns_group_t *refresh; if (group_create(r, &key, 1, 1, &refresh) == SOLARIS_OK) group_next(refresh);
            }
            ready(r, status, status == SOLARIS_OK ? response : NULL, SOLARIS_DNS_SOURCE_CACHE, hit.stale, 0u); return;
        }
    }
    dns_group_t *g = keyed ? find_group(s, &key) : NULL; int created = g == NULL;
    if (g && g->waiter_count == s->options.waiters_per_query) { ready(r, SOLARIS_EAGAIN, NULL, 0u, 0u, 0u); return; }
    if (created) {
        status = group_create(r, &key, keyed, 0, &g);
        if (status != SOLARIS_OK) { ready(r, status, NULL, 0u, 0u, 0u); return; }
    }
    r->group = g; r->group_next = g->waiters; g->waiters = r; g->waiter_count++;
    if (created) group_next(g);
}
static void cancel_request(solaris_dns_request_t *r)
{
    solaris_dns_service_t *s = r->binding->service;
    uv_mutex_lock(&s->mutex); solaris_status_t status = r->cancel_status; uv_mutex_unlock(&s->mutex);
    dns_group_t *g = r->group;
    if (!g) { ready(r, status, NULL, 0u, 0u, 0u); return; }
    if (g->waiter_count == 1u && !g->refresh) { group_settle(g, status); return; }
    solaris_dns_request_t **p = &g->waiters; while (*p != r) p = &(*p)->group_next;
    *p = r->group_next; g->waiter_count--; r->group = NULL; r->group_next = NULL;
    ready(r, status, NULL, 0u, 0u, 0u);
}
static void service_pump(void *context)
{
    solaris_dns_service_t *s = context; uv_mutex_lock(&s->mutex); s->scheduled = 0; uv_mutex_unlock(&s->mutex);
    unsigned work = 0;
    for (; work < 64u; work++) {
        solaris_dns_request_t *r = NULL; int action = 0;
        uv_mutex_lock(&s->mutex);
        solaris_dns_request_t **p = &s->requests;
        while (*p) {
            r = *p;
            if (!r->begun) { r->begun = 1; action = 1; break; }
            if (!r->ready && r->cancel_status && !r->cancel_handled) { r->cancel_handled = 1; action = 2; break; }
            if (r->client_done && !r->acked) {
                *p = r->next; r->next = NULL; r->acked = 1; s->request_count--; schedule_request_locked(r); action = 3; break;
            }
            p = &r->next;
        }
        uv_mutex_unlock(&s->mutex);
        if (!action) break;
        if (action == 1) begin_request(r); else if (action == 2) cancel_request(r);
    }
    uv_mutex_lock(&s->mutex);
    if (work == 64u) schedule_service_locked(s);
    int finish = s->closing && !s->requests && !s->groups && !s->scheduled && !s->finalizing;
    if (finish) s->finalizing = 1;
    uv_mutex_unlock(&s->mutex);
    if (finish) solaris_scope_release(&s->scope);
}
