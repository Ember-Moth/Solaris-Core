#include "dns/service/internal.h"
#include <assert.h>
#include <string.h>
#include <uv.h>

typedef struct lookup_operation lookup_operation_t;
typedef struct lookup_child { lookup_operation_t *operation; unsigned index; } lookup_child_t;
struct lookup_operation {
    solaris_scope_t scope;
    solaris_dns_binding_t *binding;
    solaris_dns_request_t *activity, *requests[2];
    solaris_deadline_t *grace;
    solaris_resolve_t *system;
    solaris_dns_lookup_view_t view;
    solaris_address_t target, addresses[SOLARIS_RESOLVER_MAX_ADDRESSES];
    solaris_address_t family[2][SOLARIS_RESOLVER_MAX_ADDRESSES];
    size_t count, family_count[2];
    lookup_child_t children[2];
    solaris_status_t status, family_status[2];
    uint64_t deadline;
    solaris_resolve_fn callback;
    void *context;
    unsigned total;
    int accepted, settled, completed[2];
};
static void settle(lookup_operation_t *op, solaris_status_t status);
static int same_address(const solaris_address_t *a, const solaris_address_t *b)
{ return a->family == b->family && a->scope_id == b->scope_id && !memcmp(a->ip, b->ip, a->family == 4u ? 4u : 16u); }
static solaris_address_t unmap(solaris_address_t a)
{
    static const uint8_t prefix[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255};
    if (a.family == 6u && !memcmp(a.ip, prefix, sizeof(prefix))) {
        memmove(a.ip, a.ip + 12, 4u); memset(a.ip + 4, 0, 12u); a.family = 4u; a.scope_id = 0;
    }
    return a;
}
static void append(lookup_operation_t *op, solaris_address_t address)
{
    address = unmap(address); address.port = op->target.port;
    for (size_t i = 0; i < op->count; i++) if (same_address(&op->addresses[i], &address)) return;
    if (op->count < SOLARIS_RESOLVER_MAX_ADDRESSES) op->addresses[op->count++] = address;
}
static solaris_status_t collect(lookup_operation_t *op)
{
    op->count = 0; unsigned first = op->binding->view->options.prefer_ipv6 ? 1u : 0u;
    for (unsigned pass = 0; pass < 2u; pass++) {
        unsigned index = first ^ pass;
        for (size_t i = 0; i < op->family_count[index]; i++) append(op, op->family[index][i]);
    }
    if (op->count) return SOLARIS_OK;
    for (unsigned i = 0; i < op->total; i++) if (op->family_status[i] != SOLARIS_OK) return op->family_status[i];
    return SOLARIS_EIO;
}
static void cancelled(void *context)
{
    lookup_operation_t *op = context;
    if (!op->settled) { op->settled = 1; op->status = SOLARIS_ECANCELLED; }
    for (unsigned i = 0; i < 2u; i++) if (op->requests[i]) (void)solaris_dns_request_cancel(op->requests[i]);
    if (op->system) solaris_resolve_cancel(op->system);
    if (op->grace) solaris_deadline_cancel(op->grace);
}
static void destroyed(void *context)
{
    lookup_operation_t *op = context;
    assert(!op->requests[0] && !op->requests[1] && !op->system && !op->grace);
    if (op->accepted) {
        solaris_status_t activity = solaris_dns_activity_status(op->activity);
        if (activity != SOLARIS_OK) op->status = activity;
        op->callback(op->context, op->status, op->status == SOLARIS_OK ? op->addresses : NULL,
            op->status == SOLARIS_OK ? op->count : 0u);
        /* This separate service activity keeps service close behind the whole
         * lookup, including getaddrinfo's final native cleanup and this callback. */
        solaris_dns_activity_finish(op->activity);
    }
    solaris_dns_binding_release(op->binding); solaris_memory_free(op);
}
static void settle(lookup_operation_t *op, solaris_status_t status)
{
    if (!op->settled || (solaris_dns_lookup_terminal(status) && !solaris_dns_lookup_terminal(op->status))) op->status = status;
    if (op->settled) return;
    op->settled = 1; solaris_scope_cancel(&op->scope);
}
static void activity_cancelled(void *context, solaris_status_t status) { settle(context, status); }
static solaris_status_t extract(lookup_operation_t *op, unsigned index, const solaris_dns_wire_t *response)
{
    if (!response || solaris_dns_wire_header(response)->rcode) return SOLARIS_EIO;
    const solaris_dns_question_t *q = solaris_dns_wire_question(response);
    uint16_t type = index ? SOLARIS_DNS_AAAA : SOLARIS_DNS_A;
    if (q->type != type || q->class_code != SOLARIS_DNS_IN) return SOLARIS_EINVAL;
    solaris_dns_name_t names[33]; size_t used = 1u; names[0] = q->name;
    for (;;) {
        const solaris_dns_record_t *cname = NULL;
        for (size_t i = 0; i < solaris_dns_wire_record_count(response); i++) {
            const solaris_dns_record_t *r = solaris_dns_wire_record(response, i);
            if (r->section != SOLARIS_DNS_ANSWER || r->class_code != SOLARIS_DNS_IN || !solaris_dns_name_equal(&r->name, &names[used - 1u])) continue;
            if (r->type == type && r->kind == SOLARIS_DNS_RDATA_ADDRESS && op->family_count[index] < SOLARIS_RESOLVER_MAX_ADDRESSES) {
                solaris_address_t *a = &op->family[index][op->family_count[index]++]; memset(a, 0, sizeof(*a));
                a->family = index ? 6u : 4u; memcpy(a->ip, r->value.address, index ? 16u : 4u);
            }
            if (r->type == SOLARIS_DNS_CNAME && r->kind == SOLARIS_DNS_RDATA_NAME) {
                if (cname && !solaris_dns_name_equal(&cname->value.target, &r->value.target)) return SOLARIS_EINVAL;
                cname = r;
            }
        }
        if (op->family_count[index]) return cname ? SOLARIS_EINVAL : SOLARIS_OK;
        if (!cname) return SOLARIS_EIO;
        if (used == 33u) return SOLARIS_EOVERFLOW;
        for (size_t i = 0; i < used; i++) if (solaris_dns_name_equal(&names[i], &cname->value.target)) return SOLARIS_EINVAL;
        names[used++] = cname->value.target;
    }
}
static void grace_done(void *context, solaris_status_t status)
{
    lookup_operation_t *op = context; op->grace = NULL;
    if (!op->settled && status == SOLARIS_OK) settle(op, collect(op));
    solaris_scope_release(&op->scope);
}
static void child_done(void *context, solaris_dns_request_t *request, const solaris_dns_service_result_t *result)
{
    lookup_child_t *child = context; lookup_operation_t *op = child->operation; unsigned index = child->index; (void)request;
    op->requests[index] = NULL; op->completed[index] = 1;
    if (op->settled) return;
    solaris_status_t status = result->status;
    if (status == SOLARIS_OK) status = extract(op, index, result->response);
    if (status != SOLARIS_OK) op->family_count[index] = 0u;
    op->family_status[index] = status;
    if (solaris_dns_lookup_terminal(status)) { settle(op, status); return; }
    if (op->completed[0] && (op->total == 1u || op->completed[1])) { settle(op, collect(op)); return; }
    if (op->family_count[index] && !op->grace) {
        uint32_t delay = op->binding->view->options.ipv6_wait_ms;
        if (!delay) { settle(op, collect(op)); return; }
        solaris_status_t rc = solaris_deadline_start(op->scope.owner, delay, grace_done, op, &op->grace);
        if (rc == SOLARIS_OK) solaris_scope_retain(&op->scope); else settle(op, rc);
    }
}
static void system_done(void *context, solaris_status_t status, const solaris_address_t *addresses, size_t count)
{
    lookup_operation_t *op = context; op->system = NULL;
    if (op->settled) return;
    if (status == SOLARIS_OK) {
        for (size_t i = 0; i < count; i++) {
            solaris_address_t a = unmap(addresses[i]); unsigned index = a.family == 6u ? 1u : 0u;
            if ((a.family == 4u || (a.family == 6u && op->binding->view->options.ipv6)) &&
                op->family_count[index] < SOLARIS_RESOLVER_MAX_ADDRESSES) op->family[index][op->family_count[index]++] = a;
        }
        status = collect(op);
    }
    settle(op, status);
}
static void begin_lookup(lookup_operation_t *op)
{
    const solaris_dns_resolver_view_options_t *v = &op->binding->view->options;
    if (op->target.family != SOLARIS_ADDRESS_DOMAIN) { append(op, op->target); settle(op, SOLARIS_OK); return; }
    if (v->hosts) {
        solaris_hosts_result_t result;
        solaris_status_t rc = solaris_hosts_lookup(v->hosts, op->target.host, 0u, &result);
        if (rc == SOLARIS_OK && result.matched) {
            if (result.kind == SOLARIS_HOSTS_ADDRESSES) {
                for (size_t i = 0; i < result.address_count; i++) {
                    solaris_address_t a = result.addresses[i]; unsigned index = a.family == 6u ? 1u : 0u;
                    if (a.family == 4u || v->ipv6) op->family[index][op->family_count[index]++] = a;
                }
                settle(op, collect(op)); return;
            }
            memset(op->target.host, 0, sizeof(op->target.host)); memcpy(op->target.host, result.terminal_name, strlen(result.terminal_name));
        }
    }
    if (!v->role[op->view.role - 1u].upstream_count) {
        if (!v->allow_system_lookup) { settle(op, SOLARIS_ENOTSUP); return; }
        solaris_status_t rc = solaris_resolve_start_scoped(op->scope.owner, &op->scope,
            &op->target, 0u, system_done, op, &op->system);
        if (rc != SOLARIS_OK) settle(op, rc);
        return;
    }
    op->total = v->ipv6 ? 2u : 1u;
    for (unsigned i = 0; i < op->total && !op->settled; i++) {
        solaris_dns_question_t question; memset(&question, 0, sizeof(question));
        solaris_status_t rc = solaris_dns_name_from_text(op->target.host, &question.name);
        question.class_code = SOLARIS_DNS_IN; question.type = i ? SOLARIS_DNS_AAAA : SOLARIS_DNS_A;
        uint16_t id = 0; if (rc == SOLARIS_OK && uv_random(NULL, NULL, &id, sizeof(id), 0, NULL)) rc = SOLARIS_EIO;
        solaris_buffer_t *bytes = NULL; solaris_dns_wire_t *query = NULL;
        solaris_dns_edns_t edns = {.present = 1u, .udp_size = SOLARIS_DNS_DEFAULT_UDP_SIZE};
        if (rc == SOLARIS_OK) rc = solaris_dns_wire_make_query(solaris_dns_service_budget(op->binding->service), id, SOLARIS_DNS_RD, &question, &edns, &bytes);
        if (rc == SOLARIS_OK) rc = solaris_dns_wire_parse(solaris_dns_service_budget(op->binding->service),
            solaris_buffer_data(bytes), solaris_buffer_length(bytes), NULL, &query, NULL);
        solaris_buffer_release(bytes);
        op->children[i] = (lookup_child_t){op, i};
        solaris_dns_query_options_t options = {.owner = op->scope.owner, .parent_scope = &op->scope,
            .view = op->view, .deadline_ns = op->deadline, .address_lookup = 1u};
        if (rc == SOLARIS_OK) rc = solaris_dns_service_query(op->binding, &options, query, child_done, &op->children[i], &op->requests[i]);
        solaris_dns_wire_release(query);
        if (rc != SOLARIS_OK) settle(op, rc);
    }
}
solaris_status_t solaris_dns_lookup_start(void *context, solaris_executor_t *owner,
    const solaris_dns_lookup_view_t *view, const solaris_address_t *target,
    uint64_t deadline, solaris_resolve_fn callback, void *user, void **out)
{
    if (!out) return SOLARIS_EINVAL;
    *out = NULL; solaris_dns_binding_t *binding = context;
    if (!binding || !owner || !view || !target || !callback || !deadline ||
        (target->family != SOLARIS_ADDRESS_DOMAIN && target->family != SOLARIS_ADDRESS_IPV4 && target->family != SOLARIS_ADDRESS_IPV6) ||
        (target->family == SOLARIS_ADDRESS_DOMAIN && (!target->host[0] || !memchr(target->host, 0, sizeof(target->host))))) return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(owner)) return SOLARIS_ETHREAD;
    lookup_operation_t *op = solaris_memory_allocate(solaris_dns_service_budget(binding->service), sizeof(*op));
    if (!op) return SOLARIS_ENOMEM;
    memset(op, 0, sizeof(*op)); op->binding = binding; op->view = *view; op->target = *target; op->deadline = deadline;
    op->callback = callback; op->context = user; op->family_status[0] = op->family_status[1] = SOLARIS_EIO;
    solaris_dns_binding_retain(binding);
    solaris_status_t rc = solaris_scope_init(&op->scope, owner, cancelled, destroyed, op);
    if (rc != SOLARIS_OK) { solaris_dns_binding_release(binding); solaris_memory_free(op); return rc; }
    solaris_dns_query_options_t options = {.owner = owner, .view = *view, .deadline_ns = deadline};
    rc = solaris_dns_activity_start(binding, &options, activity_cancelled, op, &op->activity);
    if (rc != SOLARIS_OK) { settle(op, rc); return rc; }
    op->accepted = 1; *out = op; begin_lookup(op); return SOLARIS_OK;
}
void solaris_dns_lookup_cancel(void *context, void *request)
{
    (void)context; lookup_operation_t *op = request;
    if (op && solaris_executor_is_owner(op->scope.owner)) settle(op, SOLARIS_ECANCELLED);
}
