#include "contracts/dns/service.h"
#include "support/runtime/event.h"
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)
typedef struct environment environment_t;
typedef struct client { environment_t *env; unsigned index; solaris_dns_request_t *request; const solaris_dns_wire_t *query; } client_t;
struct environment {
    solaris_executor_t *owners[2];
    solaris_budget_t *budget;
    solaris_dns_service_t *service;
    solaris_dns_resolver_view_t *view;
    solaris_dns_binding_t *binding;
    solaris_hosts_t *hosts;
    solaris_dns_lookup_t lookup;
    solaris_dns_request_t *probe;
    void *lookup_request;
    const solaris_dns_wire_t *retained;
    solaris_deadline_t *action;
    solaris_scope_t parent;
    solaris_test_event_t created, finished, closed, ready, release, checked;
    client_t clients[3];
    const char *mode;
    uint16_t port, bad_port;
    atomic_size_t calls, fail_at, failures;
    atomic_uint callbacks, policy_calls, closed_count, successes, errors;
    atomic_uint_fast64_t offset;
    unsigned expected, phase;
    int starting;
    solaris_status_t setup_status, last_status;
};
static void *allocate(void *context, size_t n)
{
    environment_t *e = context;
    if (atomic_fetch_add(&e->calls, 1u) + 1u == atomic_load(&e->fail_at)) { atomic_fetch_add(&e->failures, 1u); return NULL; }
    return malloc(n);
}
static void deallocate(void *context, void *p) { (void)context; free(p); }
static uint64_t now(void *context) { return uv_hrtime() + atomic_load(&((environment_t *)context)->offset); }
static int mode(environment_t *e, const char *name) { return !strcmp(e->mode, name); }
static int stale_mode(environment_t *e) { return mode(e, "stale") || mode(e, "stale_stop"); }
static solaris_dns_lookup_view_t identity(void)
{ return (solaris_dns_lookup_view_t){SOLARIS_DNS_CLIENT_QUERY, 11u, 12u, 13u, 14u}; }
static solaris_status_t protect(void *context, uintptr_t handle, uint32_t family, uint32_t kind)
{
    environment_t *e = context; (void)handle; CHECK(family == 4u && (kind == SOLARIS_SOCKET_TCP || kind == SOLARIS_SOCKET_UDP));
    unsigned call = atomic_fetch_add(&e->policy_calls, 1u) + 1u;
    if (mode(e, "failover") && call == 1u) return SOLARIS_EIO; /* Inject first transport preparation failure. */
    return mode(e, "deny") ? SOLARIS_EACCESS : SOLARIS_OK;
}
static void on_close(void *context)
{
    environment_t *e = context;
    CHECK(solaris_executor_is_owner(e->owners[0])); CHECK(atomic_load(&e->callbacks) == e->expected);
    CHECK(atomic_fetch_add(&e->closed_count, 1u) == 0u); solaris_test_event_signal(&e->closed);
}
static void close_task(void *context, solaris_status_t status)
{
    environment_t *e = context; CHECK(status == SOLARIS_OK);
    CHECK(solaris_dns_service_close(e->service) == SOLARIS_OK);
    if (mode(e, "callback_block") || mode(e, "queued_close")) solaris_test_event_signal(&e->checked);
}
static void completed(environment_t *e, solaris_status_t status)
{
    e->last_status = status;
    if (status == SOLARIS_OK) atomic_fetch_add(&e->successes, 1u); else atomic_fetch_add(&e->errors, 1u);
    unsigned callbacks = atomic_fetch_add(&e->callbacks, 1u) + 1u;
    if (callbacks == e->expected) {
        if (!mode(e, "stop") && !mode(e, "callback_block") && !mode(e, "queued_close")) CHECK(solaris_executor_post(e->owners[0], close_task, e) == SOLARIS_OK);
        solaris_test_event_signal(&e->finished);
    }
}
static void start_clients(void *context, solaris_status_t status);
static void schedule_network(void *context, solaris_status_t status);
static void action(void *context, solaris_status_t status)
{
    environment_t *e = context; e->action = NULL;
    if (status != SOLARIS_OK) return;
    if (mode(e, "stop")) { solaris_test_event_signal(&e->ready); return; }
    if (mode(e, "network")) { CHECK(solaris_dns_service_invalidate_network(e->service, 14u) == SOLARIS_OK); return; }
    if (mode(e, "stale_stop")) {
        CHECK(solaris_executor_post(e->owners[0], close_task, e) == SOLARIS_OK); solaris_test_event_signal(&e->finished); return;
    }
    if (mode(e, "stale")) { start_clients(e, SOLARIS_OK); return; }
    if (e->lookup_request) e->lookup.cancel(e->lookup.context, e->lookup_request);
    else if (e->clients[0].request) CHECK(solaris_dns_request_cancel(e->clients[0].request) == SOLARIS_OK);
}
static void wire_done(void *context, solaris_dns_request_t *request, const solaris_dns_service_result_t *result)
{
    client_t *client = context; environment_t *e = client->env;
    CHECK(solaris_executor_is_owner(e->owners[1]) && client->request == request && !e->starting); client->request = NULL;
    CHECK(result->view.config_revision == 11u && result->view.resolver_revision == 12u && result->view.network_revision == 13u);
    if (result->status == SOLARIS_OK) {
        CHECK(result->response && solaris_dns_wire_header(result->response)->id == solaris_dns_wire_header(client->query)->id);
        const solaris_dns_name_t *a = &solaris_dns_wire_question(result->response)->name;
        const solaris_dns_name_t *b = &solaris_dns_wire_question(client->query)->name;
        CHECK(a->length == b->length && !memcmp(a->bytes, b->bytes, a->length));
        const solaris_dns_record_t *record = solaris_dns_wire_record(result->response, mode(e, "alias") ? 1u : 0u);
        CHECK(record && record->type == SOLARIS_DNS_A);
        CHECK(record->value.address[3] == (mode(e, "hosts") ? 9u : mode(e, "stale") && e->phase == 2u ? 43u : 42u));
        if (mode(e, "hosts")) CHECK(result->source == SOLARIS_DNS_SOURCE_HOSTS);
        if (stale_mode(e) && e->phase) CHECK(result->source == SOLARIS_DNS_SOURCE_CACHE && (result->stale != 0) == (e->phase == 1u));
        if (mode(e, "alias")) CHECK(solaris_dns_wire_record(result->response, 0)->type == SOLARIS_DNS_CNAME);
        solaris_dns_wire_release(e->retained); e->retained = result->response; solaris_dns_wire_retain(e->retained);
    } else CHECK(!result->response);
    if (mode(e, "callback_block")) { solaris_test_event_signal(&e->ready); solaris_test_event_wait(&e->release); }
    if (stale_mode(e) && e->phase < 2u) {
        atomic_fetch_add(&e->callbacks, 1u); atomic_fetch_add(&e->successes, 1u); e->phase++;
        if (e->phase == 1u) { atomic_fetch_add(&e->offset, UINT64_C(2000000000)); start_clients(e, SOLARIS_OK); }
        else CHECK(solaris_deadline_start(e->owners[1], mode(e, "stale_stop") ? 50u : 150u, action, e, &e->action) == SOLARIS_OK);
        return;
    }
    completed(e, result->status);
}
static void lookup_done(void *context, solaris_status_t status, const solaris_address_t *addresses, size_t count)
{
    environment_t *e = context; CHECK(solaris_executor_is_owner(e->owners[1]) && e->lookup_request && !e->starting); e->lookup_request = NULL;
    if (status == SOLARIS_OK) {
        CHECK(addresses && count && count <= 16u);
        for (size_t i = 0; i < count; i++) CHECK(addresses[i].port == 443u);
        if (mode(e, "lookup_hosts")) CHECK(count == 1u && addresses[0].ip[3] == 9u);
        if (mode(e, "lookup")) CHECK(count == 2u && addresses[0].family == 6u && addresses[1].family == 4u);
        if (mode(e, "lookup_grace")) CHECK(count == 1u && addresses[0].family == 4u);
    } else CHECK(!addresses && !count);
    completed(e, status);
}
static void start_clients(void *context, solaris_status_t status)
{
    environment_t *e = context; CHECK(status == SOLARIS_OK); e->starting = 1;
    const char *failure = strstr(e->mode, "fail_");
    if (failure) atomic_store(&e->fail_at, atomic_load(&e->calls) + strtoul(failure + 5, NULL, 10));
    if (!strncmp(e->mode, "lookup", 6) || !strncmp(e->mode, "system", 6)) {
        solaris_address_t target; CHECK(solaris_address_parse(mode(e, "lookup_hosts") ? "hosts.test" :
            !strncmp(e->mode, "system", 6) ? "localhost" : "lookup.test", 443u, &target) == SOLARIS_OK);
        solaris_dns_lookup_view_t view = identity();
        solaris_status_t rc = e->lookup.start(e->lookup.context, e->owners[1], &view, &target,
            now(e) + (mode(e, "system_queued_timeout") ? UINT64_C(50000000) : UINT64_C(3000000000)), lookup_done, e, &e->lookup_request);
        if (rc != SOLARIS_OK) {
            CHECK(failure && rc == SOLARIS_ENOMEM && !e->lookup_request);
            e->expected = 0; e->last_status = rc; e->starting = 0;
            CHECK(solaris_executor_post(e->owners[0], close_task, e) == SOLARIS_OK); solaris_test_event_signal(&e->finished); return;
        }
        if (mode(e, "system_cancel") || mode(e, "system_queued_cancel")) e->lookup.cancel(e->lookup.context, e->lookup_request);
        e->starting = 0;
        return;
    }
    unsigned count = mode(e, "coalesce") ? 3u : mode(e, "cancel_peer") || mode(e, "role") || mode(e, "waiter_cap") || mode(e, "inflight_cap") ? 2u : 1u;
    for (unsigned i = 0; i < count; i++) {
        solaris_dns_query_options_t o = {.owner = e->owners[1], .view = identity(),
            .deadline_ns = now(e) + (mode(e, "deadline") ? UINT64_C(50000000) : UINT64_C(3000000000))};
        if (mode(e, "role") && i) o.view.role = SOLARIS_DNS_BOOTSTRAP;
        solaris_status_t rc = solaris_dns_service_query(e->binding, &o, e->clients[i].query, wire_done, &e->clients[i], &e->clients[i].request);
        if (rc != SOLARIS_OK) {
            CHECK(((!strncmp(e->mode, "fail_", 5) && rc == SOLARIS_ENOMEM) ||
                (mode(e, "namespace") && rc == SOLARIS_EINVAL)) && !e->clients[i].request);
            e->expected = 0; e->last_status = rc; CHECK(solaris_executor_post(e->owners[0], close_task, e) == SOLARIS_OK);
            e->starting = 0; solaris_test_event_signal(&e->finished); return;
        }
    }
    if (mode(e, "cancel_peer") || mode(e, "last_cancel") || mode(e, "stop"))
        CHECK(solaris_deadline_start(e->owners[1], 20u, action, e, &e->action) == SOLARIS_OK);
    if (mode(e, "network")) CHECK(solaris_executor_post(e->owners[0], schedule_network, e) == SOLARIS_OK);
    e->starting = 0;
    if (mode(e, "queued_network") || mode(e, "queued_close")) {
        solaris_test_event_signal(&e->ready); solaris_test_event_wait(&e->release);
    }
}
static void probed(void *context, solaris_dns_request_t *request, const solaris_dns_service_result_t *result)
{
    environment_t *e = context; CHECK(request == e->probe && result->status == SOLARIS_OK);
    e->probe = NULL; solaris_test_event_signal(&e->checked);
}
static void start_probe(void *context, solaris_status_t status)
{
    environment_t *e = context; CHECK(status == SOLARIS_OK);
    solaris_dns_query_options_t o = {.owner = e->owners[0], .view = identity(), .deadline_ns = now(e) + UINT64_C(3000000000)};
    CHECK(solaris_dns_service_query(e->binding, &o, e->clients[0].query, probed, e, &e->probe) == SOLARIS_OK);
}
static void invalidate_ready(void *context, solaris_status_t status)
{
    environment_t *e = context; CHECK(status == SOLARIS_OK);
    CHECK(solaris_dns_service_invalidate_network(e->service, 14u) == SOLARIS_OK); solaris_test_event_signal(&e->checked);
}
static void schedule_network(void *context, solaris_status_t status)
{
    environment_t *e = context; CHECK(status == SOLARIS_OK);
    CHECK(solaris_deadline_start(e->owners[0], 20u, action, e, &e->action) == SOLARIS_OK);
}
static void rejected_parent_done(void *context)
{
    environment_t *e = context; CHECK(!e->service && !atomic_load(&e->closed_count));
    solaris_test_event_signal(&e->closed);
}
static void setup(void *context, solaris_status_t status)
{
    environment_t *e = context; CHECK(status == SOLARIS_OK);
    solaris_address_t local; CHECK(solaris_address_parse("127.0.0.9", 0u, &local) == SOLARIS_OK);
    solaris_hosts_entry_t entries[] = {{"hosts.test", SOLARIS_HOSTS_ADDRESSES, &local, 1u, NULL},
        {"alias.test", SOLARIS_HOSTS_ALIAS, NULL, 0u, "upstream.test"}};
    CHECK(solaris_hosts_build(e->budget, entries, 2u, NULL, 0u, NULL, &e->hosts, NULL) == SOLARIS_OK);
    solaris_dns_upstream_t upstreams[2]; memset(upstreams, 0, sizeof(upstreams));
    upstreams[0].id = 101u; upstreams[0].transport = mode(e, "tcp") || mode(e, "failover") ? SOLARIS_DNS_TRANSPORT_TCP : SOLARIS_DNS_TRANSPORT_UDP;
    CHECK(solaris_address_parse("127.0.0.1", mode(e, "failover") ? e->bad_port : e->port, &upstreams[0].address) == SOLARIS_OK);
    upstreams[1] = upstreams[0]; upstreams[1].id = 102u; upstreams[1].transport = SOLARIS_DNS_TRANSPORT_UDP; upstreams[1].address.port = e->port;
    solaris_dns_resolver_view_options_t view; solaris_dns_resolver_view_options_init(&view);
    view.resolver_revision = 12u; view.network_revision = 13u; view.hosts = !strncmp(e->mode, "system", 6) ? NULL : e->hosts;
    view.wire_use_hosts = !(mode(e, "hosts_off") || mode(e, "lookup_hosts"));
    view.ipv6 = mode(e, "lookup") || mode(e, "lookup_grace") || !strncmp(e->mode, "system", 6);
    view.prefer_ipv6 = 1u; view.allow_system_lookup = !strncmp(e->mode, "system", 6); view.query_timeout_ms = 1000u;
    for (size_t i = 0; i < 5; i++) view.role[i] = (solaris_dns_role_options_t){1u, 2u, upstreams,
        !strncmp(e->mode, "system", 6) ? 0u : mode(e, "failover") ? 2u : 1u};
    CHECK(solaris_dns_resolver_view_create(e->budget, &view, &e->view) == SOLARIS_OK);
    solaris_dns_service_options_t options; solaris_dns_service_options_init(&options);
    options.owner = e->owners[0]; options.budget = e->budget; options.initial_network_revision = 13u;
    options.context = e; options.on_close = on_close; options.dialer.prepare_socket = protect; options.dialer.policy_context = e;
    if (mode(e, "waiter_cap")) options.waiters_per_query = 1u;
    if (mode(e, "inflight_cap")) options.inflight_limit = 1u;
    int reject_create = !strncmp(e->mode, "create_fail_", 12);
    if (reject_create) {
        CHECK(solaris_scope_init(&e->parent, e->owners[0], NULL, rejected_parent_done, e) == SOLARIS_OK);
        options.parent_scope = &e->parent;
        atomic_store(&e->fail_at, atomic_load(&e->calls) + strtoul(e->mode + 12, NULL, 10));
    }
    solaris_status_t rc = solaris_dns_service_create(&options, &e->service);
    if (reject_create) {
        CHECK(rc == SOLARIS_ENOMEM && !e->service); atomic_store(&e->fail_at, 0u); e->expected = 0; e->last_status = rc;
        solaris_dns_resolver_view_release(e->view); e->view = NULL; solaris_hosts_release(e->hosts); e->hosts = NULL;
        solaris_scope_cancel(&e->parent); solaris_test_event_signal(&e->created); solaris_test_event_signal(&e->finished); return;
    }
    CHECK(rc == SOLARIS_OK);
    CHECK(solaris_dns_binding_create(e->service, e->view, &e->binding) == SOLARIS_OK); e->lookup = solaris_dns_binding_lookup(e->binding);
    solaris_dns_resolver_view_release(e->view); e->view = NULL; solaris_hosts_release(e->hosts); e->hosts = NULL;
    memset(upstreams, 0xee, sizeof(upstreams)); memset(&view, 0xee, sizeof(view));
    solaris_test_event_signal(&e->created);
}
static void closed_start(void *context, solaris_status_t status)
{
    environment_t *e = context; CHECK(status == SOLARIS_OK);
    solaris_dns_query_options_t options = {.owner = e->owners[1], .view = identity(), .deadline_ns = now(e) + UINT64_C(1000000000)};
    solaris_dns_request_t *request = (void *)1;
    CHECK(solaris_dns_service_query(e->binding, &options, e->clients[0].query, wire_done, &e->clients[0], &request) ==
        (mode(e, "namespace") ? SOLARIS_EINVAL : SOLARIS_ECLOSED) && !request);
    solaris_test_event_signal(&e->checked);
}
typedef struct work_gate { uv_work_t work; solaris_test_event_t *entered, *release; } work_gate_t;
static void gate_work(uv_work_t *work)
{
    work_gate_t *gate = work->data;
    solaris_test_event_signal(gate->entered); solaris_test_event_wait(gate->release);
}
static void gate_done(uv_work_t *work, int status) { (void)work; CHECK(status == 0); }
int main(int argc, char **argv)
{
    CHECK(argc == 4); environment_t e; memset(&e, 0, sizeof(e)); e.mode = argv[1]; e.port = (uint16_t)strtoul(argv[2], NULL, 10); e.bad_port = (uint16_t)strtoul(argv[3], NULL, 10);
    int queued_system = !strncmp(e.mode, "system_queued_", 14);
    if (queued_system) CHECK(uv_os_setenv("UV_THREADPOOL_SIZE", "4") == 0);
    atomic_init(&e.calls, 0u); atomic_init(&e.fail_at, 0u); atomic_init(&e.failures, 0u); atomic_init(&e.offset, 0u);
    atomic_init(&e.callbacks, 0u); atomic_init(&e.policy_calls, 0u); atomic_init(&e.closed_count, 0u); atomic_init(&e.successes, 0u); atomic_init(&e.errors, 0u);
    CHECK(!solaris_test_event_init(&e.created, 0) && !solaris_test_event_init(&e.finished, 0) && !solaris_test_event_init(&e.closed, 0) &&
        !solaris_test_event_init(&e.ready, 0) && !solaris_test_event_init(&e.release, 0) && !solaris_test_event_init(&e.checked, 0));
    solaris_runtime_services_t services = {&e, allocate, deallocate, now, NULL};
    CHECK(solaris_budget_create(32u * 1024u * 1024u, &services, &e.budget) == SOLARIS_OK);
    for (unsigned i = 0; i < 2; i++) {
        solaris_executor_options_t options = {.id = i, .owner_context = mode(&e, "namespace") && i ? (void *)&services : (void *)&e,
            .queue_capacity = 128u, .resource_limit = 2048u, .budget = e.budget, .services = &services};
        CHECK(solaris_executor_create(&options, &e.owners[i]) == SOLARIS_OK);
        CHECK(solaris_executor_activate(e.owners[i], 1u) == SOLARIS_OK);
    }
    e.expected = mode(&e, "coalesce") || mode(&e, "stale") ? 3u : mode(&e, "cancel_peer") || mode(&e, "role") ||
        mode(&e, "waiter_cap") || mode(&e, "inflight_cap") || mode(&e, "stale_stop") ? 2u : 1u;
    for (unsigned i = 0; i < 3; i++) {
        e.clients[i] = (client_t){.env = &e, .index = i};
        solaris_dns_question_t question; memset(&question, 0, sizeof(question)); question.type = SOLARIS_DNS_A; question.class_code = SOLARIS_DNS_IN;
        const char *name = mode(&e, "hosts") || mode(&e, "hosts_off") ? "hosts.test" : mode(&e, "alias") ? "alias.test" :
            mode(&e, "inflight_cap") && i ? "other.test" : i == 1 ? "WIRE.TEST" : "wire.test";
        CHECK(solaris_dns_name_from_text(name, &question.name) == SOLARIS_OK);
        solaris_buffer_t *bytes; CHECK(solaris_dns_wire_make_query(e.budget, (uint16_t)(0x1000u + i), SOLARIS_DNS_RD, &question, NULL, &bytes) == SOLARIS_OK);
        solaris_dns_wire_t *query; CHECK(solaris_dns_wire_parse(e.budget, solaris_buffer_data(bytes), solaris_buffer_length(bytes), NULL, &query, NULL) == SOLARIS_OK);
        e.clients[i].query = query; solaris_buffer_release(bytes);
    }
    CHECK(solaris_executor_post(e.owners[0], setup, &e) == SOLARIS_OK); solaris_test_event_wait(&e.created);
    uv_loop_t gate_loop; work_gate_t gates[4]; solaris_test_event_t entered, gate_release;
    if (queued_system) {
        CHECK(uv_loop_init(&gate_loop) == 0 && !solaris_test_event_init(&entered, 0) && !solaris_test_event_init(&gate_release, 0));
        memset(gates, 0, sizeof(gates));
        for (unsigned i = 0; i < 4; i++) {
            gates[i].entered = &entered; gates[i].release = &gate_release; gates[i].work.data = &gates[i];
            CHECK(uv_queue_work(&gate_loop, &gates[i].work, gate_work, gate_done) == 0);
        }
        for (unsigned i = 0; i < 4; i++) solaris_test_event_wait(&entered);
    }
    if (e.service) CHECK(solaris_executor_post(e.owners[1], start_clients, &e) == SOLARIS_OK);
    if (mode(&e, "stop")) {
        solaris_test_event_wait(&e.ready);
        CHECK(solaris_executor_begin_quiesce(e.owners[0]) == SOLARIS_OK && solaris_executor_begin_quiesce(e.owners[1]) == SOLARIS_OK);
    } else if (mode(&e, "callback_block")) {
        solaris_test_event_wait(&e.ready); CHECK(solaris_executor_post(e.owners[0], close_task, &e) == SOLARIS_OK);
        solaris_test_event_wait(&e.checked); CHECK(!atomic_load(&e.closed_count)); solaris_test_event_signal(&e.release);
    } else if (mode(&e, "queued_network") || mode(&e, "queued_close")) {
        solaris_test_event_wait(&e.ready);
        CHECK(solaris_executor_post(e.owners[0], start_probe, &e) == SOLARIS_OK); solaris_test_event_wait(&e.checked);
        /* The same-key owner-0 probe completed, so owner-1's result is already
         * queued behind its blocked task. Revoke it before delivery. */
        CHECK(solaris_executor_post(e.owners[0], mode(&e, "queued_network") ? invalidate_ready : close_task, &e) == SOLARIS_OK);
        solaris_test_event_wait(&e.checked); CHECK(!atomic_load(&e.closed_count)); solaris_test_event_signal(&e.release);
    }
    solaris_test_event_wait(&e.finished); solaris_test_event_wait(&e.closed); atomic_store(&e.fail_at, 0u);
    if (queued_system) {
        for (unsigned i = 0; i < 4; i++) solaris_test_event_signal(&gate_release);
        CHECK(uv_run(&gate_loop, UV_RUN_DEFAULT) == 0 && uv_loop_close(&gate_loop) == 0);
        solaris_test_event_destroy(&entered); solaris_test_event_destroy(&gate_release);
    }
    if (!mode(&e, "stop")) {
        if (e.service) { CHECK(solaris_executor_post(e.owners[1], closed_start, &e) == SOLARIS_OK); solaris_test_event_wait(&e.checked); }
        CHECK(solaris_executor_begin_quiesce(e.owners[0]) == SOLARIS_OK && solaris_executor_begin_quiesce(e.owners[1]) == SOLARIS_OK);
    }
    CHECK(solaris_executor_wait_quiescent(e.owners[0]) == SOLARIS_OK && solaris_executor_wait_quiescent(e.owners[1]) == SOLARIS_OK);
    solaris_dns_binding_release(e.binding); solaris_dns_service_release(e.service);
    if (e.retained) CHECK(solaris_dns_wire_header(e.retained)->rcode == 0);
    solaris_dns_wire_release(e.retained); for (unsigned i = 0; i < 3; i++) solaris_dns_wire_release(e.clients[i].query);
    CHECK(solaris_executor_destroy(e.owners[0]) == SOLARIS_OK && solaris_executor_destroy(e.owners[1]) == SOLARIS_OK);
    CHECK(solaris_budget_used(e.budget) == 0u); solaris_budget_release(e.budget);
    solaris_test_event_destroy(&e.created); solaris_test_event_destroy(&e.finished); solaris_test_event_destroy(&e.closed);
    solaris_test_event_destroy(&e.ready); solaris_test_event_destroy(&e.release); solaris_test_event_destroy(&e.checked);
    printf("{\"callbacks\":%u,\"successes\":%u,\"errors\":%u,\"status\":%d,\"policy\":%u,\"failures\":%zu}\n",
        atomic_load(&e.callbacks), atomic_load(&e.successes), atomic_load(&e.errors), e.last_status, atomic_load(&e.policy_calls), atomic_load(&e.failures));
    return 0;
}
