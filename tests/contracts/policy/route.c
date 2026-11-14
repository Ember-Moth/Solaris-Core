#include "contracts/policy/route.h"
#include "runtime/engine/internal.h"
#include "support/runtime/event.h"
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)

typedef struct fixture { solaris_engine_t *engine; solaris_executor_t *owners[2]; atomic_int failure; atomic_uint_fast64_t time_shift; } fixture_t;
typedef struct scenario scenario_t;
typedef struct node { solaris_outbound_t outbound; scenario_t *scenario; uint64_t id; uint32_t caps; } node_t;
typedef struct lease { scenario_t *scenario; } lease_t;
enum { NORMAL, CANCEL_BEFORE_RUN, CANCEL_ACQUIRE, CANCEL_SETTLED, STOP_SETTLED, CANCEL_DNS, STOP_DNS, TIMEOUT_DNS };
struct scenario {
    fixture_t *fixture;
    solaris_executor_t *owner;
    solaris_route_job_t *job;
    solaris_route_options_t options;
    solaris_route_rule_t rules[160];
    node_t nodes[3];
    solaris_test_event_t started, ready, gate, released;
    solaris_deferred_t response, action;
    solaris_resolve_fn resolve_callback;
    void *resolve_user;
    solaris_address_t answers[3];
    size_t answer_count;
    solaris_status_t resolve_return, resolve_status, acquire_error, expected, start_status;
    uint64_t fail_target, expected_node, expected_rule, chosen_target, config_revision, selection_revision;
    unsigned retains, releases, callbacks, resolves, cancels, acquisitions, leases, lease_releases, opens;
    unsigned action_mode;
    int hold_dns, response_queued, dns_active, in_start, take, local, system_dns, fail_after, any_rule, expire_resolver;
};
static uint32_t capabilities(void *context) { return ((node_t *)context)->caps; }
static solaris_status_t stream_open(void *context, const solaris_address_t *target,
    const solaris_stream_callbacks_t *callbacks, void *user, solaris_stream_t **out)
{
    node_t *node = context; scenario_t *s = node->scenario; (void)callbacks; (void)user; *out = NULL;
    CHECK(node->id == s->expected_node && target->port == s->options.metadata.destination.port);
    s->opens++; return SOLARIS_EACCESS;
}
static solaris_status_t datagram_open(void *context, uint32_t family,
    const solaris_datagram_callbacks_t *callbacks, void *user, solaris_datagram_t **out)
{
    node_t *node = context; (void)family; (void)callbacks; (void)user; *out = NULL;
    CHECK(node->id == node->scenario->expected_node); node->scenario->opens++; return SOLARIS_EACCESS;
}
static const solaris_outbound_ops_t operations = {.capabilities = capabilities, .open_stream = stream_open, .open_datagram = datagram_open};
static void *allocate(void *context, size_t size)
{
    fixture_t *f = context; int value = atomic_load(&f->failure);
    if (!value) return NULL;
    if (value > 0) atomic_fetch_sub(&f->failure, 1);
    return malloc(size);
}
static void retain(void *context) { scenario_t *s = context; CHECK(solaris_executor_is_owner(s->owner)); s->retains++; }
static void release(void *context)
{
    scenario_t *s = context; CHECK(solaris_executor_is_owner(s->owner));
    CHECK(s->callbacks == 1 && s->leases == s->lease_releases);
    s->releases++; solaris_test_event_signal(&s->released);
}
static void release_lease(void *context)
{
    lease_t *lease = context; CHECK(solaris_executor_is_owner(lease->scenario->owner));
    lease->scenario->lease_releases++; solaris_memory_free(lease);
}
static void after_acquire(void *context)
{
    scenario_t *s = context;
    if (s->action_mode == CANCEL_SETTLED) solaris_route_cancel(s->job);
    else {
        CHECK(s->action_mode == STOP_SETTLED);
        solaris_test_event_signal(&s->ready);
        solaris_test_event_wait(&s->gate);
        CHECK(!solaris_executor_accepting(s->owner));
    }
}
static solaris_status_t acquire(void *context, solaris_executor_t *owner, uint64_t target,
    solaris_dial_plan_t *out, uint32_t *caps)
{
    scenario_t *s = context; CHECK(owner == s->owner && solaris_executor_is_owner(owner));
    s->acquisitions++;
    if (s->fail_target == target) return s->acquire_error;
    if (target == 4) target = s->chosen_target;
    CHECK(target >= 1 && target <= 3);
    lease_t *lease = solaris_memory_allocate(solaris_executor_budget(owner), sizeof(*lease));
    if (!lease) return SOLARIS_ENOMEM;
    lease->scenario = s; s->leases++;
    *out = (solaris_dial_plan_t){.outbound = &s->nodes[target - 1].outbound, .context = lease,
        .release = release_lease, .node_id = target, .selection_revision = s->selection_revision};
    *caps = s->nodes[target - 1].caps;
    if (s->action_mode == CANCEL_ACQUIRE) solaris_route_cancel(s->job);
    if (s->action_mode == CANCEL_SETTLED || s->action_mode == STOP_SETTLED) {
        CHECK(!s->action.queued); CHECK(solaris_executor_defer(owner, &s->action) == SOLARIS_OK);
    }
    return SOLARIS_OK;
}
static uint64_t test_now(void *context)
{ fixture_t *f = context; return uv_hrtime() + atomic_load(&f->time_shift); }
static void expire_resolver(scenario_t *s)
{
    if (s->expire_resolver)
        atomic_fetch_add(&s->fixture->time_shift, (s->options.timeout_ms + 1) * UINT64_C(1000000));
}
static void resolved(void *context)
{
    scenario_t *s = context; CHECK(s->dns_active); s->dns_active = 0;
    expire_resolver(s);
    s->resolve_callback(s->resolve_user, s->resolve_status,
        s->resolve_status == SOLARIS_OK ? s->answers : NULL, s->resolve_status == SOLARIS_OK ? s->answer_count : 0);
}
static void queue_response(scenario_t *s)
{
    if (s->response_queued) return;
    s->response_queued = 1;
    CHECK(solaris_executor_defer(s->owner, &s->response) == SOLARIS_OK);
}
static solaris_status_t resolve(void *context, solaris_executor_t *owner, const solaris_address_t *target,
    uint64_t timeout, solaris_resolve_fn callback, void *user, void **request)
{
    scenario_t *s = context; CHECK(owner == s->owner && timeout > 0 && !s->dns_active);
    CHECK(solaris_address_equal(target, &s->options.metadata.destination)); s->resolves++;
    if (s->resolve_return != SOLARIS_OK) { expire_resolver(s); return s->resolve_return; }
    s->resolve_callback = callback; s->resolve_user = user; s->dns_active = 1; *request = s;
    if (s->hold_dns) solaris_test_event_signal(&s->ready); else queue_response(s);
    return SOLARIS_OK;
}
static void cancel_resolve(void *context, void *request)
{
    scenario_t *s = context; CHECK(request == s && s->dns_active); s->cancels++;
    /* Deliberately return the original successful result after cancellation. */
    queue_response(s);
}
static void done(void *context, solaris_status_t status, solaris_route_result_t *result)
{
    scenario_t *s = context; CHECK(!s->in_start && solaris_executor_is_owner(s->owner));
    CHECK(++s->callbacks == 1 && status == s->expected && !s->releases && !s->dns_active);
    CHECK(result->metadata.config_revision == s->config_revision && result->metadata.selection_revision == s->selection_revision);
    CHECK(solaris_address_equal(&result->metadata.destination, &s->options.metadata.destination));
    if (status == SOLARIS_OK) {
        CHECK(result->plan.node_id == s->expected_node);
        CHECK(s->any_rule ? result->rule_index < s->options.rule_count : result->rule_index == s->expected_rule);
        CHECK(result->plan.selection_revision == s->selection_revision);
        if (s->local) CHECK(result->metadata.resolved_valid && result->dial_target.family != SOLARIS_ADDRESS_DOMAIN &&
            result->dial_target.port == s->options.metadata.destination.port &&
            solaris_address_equal(&result->dial_target, &result->metadata.resolved));
        else CHECK(solaris_address_equal(&result->dial_target, &s->options.metadata.destination));
        if (s->take) {
            solaris_dial_plan_t plan; CHECK(solaris_route_result_take_plan(result, &plan) == SOLARIS_OK && !result->plan.outbound);
            solaris_stream_t *stream; solaris_datagram_t *datagram;
            solaris_stream_callbacks_t callbacks = {0}; solaris_datagram_callbacks_t datagram_callbacks = {0};
            if (s->options.metadata.network == SOLARIS_NETWORK_TCP)
                CHECK(solaris_outbound_open_stream(plan.outbound, &result->dial_target, &callbacks, NULL, &stream) == SOLARIS_EACCESS && !stream);
            else CHECK(solaris_outbound_open_datagram(plan.outbound, SOLARIS_ADDRESS_IPV4, &datagram_callbacks, NULL, &datagram) == SOLARIS_EACCESS && !datagram);
            CHECK(solaris_dial_plan_release(&plan) == SOLARIS_OK);
            CHECK(solaris_route_result_take_plan(result, &plan) == SOLARIS_EINVAL && !plan.outbound);
        }
    } else CHECK(!result->plan.outbound && !s->opens);
    s->job = NULL;
}
static void start(void *context, solaris_status_t status)
{
    scenario_t *s = context; CHECK(status == SOLARIS_OK);
    s->options.owner = s->owner; s->options.metadata.config_revision = s->config_revision;
    s->options.metadata.selection_revision = s->selection_revision;
    if (s->system_dns) { s->options.resolve = NULL; s->options.cancel_resolve = NULL; }
    s->in_start = 1;
    atomic_store(&s->fixture->failure, s->fail_after);
    s->start_status = solaris_route_start(&s->options, &s->job);
    atomic_store(&s->fixture->failure, -1);
    CHECK(!s->callbacks);
    if (s->start_status == SOLARIS_OK) {
        CHECK(s->job && s->retains == 1);
        if (s->action_mode == CANCEL_BEFORE_RUN) solaris_route_cancel(s->job);
    } else CHECK(!s->job && !s->retains);
    s->in_start = 0; solaris_test_event_signal(&s->started);
}
static void cancel(void *context, solaris_status_t status)
{ scenario_t *s = context; CHECK(status == SOLARIS_OK); solaris_route_cancel(s->job); }
static void deliver(void *context, solaris_status_t status)
{ scenario_t *s = context; CHECK(status == SOLARIS_OK); queue_response(s); }
static void initialize(scenario_t *s, fixture_t *f, unsigned owner)
{
    memset(s, 0, sizeof(*s)); s->fixture = f; s->owner = f->owners[owner];
    CHECK(!solaris_test_event_init(&s->started, 0) && !solaris_test_event_init(&s->ready, 0) &&
        !solaris_test_event_init(&s->gate, 0) && !solaris_test_event_init(&s->released, 0));
    s->fail_after = -1; s->take = 1; s->expected_node = 2; s->chosen_target = 2;
    s->config_revision = 7; s->selection_revision = 11;
    s->response = (solaris_deferred_t){.run = resolved, .context = s};
    s->action = (solaris_deferred_t){.run = after_acquire, .context = s};
    for (size_t i = 0; i < 3; ++i) {
        s->nodes[i] = (node_t){.outbound = {&operations, &s->nodes[i], s->owner}, .scenario = s, .id = i + 1,
            .caps = SOLARIS_OUTBOUND_STREAM | SOLARIS_OUTBOUND_DATAGRAM | SOLARIS_OUTBOUND_STREAM_DOMAIN | SOLARIS_OUTBOUND_DATAGRAM_DOMAIN};
    }
    s->options = (solaris_route_options_t){.owner = s->owner, .mode = SOLARIS_MODE_RULE, .rules = s->rules,
        .direct_target = 1, .global_target = 3, .timeout_ms = 1000, .context = s, .retain = retain, .release = release,
        .acquire = acquire, .resolve = resolve, .cancel_resolve = cancel_resolve, .done = done, .user = s};
    s->options.metadata.network = SOLARIS_NETWORK_TCP;
    CHECK(solaris_address_parse("Example.COM.", 443, &s->options.metadata.destination) == SOLARIS_OK);
    CHECK(solaris_address_parse("192.168.1.19", 50000, &s->options.metadata.source) == SOLARIS_OK);
    CHECK(solaris_address_parse("10.1.2.3", 0, &s->answers[0]) == SOLARIS_OK); s->answer_count = 1;
}
static void rule(scenario_t *s, const char *kind, const char *value, int no_resolve, uint64_t target)
{
    CHECK(s->options.rule_count < sizeof(s->rules) / sizeof(*s->rules));
    CHECK(solaris_route_rule_compile(kind, value, no_resolve, target, &s->rules[s->options.rule_count++], NULL) == SOLARIS_OK);
}
static void begin(scenario_t *s)
{
    CHECK(solaris_executor_post(s->owner, start, s) == SOLARIS_OK); solaris_test_event_wait(&s->started);
    CHECK(s->start_status == SOLARIS_OK);
}
static void finish(scenario_t *s)
{
    solaris_test_event_wait(&s->released);
    CHECK(s->callbacks == 1 && s->retains == 1 && s->releases == 1 && s->lease_releases == s->leases && !s->job);
    solaris_test_event_destroy(&s->started); solaris_test_event_destroy(&s->ready);
    solaris_test_event_destroy(&s->gate); solaris_test_event_destroy(&s->released);
}
static void execute(scenario_t *s) { begin(s); finish(s); }
static void fixture_start(fixture_t *f, unsigned resources)
{
    memset(f, 0, sizeof(*f)); atomic_init(&f->failure, -1); atomic_init(&f->time_shift, 0);
    solaris_runtime_services_t services; solaris_runtime_services_init(&services); services.context = f; services.allocate = allocate; services.now_ns = test_now;
    solaris_engine_options_t options; solaris_engine_options_init(&options); options.io_workers = 2; options.io_resource_limit = resources;
    CHECK(solaris_runtime_create(&options, NULL, &services, &f->engine, NULL) == SOLARIS_OK);
    uint64_t operation; CHECK(solaris_engine_start(f->engine, &operation, NULL) == SOLARIS_OK);
    CHECK(solaris_engine_flush(f->engine, 5000, NULL) == SOLARIS_OK);
    f->owners[0] = solaris_runtime_executor(f->engine, 0); f->owners[1] = solaris_runtime_executor(f->engine, 1);
    CHECK(f->owners[0] != f->owners[1]);
}
static void fixture_stop(fixture_t *f)
{
    uint64_t operation; CHECK(solaris_engine_stop(f->engine, &operation, NULL) == SOLARIS_OK);
    CHECK(solaris_engine_flush(f->engine, 5000, NULL) == SOLARIS_OK);
    solaris_engine_snapshot_t snapshot; CHECK(solaris_engine_get_snapshot(f->engine, &snapshot, NULL) == SOLARIS_OK && !snapshot.io_buffer_bytes);
    CHECK(solaris_engine_destroy(f->engine, NULL) == SOLARIS_OK);
}
static void compile_rules(void)
{
    solaris_route_rule_t r; solaris_error_t error;
    CHECK(solaris_route_rule_compile("DOMAIN", " Example.COM. ", 0, 9, &r, &error) == SOLARIS_OK && !strcmp(r.domain, "example.com"));
    CHECK(solaris_route_rule_compile("DOMAIN-SUFFIX", ".Example.COM.", 0, 9, &r, &error) == SOLARIS_OK && !strcmp(r.domain, "example.com"));
    CHECK(solaris_route_rule_compile("IP-CIDR", "10.11.12.13/9", 1, 9, &r, &error) == SOLARIS_OK && r.address.ip[0] == 10 && !r.address.ip[1] && r.prefix_length == 9);
    CHECK(solaris_route_rule_compile("IP-CIDR6", "2001:db8::ffff/64", 0, 9, &r, &error) == SOLARIS_OK && !r.address.ip[15]);
    const char *bad[][3] = {{"NOT-A-RULE", "x", "0"}, {"DOMAIN", "", "0"}, {"DOMAIN", "a..b", "0"},
        {"DOMAIN", "a/b", "0"}, {"DOMAIN", "a", "1"}, {"IP-CIDR", "::1/128", "0"},
        {"IP-CIDR6", "127.0.0.1/8", "0"}, {"IP-CIDR", "10.0.0.1/33", "0"}, {"IP-CIDR", "10.0.0.1/-1", "0"},
        {"IP-CIDR", "10.0.0.1/1/2", "0"}, {"SRC-PORT", "65536", "0"}, {"DST-PORT", "100-99", "0"},
        {"DST-PORT", "1-2-3", "0"}, {"DST-PORT", "-1", "0"}, {"NETWORK", "sctp", "0"}, {"FINAL", "extra", "0"}};
    for (size_t i = 0; i < sizeof(bad) / sizeof(*bad); ++i) {
        memset(&r, 255, sizeof(r));
        CHECK(solaris_route_rule_compile(bad[i][0], bad[i][1], atoi(bad[i][2]), 9, &r, &error) != SOLARIS_OK);
        CHECK(!r.kind && error.code != SOLARIS_OK && error.message[0]);
    }
    CHECK(solaris_route_rule_compile("FINAL", NULL, 0, 1, &r, NULL) == SOLARIS_OK);
}
static void matching(fixture_t *f)
{
    const char *kinds[] = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR", "SRC-PORT", "DST-PORT", "NETWORK", "FINAL"};
    const char *values[] = {"example.com", "example.com", "ample", "10.0.0.0/8", "2001:db8::/32", "192.168.0.0/16", "49999-50001", "443", "tcp", ""};
    for (unsigned i = 0; i < 10; ++i) {
        scenario_t s; initialize(&s, f, i % 2); rule(&s, kinds[i], values[i], 0, 2);
        if (i == 4) CHECK(solaris_address_parse("2001:db8::9", 0, &s.answers[0]) == SOLARIS_OK);
        execute(&s); CHECK(s.resolves == (i == 3 || i == 4 ? 1u : 0u));
    }
    scenario_t s; initialize(&s, f, 0); rule(&s, "DOMAIN-SUFFIX", "example.com", 0, 2);
    CHECK(solaris_address_parse("badexample.com", 443, &s.options.metadata.destination) == SOLARIS_OK);
    s.expected_node = 1; s.expected_rule = UINT64_MAX; execute(&s); CHECK(!s.resolves);
    initialize(&s, f, 1); rule(&s, "DOMAIN-SUFFIX", "example.com", 0, 2);
    CHECK(solaris_address_parse("a.example.com", 443, &s.options.metadata.destination) == SOLARIS_OK); execute(&s);
    initialize(&s, f, 0); rule(&s, "IP-CIDR", "10.0.0.0/8", 0, 2);
    CHECK(solaris_address_parse("::ffff:10.1.2.3", 443, &s.options.metadata.destination) == SOLARIS_OK); execute(&s); CHECK(!s.resolves);
    initialize(&s, f, 1); for (unsigned i = 0; i < 140; ++i) rule(&s, "DOMAIN", "miss.example", 0, 3);
    rule(&s, "FINAL", "", 0, 2); s.expected_rule = 140; execute(&s);
}
static void resolution(fixture_t *f)
{
    scenario_t s; initialize(&s, f, 0); rule(&s, "DOMAIN", "example.com", 0, 2); rule(&s, "IP-CIDR", "0.0.0.0/0", 0, 3);
    execute(&s); CHECK(!s.resolves);
    initialize(&s, f, 1); rule(&s, "IP-CIDR", "10.0.0.0/8", 1, 3); rule(&s, "FINAL", "", 0, 2);
    s.expected_rule = 1; execute(&s); CHECK(!s.resolves);
    initialize(&s, f, 0); rule(&s, "IP-CIDR", "10.0.0.0/8", 1, 2); s.options.metadata.resolved = s.answers[0]; s.options.metadata.resolved_valid = 1;
    execute(&s); CHECK(!s.resolves);
    initialize(&s, f, 1); rule(&s, "IP-CIDR", "192.0.2.0/24", 1, 3); rule(&s, "IP-CIDR", "192.0.2.0/24", 0, 3);
    rule(&s, "IP-CIDR", "10.0.0.0/8", 1, 2); s.expected_rule = 2; execute(&s); CHECK(s.resolves == 1);
    for (unsigned failed = 0; failed < 2; ++failed) {
        initialize(&s, f, failed); rule(&s, "IP-CIDR", "10.0.0.0/8", 0, 3); rule(&s, "IP-CIDR6", "::/0", 0, 3);
        rule(&s, "FINAL", "", 0, 2); s.expected_rule = 2;
        if (failed) s.resolve_return = SOLARIS_EIO; else s.resolve_status = SOLARIS_EIO;
        execute(&s); CHECK(s.resolves == 1);
    }
    initialize(&s, f, 0); rule(&s, "IP-CIDR", "10.0.0.0/8", 0, 2); s.nodes[1].caps |= SOLARIS_OUTBOUND_LOCAL_RESOLUTION; s.local = 1;
    execute(&s); CHECK(s.resolves == 1);
    initialize(&s, f, 1); rule(&s, "IP-CIDR", "192.0.2.0/24", 0, 3); rule(&s, "IP-CIDR", "10.0.0.0/8", 0, 2);
    CHECK(solaris_address_parse("192.0.2.9", 0, &s.answers[1]) == SOLARIS_OK); s.answer_count = 2; s.expected_rule = 1;
    execute(&s); CHECK(s.resolves == 1);
    initialize(&s, f, 0); s.system_dns = 1; rule(&s, "IP-CIDR", "127.0.0.0/8", 0, 2); rule(&s, "IP-CIDR6", "::1/128", 0, 2);
    CHECK(solaris_address_parse("localhost", 443, &s.options.metadata.destination) == SOLARIS_OK);
    s.any_rule = 1; s.local = 1; s.nodes[1].caps |= SOLARIS_OUTBOUND_LOCAL_RESOLUTION;
    execute(&s); CHECK(s.resolves == 0);

}
static void terminal_resolution(fixture_t *f)
{
    const solaris_status_t statuses[] = {SOLARIS_ECANCELLED, SOLARIS_ECLOSED,
        SOLARIS_EACCESS, SOLARIS_ENETWORK_CHANGED};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        for (unsigned variant = 0; variant < 4; ++variant) {
            unsigned rejected = variant & 1u;
            scenario_t s; initialize(&s, f, rejected); s.expire_resolver = variant >= 2;
            rule(&s, "IP-CIDR", "10.0.0.0/8", 0, 3);
            rule(&s, "FINAL", "", 0, 2);
            s.expected = statuses[i];
            if (rejected) s.resolve_return = statuses[i];
            else s.resolve_status = statuses[i];
            execute(&s);
            CHECK(s.resolves == 1 && !s.acquisitions && !s.opens);
        }
    }
}
static void modes(fixture_t *f)
{
    for (solaris_mode_t mode = SOLARIS_MODE_RULE; mode <= SOLARIS_MODE_DIRECT; ++mode) {
        scenario_t s; initialize(&s, f, 0); s.options.mode = mode; rule(&s, "FINAL", "", 0, 2);
        s.expected_node = mode == SOLARIS_MODE_RULE ? 2 : mode == SOLARIS_MODE_GLOBAL ? 3 : 1;
        s.expected_rule = mode == SOLARIS_MODE_RULE ? 0 : UINT64_MAX; execute(&s); CHECK(!s.resolves);
    }
    scenario_t s; initialize(&s, f, 1); s.expected_node = 1; s.expected_rule = UINT64_MAX; s.take = 0; execute(&s);
    initialize(&s, f, 0); s.options.metadata.network = SOLARIS_NETWORK_UDP;
    rule(&s, "NETWORK", "udp", 0, 3); rule(&s, "FINAL", "", 0, 2); s.nodes[2].caps &= ~SOLARIS_OUTBOUND_DATAGRAM;
    s.expected_rule = 1; execute(&s); CHECK(s.acquisitions == 2 && s.lease_releases == 2 && s.opens == 1);
    initialize(&s, f, 1); s.options.mode = SOLARIS_MODE_GLOBAL; s.options.metadata.network = SOLARIS_NETWORK_UDP;
    s.nodes[2].caps &= ~SOLARIS_OUTBOUND_DATAGRAM; s.expected = SOLARIS_ENOTSUP; execute(&s); CHECK(s.acquisitions == 1);
    initialize(&s, f, 0); rule(&s, "FINAL", "", 0, 2); s.nodes[1].caps &= ~SOLARIS_OUTBOUND_STREAM; s.expected = SOLARIS_ENOTSUP; execute(&s);
    initialize(&s, f, 1); rule(&s, "FINAL", "", 0, 2); rule(&s, "FINAL", "", 0, 3);
    s.fail_target = 2; s.acquire_error = SOLARIS_EAGAIN; s.expected = SOLARIS_EAGAIN; execute(&s); CHECK(s.acquisitions == 1);
}
static void cancellations(fixture_t *f)
{
    for (unsigned mode = CANCEL_BEFORE_RUN; mode <= CANCEL_SETTLED; ++mode) {
        scenario_t s; initialize(&s, f, 0); rule(&s, "FINAL", "", 0, 2);
        s.action_mode = mode; s.expected = SOLARIS_ECANCELLED; execute(&s); CHECK(!s.opens);
    }
    for (unsigned timeout = 0; timeout < 2; ++timeout) {
        scenario_t s; initialize(&s, f, 1); rule(&s, "IP-CIDR", "10.0.0.0/8", 0, 2);
        s.hold_dns = 1; s.options.timeout_ms = timeout ? 30 : 1000;
        s.expected = timeout ? SOLARIS_ETIMEDOUT : SOLARIS_ECANCELLED;
        begin(&s); solaris_test_event_wait(&s.ready);
        if (!timeout) CHECK(solaris_executor_post(s.owner, cancel, &s) == SOLARIS_OK);
        finish(&s); CHECK(s.resolves == 1 && s.cancels == 1 && !s.acquisitions && !s.opens);
    }
}
static void revisions(fixture_t *f)
{
    scenario_t old, fresh; initialize(&old, f, 0); initialize(&fresh, f, 1);
    rule(&old, "IP-CIDR", "10.0.0.0/8", 0, 4); old.hold_dns = 1;
    rule(&fresh, "FINAL", "", 0, 4); fresh.config_revision = 8; fresh.selection_revision = 12;
    fresh.chosen_target = fresh.expected_node = 3;
    begin(&old); solaris_test_event_wait(&old.ready);
    execute(&fresh);
    CHECK(solaris_executor_post(old.owner, deliver, &old) == SOLARIS_OK); finish(&old);
    CHECK(old.resolves == 1 && old.opens == 1 && fresh.opens == 1);
}
static void rejected_starts(fixture_t *f)
{
    for (int failure = 0; failure < 2; ++failure) {
        scenario_t s; initialize(&s, f, 0); rule(&s, "FINAL", "", 0, 2); s.fail_after = failure;
        CHECK(solaris_executor_post(s.owner, start, &s) == SOLARIS_OK); solaris_test_event_wait(&s.started);
        CHECK(s.start_status == SOLARIS_ENOMEM && !s.callbacks && !s.retains && !s.job);
        solaris_test_event_destroy(&s.started); solaris_test_event_destroy(&s.ready);
        solaris_test_event_destroy(&s.gate); solaris_test_event_destroy(&s.released);
    }
    scenario_t s; initialize(&s, f, 0);
    CHECK(solaris_route_start(&s.options, &s.job) == SOLARIS_ETHREAD && !s.job);
    solaris_test_event_destroy(&s.started); solaris_test_event_destroy(&s.ready);
    solaris_test_event_destroy(&s.gate); solaris_test_event_destroy(&s.released);
}
static void stopped(unsigned action)
{
    fixture_t f; fixture_start(&f, 64); scenario_t s; initialize(&s, &f, 0);
    s.action_mode = action; s.expected = SOLARIS_ECANCELLED;
    if (action == STOP_DNS) { s.hold_dns = 1; rule(&s, "IP-CIDR", "10.0.0.0/8", 0, 2); }
    else rule(&s, "FINAL", "", 0, 2);
    begin(&s); solaris_test_event_wait(&s.ready);
    uint64_t operation; CHECK(solaris_engine_stop(f.engine, &operation, NULL) == SOLARIS_OK);
    if (action == STOP_SETTLED) {
        uint64_t until = uv_hrtime() + UINT64_C(2000000000);
        while (solaris_executor_accepting(s.owner)) { CHECK(uv_hrtime() < until); uv_sleep(1); }
        solaris_test_event_signal(&s.gate);
    }
    finish(&s); CHECK(!s.opens);
    CHECK(solaris_engine_flush(f.engine, 5000, NULL) == SOLARIS_OK);
    fixture_stop(&f);
}
static void resource_limit(void)
{
    fixture_t f; fixture_start(&f, 1); scenario_t s; initialize(&s, &f, 0);
    CHECK(solaris_executor_post(s.owner, start, &s) == SOLARIS_OK); solaris_test_event_wait(&s.started);
    CHECK(s.start_status == SOLARIS_EAGAIN && !s.callbacks && !s.retains && !s.job);
    solaris_test_event_destroy(&s.started); solaris_test_event_destroy(&s.ready);
    solaris_test_event_destroy(&s.gate); solaris_test_event_destroy(&s.released);
    fixture_stop(&f);
}
int main(void)
{
    compile_rules(); fixture_t f; fixture_start(&f, 512);
    matching(&f); resolution(&f); terminal_resolution(&f); modes(&f); cancellations(&f); revisions(&f); rejected_starts(&f);
    fixture_stop(&f); stopped(STOP_DNS); stopped(STOP_SETTLED); resource_limit();
    puts("M2 route: 10 matchers, lazy DNS/no-resolve, same-plan UDP filtering, pinned revisions, deferred completion, cancellation after selection, stop and allocation rollback passed");
    return 0;
}
