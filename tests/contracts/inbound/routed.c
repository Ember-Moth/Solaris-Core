#include "contracts/inbound/proxy.h"
#include "contracts/module/module.h"
#include "runtime/engine/internal.h"
#include "transport/socket/tcp.h"
#include "support/runtime/event.h"
#include <stdatomic.h>
#include <stdio.h>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <uv.h>
#define CHECK(x)                                                                                                       \
    do {                                                                                                               \
        if (!(x)) {                                                                                                    \
            fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x);                                                    \
            abort();                                                                                                   \
        }                                                                                                              \
    } while (0)
typedef struct fixture fixture_t;
typedef struct view {
    fixture_t *fixture;
    solaris_proxy_inbound_t *inbound;
    uint32_t revision, auth_revision;
    atomic_uint refs;
    int udp;
    solaris_route_rule_t rules[2];
} view_t;
typedef struct plan_lease {
    solaris_dial_plan_t inner;
    view_t *view;
} plan_lease_t;
typedef struct dns_request {
    struct dns_request *next;
    fixture_t *fixture;
    solaris_deferred_t deferred;
    solaris_resolve_fn callback;
    void *context;
    solaris_address_t address;
    uint32_t revision;
    int cancelled;
} dns_request_t;
struct fixture {
    solaris_engine_t *engine;
    solaris_executor_t *owner;
    solaris_module_instance_t *direct, *block;
    solaris_scope_t service, probe;
    solaris_tcp_listener_t *listener;
    solaris_address_t bound;
    solaris_proxy_inbound_options_t base;
    view_t views[16], *active;
    dns_request_t *dns;
    uv_mutex_t output;
    solaris_test_event_t ready;
    uint32_t flip_revision;
    int service_open, hold_dns;
    size_t probe_budget;
};
typedef struct command {
    fixture_t *fixture;
    uint8_t type;
    uint8_t *data;
    size_t length;
} command_t;
static uint32_t get32(const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}
static void put32(uint8_t *p, uint32_t n)
{
    p[0] = (uint8_t)(n >> 24);
    p[1] = (uint8_t)(n >> 16);
    p[2] = (uint8_t)(n >> 8);
    p[3] = (uint8_t)n;
}
static void event(fixture_t *f, uint8_t kind, const void *bytes, size_t length)
{
    uint8_t head[5] = {kind};
    put32(head + 1, (uint32_t)length);
    uv_mutex_lock(&f->output);
    CHECK(fwrite(head, 1, 5, stdout) == 5);
    CHECK(!length || fwrite(bytes, 1, length, stdout) == length);
    CHECK(!fflush(stdout));
    uv_mutex_unlock(&f->output);
}
static void number(fixture_t *f, uint8_t kind, uint32_t value)
{
    uint8_t bytes[4];
    put32(bytes, value);
    event(f, kind, bytes, sizeof(bytes));
}
static void retain(void *context)
{
    view_t *v = context;
    atomic_fetch_add(&v->refs, 1);
}
static void release(void *context)
{
    view_t *v = context;
    CHECK(atomic_fetch_sub(&v->refs, 1) > 0);
}
static void inbound_closed(void *context, const solaris_proxy_inbound_snapshot_t *snapshot, solaris_status_t status)
{
    view_t *v = context;
    (void)status;
    CHECK(snapshot->closing && !snapshot->connections);
    v->inbound = NULL;
    number(v->fixture, 'V', v->revision);
}
static void publish(fixture_t *f, view_t *next)
{
    view_t *previous = f->active;
    f->active = next;
    if (previous && previous != next && previous->inbound)
        CHECK(solaris_proxy_inbound_retire(previous->inbound) == SOLARIS_OK);
}
static solaris_status_t authenticate(void *context, const uint8_t *username, size_t user_length,
                                     const uint8_t *password, size_t pass_length)
{
    view_t *v = context;
    const char *expected = v->auth_revision == 1 ? "pass" : "newpass";
    return user_length == 4 && !memcmp(username, "user", 4) && pass_length == strlen(expected) &&
                   !memcmp(password, expected, pass_length)
               ? SOLARIS_OK
               : SOLARIS_EACCESS;
}
static void plan_release(void *context)
{
    plan_lease_t *lease = context;
    CHECK(solaris_dial_plan_release(&lease->inner) == SOLARIS_OK);
    release(lease->view);
    solaris_memory_free(lease);
}
static solaris_status_t acquire(void *context, solaris_executor_t *owner, uint64_t target, solaris_dial_plan_t *plan,
                                uint32_t *caps)
{
    view_t *v = context;
    CHECK(owner == v->fixture->owner && atomic_load(&v->refs));
    solaris_module_instance_t *module = target == 1 ? v->fixture->direct : v->fixture->block;
    CHECK(target == 1 || target == 2);
    solaris_status_t rc = solaris_module_plan_acquire(module, ((uint64_t)v->revision << 32) | target, plan);
    if (rc == SOLARIS_OK) {
        rc = solaris_outbound_capabilities(plan->outbound, caps);
        plan->selection_revision = v->revision;
        if (rc != SOLARIS_OK)
            (void)solaris_dial_plan_release(plan);
        else {
            plan_lease_t *lease = solaris_memory_allocate(solaris_executor_budget(owner), sizeof(*lease));
            if (!lease) {
                (void)solaris_dial_plan_release(plan);
                rc = SOLARIS_ENOMEM;
            } else {
                lease->inner = *plan;
                lease->view = v;
                retain(v);
                plan->context = lease;
                plan->release = plan_release;
            }
        }
    }
    uint8_t bytes[8];
    put32(bytes, v->revision);
    put32(bytes + 4, (uint32_t)target);
    event(v->fixture, 'P', bytes, 8);
    return rc;
}
static void dns_complete(void *context)
{
    dns_request_t *request = context;
    fixture_t *f = request->fixture;
    dns_request_t **cursor = &f->dns;
    while (*cursor != request) {
        CHECK(*cursor);
        cursor = &(*cursor)->next;
    }
    *cursor = request->next;
    /* The mock deliberately publishes success even after cancellation. */
    request->callback(request->context, SOLARIS_OK, &request->address, 1);
    solaris_memory_free(request);
}
static solaris_status_t resolve(void *context, solaris_executor_t *owner, const solaris_address_t *target,
                                uint64_t timeout, solaris_resolve_fn callback, void *user, void **out)
{
    view_t *v = context;
    fixture_t *f = v->fixture;
    CHECK(owner == f->owner && timeout && atomic_load(&v->refs));
    dns_request_t *request = solaris_memory_allocate(solaris_executor_budget(owner), sizeof(*request));
    if (!request)
        return SOLARIS_ENOMEM;
    memset(request, 0, sizeof(*request));
    request->fixture = f;
    request->callback = callback;
    request->context = user;
    request->revision = v->revision;
    CHECK(solaris_address_parse("127.0.0.1", target->port, &request->address) == SOLARIS_OK);
    request->deferred = (solaris_deferred_t){.run = dns_complete, .context = request};
    request->next = f->dns;
    f->dns = request;
    *out = request;
    uint8_t bytes[8];
    put32(bytes, v->revision);
    put32(bytes + 4, target->port);
    event(f, 'D', bytes, 8);
    if (!f->hold_dns)
        CHECK(solaris_executor_defer(owner, &request->deferred) == SOLARIS_OK);
    return SOLARIS_OK;
}
static void cancel_resolve(void *context, void *opaque)
{
    view_t *v = context;
    dns_request_t *request = opaque;
    CHECK(request->fixture == v->fixture && !request->cancelled);
    request->cancelled = 1;
    number(v->fixture, 'K', v->revision);
    if (!request->deferred.queued)
        CHECK(solaris_executor_defer(v->fixture->owner, &request->deferred) == SOLARIS_OK);
}
static solaris_status_t route(void *context, solaris_executor_t *owner, const solaris_inbound_request_t *request,
                              solaris_route_options_t *out)
{
    view_t *original = context;
    fixture_t *f = original->fixture;
    view_t *v = original;
    CHECK(owner == f->owner && atomic_load(&original->refs));
    if (request->network == SOLARIS_INBOUND_UDP) {
        v = f->active;
        if (!v || !v->udp || v->auth_revision != original->auth_revision)
            return SOLARIS_EACCESS;
    }
    retain(v);
    *out = (solaris_route_options_t){.mode = SOLARIS_MODE_RULE,
                                     .rules = v->rules,
                                     .rule_count = 2,
                                     .direct_target = 1,
                                     .global_target = 1,
                                     .timeout_ms = 5000,
                                     .context = v,
                                     .retain = retain,
                                     .release = release,
                                     .acquire = acquire,
                                     .resolve = resolve,
                                     .cancel_resolve = cancel_resolve};
    out->metadata.config_revision = v->revision;
    out->metadata.selection_revision = v->revision;
    uint8_t bytes[16];
    put32(bytes, v->revision);
    put32(bytes + 4, request->network);
    put32(bytes + 8, request->source.port);
    put32(bytes + 12, request->destination.port);
    event(f, 'R', bytes, 16);
    if (request->network == SOLARIS_INBOUND_UDP && f->flip_revision) {
        uint32_t revision = f->flip_revision;
        f->flip_revision = 0;
        CHECK(revision < 16 && f->views[revision].inbound);
        publish(f, &f->views[revision]);
    }
    return SOLARIS_OK;
}
static solaris_status_t create_view(fixture_t *f, uint32_t revision, uint32_t auth_revision, int udp)
{
    CHECK(revision > 0 && revision < 16 && !f->views[revision].revision);
    view_t *v = &f->views[revision];
    memset(v, 0, sizeof(*v));
    v->fixture = f;
    v->revision = revision;
    v->auth_revision = auth_revision;
    v->udp = udp;
    atomic_init(&v->refs, 0);
    CHECK(solaris_route_rule_compile("IP-CIDR", "127.0.0.0/8", 0, 1, &v->rules[0], NULL) == SOLARIS_OK);
    CHECK(solaris_route_rule_compile("FINAL", NULL, 0, 2, &v->rules[1], NULL) == SOLARIS_OK);
    solaris_proxy_inbound_options_t options = f->base;
    options.owner = f->owner;
    options.parent_scope = &f->service;
    options.context = v;
    options.inbound_id = 42;
    options.retain = retain;
    options.release = release;
    options.route = route;
    options.on_close = inbound_closed;
    options.udp = udp;
    return solaris_proxy_inbound_detached_create(&options, &v->inbound);
}
static solaris_status_t accepted(void *context, const solaris_address_t *peer, const solaris_address_t *local,
                                 solaris_stream_t *stream, solaris_stream_callbacks_t *callbacks, void **stream_context)
{
    fixture_t *f = context;
    view_t *v = f->active;
    if (!v || !v->inbound)
        return SOLARIS_ECLOSED;
    retain(v);
    solaris_status_t rc = solaris_proxy_inbound_accept(v->inbound, peer, local, stream, callbacks, stream_context);
    release(v);
    if (rc == SOLARIS_OK)
        number(f, 'O', v->revision);
    return rc;
}
static void listener_closed(void *context, solaris_status_t status)
{
    fixture_t *f = context;
    (void)status;
    f->listener = NULL;
    number(f, 'L', 0);
}
static void service_cancel(void *context)
{
    fixture_t *f = context;
    f->active = NULL;
    if (f->listener)
        solaris_tcp_listener_close(f->listener);
    for (size_t i = 1; i < 16; ++i)
        if (f->views[i].inbound)
            CHECK(solaris_proxy_inbound_close(f->views[i].inbound) == SOLARIS_OK);
}
static void service_done(void *context)
{
    fixture_t *f = context;
    CHECK(!f->listener && !f->dns);
    for (size_t i = 1; i < 16; ++i)
        CHECK(!f->views[i].inbound && !atomic_load(&f->views[i].refs));
    f->service_open = 0;
    number(f, 'S', 0);
}
static void probe_done(void *context)
{
    fixture_t *f = context;
    CHECK(solaris_budget_used(solaris_executor_budget(f->owner)) == f->probe_budget);
    number(f, 'F', 0);
}
static void unexpected_close(void *context, const solaris_proxy_inbound_snapshot_t *snapshot, solaris_status_t status)
{
    (void)context;
    (void)snapshot;
    (void)status;
    CHECK(0);
}
static solaris_status_t no_plan(void *context, solaris_executor_t *owner, const solaris_inbound_request_t *request,
                                solaris_dial_plan_t *out)
{
    (void)context;
    (void)owner;
    (void)request;
    (void)out;
    return SOLARIS_ENOTSUP;
}
static void execute(void *context, solaris_status_t status)
{
    command_t *command = context;
    fixture_t *f = command->fixture;
    solaris_status_t rc = status;
    if (status != SOLARIS_OK)
        goto done;
    if (command->type == 'N') {
        CHECK(!f->service_open && command->length == 20);
        memset(f->views, 0, sizeof(f->views));
        f->hold_dns = 0;
        f->flip_revision = 0;
        solaris_proxy_inbound_options_init(&f->base);
        f->base.protocol = command->data[0];
        f->base.authenticate = command->data[1] ? authenticate : NULL;
        f->base.handshake_timeout_ms = get32(command->data + 4);
        f->base.idle_timeout_ms = get32(command->data + 8);
        f->base.connection_limit = get32(command->data + 12);
        f->base.header_limit = get32(command->data + 16);
        f->base.pending_packet_limit = 1;
        CHECK(solaris_scope_init(&f->service, f->owner, service_cancel, service_done, f) == SOLARIS_OK);
        f->service_open = 1;
        CHECK(create_view(f, 1, 1, command->data[3]) == SOLARIS_OK);
        f->active = &f->views[1];
        solaris_dialer_options_t stream;
        solaris_dialer_options_init(&stream);
        stream.read_chunk_size = 8192;
        CHECK(solaris_tcp_listener_open_scoped(f->owner, &f->service, &f->base.listen, &stream, accepted,
                                               listener_closed, f, &f->listener, &f->bound) == SOLARIS_OK);
        number(f, 'B', f->bound.port);
    } else if (command->type == 'S') {
        CHECK(f->service_open);
        solaris_scope_cancel(&f->service);
    } else if (command->type == 'G' || command->type == 'V') {
        CHECK(command->length == 12);
        uint32_t revision = get32(command->data);
        CHECK(create_view(f, revision, get32(command->data + 4), get32(command->data + 8)) == SOLARIS_OK);
        if (command->type == 'G')
            publish(f, &f->views[revision]);
    } else if (command->type == 'H') {
        CHECK(command->length == 4);
        f->hold_dns = (int)get32(command->data);
    } else if (command->type == 'J') {
        CHECK(command->length == 4);
        f->flip_revision = get32(command->data);
    } else if (command->type == 'X') {
        f->hold_dns = 0;
        for (dns_request_t *request = f->dns; request; request = request->next)
            if (!request->deferred.queued)
                CHECK(solaris_executor_defer(f->owner, &request->deferred) == SOLARIS_OK);
    } else if (command->type == 'I')
        publish(f, NULL);
    else if (command->type == 'L') {
        CHECK(f->listener);
        solaris_tcp_listener_close(f->listener);
    } else if (command->type == 'Q') {
        CHECK(command->length == 4);
        uint32_t revision = get32(command->data);
        CHECK(revision > 0 && revision < 16);
        uint8_t bytes[8];
        put32(bytes, atomic_load(&f->views[revision].refs));
        solaris_proxy_inbound_snapshot_t snapshot = {0};
        if (f->views[revision].inbound)
            CHECK(solaris_proxy_inbound_snapshot(f->views[revision].inbound, &snapshot) == SOLARIS_OK);
        put32(bytes + 4, (uint32_t)snapshot.udp_dropped);
        event(f, 'Q', bytes, 8);
    } else if (command->type == 'F') {
        f->probe_budget = solaris_budget_used(solaris_executor_budget(f->owner));
        CHECK(solaris_scope_init(&f->probe, f->owner, NULL, probe_done, f) == SOLARIS_OK);
        solaris_proxy_inbound_options_t options;
        solaris_proxy_inbound_options_init(&options);
        options.owner = f->owner;
        options.parent_scope = &f->probe;
        options.protocol = SOLARIS_INBOUND_HTTP;
        options.context = f;
        options.select = no_plan;
        options.on_close = unexpected_close;
        options.listen = f->bound;
        solaris_proxy_inbound_t *rejected = NULL;
        rc = solaris_proxy_inbound_create(&options, &rejected);
        CHECK(rc != SOLARIS_OK && !rejected);
        rc = SOLARIS_OK;
        solaris_scope_cancel(&f->probe);
    } else
        CHECK(0);
done:
    number(f, 'A', (uint32_t)rc);
    solaris_test_event_signal(&f->ready);
}
static void create_modules(void *context, solaris_status_t status)
{
    fixture_t *f = context;
    CHECK(status == SOLARIS_OK);
    solaris_registry_t *registry;
    CHECK(solaris_builtin_registry_create(solaris_executor_budget(f->owner), &registry, NULL) == SOLARIS_OK);
    solaris_module_config_t *config;
    solaris_config_view_t view = {.kind = SOLARIS_CONFIG_MAP};
    solaris_module_services_t services = {.owner = f->owner};
    CHECK(solaris_registry_compile(registry, "direct", &view, &config, NULL) == SOLARIS_OK);
    CHECK(solaris_module_create(config, &services, NULL, NULL, &f->direct, NULL) == SOLARIS_OK);
    solaris_module_config_release(config);
    CHECK(solaris_registry_compile(registry, "block", &view, &config, NULL) == SOLARIS_OK);
    CHECK(solaris_module_create(config, &services, NULL, NULL, &f->block, NULL) == SOLARIS_OK);
    solaris_module_config_release(config);
    solaris_registry_destroy(registry);
    solaris_test_event_signal(&f->ready);
}
int main(void)
{
#ifdef _WIN32
    /* Length-prefixed frames must preserve LF and Ctrl-Z on Windows pipes. */
    CHECK(_setmode(_fileno(stdin), _O_BINARY) != -1);
    CHECK(_setmode(_fileno(stdout), _O_BINARY) != -1);
#endif
    fixture_t f = {0};
    CHECK(!uv_mutex_init(&f.output) && !solaris_test_event_init(&f.ready, 0));
    solaris_engine_options_t options;
    solaris_engine_options_init(&options);
    options.io_workers = 1;
    CHECK(solaris_engine_create(&options, NULL, &f.engine, NULL) == SOLARIS_OK);
    uint64_t operation;
    CHECK(solaris_engine_start(f.engine, &operation, NULL) == SOLARIS_OK);
    CHECK(solaris_engine_flush(f.engine, 5000, NULL) == SOLARIS_OK);
    f.owner = solaris_runtime_executor(f.engine, 0);
    CHECK(solaris_executor_post(f.owner, create_modules, &f) == SOLARIS_OK);
    solaris_test_event_wait(&f.ready);
    uint8_t head[5];
    while (fread(head, 1, 5, stdin) == 5) {
        uint32_t n = get32(head + 1);
        CHECK(n <= 65536);
        uint8_t *data = malloc(n ? n : 1);
        CHECK(data && fread(data, 1, n, stdin) == n);
        if (head[0] == 'T') {
            free(data);
            break;
        }
        command_t command = {&f, head[0], data, n};
        CHECK(solaris_executor_post(f.owner, execute, &command) == SOLARIS_OK);
        solaris_test_event_wait(&f.ready);
        free(data);
    }
    CHECK(solaris_engine_stop(f.engine, &operation, NULL) == SOLARIS_OK);
    CHECK(solaris_engine_flush(f.engine, 5000, NULL) == SOLARIS_OK && !f.service_open && !f.dns);
    solaris_engine_snapshot_t snapshot;
    CHECK(solaris_engine_get_snapshot(f.engine, &snapshot, NULL) == SOLARIS_OK && !snapshot.io_buffer_bytes);
    CHECK(solaris_engine_destroy(f.engine, NULL) == SOLARIS_OK);
    event(&f, 'Z', NULL, 0);
    solaris_test_event_destroy(&f.ready);
    uv_mutex_destroy(&f.output);
    return 0;
}
