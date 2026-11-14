#include "contracts/inbound/proxy.h"
#include "contracts/module/module.h"
#include "runtime/engine/internal.h"
#include "support/runtime/event.h"
#include <stdatomic.h>
#include <stdio.h>
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
typedef struct fixture {
    solaris_engine_t *engine;
    solaris_executor_t *owner;
    solaris_proxy_inbound_t *inbound, *spare;
    solaris_module_instance_t *module;
    solaris_outbound_t delayed;
    uv_mutex_t output;
    solaris_test_event_t ready;
    unsigned mode;
    atomic_int fail_after;
    atomic_uint_fast64_t clock_ns;
} fixture_t;
typedef struct command {
    fixture_t *test;
    uint8_t type;
    uint8_t *data;
    uint32_t length;
} command_t;
static uint64_t manual_clock(void *context)
{
    return atomic_load(&((fixture_t *)context)->clock_ns);
}
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
static void event(fixture_t *f, uint8_t type, const void *data, size_t n)
{
    uint8_t head[5] = {type};
    put32(head + 1, (uint32_t)n);
    uv_mutex_lock(&f->output);
    CHECK(fwrite(head, 1, 5, stdout) == 5);
    CHECK(!n || fwrite(data, 1, n, stdout) == n);
    CHECK(!fflush(stdout));
    uv_mutex_unlock(&f->output);
}
static void result(fixture_t *f, uint8_t type, solaris_status_t rc)
{
    uint8_t p[4];
    put32(p, (uint32_t)rc);
    event(f, type, p, 4);
}
static void *allocate(void *context, size_t n)
{
    fixture_t *f = context;
    int left = atomic_load(&f->fail_after);
    if (!left)
        return NULL;
    if (left > 0)
        atomic_fetch_sub(&f->fail_after, 1);
    return malloc(n);
}
static solaris_status_t authenticate(void *context, const uint8_t *user, size_t un, const uint8_t *pass, size_t pn)
{
    fixture_t *f = context;
    if (f->mode == 2)
        CHECK(solaris_proxy_inbound_close(f->inbound) == SOLARIS_OK);
    return un == 4 && pn == 4 && !memcmp(user, "user", 4) && !memcmp(pass, "pass", 4) ? SOLARIS_OK : SOLARIS_EACCESS;
}
typedef struct delayed_stream {
    solaris_stream_t stream;
    solaris_stream_callbacks_t callbacks;
    void *context;
    solaris_deadline_t *deadline;
} delayed_stream_t;
static solaris_status_t delayed_close(void *context)
{
    delayed_stream_t *s = context;
    if (s->deadline)
        solaris_deadline_cancel(s->deadline);
    return SOLARIS_OK;
}
static const solaris_stream_ops_t delayed_stream_ops = {.close = delayed_close};
static void delayed_done(void *context, solaris_status_t status)
{
    delayed_stream_t *s = context;
    s->deadline = NULL;
    if (status == SOLARIS_OK)
        status = SOLARIS_ETIMEDOUT;
    s->callbacks.on_open(s->context, &s->stream, status);
    s->callbacks.on_close(s->context, &s->stream, status);
    free(s);
}
static uint32_t delayed_capabilities(void *context)
{
    (void)context;
    return SOLARIS_OUTBOUND_STREAM;
}
static solaris_status_t delayed_open(void *context, const solaris_address_t *destination,
                                     const solaris_stream_callbacks_t *callbacks, void *user, solaris_stream_t **out)
{
    fixture_t *f = context;
    (void)destination;
    delayed_stream_t *s = calloc(1, sizeof(*s));
    CHECK(s);
    s->stream = (solaris_stream_t){&delayed_stream_ops, s, f->owner};
    s->callbacks = *callbacks;
    s->context = user;
    solaris_status_t rc = solaris_deadline_start(f->owner, 60000, delayed_done, s, &s->deadline);
    if (rc != SOLARIS_OK) {
        free(s);
        return rc;
    }
    *out = &s->stream;
    return SOLARIS_OK;
}
static const solaris_outbound_ops_t delayed_ops = {.capabilities = delayed_capabilities, .open_stream = delayed_open};
static solaris_status_t select_plan(void *context, solaris_executor_t *owner, const solaris_inbound_request_t *request,
                                    solaris_dial_plan_t *out)
{
    fixture_t *f = context;
    CHECK(owner == f->owner && request->source.port && request->destination.port);
    CHECK(request->protocol == SOLARIS_INBOUND_HTTP || request->protocol == SOLARIS_INBOUND_SOCKS5);
    uint8_t p[8];
    put32(p, request->protocol);
    put32(p + 4, request->network);
    event(f, 'R', p, 8);
    if (f->mode == 4) {
        f->delayed = (solaris_outbound_t){&delayed_ops, f, owner};
        *out = (solaris_dial_plan_t){.outbound = &f->delayed};
        return SOLARIS_OK;
    }
    solaris_status_t rc = f->mode == 1 ? SOLARIS_EACCESS : solaris_module_plan_acquire(f->module, 1, out);
    if (f->mode == 3)
        CHECK(solaris_proxy_inbound_close(f->inbound) == SOLARIS_OK);
    return rc;
}
static void closed(void *context, const solaris_proxy_inbound_snapshot_t *snapshot, solaris_status_t status)
{
    fixture_t *f = context;
    CHECK(!snapshot->connections && snapshot->closing);
    solaris_proxy_inbound_snapshot_t active;
    if (f->inbound && solaris_proxy_inbound_snapshot(f->inbound, &active) == SOLARIS_OK &&
        solaris_address_equal(&active.bound, &snapshot->bound)) f->inbound = NULL;
    else { CHECK(f->spare); f->spare = NULL; }
    result(f, 'S', status);
}
static void execute(void *context, solaris_status_t status)
{
    command_t *c = context;
    fixture_t *f = c->test;
    solaris_status_t rc = status;
    if (rc != SOLARIS_OK)
        goto done;
    if (c->type == 'N') {
        CHECK(c->length == 20);
        if (f->inbound) { CHECK(!f->spare); f->spare = f->inbound; f->inbound = NULL; }
        solaris_proxy_inbound_options_t o;
        solaris_proxy_inbound_options_init(&o);
        o.owner = f->owner;
        o.context = f;
        o.select = select_plan;
        o.on_close = closed;
        o.protocol = c->data[0];
        o.authenticate = c->data[1] ? authenticate : NULL;
        o.udp = c->data[3];
        CHECK(solaris_address_parse(c->data[2] == 6 ? "::1" : "127.0.0.1", 0, &o.listen) == SOLARIS_OK);
        o.handshake_timeout_ms = get32(c->data + 4);
        o.idle_timeout_ms = get32(c->data + 8);
        o.connection_limit = get32(c->data + 12);
        o.header_limit = get32(c->data + 16);
        rc = solaris_proxy_inbound_create(&o, &f->inbound);
        if (rc == SOLARIS_OK) {
            solaris_proxy_inbound_snapshot_t s;
            CHECK(solaris_proxy_inbound_snapshot(f->inbound, &s) == SOLARIS_OK);
            uint8_t p[4];
            put32(p, s.bound.port);
            event(f, 'B', p, 4);
        } else
            CHECK(!f->inbound);
    } else if (c->type == 'S') {
        CHECK(f->inbound);
        rc = solaris_proxy_inbound_close(f->inbound);
    } else if (c->type == 'W') {
        solaris_proxy_inbound_t *swap = f->inbound; f->inbound = f->spare; f->spare = swap;
    } else if (c->type == 'G') {
        CHECK(c->length == 4);
        f->mode = get32(c->data);
    } else if (c->type == 'M') {
        CHECK(c->length == 4);
        atomic_store(&f->fail_after, (int32_t)get32(c->data));
    } else if (c->type == 'K') {
        CHECK(c->length == 4);
        atomic_fetch_add(&f->clock_ns, (uint64_t)get32(c->data) * UINT64_C(1000000));
    } else if (c->type == 'Q') {
        solaris_proxy_inbound_snapshot_t s;
        CHECK(solaris_proxy_inbound_snapshot(f->inbound, &s) == SOLARIS_OK);
        uint8_t p[24];
        put32(p, (uint32_t)s.connections);
        put32(p + 4, (uint32_t)s.accepted);
        put32(p + 8, (uint32_t)s.rejected);
        put32(p + 12, (uint32_t)s.authentication_failed);
        put32(p + 16, (uint32_t)s.protocol_failed);
        put32(p + 20, (uint32_t)s.udp_dropped);
        event(f, 'Q', p, 24);
    } else
        CHECK(0);
done:
    result(f, 'A', rc);
    solaris_test_event_signal(&f->ready);
}
static void create_module(void *context, solaris_status_t status)
{
    fixture_t *f = context;
    CHECK(status == SOLARIS_OK);
    solaris_registry_t *registry;
    solaris_module_config_t *config;
    CHECK(solaris_builtin_registry_create(solaris_executor_budget(f->owner), &registry, NULL) == SOLARIS_OK);
    solaris_config_view_t view = {.kind = SOLARIS_CONFIG_MAP};
    CHECK(solaris_registry_compile(registry, "direct", &view, &config, NULL) == SOLARIS_OK);
    solaris_module_services_t services = {.owner = f->owner};
    CHECK(solaris_module_create(config, &services, NULL, NULL, &f->module, NULL) == SOLARIS_OK);
    solaris_module_config_release(config);
    solaris_registry_destroy(registry);
    solaris_test_event_signal(&f->ready);
}
int main(int argc, char **argv)
{
    fixture_t f = {0};
    atomic_init(&f.fail_after, -1);
    atomic_init(&f.clock_ns, UINT64_C(1000000000));
    CHECK(!uv_mutex_init(&f.output) && !solaris_test_event_init(&f.ready, 0));
    solaris_runtime_services_t services;
    solaris_runtime_services_init(&services);
    services.context = &f;
    services.allocate = allocate;
    if (argc == 2 && !strcmp(argv[1], "--manual-clock")) services.now_ns = manual_clock;
    else CHECK(argc == 1);
    solaris_engine_options_t options;
    solaris_engine_options_init(&options);
    options.io_workers = 1;
    CHECK(solaris_runtime_create(&options, NULL, &services, &f.engine, NULL) == SOLARIS_OK);
    uint64_t op;
    CHECK(solaris_engine_start(f.engine, &op, NULL) == SOLARIS_OK);
    CHECK(solaris_engine_flush(f.engine, 5000, NULL) == SOLARIS_OK);
    f.owner = solaris_runtime_executor(f.engine, 0);
    CHECK(solaris_executor_post(f.owner, create_module, &f) == SOLARIS_OK);
    solaris_test_event_wait(&f.ready);
    uint8_t head[5];
    while (fread(head, 1, 5, stdin) == 5) {
        uint32_t n = get32(head + 1);
        CHECK(n <= 65536);
        uint8_t *bytes = malloc(n ? n : 1);
        CHECK(bytes && fread(bytes, 1, n, stdin) == n);
        if (head[0] == 'T') {
            free(bytes);
            break;
        }
        command_t c = {&f, head[0], bytes, n};
        CHECK(solaris_executor_post(f.owner, execute, &c) == SOLARIS_OK);
        solaris_test_event_wait(&f.ready);
        free(bytes);
    }
    atomic_store(&f.fail_after, -1);
    CHECK(solaris_engine_stop(f.engine, &op, NULL) == SOLARIS_OK);
    CHECK(solaris_engine_flush(f.engine, 5000, NULL) == SOLARIS_OK && !f.inbound && !f.spare);
    solaris_engine_snapshot_t snapshot;
    CHECK(solaris_engine_get_snapshot(f.engine, &snapshot, NULL) == SOLARIS_OK && !snapshot.io_buffer_bytes);
    CHECK(solaris_engine_destroy(f.engine, NULL) == SOLARIS_OK);
    event(&f, 'Z', NULL, 0);
    solaris_test_event_destroy(&f.ready);
    uv_mutex_destroy(&f.output);
    return 0;
}
