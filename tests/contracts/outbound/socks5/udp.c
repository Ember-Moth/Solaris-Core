#include "contracts/module/module.h"
#include "support/runtime/event.h"
#include <uv.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)
enum { CLOSE, CONTROL_EOF, CONTROL_DATA, CONTROL_GONE, DENY_SOCKET, ZERO_RELAY,
    DOMAIN_RELAY, DOMAIN_SERVER, CANCEL_DNS, CANCEL_BEFORE, EXPIRED, WRONG_FAMILY, REJECT, STOP, ALLOCATE };
typedef struct test test_t;
typedef struct mock {
    test_t *test;
    solaris_stream_t stream;
    solaris_stream_callbacks_t callbacks;
    void *context;
    solaris_deferred_t opened, read, written, closed;
    solaris_slice_t slice;
    solaris_io_done_fn done;
    void *user;
    uint8_t input[64];
    size_t size;
    int phase, busy, reading, closing, held;
} mock_t;
struct test {
    solaris_executor_t *owner;
    solaris_budget_t *budget, *fixture_budget;
    solaris_module_config_t *config;
    solaris_datagram_t *channel;
    solaris_test_event_t ready, held, complete;
    solaris_deferred_t inject;
    mock_t mock;
    atomic_uint opens, closes;
    atomic_uint_fast64_t clock;
    unsigned factory_calls, policies, writes, completions;
    int mode, failure, allocations, fail_at;
    uint16_t relay_port;
    solaris_status_t start_status, open_status, close_status;
};
static void queue(test_t *test, solaris_deferred_t *node, void (*run)(void *), void *context)
{ node->run = run; node->context = context; CHECK(solaris_executor_defer(test->owner, node) == SOLARIS_OK); }
static uint64_t now(void *context) { return atomic_load(&((test_t *)context)->clock); }
static void *allocate(void *context, size_t size)
{ test_t *test = context; return ++test->allocations == test->fail_at ? NULL : malloc(size); }
static void mock_closed(void *context)
{ mock_t *mock = context; CHECK(!mock->busy); mock->callbacks.on_close(mock->context, &mock->stream, SOLARIS_OK); }
static void maybe_closed(mock_t *mock)
{
    if (mock->closing && !mock->busy && !mock->closed.queued) {
        if (mock->test->mode == CONTROL_EOF || mock->test->mode == CONTROL_DATA) {
            if (!mock->held) { mock->held = 1; solaris_test_event_signal(&mock->test->held); }
        } else queue(mock->test, &mock->closed, mock_closed, mock);
    }
}
static void mock_written(void *context)
{
    mock_t *mock = context; CHECK(mock->busy); mock->busy = 0;
    const solaris_buffer_t *buffer = mock->slice.buffer; mock->slice.buffer = NULL;
    mock->done(mock->user, mock->closing ? SOLARIS_ECANCELLED : SOLARIS_OK); solaris_buffer_release(buffer); maybe_closed(mock);
}
static void mock_read(void *context)
{
    mock_t *mock = context; if (mock->closing || !mock->reading || !mock->size) return;
    solaris_buffer_t *buffer; CHECK(solaris_buffer_copy(mock->test->fixture_budget, mock->input, mock->size, &buffer) == SOLARIS_OK); mock->size = 0u;
    if (mock->test->mode == EXPIRED && mock->phase == 2) atomic_store(&mock->test->clock, UINT64_C(11000000));
    mock->callbacks.on_data(mock->context, &mock->stream, buffer); solaris_buffer_release(buffer);
}
static solaris_status_t write_mock(void *state, const solaris_slice_t *slice, solaris_io_done_fn done, void *context)
{
    mock_t *mock = state; test_t *test = mock->test; CHECK(!mock->busy && mock->size == 0u);
    mock->busy = 1; mock->slice = *slice; solaris_buffer_retain(slice->buffer); mock->done = done; mock->user = context;
    const uint8_t *bytes = solaris_buffer_data(slice->buffer) + slice->offset;
    if (mock->phase++ == 0) {
        CHECK(slice->length == 3u && memcmp(bytes, "\5\1\0", 3u) == 0);
        memcpy(mock->input, "\5\0", 2u); mock->size = 2u;
    } else {
        CHECK(mock->phase == 2 && slice->length == 10u && memcmp(bytes, "\5\3\0\1\0\0\0\0\0\0", 10u) == 0);
        memcpy(mock->input, "\5\0\0", 3u); mock->size = 3u;
        if (test->mode == DOMAIN_RELAY) {
            memcpy(mock->input + mock->size, "\3\11localhost", 11u); mock->size += 11u;
        } else if (test->mode == WRONG_FAMILY) {
            mock->input[mock->size++] = 4u; memset(mock->input + mock->size, 0, 16u); mock->input[mock->size + 15u] = 1u; mock->size += 16u;
        } else { memcpy(mock->input + mock->size, "\1\0\0\0\0", 5u); mock->size += 5u; }
        uint16_t port = test->mode == ZERO_RELAY ? 0u : test->relay_port;
        mock->input[mock->size++] = (uint8_t)(port >> 8); mock->input[mock->size++] = (uint8_t)port;
    }
    queue(test, &mock->written, mock_written, mock);
    if (mock->reading && !mock->read.queued) queue(test, &mock->read, mock_read, mock);
    return SOLARIS_OK;
}
static solaris_status_t read_mock(void *state, int enabled)
{
    mock_t *mock = state; mock->reading = enabled;
    if (enabled && !mock->closing && mock->size && !mock->read.queued) queue(mock->test, &mock->read, mock_read, mock);
    return SOLARIS_OK;
}
static solaris_status_t close_mock(void *state) { mock_t *mock = state; mock->closing = 1; maybe_closed(mock); return SOLARIS_OK; }
static solaris_status_t snapshot_mock(void *state, solaris_io_snapshot_t *out) { (void)state; memset(out, 0, sizeof(*out)); return SOLARIS_OK; }
static const solaris_stream_ops_t mock_ops = {write_mock, NULL, read_mock, close_mock, snapshot_mock, NULL};
static void mock_opened(void *context)
{ mock_t *mock = context; mock->callbacks.on_open(mock->context, &mock->stream, SOLARIS_OK); }
static solaris_status_t factory(void *context, solaris_executor_t *owner, const solaris_dialer_options_t *options,
    const solaris_address_t *peer, const solaris_stream_callbacks_t *callbacks, void *user, solaris_stream_t **out)
{
    (void)options; test_t *test = context; *out = NULL; test->factory_calls++;
    CHECK(owner == test->owner && peer->family == SOLARIS_ADDRESS_IPV4 && peer->port == 1080u);
    if (test->mode == REJECT) return SOLARIS_EACCESS;
    mock_t *mock = &test->mock; mock->test = test; mock->stream = (solaris_stream_t){&mock_ops, mock, owner};
    mock->callbacks = *callbacks; mock->context = user; mock->reading = 1; *out = &mock->stream;
    queue(test, &mock->opened, mock_opened, mock); return SOLARIS_OK;
}
static solaris_status_t policy(void *context, uintptr_t socket, uint32_t family, uint32_t kind)
{
    (void)socket; test_t *test = context; CHECK(kind == SOLARIS_SOCKET_UDP && family == SOLARIS_ADDRESS_IPV4);
    test->policies++; return test->mode == DENY_SOCKET ? SOLARIS_EACCESS : SOLARIS_OK;
}
static void inject(void *context)
{
    test_t *test = context; mock_t *mock = &test->mock;
    if (test->mode == CONTROL_EOF) mock->callbacks.on_eof(mock->context, &mock->stream);
    else if (test->mode == CONTROL_GONE) { mock->closing = 1; mock_closed(mock); }
    else {
        solaris_buffer_t *buffer; CHECK(solaris_buffer_copy(test->fixture_budget, "invalid control data", 20u, &buffer) == SOLARIS_OK);
        mock->callbacks.on_data(mock->context, &mock->stream, buffer); solaris_buffer_release(buffer);
    }
}
static void sent(void *context, solaris_status_t status)
{ test_t *test = context; CHECK(status == SOLARIS_OK || status == SOLARIS_ECANCELLED); test->completions++; }
static void opened(void *context, solaris_datagram_t *channel, solaris_status_t status)
{
    test_t *test = context; CHECK(channel == test->channel && atomic_fetch_add(&test->opens, 1u) == 0u); test->open_status = status;
    if (status != SOLARIS_OK) return;
    solaris_buffer_t *buffer; CHECK(solaris_buffer_copy(test->fixture_budget, "payload", 7u, &buffer) == SOLARIS_OK);
    solaris_address_t target; CHECK(solaris_address_parse("127.0.0.1", 80u, &target) == SOLARIS_OK);
    solaris_slice_t slice = {buffer, 0u, 7u}; status = solaris_datagram_send(channel, &target, &slice, sent, test);
    if (status == SOLARIS_OK) { test->writes++; CHECK(solaris_datagram_send(channel, &target, &slice, sent, test) == SOLARIS_EAGAIN); }
    else CHECK(test->mode == ALLOCATE && status == SOLARIS_ENOMEM);
    solaris_buffer_release(buffer);
    if (test->mode == CONTROL_EOF || test->mode == CONTROL_DATA || test->mode == CONTROL_GONE) queue(test, &test->inject, inject, test);
    else if (test->mode == STOP) solaris_test_event_signal(&test->held);
    else CHECK(solaris_datagram_close(channel) == SOLARIS_OK);
}
static void packet(void *context, solaris_datagram_t *channel, const solaris_address_t *peer, const solaris_buffer_t *buffer)
{ (void)context; (void)channel; (void)peer; (void)buffer; CHECK(0); }
static void closed(void *context, solaris_datagram_t *channel, solaris_status_t status)
{
    test_t *test = context; CHECK(channel == test->channel && atomic_fetch_add(&test->closes, 1u) == 0u);
    test->close_status = status; CHECK(test->completions == test->writes);
    solaris_io_snapshot_t stats; CHECK(solaris_datagram_get_snapshot(channel, &stats) == SOLARIS_OK && stats.pending_requests == 0u && stats.pending_bytes == 0u);
    solaris_test_event_signal(&test->complete);
}
static const solaris_datagram_callbacks_t callbacks = {opened, packet, NULL, closed};
static void start(void *context, solaris_status_t status)
{
    test_t *test = context; CHECK(status == SOLARIS_OK);
    solaris_module_services_t services = {.owner = test->owner, .carrier = {.context = test, .open = factory},
        .dialer = {.pending_byte_limit = 7u, .pending_request_limit = 1u, .open_timeout_ms = 10u, .prepare_socket = policy, .policy_context = test}};
    if (test->mode == WRONG_FAMILY) CHECK(solaris_address_parse("127.0.0.1", 0u, &services.dialer.local_bind) == SOLARIS_OK);
    test->allocations = 0; test->fail_at = test->failure;
    solaris_module_instance_t *instance = NULL; test->start_status = solaris_module_create(test->config, &services, NULL, NULL, &instance, NULL);
    if (test->start_status == SOLARIS_OK) {
        test->start_status = solaris_outbound_open_datagram(solaris_module_outbound(instance), SOLARIS_ADDRESS_IPV4, &callbacks, test, &test->channel);
        CHECK(solaris_module_retire(instance) == SOLARIS_OK);
    }
    if (test->start_status != SOLARIS_OK) {
        CHECK(test->channel == NULL && (test->mode == REJECT || test->mode == ALLOCATE)); solaris_test_event_signal(&test->complete);
    } else if (test->mode == CANCEL_BEFORE || test->mode == CANCEL_DNS) CHECK(solaris_datagram_close(test->channel) == SOLARIS_OK);
    solaris_test_event_signal(&test->ready);
}
static void run(int mode, int failure, uint16_t port)
{
    test_t test = {.mode = mode, .failure = failure, .relay_port = port};
    atomic_init(&test.opens, 0u); atomic_init(&test.closes, 0u); atomic_init(&test.clock, 0u);
    solaris_runtime_services_t services; solaris_runtime_services_init(&services); services.context = &test; services.allocate = allocate; services.now_ns = now;
    CHECK(solaris_budget_create(4u * 1024u * 1024u, &services, &test.budget) == SOLARIS_OK && solaris_budget_create(4096u, NULL, &test.fixture_budget) == SOLARIS_OK);
    solaris_registry_t *registry; CHECK(solaris_builtin_registry_create(test.budget, &registry, NULL) == SOLARIS_OK);
    const char *server = mode == DOMAIN_SERVER || mode == CANCEL_DNS ? "localhost" : "127.0.0.1";
    solaris_config_field_t fields[] = {{.name = "server", .value = {.kind = SOLARIS_CONFIG_STRING, .value.string = {server, strlen(server)}}},
        {.name = "port", .value = {.kind = SOLARIS_CONFIG_INTEGER, .value.integer = 1080}}};
    solaris_config_view_t view = {.kind = SOLARIS_CONFIG_MAP, .value.map = {fields, 2u}};
    CHECK(solaris_registry_compile(registry, "socks5", &view, &test.config, NULL) == SOLARIS_OK); solaris_registry_destroy(registry);
    solaris_test_event_t *events[] = {&test.ready, &test.held, &test.complete}; for (unsigned i = 0u; i < 3u; ++i) CHECK(solaris_test_event_init(events[i], 0u) == 0);
    solaris_executor_options_t options = {.id = 0u, .queue_capacity = 2u, .resource_limit = 64u, .budget = test.budget, .services = &services};
    CHECK(solaris_executor_create(&options, &test.owner) == SOLARIS_OK && solaris_executor_activate(test.owner, 1u) == SOLARIS_OK);
    CHECK(solaris_executor_post(test.owner, start, &test) == SOLARIS_OK); solaris_test_event_wait(&test.ready); solaris_module_config_release(test.config);
    if (mode == CONTROL_EOF || mode == CONTROL_DATA) {
        solaris_test_event_wait(&test.held); CHECK(atomic_load(&test.opens) == 1u && atomic_load(&test.closes) == 0u);
        queue(&test, &test.mock.closed, mock_closed, &test.mock);
    } else if (mode == STOP) {
        solaris_test_event_wait(&test.held); CHECK(solaris_executor_begin_quiesce(test.owner) == SOLARIS_OK);
    }
    solaris_test_event_wait(&test.complete);
    CHECK(solaris_executor_quiesce(test.owner) == SOLARIS_OK && solaris_executor_destroy(test.owner) == SOLARIS_OK);
    if (test.start_status == SOLARIS_OK) {
        CHECK(atomic_load(&test.opens) == 1u && atomic_load(&test.closes) == 1u);
        if (mode == CONTROL_EOF || mode == CONTROL_DATA || mode == CONTROL_GONE) CHECK(test.open_status == SOLARIS_OK && test.close_status == SOLARIS_EIO && test.writes == 1u);
        else if (mode == DENY_SOCKET) CHECK(test.open_status == SOLARIS_EACCESS && test.close_status == SOLARIS_EACCESS && test.policies == 1u);
        else if (mode == ZERO_RELAY || mode == WRONG_FAMILY) CHECK(test.open_status != SOLARIS_OK && test.policies == 0u);
        else if (mode == EXPIRED) CHECK(test.open_status == SOLARIS_ETIMEDOUT && test.close_status == SOLARIS_ETIMEDOUT && test.policies == 0u);
        else if (mode == CANCEL_BEFORE || mode == CANCEL_DNS) CHECK(test.open_status == SOLARIS_ECANCELLED && test.close_status == SOLARIS_OK);
        else if (mode == STOP) CHECK(test.close_status == SOLARIS_ECANCELLED);
        else if (mode == ALLOCATE) CHECK(test.close_status == SOLARIS_OK || test.close_status == SOLARIS_ENOMEM);
        else CHECK(test.open_status == SOLARIS_OK && test.close_status == SOLARIS_OK && test.writes == 1u);
    } else CHECK(atomic_load(&test.opens) == 0u && atomic_load(&test.closes) == 0u);
    for (unsigned i = 0u; i < 3u; ++i) solaris_test_event_destroy(events[i]);
    CHECK(solaris_budget_used(test.budget) == 0u && solaris_budget_used(test.fixture_budget) == 0u);
    solaris_budget_release(test.budget); solaris_budget_release(test.fixture_budget);
}
int main(void)
{
    uv_loop_t loop; uv_udp_t sink; struct sockaddr_in address; int length = sizeof(address);
    CHECK(uv_loop_init(&loop) == 0 && uv_udp_init(&loop, &sink) == 0 && uv_ip4_addr("127.0.0.1", 0, &address) == 0);
    CHECK(uv_udp_bind(&sink, (struct sockaddr *)&address, 0u) == 0 && uv_udp_getsockname(&sink, (struct sockaddr *)&address, &length) == 0);
    uint16_t port = ntohs(address.sin_port);
    for (int mode = CLOSE; mode < ALLOCATE; ++mode) run(mode, 0, port);
    for (int failure = 1; failure <= 24; ++failure) run(ALLOCATE, failure, port);
    uv_close((uv_handle_t *)&sink, NULL); (void)uv_run(&loop, UV_RUN_DEFAULT); CHECK(uv_loop_close(&loop) == 0);
    puts("SOCKS5 UDP: control lifetime, actual close barrier, DNS cancellation, policy, relay and allocation boundaries passed"); return 0;
}
