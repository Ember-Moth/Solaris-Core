#include <solaris/core.h>
#include "contracts/module/module.h"
#include "runtime/engine/internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>
#include "support/runtime/event.h"

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)

static solaris_outbound_t *create_outbound(solaris_executor_t *owner, const char *type,
                                            const solaris_dialer_options_t *options,
                                            solaris_module_instance_t **instance)
{
    solaris_registry_t *registry;
    CHECK(solaris_builtin_registry_create(solaris_executor_budget(owner), &registry, NULL) == SOLARIS_OK);
    solaris_config_view_t view = {.kind = SOLARIS_CONFIG_MAP};
    solaris_config_field_t fields[3] = {
        {.name = "pending-bytes", .value = {.kind = SOLARIS_CONFIG_INTEGER}},
        {.name = "pending-requests", .value = {.kind = SOLARIS_CONFIG_INTEGER}},
        {.name = "open-timeout-ms", .value = {.kind = SOLARIS_CONFIG_INTEGER}}
    };
    solaris_module_services_t services = {.owner = owner};
    if (options != NULL) {
        fields[0].value.value.integer = (int64_t)options->pending_byte_limit;
        fields[1].value.value.integer = (int64_t)options->pending_request_limit;
        fields[2].value.value.integer = (int64_t)options->open_timeout_ms;
        view.value.map.fields = fields; view.value.map.count = 3u;
        services.dialer = *options;
        /* The compiled config, rather than injected defaults, must supply
         * the small queues and deadline exercised by these tests. */
        services.dialer.pending_byte_limit = 0u;
        services.dialer.pending_request_limit = 0u;
        services.dialer.open_timeout_ms = 0u;
    }
    solaris_module_config_t *config;
    CHECK(solaris_registry_compile(registry, type, &view, &config, NULL) == SOLARIS_OK);
    CHECK(solaris_module_create(config, &services, NULL, NULL, instance, NULL) == SOLARIS_OK);
    solaris_module_config_release(config);
    solaris_registry_destroy(registry);
    return solaris_module_outbound(*instance);
}

enum { TCP_NORMAL, TCP_CANCEL, TCP_WRITE_CANCEL, TCP_IDLE, TCP_TIMEOUT, TCP_EARLY_EOF };
typedef struct tcp_case {
    solaris_engine_t *engine;
    solaris_executor_t *executor;
    solaris_stream_t *stream;
    solaris_address_t destination;
    solaris_deadline_t *resume;
    solaris_test_event_t done, ready;
    int mode, bind_local;
    unsigned int opens, closes, writes, shutdowns, eof, backpressure, writable, prepared;
    size_t received;
    char bytes[64];
    solaris_status_t open_status, close_status;
    solaris_io_snapshot_t final;
    uv_mutex_t *clock_mutex;
    uint64_t *clock_ns;
} tcp_case_t;

static solaris_status_t tcp_policy(void *context, uintptr_t descriptor, uint32_t family, uint32_t kind)
{
    tcp_case_t *test = context;
    CHECK(solaris_executor_is_owner(test->executor) && kind == SOLARIS_SOCKET_TCP);
    CHECK(family == SOLARIS_ADDRESS_IPV4 || family == SOLARIS_ADDRESS_IPV6);
    struct sockaddr_storage peer;
#ifdef _WIN32
    int length = sizeof(peer);
    CHECK(getpeername((SOCKET)descriptor, (struct sockaddr *)&peer, &length) != 0);
#else
    socklen_t length = sizeof(peer);
    CHECK(getpeername((int)descriptor, (struct sockaddr *)&peer, &length) != 0);
#endif
    test->prepared++;
    return SOLARIS_OK;
}

static void tcp_shutdown_done(void *context, solaris_status_t status)
{
    tcp_case_t *test = context; CHECK(status == SOLARIS_OK); test->shutdowns++;
}
static void tcp_write_done(void *context, solaris_status_t status)
{
    tcp_case_t *test = context;
    CHECK(solaris_executor_is_owner(test->executor));
    if (test->mode == TCP_WRITE_CANCEL) {
        CHECK(status == SOLARIS_OK || status == SOLARIS_ECANCELLED || status == SOLARIS_EIO);
        test->writes++; return;
    }
    CHECK(status == SOLARIS_OK);
    if (test->mode == TCP_EARLY_EOF) { test->writes++; return; }
    if (++test->writes == 2u) {
        CHECK(solaris_stream_shutdown_write(test->stream, tcp_shutdown_done, test) == SOLARIS_OK);
    }
}
static void send_tcp_part(tcp_case_t *test, const char *text)
{
    solaris_buffer_t *buffer = NULL;
    CHECK(solaris_buffer_copy(solaris_executor_budget(test->executor), text, 3u, &buffer) == SOLARIS_OK);
    const solaris_slice_t slice = {buffer, 0u, 3u};
    CHECK(solaris_stream_write(test->stream, &slice, tcp_write_done, test) == SOLARIS_OK);
    solaris_buffer_release(buffer);
}
static void resume_tcp(void *context, solaris_status_t status)
{
    tcp_case_t *test = context; test->resume = NULL;
    CHECK(status == SOLARIS_OK && test->received == 0u);
    CHECK(solaris_stream_set_reading(test->stream, 1) == SOLARIS_OK);
}
static void tcp_open(void *context, solaris_stream_t *stream, solaris_status_t status)
{
    tcp_case_t *test = context;
    CHECK(solaris_executor_is_owner(test->executor));
    CHECK(stream == test->stream && ++test->opens == 1u);
    test->open_status = status;
    CHECK(solaris_engine_flush(test->engine, 0u, NULL) == SOLARIS_EDEADLOCK);
    if (test->mode == TCP_CANCEL) { CHECK(status == SOLARIS_ECANCELLED); return; }
    if (test->mode == TCP_TIMEOUT) { CHECK(status == SOLARIS_ETIMEDOUT); return; }
    CHECK(status == SOLARIS_OK);
    if (test->mode == TCP_IDLE) { solaris_test_event_signal(&test->ready); return; }
    if (test->mode == TCP_EARLY_EOF) {
        solaris_buffer_t *buffer = NULL;
        CHECK(solaris_buffer_copy(solaris_executor_budget(test->executor), "EARLY", 5u, &buffer) == SOLARIS_OK);
        const solaris_slice_t slice = {buffer, 0u, 5u};
        CHECK(solaris_stream_write(stream, &slice, tcp_write_done, test) == SOLARIS_OK);
        solaris_buffer_release(buffer);
        return;
    }
    if (test->mode == TCP_WRITE_CANCEL) {
        solaris_buffer_t *buffer = NULL;
        CHECK(solaris_buffer_allocate(solaris_executor_budget(test->executor), 65536u, &buffer) == SOLARIS_OK);
        memset(solaris_buffer_mutable_data(buffer), 'X', 65536u);
        CHECK(solaris_buffer_set_length(buffer, 65536u) == SOLARIS_OK);
        const solaris_slice_t slice = {buffer, 0u, 65536u};
        CHECK(solaris_stream_write(stream, &slice, tcp_write_done, test) == SOLARIS_OK);
        solaris_buffer_release(buffer);
        CHECK(solaris_stream_close(stream) == SOLARIS_OK);
        return;
    }
    CHECK(solaris_stream_set_reading(stream, 0) == SOLARIS_OK);
    send_tcp_part(test, "abc");
    solaris_buffer_t *second = NULL;
    CHECK(solaris_buffer_copy(solaris_executor_budget(test->executor), "def", 3u, &second) == SOLARIS_OK);
    const solaris_slice_t slice = {second, 0u, 3u};
    CHECK(solaris_stream_write(stream, &slice, tcp_write_done, test) == SOLARIS_EAGAIN);
    test->backpressure++;
    solaris_buffer_release(second);
    CHECK(solaris_deadline_start(test->executor, 5u, resume_tcp, test, &test->resume) == SOLARIS_OK);
}
static void tcp_data(void *context, solaris_stream_t *stream, const solaris_buffer_t *buffer)
{
    tcp_case_t *test = context; CHECK(stream == test->stream && (test->mode == TCP_NORMAL || test->mode == TCP_EARLY_EOF));
    size_t length = solaris_buffer_length(buffer);
    CHECK(test->received + length <= sizeof(test->bytes));
    memcpy(test->bytes + test->received, solaris_buffer_data(buffer), length);
    test->received += length;
}
static void tcp_eof(void *context, solaris_stream_t *stream)
{
    tcp_case_t *test = context; CHECK(stream == test->stream);
    if (test->mode == TCP_EARLY_EOF) {
        CHECK(test->received == 5u && memcmp(test->bytes, "HELLO", 5u) == 0);
        test->eof++;
        solaris_buffer_t *buffer = NULL;
        CHECK(solaris_buffer_copy(solaris_executor_budget(test->executor), "LATE", 4u, &buffer) == SOLARIS_OK);
        const solaris_slice_t slice = {buffer, 0u, 4u};
        CHECK(solaris_stream_write(stream, &slice, tcp_write_done, test) == SOLARIS_OK);
        solaris_buffer_release(buffer);
        CHECK(solaris_stream_shutdown_write(stream, tcp_shutdown_done, test) == SOLARIS_OK);
        return;
    }
    CHECK(test->mode == TCP_NORMAL);
    CHECK(test->received == 10u && memcmp(test->bytes, "abcdefTAIL", 10u) == 0);
    test->eof++;
}
static void tcp_writable(void *context, solaris_stream_t *stream)
{
    tcp_case_t *test = context; CHECK(stream == test->stream && test->mode == TCP_NORMAL);
    CHECK(test->writes == 1u && ++test->writable == 1u);
    send_tcp_part(test, "def");
}
static void tcp_closed(void *context, solaris_stream_t *stream, solaris_status_t status)
{
    tcp_case_t *test = context; CHECK(stream == test->stream && ++test->closes == 1u);
    CHECK(solaris_stream_get_snapshot(stream, &test->final) == SOLARIS_OK);
    CHECK(test->final.pending_requests == 0u && test->final.pending_bytes == 0u);
    test->close_status = status; test->stream = NULL;
    CHECK(solaris_engine_destroy(test->engine, NULL) == SOLARIS_EDEADLOCK);
    solaris_test_event_signal(&test->done);
}
static const solaris_stream_callbacks_t tcp_callbacks = {tcp_open, tcp_data, tcp_eof, tcp_writable, tcp_closed};

static void start_tcp(void *context, solaris_status_t status)
{
    tcp_case_t *test = context; CHECK(status == SOLARIS_OK);
    solaris_dialer_options_t options; solaris_dialer_options_init(&options);
    options.prepare_socket = tcp_policy; options.policy_context = test;
    if (test->bind_local) {
        CHECK(solaris_address_parse(test->destination.family == SOLARIS_ADDRESS_IPV6 ? "::1" : "127.0.0.1",
                                     0u, &options.local_bind) == SOLARIS_OK);
    }
    if (test->mode == TCP_NORMAL) { options.pending_byte_limit = 3u; options.pending_request_limit = 1u; }
    if (test->mode == TCP_TIMEOUT) options.open_timeout_ms = 10u;
    solaris_module_instance_t *instance;
    solaris_outbound_t *outbound = create_outbound(test->executor, "direct", &options, &instance);
    CHECK(solaris_outbound_open_stream(outbound, &test->destination,
                                        &tcp_callbacks, test, &test->stream) == SOLARIS_OK);
    CHECK(solaris_module_retire(instance) == SOLARIS_OK); /* channel owns its lifetime */
    CHECK(test->opens == 0u); /* no inline completion */
    if (test->mode == TCP_CANCEL) CHECK(solaris_stream_close(test->stream) == SOLARIS_OK);
    if (test->mode == TCP_TIMEOUT) {
        uv_mutex_lock(test->clock_mutex); *test->clock_ns += UINT64_C(11000000); uv_mutex_unlock(test->clock_mutex);
        solaris_executor_wake(test->executor);
    }
}
static void init_tcp(tcp_case_t *test, solaris_engine_t *engine, uint64_t key,
                      const char *host, uint16_t port, int mode)
{
    memset(test, 0, sizeof(*test)); test->engine = engine; test->mode = mode;
    test->executor = solaris_runtime_executor(engine, key);
    CHECK(solaris_address_parse(host, port, &test->destination) == SOLARIS_OK);
    CHECK(solaris_test_event_init(&test->done, 0) == 0 && solaris_test_event_init(&test->ready, 0) == 0);
}
static void free_tcp(tcp_case_t *test) { solaris_test_event_destroy(&test->done); solaris_test_event_destroy(&test->ready); }

enum { UDP_NORMAL4, UDP_NORMAL6, UDP_CANCEL, UDP_IDLE };
typedef struct udp_case {
    solaris_engine_t *engine;
    solaris_executor_t *executor;
    solaris_datagram_t *channel;
    solaris_address_t a, b;
    uint16_t alternate_port, local_port;
    uint32_t family;
    int mode;
    solaris_buffer_t *third;
    solaris_test_event_t done, ready;
    unsigned int opens, closes, sends, packets, a_count, b_count, second_a, empty, alternate, prepared;
    solaris_status_t close_status;
    solaris_io_snapshot_t final;
} udp_case_t;

static void maybe_close_udp(udp_case_t *test)
{
    if ((test->mode == UDP_NORMAL4 && test->packets == 5u && test->sends == 3u) ||
        (test->mode == UDP_NORMAL6 && test->packets == 2u && test->sends == 2u)) {
        CHECK(solaris_datagram_close(test->channel) == SOLARIS_OK);
    }
}
static void udp_sent(void *context, solaris_status_t status)
{
    udp_case_t *test = context;
    CHECK(status == SOLARIS_OK || (test->mode == UDP_CANCEL && status == SOLARIS_ECANCELLED));
    test->sends++;
    maybe_close_udp(test);
}
static solaris_status_t udp_policy(void *context, uintptr_t handle, uint32_t family, uint32_t kind)
{
    (void)handle;
    udp_case_t *test = context; CHECK(kind == SOLARIS_SOCKET_UDP && family == test->family);
    CHECK(solaris_executor_is_owner(test->executor)); test->prepared++;
    return SOLARIS_OK;
}
static void rejected_completion(void *context, solaris_status_t status)
{ (void)context; (void)status; CHECK(0); }
static void udp_open(void *context, solaris_datagram_t *channel, solaris_status_t status)
{
    udp_case_t *test = context;
    CHECK(status == SOLARIS_OK && channel == test->channel && ++test->opens == 1u);
    solaris_address_t local; CHECK(solaris_datagram_local_address(channel, &local) == SOLARIS_OK);
    CHECK(local.family == test->family && local.port != 0u); test->local_port = local.port;
    if (test->mode == UDP_IDLE) { solaris_test_event_signal(&test->ready); return; }
    solaris_buffer_t *oversize = NULL;
    CHECK(solaris_buffer_allocate(solaris_executor_budget(test->executor), 65528u, &oversize) == SOLARIS_OK);
    CHECK(solaris_buffer_set_length(oversize, 65528u) == SOLARIS_OK);
    const solaris_slice_t too_large = {oversize, 0u, 65528u};
    CHECK(solaris_datagram_send(channel, &test->a, &too_large, rejected_completion, NULL) == SOLARIS_EMSGSIZE);
    solaris_buffer_release(oversize);
    solaris_buffer_t *first = NULL, *second = NULL;
    CHECK(solaris_buffer_copy(solaris_executor_budget(test->executor),
        test->mode == UDP_NORMAL6 ? "V6" : test->mode == UDP_CANCEL ? "X" : "A",
        test->mode == UDP_NORMAL6 ? 2u : 1u, &first) == SOLARIS_OK);
    CHECK(solaris_buffer_copy(solaris_executor_budget(test->executor),
        test->mode == UDP_NORMAL6 ? "" : test->mode == UDP_CANCEL ? "Y" : "B",
        test->mode == UDP_NORMAL6 ? 0u : 1u, &second) == SOLARIS_OK);
    CHECK(solaris_buffer_copy(solaris_executor_budget(test->executor), "A2", 2u, &test->third) == SOLARIS_OK);
    solaris_address_t domain;
    CHECK(solaris_address_parse("localhost", test->a.port, &domain) == SOLARIS_OK);
    const solaris_slice_t valid = {first, 0u, solaris_buffer_length(first)};
    CHECK(solaris_datagram_send(channel, &domain, &valid, rejected_completion, NULL) == SOLARIS_ENOTSUP);
    const solaris_slice_t invalid = {first, solaris_buffer_length(first) + 1u, 1u};
    CHECK(solaris_datagram_send(channel, &test->a, &invalid, rejected_completion, NULL) == SOLARIS_EINVAL);
    solaris_datagram_message_t messages[3] = {
        {test->a, {first, 0u, solaris_buffer_length(first)}, udp_sent, test},
        {test->b, {second, 0u, solaris_buffer_length(second)}, udp_sent, test},
        {test->a, {test->third, 0u, 2u}, udp_sent, test}
    };
    size_t accepted = 999u;
    solaris_status_t rc = solaris_datagram_send_batch(channel, messages,
        test->mode == UDP_NORMAL6 ? 2u : 3u, &accepted);
    CHECK(accepted == 2u && rc == (test->mode == UDP_NORMAL6 ? SOLARIS_OK : SOLARIS_EAGAIN));
    solaris_buffer_release(first); solaris_buffer_release(second);
    if (test->mode == UDP_NORMAL6) { solaris_buffer_release(test->third); test->third = NULL; }
    if (test->mode == UDP_CANCEL) CHECK(solaris_datagram_close(channel) == SOLARIS_OK);
}
static void udp_writable(void *context, solaris_datagram_t *channel)
{
    udp_case_t *test = context;
    CHECK(test->mode == UDP_NORMAL4 && test->third != NULL && channel == test->channel);
    const solaris_slice_t data = {test->third, 0u, 2u};
    CHECK(solaris_datagram_send(channel, &test->a, &data, udp_sent, test) == SOLARIS_OK);
    solaris_buffer_release(test->third); test->third = NULL;
}
static void udp_packet(void *context, solaris_datagram_t *channel, const solaris_address_t *source,
                         const solaris_buffer_t *buffer)
{
    udp_case_t *test = context; CHECK(channel == test->channel);
    CHECK(test->mode == UDP_NORMAL4 || test->mode == UDP_NORMAL6);
    const size_t size = solaris_buffer_length(buffer);
    const uint8_t *data = solaris_buffer_data(buffer);
    test->packets++;
    if (size == 0u) { CHECK(source->port == test->a.port); test->empty++; }
    else if (test->mode == UDP_NORMAL6) { CHECK(size == 2u && memcmp(data, "V6", 2u) == 0); test->a_count++; }
    else if (size == 1u && data[0] == 'A') { CHECK(source->port == test->a.port); test->a_count++; }
    else if (size == 1u && data[0] == 'B') { CHECK(source->port == test->b.port); test->b_count++; }
    else if (size == 2u && memcmp(data, "A2", 2u) == 0) { CHECK(source->port == test->a.port); test->second_a++; }
    else if (size == 3u && memcmp(data, "ALT", 3u) == 0) { CHECK(source->port == test->alternate_port); test->alternate++; }
    else CHECK(0);
    CHECK(source->family == test->family);
    maybe_close_udp(test);
}
static void udp_closed(void *context, solaris_datagram_t *channel, solaris_status_t status)
{
    udp_case_t *test = context; CHECK(channel == test->channel && ++test->closes == 1u);
    CHECK(solaris_datagram_get_snapshot(channel, &test->final) == SOLARIS_OK);
    CHECK(test->final.pending_requests == 0u && test->final.pending_bytes == 0u);
    solaris_buffer_release(test->third); test->third = NULL;
    test->close_status = status; test->channel = NULL;
    solaris_test_event_signal(&test->done);
}
static const solaris_datagram_callbacks_t udp_callbacks = {udp_open, udp_packet, udp_writable, udp_closed};
static void start_udp(void *context, solaris_status_t status)
{
    udp_case_t *test = context; CHECK(status == SOLARIS_OK);
    solaris_dialer_options_t options; solaris_dialer_options_init(&options);
    options.pending_request_limit = 2u; options.prepare_socket = udp_policy; options.policy_context = test;
    CHECK(solaris_address_parse(test->family == SOLARIS_ADDRESS_IPV6 ? "::1" : "127.0.0.1", 0, &options.local_bind) == SOLARIS_OK);
    solaris_module_instance_t *instance;
    solaris_outbound_t *outbound = create_outbound(test->executor, "direct", &options, &instance);
    CHECK(solaris_outbound_open_datagram(outbound, test->family,
                                          &udp_callbacks, test, &test->channel) == SOLARIS_OK);
    CHECK(solaris_module_retire(instance) == SOLARIS_OK);
    CHECK(test->opens == 0u);
}
static void init_udp(udp_case_t *test, solaris_engine_t *engine, uint64_t key,
                      uint32_t family, uint16_t a, uint16_t b, uint16_t alternate, int mode)
{
    memset(test, 0, sizeof(*test)); test->engine = engine; test->mode = mode; test->family = family;
    test->executor = solaris_runtime_executor(engine, key); test->alternate_port = alternate;
    const char *host = family == SOLARIS_ADDRESS_IPV6 ? "::1" : "127.0.0.1";
    CHECK(solaris_address_parse(host, a, &test->a) == SOLARIS_OK && solaris_address_parse(host, b, &test->b) == SOLARIS_OK);
    CHECK(solaris_test_event_init(&test->done, 0) == 0 && solaris_test_event_init(&test->ready, 0) == 0);
}
static void free_udp(udp_case_t *test) { solaris_test_event_destroy(&test->done); solaris_test_event_destroy(&test->ready); }

typedef struct deny_case { solaris_executor_t *executor; solaris_address_t destination; solaris_test_event_t done; unsigned int prepared; } deny_case_t;
static solaris_status_t reject_socket(void *context, uintptr_t handle, uint32_t family, uint32_t kind)
{
    (void)handle; (void)family; (void)kind;
    deny_case_t *test = context; test->prepared++; return SOLARIS_EACCESS;
}
static void deny_paths(void *context, solaris_status_t status)
{
    deny_case_t *test = context; CHECK(status == SOLARIS_OK);
    solaris_module_instance_t *block_instance, *direct_instance;
    solaris_stream_t *stream = NULL; solaris_datagram_t *datagram = NULL;
    solaris_outbound_t *block = create_outbound(test->executor, "reject", NULL, &block_instance);
    CHECK(solaris_outbound_open_stream(block, &test->destination, &tcp_callbacks, NULL, &stream) == SOLARIS_EACCESS);
    CHECK(solaris_outbound_open_datagram(block, SOLARIS_ADDRESS_IPV4, &udp_callbacks, NULL, &datagram) == SOLARIS_EACCESS);
    CHECK(solaris_module_retire(block_instance) == SOLARIS_OK);
    solaris_dialer_options_t options; solaris_dialer_options_init(&options);
    options.prepare_socket = reject_socket; options.policy_context = test;
    solaris_outbound_t *direct = create_outbound(test->executor, "direct", &options, &direct_instance);
    CHECK(solaris_outbound_open_stream(direct, &test->destination, &tcp_callbacks, NULL, &stream) == SOLARIS_EACCESS);
    CHECK(solaris_outbound_open_datagram(direct, SOLARIS_ADDRESS_IPV4, &udp_callbacks, NULL, &datagram) == SOLARIS_EACCESS);
    CHECK(stream == NULL && datagram == NULL && test->prepared == 2u);
    CHECK(solaris_module_retire(direct_instance) == SOLARIS_OK);
    CHECK(solaris_outbound_open_stream(direct, &test->destination, &tcp_callbacks, NULL, &stream) == SOLARIS_ECLOSED);
    solaris_test_event_signal(&test->done);
}

typedef struct fake_clock { uv_mutex_t mutex; uint64_t now; } fake_clock_t;
static uint64_t fake_now(void *context)
{
    fake_clock_t *clock = context; uv_mutex_lock(&clock->mutex);
    uint64_t now = clock->now; uv_mutex_unlock(&clock->mutex); return now;
}
static void test_timeout(uint16_t port)
{
    fake_clock_t clock; memset(&clock, 0, sizeof(clock)); CHECK(uv_mutex_init(&clock.mutex) == 0);
    solaris_runtime_services_t services; solaris_runtime_services_init(&services);
    services.context = &clock; services.now_ns = fake_now;
    solaris_engine_t *engine = NULL;
    CHECK(solaris_runtime_create(NULL, NULL, &services, &engine, NULL) == SOLARIS_OK);
    uint64_t operation; CHECK(solaris_engine_start(engine, &operation, NULL) == SOLARIS_OK);
    CHECK(solaris_engine_flush(engine, 5000u, NULL) == SOLARIS_OK);
    tcp_case_t test; init_tcp(&test, engine, 0u, "localhost", port, TCP_TIMEOUT);
    test.clock_mutex = &clock.mutex; test.clock_ns = &clock.now;
    CHECK(solaris_executor_post(test.executor, start_tcp, &test) == SOLARIS_OK);
    solaris_test_event_wait(&test.done);
    CHECK(test.open_status == SOLARIS_ETIMEDOUT && test.close_status == SOLARIS_ETIMEDOUT && test.opens == 1u);
    CHECK(solaris_engine_destroy(engine, NULL) == SOLARIS_OK);
    free_tcp(&test); uv_mutex_destroy(&clock.mutex);
}

int main(int argc, char **argv)
{
    CHECK(argc == 7);
    uint16_t ports[6];
    for (size_t i = 0; i < 6u; i++) { long port = strtol(argv[i + 1u], NULL, 10); CHECK(port > 0 && port < 65536); ports[i] = (uint16_t)port; }
    solaris_engine_options_t options; solaris_engine_options_init(&options); options.io_workers = 2u;
    solaris_engine_t *engine = NULL; CHECK(solaris_engine_create(&options, NULL, &engine, NULL) == SOLARIS_OK);
    uint64_t operation; CHECK(solaris_engine_start(engine, &operation, NULL) == SOLARIS_OK);
    CHECK(solaris_engine_flush(engine, 5000u, NULL) == SOLARIS_OK);
    tcp_case_t tcp[6];
    init_tcp(&tcp[0], engine, 0u, "127.0.0.1", ports[0], TCP_NORMAL); tcp[0].bind_local = 1;
    init_tcp(&tcp[1], engine, 1u, "localhost", ports[0], TCP_NORMAL);
    init_tcp(&tcp[2], engine, 1u, "::1", ports[1], TCP_NORMAL); tcp[2].bind_local = 1;
    init_tcp(&tcp[3], engine, 0u, "localhost", ports[0], TCP_CANCEL);
    init_tcp(&tcp[4], engine, 1u, "127.0.0.1", ports[0], TCP_WRITE_CANCEL);
    init_tcp(&tcp[5], engine, 0u, "127.0.0.1", ports[0], TCP_EARLY_EOF);
    for (size_t i = 0; i < 6u; i++) CHECK(solaris_executor_post(tcp[i].executor, start_tcp, &tcp[i]) == SOLARIS_OK);
    udp_case_t udp[3];
    init_udp(&udp[0], engine, 0u, SOLARIS_ADDRESS_IPV4, ports[2], ports[3], ports[4], UDP_NORMAL4);
    init_udp(&udp[1], engine, 1u, SOLARIS_ADDRESS_IPV6, ports[5], ports[5], 0u, UDP_NORMAL6);
    init_udp(&udp[2], engine, 1u, SOLARIS_ADDRESS_IPV4, ports[2], ports[3], ports[4], UDP_CANCEL);
    for (size_t i = 0; i < 3u; i++) CHECK(solaris_executor_post(udp[i].executor, start_udp, &udp[i]) == SOLARIS_OK);
    deny_case_t deny; memset(&deny, 0, sizeof(deny)); deny.executor = solaris_runtime_executor(engine, 0u);
    CHECK(solaris_test_event_init(&deny.done, 0) == 0 && solaris_address_parse("127.0.0.1", ports[0], &deny.destination) == SOLARIS_OK);
    CHECK(solaris_executor_post(deny.executor, deny_paths, &deny) == SOLARIS_OK); solaris_test_event_wait(&deny.done);
    for (size_t i = 0; i < 6u; i++) {
        fprintf(stderr, "Await TCP case %zu\n", i);
        solaris_test_event_wait(&tcp[i].done);
    }
    for (size_t i = 0; i < 3u; i++) {
        fprintf(stderr, "Await UDP case %zu\n", i);
        solaris_test_event_wait(&udp[i].done);
    }
    for (size_t i = 0; i < 3u; i++) {
        CHECK(tcp[i].open_status == SOLARIS_OK && tcp[i].close_status == SOLARIS_OK);
        CHECK(tcp[i].writes == 2u && tcp[i].shutdowns == 1u && tcp[i].eof == 1u && tcp[i].backpressure == 1u);
        CHECK(tcp[i].final.bytes_written == 6u && tcp[i].final.bytes_read == 10u && tcp[i].prepared > 0u);
    }
    CHECK(tcp[3].open_status == SOLARIS_ECANCELLED && tcp[3].prepared == 0u);
    CHECK(tcp[4].writes == 1u);
    CHECK(tcp[5].writes == 2u && tcp[5].shutdowns == 1u && tcp[5].eof == 1u && tcp[5].close_status == SOLARIS_OK);
    CHECK(udp[0].a_count == 1u && udp[0].b_count == 1u && udp[0].second_a == 1u && udp[0].empty == 1u && udp[0].alternate == 1u);
    CHECK(udp[1].a_count == 1u && udp[1].empty == 1u && udp[2].sends == 2u && udp[2].packets == 0u);
    tcp_case_t idle_tcp; udp_case_t idle_udp;
    init_tcp(&idle_tcp, engine, 0u, "127.0.0.1", ports[0], TCP_IDLE);
    init_udp(&idle_udp, engine, 1u, SOLARIS_ADDRESS_IPV4, ports[2], ports[3], ports[4], UDP_IDLE);
    CHECK(solaris_executor_post(idle_tcp.executor, start_tcp, &idle_tcp) == SOLARIS_OK);
    CHECK(solaris_executor_post(idle_udp.executor, start_udp, &idle_udp) == SOLARIS_OK);
    solaris_test_event_wait(&idle_tcp.ready); solaris_test_event_wait(&idle_udp.ready);
    CHECK(solaris_stream_set_reading(idle_tcp.stream, 0) == SOLARIS_ETHREAD);
    CHECK(solaris_datagram_close(idle_udp.channel) == SOLARIS_ETHREAD);
    CHECK(solaris_engine_stop(engine, &operation, NULL) == SOLARIS_OK);
    CHECK(solaris_engine_flush(engine, 5000u, NULL) == SOLARIS_OK);
    CHECK(idle_tcp.closes == 1u && idle_tcp.close_status == SOLARIS_ECANCELLED);
    CHECK(idle_udp.closes == 1u && idle_udp.close_status == SOLARIS_ECANCELLED);
    solaris_engine_snapshot_t snapshot; CHECK(solaris_engine_get_snapshot(engine, &snapshot, NULL) == SOLARIS_OK);
    CHECK(snapshot.io_buffer_bytes == 0u);
    CHECK(solaris_engine_destroy(engine, NULL) == SOLARIS_OK);
    test_timeout(ports[0]);
    printf("{\"udp4_port\":%u,\"udp6_port\":%u,\"tcp_cases\":6,\"udp_cases\":3,\"timeout\":true,\"budget_drained\":true}\n",
        (unsigned)udp[0].local_port, (unsigned)udp[1].local_port);
    for (size_t i = 0; i < 6u; i++) free_tcp(&tcp[i]);
    for (size_t i = 0; i < 3u; i++) free_udp(&udp[i]);
    free_tcp(&idle_tcp); free_udp(&idle_udp); solaris_test_event_destroy(&deny.done);
    return 0;
}
