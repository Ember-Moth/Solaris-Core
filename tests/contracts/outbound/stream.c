#include "contracts/module/module.h"
#include "runtime/executor/executor.h"
#include "support/runtime/event.h"
#include "transport/tls/tls.h"
#include "observe/connections/tracker.h"
#include "solaris_builtin_modules.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)
#define PROXY_PAYLOAD 65541u
enum { PROXY_ECHO, PROXY_CANCEL, PROXY_WRITE_CANCEL, PROXY_DENIED };
typedef struct proxy_case {
    solaris_executor_t *owner;
    solaris_replay_store_t *replay;
    solaris_module_config_t *config;
    solaris_module_instance_t *instance;
    solaris_tls_context_t *inner_trust;
    solaris_stream_callbacks_t carrier_callbacks;
    void *carrier_context;
    solaris_io_snapshot_t outer_snapshot;
    solaris_tracker_t *tracker;
    solaris_traffic_counter_t *traffic;
    uint64_t connection_ids[10];
    unsigned int rounds;
    solaris_stream_t *stream;
    solaris_address_t destination;
    solaris_test_event_t ready, done;
    solaris_deadline_t *resume;
    int mode, half_close;
    unsigned int opens, closes, writes, shutdowns, eof, writable;
    size_t received;
    solaris_status_t open_status, close_status;
} proxy_case_t;
static unsigned char pattern(size_t i) { return (unsigned char)((i * 17u + 29u) & 255u); }
static void written(void *context, solaris_status_t status)
{
    proxy_case_t *test = context;
    if (test->mode == PROXY_ECHO) CHECK(status == SOLARIS_OK);
    if (test->mode == PROXY_WRITE_CANCEL) CHECK(status == SOLARIS_ECANCELLED);
    test->writes++;
}
static void shutdown_done(void *context, solaris_status_t status)
{ CHECK(status == SOLARIS_OK); ((proxy_case_t *)context)->shutdowns++; }
static void resumed(void *context, solaris_status_t status)
{
    proxy_case_t *test = context; test->resume = NULL;
    CHECK(status == SOLARIS_OK && test->received == 0u);
    CHECK(solaris_stream_set_reading(test->stream, 1) == SOLARIS_OK);
}
static void opened(void *context, solaris_stream_t *stream, solaris_status_t status)
{
    proxy_case_t *test = context;
    CHECK(stream == test->stream && ++test->opens <= test->rounds);
    test->open_status = status;
    if (test->mode == PROXY_CANCEL) { CHECK(status == SOLARIS_ECANCELLED); return; }
    if (test->mode == PROXY_DENIED && status != SOLARIS_OK) return;
    CHECK(status == SOLARIS_OK);
    solaris_buffer_t *buffer;
    CHECK(solaris_buffer_allocate(solaris_executor_budget(test->owner), PROXY_PAYLOAD, &buffer) == SOLARIS_OK);
    for (size_t i = 0u; i < PROXY_PAYLOAD; ++i) solaris_buffer_mutable_data(buffer)[i] = pattern(i);
    CHECK(solaris_buffer_set_length(buffer, PROXY_PAYLOAD) == SOLARIS_OK);
    solaris_slice_t slice = {buffer, 0u, PROXY_PAYLOAD};
    CHECK(solaris_stream_write(stream, &slice, written, test) == SOLARIS_OK);
    CHECK(solaris_stream_write(stream, &slice, written, test) == SOLARIS_EAGAIN);
    solaris_buffer_release(buffer);
    if (test->mode == PROXY_WRITE_CANCEL) { CHECK(solaris_stream_close(stream) == SOLARIS_OK); return; }
    if (test->mode == PROXY_DENIED) return;
    CHECK(solaris_stream_set_reading(stream, 0) == SOLARIS_OK);
    CHECK(solaris_deadline_start(test->owner, 5u, resumed, test, &test->resume) == SOLARIS_OK);
}
static void data(void *context, solaris_stream_t *stream, const solaris_buffer_t *buffer)
{
    proxy_case_t *test = context;
    CHECK(test->mode == PROXY_ECHO && stream == test->stream);
    size_t count = solaris_buffer_length(buffer);
    CHECK(test->received + count <= PROXY_PAYLOAD);
    for (size_t i = 0u; i < count; ++i) CHECK(solaris_buffer_data(buffer)[i] == pattern(test->received + i));
    test->received += count;
    if (test->received == PROXY_PAYLOAD) {
        if (test->half_close) CHECK(solaris_stream_shutdown_write(stream, shutdown_done, test) == SOLARIS_OK);
        else { CHECK(solaris_stream_shutdown_write(stream, shutdown_done, test) == SOLARIS_ENOTSUP); CHECK(solaris_stream_close(stream) == SOLARIS_OK); }
    }
}
static void stream_eof(void *context, solaris_stream_t *stream)
{ proxy_case_t *test = context; CHECK(stream == test->stream); test->eof++; }
static void writable(void *context, solaris_stream_t *stream)
{ proxy_case_t *test = context; CHECK(stream == test->stream); test->writable++; }
static solaris_status_t open_next(proxy_case_t *test);
static void closed(void *context, solaris_stream_t *stream, solaris_status_t status)
{
    proxy_case_t *test = context;
    CHECK(stream == test->stream && ++test->closes <= test->rounds);
    test->close_status = status;
    solaris_io_snapshot_t snapshot;
    CHECK(solaris_stream_get_snapshot(stream, &snapshot) == SOLARIS_OK);
    CHECK(snapshot.pending_bytes == 0u && snapshot.pending_requests == 0u);
    if (test->mode == PROXY_ECHO) {
        CHECK(snapshot.bytes_read == PROXY_PAYLOAD && snapshot.bytes_written == PROXY_PAYLOAD);
        CHECK(!test->half_close || (snapshot.read_eof && snapshot.write_shutdown));
        if (test->inner_trust != NULL) CHECK(test->outer_snapshot.raw_read && test->outer_snapshot.raw_write);
    }
    if (test->mode == PROXY_ECHO && test->closes < test->rounds) {
        test->received = 0u;
        CHECK(open_next(test) == SOLARIS_OK);
        return;
    }
    if (test->instance != NULL) { CHECK(solaris_module_retire(test->instance) == SOLARIS_OK); test->instance = NULL; }
    solaris_test_event_signal(&test->done);
}
static const solaris_stream_callbacks_t callbacks = {opened, data, stream_eof, writable, closed};
#if SOLARIS_HAS_TLS
static void carrier_opened(void *context, solaris_stream_t *stream, solaris_status_t status)
{ proxy_case_t *test = context; test->carrier_callbacks.on_open(test->carrier_context, stream, status); }
static void carrier_data(void *context, solaris_stream_t *stream, const solaris_buffer_t *buffer)
{ proxy_case_t *test = context; test->carrier_callbacks.on_data(test->carrier_context, stream, buffer); }
static void carrier_eof(void *context, solaris_stream_t *stream)
{ proxy_case_t *test = context; if (test->carrier_callbacks.on_eof != NULL) test->carrier_callbacks.on_eof(test->carrier_context, stream); }
static void carrier_writable(void *context, solaris_stream_t *stream)
{ proxy_case_t *test = context; if (test->carrier_callbacks.on_writable != NULL) test->carrier_callbacks.on_writable(test->carrier_context, stream); }
static void carrier_closed(void *context, solaris_stream_t *stream, solaris_status_t status)
{
    proxy_case_t *test = context;
    CHECK(solaris_stream_get_snapshot(stream, &test->outer_snapshot) == SOLARIS_OK);
    test->carrier_callbacks.on_close(test->carrier_context, stream, status);
}
static const solaris_stream_callbacks_t carrier_callbacks = {carrier_opened, carrier_data, carrier_eof, carrier_writable, carrier_closed};
#endif
static solaris_status_t open_observed(proxy_case_t *test, const solaris_address_t *target,
    const solaris_stream_callbacks_t *cb, void *user, solaris_stream_t **out)
{
    solaris_dial_plan_t source, observed;
    CHECK(solaris_module_plan_acquire(test->instance, 7u, &source) == SOLARIS_OK);
    solaris_observe_options_t options = {.kind = SOLARIS_FLOW_STREAM, .purpose = SOLARIS_FLOW_USER, .target = *target};
    CHECK(solaris_observe_plan(test->tracker, &source, &options, &observed, &test->connection_ids[test->closes]) == SOLARIS_OK);
    CHECK(source.outbound == NULL);
    solaris_status_t rc = solaris_outbound_open_stream(observed.outbound, target, cb, user, out);
    CHECK(solaris_dial_plan_release(&observed) == SOLARIS_OK); return rc;
}
#if SOLARIS_HAS_TLS
static solaris_status_t open_carrier(void *context, solaris_executor_t *owner, const solaris_dialer_options_t *options,
    const solaris_address_t *peer, const solaris_stream_callbacks_t *cb, void *user, solaris_stream_t **out)
{
    (void)options; proxy_case_t *test = context; CHECK(owner == test->owner);
    test->carrier_callbacks = *cb; test->carrier_context = user;
    return open_observed(test, peer, &carrier_callbacks, test, out);
}
#endif
static solaris_status_t open_next(proxy_case_t *test)
{
#if SOLARIS_HAS_TLS
    if (test->inner_trust == NULL)
        return open_observed(test, &test->destination, &callbacks, test, &test->stream);
    solaris_stream_factory_t factory = {.context = test, .open = open_carrier};
    solaris_dialer_options_t options = {.pending_byte_limit = PROXY_PAYLOAD, .pending_request_limit = 1u,
        .read_chunk_size = 113u, .open_timeout_ms = 3000u};
    return solaris_tls_open(test->owner, test->inner_trust, "localhost", SOLARIS_TLS_1_3,
        &factory, &options, &test->destination, &callbacks, test, &test->stream);
#else
    return open_observed(test, &test->destination, &callbacks, test, &test->stream);
#endif
}
static void start(void *context, solaris_status_t status)
{
    proxy_case_t *test = context; CHECK(status == SOLARIS_OK);
    solaris_module_services_t services = {.owner = test->owner, .replay = test->replay, .dialer = {.traffic = test->traffic}};
    solaris_module_instance_t *instance;
    CHECK(solaris_module_create(test->config, &services, NULL, NULL, &instance, NULL) == SOLARIS_OK);
    solaris_outbound_t *outbound = solaris_module_outbound(instance);
    uint32_t caps = 0u;
    CHECK(solaris_outbound_capabilities(outbound, &caps) == SOLARIS_OK);
    CHECK(caps & SOLARIS_OUTBOUND_STREAM);
    test->half_close = (caps & SOLARIS_OUTBOUND_HALF_CLOSE) != 0;
    test->instance = instance; CHECK(open_next(test) == SOLARIS_OK);
    if (test->rounds == 1u) { CHECK(solaris_module_retire(instance) == SOLARIS_OK); test->instance = NULL; }
    if (test->mode == PROXY_CANCEL) CHECK(solaris_stream_close(test->stream) == SOLARIS_OK);
    solaris_test_event_signal(&test->ready);
}
static solaris_config_field_t string_field(const char *name, const char *value)
{
    solaris_config_field_t field = {.name = name, .value = {.kind = SOLARIS_CONFIG_STRING}};
    field.value.value.string.data = value; field.value.value.string.length = strlen(value); return field;
}
static solaris_config_field_t integer_field(const char *name, int64_t value)
{
    solaris_config_field_t field = {.name = name, .value = {.kind = SOLARIS_CONFIG_INTEGER}};
    field.value.value.integer = value; return field;
}
int main(int argc, char **argv)
{
    CHECK(argc >= 9 && argc <= 13);
    solaris_budget_t *budget;
    CHECK(solaris_budget_create(16u * 1024u * 1024u, NULL, &budget) == SOLARIS_OK);
    solaris_registry_t *registry;
    CHECK(solaris_builtin_registry_create(budget, &registry, NULL) == SOLARIS_OK);
    solaris_config_field_t fields[16]; size_t n = 0u;
    const char *server = getenv("SOLARIS_TEST_SERVER");
    fields[n++] = string_field("server", server != NULL ? server : "127.0.0.1");
    fields[n++] = integer_field("port", atoi(argv[2]));
    fields[n++] = integer_field("pending-bytes", PROXY_PAYLOAD);
    fields[n++] = integer_field("pending-requests", 1);
    fields[n++] = integer_field("read-chunk-size", 113);
    const char *timeout = getenv("SOLARIS_TEST_OPEN_TIMEOUT_MS");
    if (timeout != NULL) fields[n++] = integer_field("open-timeout-ms", atoi(timeout));
    if (strcmp(argv[1], "socks5") == 0) {
        if (strcmp(argv[5], "-") != 0 || strcmp(argv[6], "-") != 0) {
            fields[n++] = string_field("username", argv[6]); fields[n++] = string_field("password", argv[5]);
        }
    } else {
        fields[n++] = string_field(strcmp(argv[1], "vless") == 0 ? "uuid" : "password", argv[5]);
        if (strcmp(argv[6], "-") != 0) fields[n++] = string_field("cipher", argv[6]);
    }
    if (argc >= 11) fields[n++] = string_field("encryption", argv[10]);
    if (argc >= 12) fields[n++] = string_field("flow", argv[11]);
    char pem[16384];
    if (strcmp(argv[7], "-") != 0) {
        FILE *file = fopen(argv[7], "rb"); CHECK(file != NULL);
        size_t size = fread(pem, 1u, sizeof(pem) - 1u, file); fclose(file); CHECK(size > 0u); pem[size] = '\0';
        fields[n++] = (solaris_config_field_t){.name = "tls", .value = {.kind = SOLARIS_CONFIG_BOOL, .value.boolean = 1}};
        fields[n++] = string_field("servername", "localhost"); fields[n++] = string_field("ca-pem", pem);
    }
    solaris_config_view_t view = {.kind = SOLARIS_CONFIG_MAP, .value.map = {.fields = fields, .count = n}};
    solaris_module_config_t *config;
    solaris_error_t error;
    solaris_status_t rc = solaris_registry_compile(registry, argv[1], &view, &config, &error);
    if (rc != SOLARIS_OK) fprintf(stderr, "compile: %s\n", error.message);
    CHECK(rc == SOLARIS_OK); solaris_registry_destroy(registry);
    solaris_tls_context_t *inner_trust = NULL;
#if SOLARIS_HAS_TLS
    if (argc == 13) {
        FILE *file = fopen(argv[12], "rb"); CHECK(file != NULL);
        size_t size = fread(pem, 1u, sizeof(pem), file); CHECK(feof(file)); fclose(file);
        CHECK(solaris_tls_context_create(budget, pem, size, &inner_trust) == SOLARIS_OK);
    }
#else
    CHECK(argc != 13);
#endif
    solaris_replay_store_t *replay;
    CHECK(solaris_replay_create(budget, 1024u, 0u, NULL, NULL, &replay) == SOLARIS_OK);
    solaris_tracker_t *tracker; CHECK(solaris_tracker_create(budget, 16u, 32u, &tracker) == SOLARIS_OK);
    proxy_case_t tests[2] = {{0}};
    for (size_t i = 0u; i < 2u; ++i) {
        proxy_case_t *test = &tests[i]; test->config = config; test->replay = replay; test->inner_trust = inner_trust;
        test->tracker = tracker;
        CHECK(solaris_traffic_counter_create(budget, &test->traffic) == SOLARIS_OK);
        test->mode = atoi(argv[8]); test->rounds = argc >= 10 ? (unsigned int)atoi(argv[9]) : 1u; CHECK(test->rounds >= 1u && test->rounds <= 10u);
        CHECK(solaris_test_event_init(&test->ready, 0u) == 0 && solaris_test_event_init(&test->done, 0u) == 0);
        CHECK(solaris_address_parse(argv[3], (uint16_t)atoi(argv[4]), &test->destination) == SOLARIS_OK);
        solaris_executor_options_t options = {.id = (uint32_t)i, .queue_capacity = 16u, .resource_limit = 128u, .budget = budget};
        CHECK(solaris_executor_create(&options, &test->owner) == SOLARIS_OK);
        CHECK(solaris_executor_activate(test->owner, 1u) == SOLARIS_OK);
        CHECK(solaris_executor_post(test->owner, start, test) == SOLARIS_OK);
    }
    for (size_t i = 0u; i < 2u; ++i) solaris_test_event_wait(&tests[i].ready);
    solaris_module_config_release(config);
    for (size_t i = 0u; i < 2u; ++i) {
        proxy_case_t *test = &tests[i]; solaris_test_event_wait(&test->done);
        CHECK(solaris_executor_quiesce(test->owner) == SOLARIS_OK);
        CHECK(solaris_executor_destroy(test->owner) == SOLARIS_OK);
        CHECK(test->opens == test->rounds && test->closes == test->rounds && test->resume == NULL);
        if (test->mode == PROXY_ECHO) CHECK(test->open_status == SOLARIS_OK && test->close_status == SOLARIS_OK &&
            test->received == PROXY_PAYLOAD && test->writes == test->rounds && test->shutdowns == test->rounds * (unsigned int)test->half_close && test->eof == test->rounds * (unsigned int)test->half_close && test->writable == test->rounds);
        if (test->mode == PROXY_WRITE_CANCEL) CHECK(test->writes == 1u);
        if (test->mode == PROXY_DENIED) CHECK(test->received == 0u && test->close_status != SOLARIS_OK);
        for (unsigned int round = 0u; round < test->rounds; ++round) {
            solaris_connection_snapshot_t snapshot;
            CHECK(solaris_tracker_snapshot(tracker, test->connection_ids[round], &snapshot) == SOLARIS_OK);
            CHECK(snapshot.state == SOLARIS_CONNECTION_CLOSED && snapshot.worker_id == i && snapshot.node_id == 7u &&
                snapshot.kind == SOLARIS_FLOW_STREAM && snapshot.active_channels == 0u && snapshot.pending_requests == 0u);
            if (test->mode == PROXY_ECHO && test->inner_trust == NULL)
                CHECK(snapshot.bytes_read == PROXY_PAYLOAD && snapshot.bytes_written == PROXY_PAYLOAD && snapshot.rejections == 1u);
        }
        solaris_traffic_snapshot_t wire; CHECK(solaris_traffic_counter_snapshot(test->traffic, &wire) == SOLARIS_OK && !wire.saturated);
        if (test->mode == PROXY_ECHO) CHECK(wire.stream_read >= test->rounds * PROXY_PAYLOAD && wire.stream_written >= test->rounds * PROXY_PAYLOAD);
        CHECK(wire.packets_read == 0u && wire.packets_written == 0u);
        solaris_traffic_counter_release(test->traffic);
        solaris_test_event_destroy(&test->ready); solaris_test_event_destroy(&test->done);
    }
    solaris_replay_release(replay);
#if SOLARIS_HAS_TLS
    solaris_tls_context_release(inner_trust);
#endif
    solaris_tracker_totals_t totals; CHECK(solaris_tracker_totals(tracker, SOLARIS_FLOW_USER, &totals) == SOLARIS_OK);
    CHECK(totals.created == 2u * tests[0].rounds && totals.closed == totals.created && totals.active == 0u);
    if (tests[0].mode == PROXY_ECHO && inner_trust == NULL)
        CHECK(totals.bytes_read == 2u * tests[0].rounds * PROXY_PAYLOAD && totals.bytes_written == totals.bytes_read);
    CHECK(solaris_tracker_destroy(tracker) == SOLARIS_OK);
    CHECK(solaris_budget_used(budget) == 0u); solaris_budget_release(budget);
    printf("%s mode %s: two workers, payload integrity, close and budget passed\n", argv[1], argv[8]);
    return 0;
}
