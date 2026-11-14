#include "support/runtime/env.h"
#include "support/runtime/files.h"
#include "contracts/module/module.h"
#include "support/runtime/event.h"
#include "observe/connections/tracker.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)
#define PACKETS 7u
typedef struct udp_case {
    solaris_executor_t *owner;
    solaris_module_config_t *config;
    solaris_replay_store_t *replay;
    solaris_datagram_t *channel;
    solaris_deadline_t *timer;
    solaris_deferred_t advance;
    solaris_test_event_t ready, done;
    solaris_address_t destinations[PACKETS], sources[PACKETS];
    size_t lengths[PACKETS];
    unsigned int opens, closes, sent, completed, received, writable;
    unsigned int seen[PACKETS];
    int mode, uot, deny_udp443, finishing;
    size_t message_limit;
    uint64_t bytes;
    solaris_tracker_t *tracker;
    solaris_traffic_counter_t *traffic;
    uint64_t connection_id;
} udp_case_t;
static uint8_t pattern(unsigned int packet, size_t n) { return n == 0u ? (uint8_t)packet : (uint8_t)(packet + n * 19u); }
static void pump(udp_case_t *test);
static void finish(udp_case_t *test)
{
    if (!test->finishing && test->mode == 0 && test->received == PACKETS && test->completed == PACKETS) {
        test->finishing = 1;
        if (test->timer != NULL) solaris_deadline_cancel(test->timer);
        CHECK(solaris_datagram_close(test->channel) == SOLARIS_OK);
    }
}
static void advance(void *context)
{
    udp_case_t *test = context;
    if (!test->finishing) { pump(test); finish(test); }
}
static void sent(void *context, solaris_status_t status)
{
    udp_case_t *test = context;
    if (status != SOLARIS_OK) fprintf(stderr, "UDP send status=%d sent=%u received=%u\n", status, test->sent, test->received);
    if (test->mode == 3)
        CHECK(status == SOLARIS_OK || status == SOLARIS_EIO || status == SOLARIS_EACCESS || status == SOLARIS_ECANCELLED || status == SOLARIS_ECLOSED);
    else if (test->mode != 2) CHECK(status == SOLARIS_OK);
    test->completed++;
    /* A reply may precede the local send completion. Advance after this
     * completion unwinds, so lower layers can also deliver their promised
     * writable notification before the fixture closes the final packet. */
    if (test->mode == 0 && !test->advance.queued)
        CHECK(solaris_executor_defer(test->owner, &test->advance) == SOLARIS_OK);
}
static void timer(void *context, solaris_status_t status)
{
    udp_case_t *test = context; test->timer = NULL;
    if (test->mode == 0 && status == SOLARIS_OK)
        fprintf(stderr, "UDP timed out: sent=%u completed=%u received=%u\n", test->sent, test->completed, test->received);
    if (test->mode == 3 && status == SOLARIS_OK) CHECK(solaris_datagram_close(test->channel) == SOLARIS_OK);
    else CHECK(status == SOLARIS_ECANCELLED);
}
static void opened(void *context, solaris_datagram_t *channel, solaris_status_t status)
{
    udp_case_t *test = context; CHECK(channel == test->channel && ++test->opens == 1u);
    if (test->mode == 1) { CHECK(status == SOLARIS_ECANCELLED); return; }
    if (test->mode == 3 && status != SOLARIS_OK) return;
    CHECK(status == SOLARIS_OK);
    CHECK(solaris_deadline_start(test->owner, test->mode == 3 ? 100u : 5000u, timer, test, &test->timer) == SOLARIS_OK);
    solaris_buffer_t *oversized;
    CHECK(solaris_buffer_allocate(solaris_executor_budget(test->owner), test->message_limit + 1u, &oversized) == SOLARIS_OK);
    CHECK(solaris_buffer_set_length(oversized, test->message_limit + 1u) == SOLARIS_OK);
    solaris_slice_t too_large = {oversized, 0u, test->message_limit + 1u};
    CHECK(solaris_datagram_send(channel, &test->destinations[0], &too_large, sent, test) == SOLARIS_EMSGSIZE);
    solaris_buffer_release(oversized);
    if (test->deny_udp443) {
        solaris_buffer_t *buffer; CHECK(solaris_buffer_copy(solaris_executor_budget(test->owner), "deny", 4u, &buffer) == SOLARIS_OK);
        solaris_slice_t slice = {buffer, 0u, 4u}; solaris_address_t target = test->destinations[0]; target.port = 443u;
        CHECK(solaris_datagram_send(channel, &target, &slice, sent, test) == SOLARIS_EACCESS);
        solaris_buffer_release(buffer);
    }
    pump(test);
}
static void packet(void *context, solaris_datagram_t *channel, const solaris_address_t *source, const solaris_buffer_t *buffer)
{
    udp_case_t *test = context; CHECK(test->mode == 0 && channel == test->channel);
    size_t length = solaris_buffer_length(buffer); unsigned int index = length == 0u ? 5u : solaris_buffer_data(buffer)[0];
    CHECK(index < PACKETS && test->seen[index]++ == 0u && length == test->lengths[index]);
    if (!solaris_address_equal(source, &test->sources[index]))
        fprintf(stderr, "UDP source mismatch: family=%u host=%s port=%u expected family=%u host=%s port=%u\n",
            source->family, source->host, source->port, test->sources[index].family, test->sources[index].host, test->sources[index].port);
    CHECK(solaris_address_equal(source, &test->sources[index]));
    for (size_t i = 0u; i < length; ++i) CHECK(solaris_buffer_data(buffer)[i] == pattern(index, i));
    test->received++; pump(test); finish(test);
}
static void writable(void *context, solaris_datagram_t *channel)
{ udp_case_t *test = context; CHECK(channel == test->channel); test->writable++; }
static void closed(void *context, solaris_datagram_t *channel, solaris_status_t status)
{
    udp_case_t *test = context; CHECK(channel == test->channel && ++test->closes == 1u);
    if (status != SOLARIS_OK && test->mode != 3)
        fprintf(stderr, "UDP close status=%d mode=%d uot=%d sent=%u received=%u\n", status, test->mode, test->uot, test->sent, test->received);
    CHECK(status == SOLARIS_OK || test->mode == 3);
    if (test->timer != NULL) solaris_deadline_cancel(test->timer);
    solaris_io_snapshot_t stats; CHECK(solaris_datagram_get_snapshot(channel, &stats) == SOLARIS_OK);
    CHECK(stats.pending_bytes == 0u && stats.pending_requests == 0u);
    if (test->mode == 0) CHECK(stats.bytes_read == test->bytes && stats.bytes_written == test->bytes &&
        stats.packets_read == PACKETS && stats.packets_written == PACKETS && stats.max_message_bytes == test->message_limit);
    solaris_test_event_signal(&test->done);
}
static const solaris_datagram_callbacks_t callbacks = {opened, packet, writable, closed};
static void pump(udp_case_t *test)
{
    if (test->finishing || test->sent == PACKETS ||
        (test->mode == 0 && (test->sent > test->received || test->sent > test->completed)) ||
        (test->mode != 0 && test->sent != 0u)) return;
    unsigned int index = test->sent;
    solaris_buffer_t *buffer; CHECK(solaris_buffer_allocate(solaris_executor_budget(test->owner), test->lengths[index], &buffer) == SOLARIS_OK);
    for (size_t i = 0u; i < test->lengths[index]; ++i) solaris_buffer_mutable_data(buffer)[i] = pattern(index, i);
    CHECK(solaris_buffer_set_length(buffer, test->lengths[index]) == SOLARIS_OK);
    solaris_slice_t slice = {buffer, 0u, test->lengths[index]};
    solaris_status_t status = solaris_datagram_send(test->channel, &test->destinations[index], &slice, sent, test);
    if (status != SOLARIS_OK) {
        solaris_io_snapshot_t snapshot = {0}; (void)solaris_datagram_get_snapshot(test->channel, &snapshot);
        fprintf(stderr, "UDP first-submit rc=%d index=%u sent=%u completed=%u received=%u pending=%zu bytes=%zu family=%u mode=%d\n",
            status, index, test->sent, test->completed, test->received, snapshot.pending_requests,
            snapshot.pending_bytes, test->destinations[index].family, test->mode);
    }
    CHECK(status == SOLARIS_OK);
    CHECK(solaris_datagram_send(test->channel, &test->destinations[index], &slice, sent, test) == SOLARIS_EAGAIN);
    test->sent++; test->bytes += test->lengths[index]; solaris_buffer_release(buffer);
    if (test->mode == 2) {
        solaris_deadline_cancel(test->timer); CHECK(solaris_datagram_close(test->channel) == SOLARIS_OK);
    }
}
static void start(void *context, solaris_status_t status)
{
    udp_case_t *test = context; CHECK(status == SOLARIS_OK);
    solaris_module_services_t services = {.owner = test->owner, .replay = test->replay, .dialer = {.traffic = test->traffic}};
    solaris_module_instance_t *instance;
    CHECK(solaris_module_create(test->config, &services, NULL, NULL, &instance, NULL) == SOLARIS_OK);
    solaris_dial_plan_t source, observed; CHECK(solaris_module_plan_acquire(instance, 7u, &source) == SOLARIS_OK);
    solaris_observe_options_t options = {.kind = SOLARIS_FLOW_DATAGRAM, .target = test->destinations[0]};
    CHECK(solaris_observe_plan(test->tracker, &source, &options, &observed, &test->connection_id) == SOLARIS_OK);
    CHECK(solaris_outbound_open_datagram(observed.outbound, test->destinations[0].family,
        &callbacks, test, &test->channel) == SOLARIS_OK);
    CHECK(solaris_dial_plan_release(&observed) == SOLARIS_OK);
    CHECK(solaris_module_retire(instance) == SOLARIS_OK);
    if (test->mode == 1) CHECK(solaris_datagram_close(test->channel) == SOLARIS_OK);
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
    CHECK(argc >= 10 && argc <= 14);
    int uot = argc >= 11 && strcmp(argv[10], "native") != 0;
    int no_empty = solaris_test_env_set("SOLARIS_TEST_SKIP_EMPTY") || (argc >= 11 && (strcmp(argv[10], "xudp-sing") == 0 || strcmp(argv[10], "xudp-xray") == 0));
    int numeric_reply = solaris_test_env_set("SOLARIS_TEST_NUMERIC_REPLIES") || (argc >= 11 && strcmp(argv[10], "xudp-xray") == 0 && atoi(argv[8]) == 6);
    solaris_budget_t *budget; CHECK(solaris_budget_create(16u * 1024u * 1024u, NULL, &budget) == SOLARIS_OK);
    solaris_replay_store_t *replay; CHECK(solaris_replay_create(budget, 1024u, 0u, NULL, NULL, &replay) == SOLARIS_OK);
    solaris_tracker_t *tracker; CHECK(solaris_tracker_create(budget, 8u, 8u, &tracker) == SOLARIS_OK);
    solaris_registry_t *registry; CHECK(solaris_builtin_registry_create(budget, &registry, NULL) == SOLARIS_OK);
    solaris_config_field_t fields[16]; size_t count = 0u;
    fields[count++] = string_field("server", argv[9]); fields[count++] = integer_field("port", atoi(argv[2]));
    if (strcmp(argv[1], "socks5") == 0) {
        if (strcmp(argv[3], "-") != 0 || strcmp(argv[4], "-") != 0) {
            fields[count++] = string_field("username", argv[4]); fields[count++] = string_field("password", argv[3]);
        }
    } else fields[count++] = string_field(strcmp(argv[1], "vless") == 0 ? "uuid" : "password", argv[3]);
    fields[count++] = integer_field("pending-bytes", uot ? 65535 : 65000);
    fields[count++] = integer_field("pending-requests", 1);
    if (strcmp(argv[1], "socks5") != 0 && strcmp(argv[4], "-") != 0) {
        fields[count++] = string_field("cipher", argv[4]);
        fields[count++] = (solaris_config_field_t){.name = "udp-over-tcp", .value = {.kind = SOLARIS_CONFIG_BOOL, .value.boolean = uot}};
    }
    char pem[16384];
    if (argc >= 12 && strcmp(argv[11], "-") != 0) {
        FILE *file = solaris_test_fopen(argv[11], "rb"); CHECK(file != NULL);
        size_t size = fread(pem, 1u, sizeof(pem) - 1u, file); fclose(file); CHECK(size > 0u); pem[size] = '\0';
        fields[count++] = (solaris_config_field_t){.name = "tls", .value = {.kind = SOLARIS_CONFIG_BOOL, .value.boolean = 1}};
        fields[count++] = string_field("servername", "localhost"); fields[count++] = string_field("ca-pem", pem);
    }
    if (argc >= 13) fields[count++] = string_field("encryption", argv[12]);
    if (argc == 14) fields[count++] = string_field("flow", argv[13]);
    solaris_config_view_t view = {.kind = SOLARIS_CONFIG_MAP, .value.map = {.fields = fields, .count = count}};
    solaris_module_config_t *config; CHECK(solaris_registry_compile(registry, argv[1], &view, &config, NULL) == SOLARIS_OK);
    solaris_registry_destroy(registry); udp_case_t cases[2] = {{0}};
    for (unsigned int i = 0u; i < 2u; ++i) {
        udp_case_t *test = &cases[i]; test->config = config; test->replay = replay; test->mode = atoi(argv[8]) >= 4 ? 0 : atoi(argv[8]);
        test->tracker = tracker;
        test->advance = (solaris_deferred_t){.run = advance, .context = test};
        CHECK(solaris_traffic_counter_create(budget, &test->traffic) == SOLARIS_OK);
        test->deny_udp443 = argc == 14 && strcmp(argv[13], "xtls-rprx-vision") == 0;
        test->uot = uot; test->message_limit = uot ? 65535u : 65000u;
        CHECK(solaris_test_event_init(&test->ready, 0u) == 0 && solaris_test_event_init(&test->done, 0u) == 0);
        for (unsigned int n = 0u; n < PACKETS; ++n) {
            int ipv6 = atoi(argv[8]) == 4 || (atoi(argv[8]) == 6 && n == 3u);
            int domain = atoi(argv[8]) == 5 || (atoi(argv[8]) == 6 && n == 4u);
            const char *host = ipv6 ? "::1" : domain ? "localhost" : "127.0.0.1";
            uint16_t port = (uint16_t)atoi(argv[ipv6 ? 7 : !domain && n == 1u ? 6 : 5]);
            CHECK(solaris_address_parse(host, port, &test->destinations[n]) == SOLARIS_OK);
            CHECK(solaris_address_parse(ipv6 ? "::1" : domain && !numeric_reply ? "localhost" : "127.0.0.1",
                atoi(argv[8]) == 7 ? (uint16_t)atoi(argv[6]) : port, &test->sources[n]) == SOLARIS_OK);
            test->lengths[n] = n == 5u && !no_empty ? 0u : n == 6u ? 6000u : 1024u + n;
        }
        solaris_executor_options_t options = {.id = i, .queue_capacity = 16u, .resource_limit = 128u, .budget = budget};
        CHECK(solaris_executor_create(&options, &test->owner) == SOLARIS_OK);
        CHECK(solaris_executor_activate(test->owner, 1u) == SOLARIS_OK);
        CHECK(solaris_executor_post(test->owner, start, test) == SOLARIS_OK);
    }
    for (unsigned int i = 0u; i < 2u; ++i) solaris_test_event_wait(&cases[i].ready);
    solaris_module_config_release(config);
    for (unsigned int i = 0u; i < 2u; ++i) {
        udp_case_t *test = &cases[i]; solaris_test_event_wait(&test->done);
        CHECK(solaris_executor_quiesce(test->owner) == SOLARIS_OK && solaris_executor_destroy(test->owner) == SOLARIS_OK);
        CHECK(test->opens == 1u && test->closes == 1u && test->timer == NULL && test->completed == test->sent);
        if (test->mode == 0) CHECK(test->received == PACKETS && test->writable == PACKETS);
        else CHECK(test->received == 0u);
        solaris_connection_snapshot_t snapshot;
        CHECK(solaris_tracker_snapshot(tracker, test->connection_id, &snapshot) == SOLARIS_OK && snapshot.state == SOLARIS_CONNECTION_CLOSED);
        CHECK(snapshot.worker_id == i && snapshot.node_id == 7u && snapshot.active_channels == 0u && snapshot.pending_requests == 0u);
        if (test->mode == 0) CHECK(snapshot.packets_read == PACKETS && snapshot.packets_written == PACKETS &&
            snapshot.bytes_read == test->bytes && snapshot.bytes_written == test->bytes);
        solaris_traffic_snapshot_t wire; CHECK(solaris_traffic_counter_snapshot(test->traffic, &wire) == SOLARIS_OK && !wire.saturated);
        if (test->mode == 0) {
            if (test->uot) CHECK(wire.stream_read >= test->bytes && wire.stream_written >= test->bytes && wire.packets_read == 0u && wire.packets_written == 0u);
            else CHECK(wire.datagram_read >= test->bytes && wire.datagram_written >= test->bytes && wire.packets_read == PACKETS && wire.packets_written == PACKETS);
        }
        solaris_traffic_counter_release(test->traffic);
        solaris_test_event_destroy(&test->ready); solaris_test_event_destroy(&test->done);
    }
    solaris_replay_release(replay);
    solaris_tracker_totals_t totals; CHECK(solaris_tracker_totals(tracker, SOLARIS_FLOW_USER, &totals) == SOLARIS_OK && totals.closed == 2u && totals.active == 0u);
    if (cases[0].mode == 0) CHECK(totals.packets_read == 2u * PACKETS && totals.packets_written == 2u * PACKETS &&
        totals.bytes_read == cases[0].bytes + cases[1].bytes && totals.bytes_written == totals.bytes_read);
    CHECK(solaris_tracker_destroy(tracker) == SOLARIS_OK);
    CHECK(solaris_budget_used(budget) == 0u); solaris_budget_release(budget);
    puts("UDP: multi-destination, source, sizes, backpressure and close passed"); return 0;
}
