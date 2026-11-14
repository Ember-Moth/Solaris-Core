#include "support/runtime/env.h"
#include "support/runtime/files.h"
#include "contracts/module/module.h"
#include "contracts/flow/udp.h"
#include "support/runtime/event.h"
#include "observe/connections/tracker.h"
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)
enum { PACKETS = 7 };
typedef struct fixture fixture_t;
typedef struct slot {
    fixture_t *fixture;
    solaris_executor_t *owner;
    solaris_udp_key_t key;
    solaris_udp_reply_endpoint_t endpoint;
    solaris_test_event_t gate, entered, sent, received, closed;
    solaris_address_t targets[PACKETS];
    solaris_address_t sources[PACKETS];
    size_t lengths[PACKETS];
    unsigned seen[PACKETS], selections, completions, replies, closes;
    atomic_uint references;
    uint64_t id;
    uint64_t connection_id;
    solaris_udp_snapshot_t final;
    solaris_status_t close_status;
    solaris_traffic_counter_t *traffic;
} slot_t;
struct fixture {
    solaris_budget_t *budget;
    solaris_replay_store_t *replay;
    solaris_module_config_t *config;
    solaris_udp_dispatcher_t *dispatcher;
    solaris_tracker_t *tracker;
    solaris_executor_t *workers[2];
    slot_t slots[2];
    int failure, trace;
};
static uint8_t pattern(unsigned index, size_t n) { return n == 0u ? (uint8_t)index : (uint8_t)(index + 19u * n); }
static void retain(void *context) { atomic_fetch_add(&((slot_t *)context)->references, 1u); }
static void release(void *context) { CHECK(atomic_fetch_sub(&((slot_t *)context)->references, 1u) > 1u); }
static solaris_status_t reply(void *context, uint64_t generation, const solaris_udp_key_t *key,
    const solaris_address_t *source, const solaris_buffer_t *payload)
{
    slot_t *slot = context; CHECK(generation == 9u && key->client_id == slot->key.client_id && solaris_executor_is_owner(slot->owner));
    size_t size = solaris_buffer_length(payload); unsigned index = size == 0u ? 5u : solaris_buffer_data(payload)[0];
    if (slot->fixture->trace) fprintf(stderr, "association %llu reply %u bytes=%zu\n", (unsigned long long)key->client_id, index, size);
    CHECK(index < PACKETS && slot->seen[index]++ == 0u && size == slot->lengths[index]);
    CHECK(solaris_address_equal(source, &slot->sources[index]));
    for (size_t n = 0u; n < size; ++n) CHECK(solaris_buffer_data(payload)[n] == pattern(index, n));
    slot->replies++; solaris_test_event_signal(&slot->received); return SOLARIS_OK;
}
static void sent(void *context, solaris_status_t status)
{
    slot_t *slot = context; CHECK(solaris_executor_is_owner(slot->owner));
    if (slot->fixture->failure) CHECK(status == SOLARIS_OK || status == SOLARIS_EIO || status == SOLARIS_ECLOSED || status == SOLARIS_ECANCELLED);
    else CHECK(status == SOLARIS_OK);
    slot->completions++; solaris_test_event_signal(&slot->sent);
    if (slot->fixture->trace) fprintf(stderr, "association %llu send completion %u status=%d\n", (unsigned long long)slot->key.client_id, slot->completions, status);
}
static void release_plan(void *context)
{ CHECK(solaris_module_retire(context) == SOLARIS_OK && solaris_module_release(context) == SOLARIS_OK); }
static solaris_status_t select_plan(void *context, solaris_executor_t *owner,
    const solaris_udp_key_t *key, const solaris_address_t *target, solaris_udp_plan_t *out)
{
    fixture_t *f = context; CHECK(key->client_id < 2u);
    slot_t *slot = &f->slots[key->client_id]; CHECK(slot->owner == owner && ++slot->selections == 1u);
    solaris_module_services_t services = {.owner = owner, .replay = f->replay, .dialer = {.traffic = slot->traffic}};
    solaris_module_instance_t *instance;
    CHECK(solaris_module_create(f->config, &services, NULL, NULL, &instance, NULL) == SOLARIS_OK);
    CHECK(solaris_module_retain(instance) == SOLARIS_OK);
    solaris_dial_plan_t source = {.outbound = solaris_module_outbound(instance), .context = instance, .release = release_plan, .node_id = 7u};
    solaris_observe_options_t options = {.kind = SOLARIS_FLOW_DATAGRAM, .target = *target};
    CHECK(solaris_observe_plan(f->tracker, &source, &options, out, &slot->connection_id) == SOLARIS_OK); return SOLARIS_OK;
}
static void closed(void *context, const solaris_udp_key_t *key,
    const solaris_udp_snapshot_t *snapshot, solaris_status_t status)
{
    slot_t *slot = &((fixture_t *)context)->slots[key->client_id];
    CHECK(solaris_executor_is_owner(slot->owner) && ++slot->closes == 1u);
    slot->final = *snapshot; slot->close_status = status; solaris_test_event_signal(&slot->closed);
    if (slot->fixture->trace) fprintf(stderr, "association %llu closed status=%d sent=%llu received=%llu\n",
        (unsigned long long)key->client_id, status, (unsigned long long)snapshot->sent, (unsigned long long)snapshot->received);
}
static void gate(void *context, solaris_status_t status)
{
    slot_t *slot = context; CHECK(status == SOLARIS_OK);
    solaris_test_event_signal(&slot->entered); solaris_test_event_wait(&slot->gate);
}
static void fence(void *context, solaris_status_t status)
{ CHECK(status == SOLARIS_OK); solaris_test_event_signal(context); }
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
static void submit(slot_t *slot, unsigned first, unsigned count)
{
    solaris_datagram_message_t messages[4]; solaris_buffer_t *buffers[4]; CHECK(count <= 4u);
    for (unsigned i = 0u; i < count; ++i) {
        unsigned index = first + i; size_t length = slot->lengths[index];
        CHECK(solaris_buffer_allocate(slot->fixture->budget, length, &buffers[i]) == SOLARIS_OK);
        for (size_t n = 0u; n < length; ++n) solaris_buffer_mutable_data(buffers[i])[n] = pattern(index, n);
        CHECK(solaris_buffer_set_length(buffers[i], length) == SOLARIS_OK);
        messages[i] = (solaris_datagram_message_t){slot->targets[index], {buffers[i], 0u, length}, sent, slot};
    }
    size_t accepted;
    CHECK(solaris_udp_submit_batch(slot->fixture->dispatcher, &slot->key, messages, count, &slot->endpoint, &accepted) ==
        (count == 4u ? SOLARIS_EAGAIN : SOLARIS_OK));
    CHECK(accepted == (count == 4u ? 3u : count));
    for (unsigned i = 0u; i < count; ++i) solaris_buffer_release(buffers[i]);
}
int main(int argc, char **argv)
{
    CHECK(argc >= 11 && argc <= 14); CHECK(atoi(argv[8]) == 6 || atoi(argv[8]) == 3);
    int uot = strcmp(argv[10], "native") != 0;
    int empty = !solaris_test_env_set("SOLARIS_TEST_SKIP_EMPTY") && strcmp(argv[10], "xudp-sing") != 0 && strcmp(argv[10], "xudp-xray") != 0;
    fixture_t f = {.failure = atoi(argv[8]) == 3, .trace = solaris_test_env_set("SOLARIS_TEST_TRACE")};
    CHECK(solaris_budget_create(16u * 1024u * 1024u, NULL, &f.budget) == SOLARIS_OK);
    CHECK(solaris_tracker_create(f.budget, 8u, 8u, &f.tracker) == SOLARIS_OK);
    CHECK(solaris_replay_create(f.budget, 1024u, 0u, NULL, NULL, &f.replay) == SOLARIS_OK);
    solaris_registry_t *registry; CHECK(solaris_builtin_registry_create(f.budget, &registry, NULL) == SOLARIS_OK);
    solaris_config_field_t fields[16]; size_t count = 0u;
    fields[count++] = string_field("server", argv[9]); fields[count++] = integer_field("port", atoi(argv[2]));
    if (strcmp(argv[1], "socks5") == 0) {
        if (strcmp(argv[3], "-") != 0 || strcmp(argv[4], "-") != 0) {
            fields[count++] = string_field("username", argv[4]); fields[count++] = string_field("password", argv[3]);
        }
    } else fields[count++] = string_field(strcmp(argv[1], "vless") == 0 ? "uuid" : "password", argv[3]);
    fields[count++] = integer_field("pending-bytes", 65535); fields[count++] = integer_field("pending-requests", 1);
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
    CHECK(solaris_registry_compile(registry, argv[1], &view, &f.config, NULL) == SOLARIS_OK); solaris_registry_destroy(registry);
    for (unsigned i = 0u; i < 2u; ++i) {
        slot_t *slot = &f.slots[i]; slot->fixture = &f;
        CHECK(solaris_traffic_counter_create(f.budget, &slot->traffic) == SOLARIS_OK);
        solaris_executor_options_t options = {.id = i, .queue_capacity = 16u, .resource_limit = 256u, .budget = f.budget};
        CHECK(solaris_executor_create(&options, &f.workers[i]) == SOLARIS_OK && solaris_executor_activate(f.workers[i], 1u) == SOLARIS_OK);
        slot->owner = f.workers[i]; slot->key.inbound_id = 1u; slot->key.inbound_generation = 1u; slot->key.client_id = i;
        CHECK(solaris_address_parse("10.0.0.2", 12345u, &slot->key.source) == SOLARIS_OK);
        slot->endpoint = (solaris_udp_reply_endpoint_t){slot, 9u, retain, release, reply}; atomic_init(&slot->references, 1u);
        CHECK(solaris_test_event_init(&slot->gate, 0u) == 0 && solaris_test_event_init(&slot->entered, 0u) == 0 &&
            solaris_test_event_init(&slot->sent, 0u) == 0 && solaris_test_event_init(&slot->received, 0u) == 0 &&
            solaris_test_event_init(&slot->closed, 0u) == 0);
        for (unsigned n = 0u; n < PACKETS; ++n) {
            CHECK(solaris_address_parse(n == 3u ? "::1" : n == 4u ? "localhost" : "127.0.0.1",
                (uint16_t)atoi(argv[n == 3u ? 7 : n == 1u ? 6 : 5]), &slot->targets[n]) == SOLARIS_OK);
            slot->sources[n] = slot->targets[n];
            if (n == 4u && solaris_test_env_set("SOLARIS_TEST_NUMERIC_REPLIES"))
                CHECK(solaris_address_parse("127.0.0.1", slot->targets[n].port, &slot->sources[n]) == SOLARIS_OK);
            slot->lengths[n] = n == 5u && empty ? 0u : n == 6u ? 6000u : 1024u + n;
        }
        CHECK(solaris_executor_post(slot->owner, gate, slot) == SOLARIS_OK); solaris_test_event_wait(&slot->entered);
    }
    solaris_udp_dispatcher_options_t options = {.workers = f.workers, .worker_count = 2u, .budget = f.budget,
        .association_limit = 4u, .mapping_limit = 4u, .pending_packet_limit = 3u, .pending_byte_limit = 65535u,
        .context = &f, .select = select_plan, .on_close = closed};
    CHECK(solaris_udp_dispatcher_create(&options, &f.dispatcher) == SOLARIS_OK);
    for (unsigned i = 0u; i < 2u; ++i) {
        CHECK(solaris_udp_dispatcher_set_workers(f.dispatcher, &f.workers[i], 1u) == SOLARIS_OK);
        submit(&f.slots[i], 0u, 4u);
    }
    CHECK(solaris_udp_dispatcher_set_workers(f.dispatcher, f.workers, 2u) == SOLARIS_OK);
    for (unsigned i = 0u; i < 2u; ++i) solaris_test_event_signal(&f.slots[i].gate);
    for (unsigned i = 0u; i < 2u; ++i) for (unsigned n = 0u; n < 3u; ++n) {
        solaris_test_event_wait(&f.slots[i].sent);
        if (!f.failure) solaris_test_event_wait(&f.slots[i].received);
    }
    solaris_module_config_release(f.config); f.config = NULL;
    if (f.failure) {
        for (unsigned i = 0u; i < 2u; ++i) solaris_test_event_wait(&f.slots[i].closed);
    } else {
    /* Worker selection changes do not move either existing association. */
    CHECK(solaris_udp_dispatcher_set_workers(f.dispatcher, &f.workers[0], 1u) == SOLARIS_OK);
    for (unsigned n = 3u; n < PACKETS; ++n) {
        for (unsigned i = 0u; i < 2u; ++i) submit(&f.slots[i], n, 1u);
        for (unsigned i = 0u; i < 2u; ++i) {
            solaris_test_event_wait(&f.slots[i].sent); solaris_test_event_wait(&f.slots[i].received);
        }
    }
    for (unsigned i = 0u; i < 2u; ++i) {
        slot_t *slot = &f.slots[i]; solaris_udp_snapshot_t snapshot;
        CHECK(solaris_executor_post(slot->owner, fence, &slot->entered) == SOLARIS_OK);
        solaris_test_event_wait(&slot->entered);
        CHECK(solaris_udp_association_snapshot(f.dispatcher, &slot->key, &snapshot) == SOLARIS_OK);
        CHECK(snapshot.worker_id == i && snapshot.accepted == PACKETS && snapshot.sent == PACKETS && snapshot.received == PACKETS);
        CHECK(snapshot.queue_rejections == 1u && snapshot.mappings == 4u && snapshot.active_lanes == 3u && snapshot.pending_packets == 0u);
        CHECK(snapshot.mapping_mode == SOLARIS_UDP_ASSOCIATION_LANES);
        if (uot) CHECK(snapshot.ipv4_local_port == 0u && snapshot.ipv6_local_port == 0u);
        slot->id = snapshot.id;
        solaris_connection_snapshot_t connection;
        CHECK(solaris_tracker_snapshot(f.tracker, slot->connection_id, &connection) == SOLARIS_OK);
        CHECK(connection.node_id == 7u && connection.worker_id == i && connection.active_channels == 3u &&
            connection.packets_written == PACKETS && connection.packets_read == PACKETS);
    }
    CHECK(solaris_tracker_close_connection(f.tracker, f.slots[0].connection_id) == SOLARIS_OK);
    solaris_test_event_wait(&f.slots[0].closed);
    CHECK(solaris_executor_begin_quiesce(f.workers[1]) == SOLARIS_OK); solaris_test_event_wait(&f.slots[1].closed);
    }
    CHECK(solaris_udp_dispatcher_close(f.dispatcher) == SOLARIS_OK);
    for (unsigned i = 0u; i < 2u; ++i) CHECK(solaris_executor_quiesce(f.workers[i]) == SOLARIS_OK);
    CHECK(solaris_udp_dispatcher_destroy(f.dispatcher) == SOLARIS_OK);
    for (unsigned i = 0u; i < 2u; ++i) {
        slot_t *slot = &f.slots[i]; CHECK(solaris_executor_destroy(f.workers[i]) == SOLARIS_OK);
        CHECK(slot->selections == 1u && slot->completions == (f.failure ? 3u : PACKETS) &&
            slot->replies == (f.failure ? 0u : PACKETS) && slot->closes == 1u);
        if (f.failure) CHECK(slot->close_status == SOLARIS_EIO || slot->close_status == SOLARIS_ECLOSED);
        else CHECK(slot->close_status == SOLARIS_ECANCELLED);
        CHECK(slot->final.accepted == slot->final.sent + slot->final.failed);
        CHECK(slot->final.pending_bytes == 0u && slot->final.pending_packets == 0u && slot->final.active_lanes == 0u);
        CHECK(atomic_load(&slot->references) == 1u);
        solaris_connection_snapshot_t connection;
        CHECK(solaris_tracker_snapshot(f.tracker, slot->connection_id, &connection) == SOLARIS_OK && connection.state == SOLARIS_CONNECTION_CLOSED);
        CHECK(connection.active_channels == 0u && connection.pending_requests == 0u && connection.pending_bytes == 0u);
        CHECK(solaris_tracker_close_connection(f.tracker, slot->connection_id) == SOLARIS_ECLOSED);
        solaris_traffic_snapshot_t wire; CHECK(solaris_traffic_counter_snapshot(slot->traffic, &wire) == SOLARIS_OK && !wire.saturated);
        if (!f.failure) {
            uint64_t bytes = 0u; for (size_t n = 0u; n < PACKETS; ++n) bytes += slot->lengths[n];
            if (uot) CHECK(wire.stream_read >= bytes && wire.stream_written >= bytes && wire.packets_read == 0u && wire.packets_written == 0u);
            else CHECK(wire.datagram_read >= bytes && wire.datagram_written >= bytes && wire.packets_read == PACKETS && wire.packets_written == PACKETS);
        }
        solaris_traffic_counter_release(slot->traffic);
        solaris_test_event_destroy(&slot->gate); solaris_test_event_destroy(&slot->entered);
        solaris_test_event_destroy(&slot->sent); solaris_test_event_destroy(&slot->received); solaris_test_event_destroy(&slot->closed);
    }
    solaris_replay_release(f.replay);
    solaris_tracker_totals_t totals; CHECK(solaris_tracker_totals(f.tracker, SOLARIS_FLOW_USER, &totals) == SOLARIS_OK && totals.created == 2u && totals.closed == 2u && totals.active == 0u);
    if (!f.failure) CHECK(totals.packets_read == 2u * PACKETS && totals.packets_written == 2u * PACKETS && totals.bytes_read == totals.bytes_written);
    CHECK(solaris_tracker_destroy(f.tracker) == SOLARIS_OK);
    CHECK(solaris_budget_used(f.budget) == 0u); solaris_budget_release(f.budget);
    puts("Proxy association: shared path, two pinned workers, three lanes, bounded batch, replies and stop passed"); return 0;
}
