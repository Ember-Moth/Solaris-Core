#include <solaris/core.h>
#include "contracts/module/module.h"
#include "contracts/flow/udp.h"
#include "runtime/engine/internal.h"
#include "support/runtime/event.h"
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)

typedef struct fixture fixture_t;
typedef struct slot {
    fixture_t *fixture;
    solaris_udp_key_t key;
    solaris_udp_reply_endpoint_t reply;
    solaris_executor_t *owner;
    solaris_test_event_t sent, received, closed;
    atomic_uint references, selections;
    unsigned replies, alternatives, empty4, empty6, closes;
    solaris_udp_snapshot_t final;
    solaris_status_t close_status;
} slot_t;
struct fixture {
    solaris_engine_t *engine;
    solaris_executor_t *workers[2];
    solaris_udp_dispatcher_t *dispatcher;
    slot_t slots[3];
    solaris_address_t a, b, ipv6;
    uint16_t alternate;
    atomic_uint prepared;
};
typedef struct ticket { slot_t *slot; solaris_status_t expected; } ticket_t;

static void retain_reply(void *context) { atomic_fetch_add(&((slot_t *)context)->references, 1u); }
static void release_reply(void *context) { CHECK(atomic_fetch_sub(&((slot_t *)context)->references, 1u) > 1u); }
static solaris_status_t reply(void *context, uint64_t generation, const solaris_udp_key_t *key,
                              const solaris_address_t *peer, const solaris_buffer_t *payload)
{
    slot_t *slot = context;
    CHECK(generation == slot->reply.generation && key->inbound_id == slot->key.inbound_id);
    CHECK(solaris_executor_is_owner(slot->owner));
    const uint8_t *bytes = solaris_buffer_data(payload);
    size_t length = solaris_buffer_length(payload);
    if (length == 3u && memcmp(bytes, "ALT", 3u) == 0) {
        CHECK(peer->port == slot->fixture->alternate && peer->family == SOLARIS_ADDRESS_IPV4); slot->alternatives++;
    } else if (length == 1u && bytes[0] == 'B') {
        CHECK(solaris_address_equal(peer, &slot->fixture->b));
    } else if (peer->family == SOLARIS_ADDRESS_IPV6) {
        CHECK(length == 0u && solaris_address_equal(peer, &slot->fixture->ipv6)); slot->empty6++;
    } else {
        CHECK(solaris_address_equal(peer, &slot->fixture->a));
        if (length == 0u) slot->empty4++;
    }
    slot->replies++;
    solaris_test_event_signal(&slot->received);
    return SOLARIS_OK;
}
static void sent(void *context, solaris_status_t status)
{
    ticket_t *ticket = context;
    CHECK(status == ticket->expected && solaris_executor_current() != NULL);
    if (ticket->slot->owner != NULL) CHECK(solaris_executor_is_owner(ticket->slot->owner));
    solaris_test_event_signal(&ticket->slot->sent);
}
static solaris_status_t prepare(void *context, uintptr_t handle, uint32_t family, uint32_t kind)
{
    (void)handle; (void)family;
    CHECK(kind == SOLARIS_SOCKET_UDP && solaris_executor_current() != NULL);
    atomic_fetch_add(&((fixture_t *)context)->prepared, 1u);
    return SOLARIS_OK;
}
static void release_plan(void *context)
{
    CHECK(solaris_module_retire(context) == SOLARIS_OK);
    CHECK(solaris_module_release(context) == SOLARIS_OK);
}
static solaris_status_t select_plan(void *context, solaris_executor_t *owner,
                                    const solaris_udp_key_t *key, const solaris_address_t *target,
                                    solaris_udp_plan_t *out)
{
    (void)target;
    fixture_t *fixture = context;
    CHECK(key->inbound_id >= 1u && key->inbound_id <= 3u && solaris_executor_is_owner(owner));
    slot_t *slot = &fixture->slots[key->inbound_id - 1u];
    slot->owner = owner; atomic_fetch_add(&slot->selections, 1u);
    solaris_registry_t *registry;
    CHECK(solaris_builtin_registry_create(solaris_executor_budget(owner), &registry, NULL) == SOLARIS_OK);
    solaris_config_view_t view = {.kind = SOLARIS_CONFIG_MAP};
    solaris_module_config_t *config;
    CHECK(solaris_registry_compile(registry, "direct", &view, &config, NULL) == SOLARIS_OK);
    solaris_module_services_t services = {.owner = owner};
    solaris_dialer_options_init(&services.dialer);
    services.dialer.pending_request_limit = 1u;
    services.dialer.prepare_socket = prepare; services.dialer.policy_context = fixture;
    solaris_module_instance_t *instance;
    CHECK(solaris_module_create(config, &services, NULL, NULL, &instance, NULL) == SOLARIS_OK);
    CHECK(solaris_module_retain(instance) == SOLARIS_OK);
    solaris_module_config_release(config); solaris_registry_destroy(registry);
    out->outbound = solaris_module_outbound(instance); out->context = instance; out->release = release_plan;
    return SOLARIS_OK;
}
static void association_closed(void *context, const solaris_udp_key_t *key,
                                 const solaris_udp_snapshot_t *snapshot, solaris_status_t status)
{
    fixture_t *fixture = context;
    slot_t *slot = &fixture->slots[key->inbound_id - 1u];
    CHECK(solaris_executor_current() != NULL && snapshot->pending_packets == 0u && snapshot->pending_bytes == 0u);
    slot->final = *snapshot; slot->close_status = status; slot->closes++;
    solaris_test_event_signal(&slot->closed);
}
static void fixture_start(fixture_t *fixture, const uint16_t *ports)
{
    memset(fixture, 0, sizeof(*fixture));
    solaris_engine_options_t options; solaris_engine_options_init(&options); options.io_workers = 2u;
    CHECK(solaris_engine_create(&options, NULL, &fixture->engine, NULL) == SOLARIS_OK);
    uint64_t operation;
    CHECK(solaris_engine_start(fixture->engine, &operation, NULL) == SOLARIS_OK);
    CHECK(solaris_engine_flush(fixture->engine, 5000u, NULL) == SOLARIS_OK);
    for (size_t i = 0; i < 2u; ++i) fixture->workers[i] = solaris_runtime_executor(fixture->engine, i);
    CHECK(solaris_address_parse("127.0.0.1", ports[0], &fixture->a) == SOLARIS_OK);
    CHECK(solaris_address_parse("127.0.0.1", ports[1], &fixture->b) == SOLARIS_OK);
    CHECK(solaris_address_parse("::1", ports[3], &fixture->ipv6) == SOLARIS_OK);
    fixture->alternate = ports[2];
    solaris_udp_dispatcher_options_t dispatcher = {
        .workers = fixture->workers, .worker_count = 2u, .budget = solaris_executor_budget(fixture->workers[0]),
        .association_limit = 8u, .mapping_limit = 4u, .pending_packet_limit = 3u, .pending_byte_limit = 131072u,
        .context = fixture, .select = select_plan, .on_close = association_closed
    };
    CHECK(solaris_udp_dispatcher_create(&dispatcher, &fixture->dispatcher) == SOLARIS_OK);
    for (size_t i = 0; i < 3u; ++i) {
        slot_t *slot = &fixture->slots[i]; slot->fixture = fixture;
        slot->key.inbound_id = i + 1u; slot->key.inbound_generation = 1u; slot->key.client_id = 10u;
        CHECK(solaris_address_parse("10.0.0.2", 12345u, &slot->key.source) == SOLARIS_OK);
        slot->reply = (solaris_udp_reply_endpoint_t){slot, 5u, retain_reply, release_reply, reply};
        atomic_init(&slot->references, 1u); atomic_init(&slot->selections, 0u);
        CHECK(solaris_test_event_init(&slot->sent, 0) == 0 && solaris_test_event_init(&slot->received, 0) == 0);
        CHECK(solaris_test_event_init(&slot->closed, 0) == 0);
    }
}
static void fixture_stop(fixture_t *fixture)
{
    CHECK(solaris_udp_dispatcher_close(fixture->dispatcher) == SOLARIS_OK);
    CHECK(solaris_udp_dispatcher_close(fixture->dispatcher) == SOLARIS_OK);
    uint64_t operation;
    CHECK(solaris_engine_stop(fixture->engine, &operation, NULL) == SOLARIS_OK);
    CHECK(solaris_engine_flush(fixture->engine, 5000u, NULL) == SOLARIS_OK);
    CHECK(solaris_udp_dispatcher_destroy(fixture->dispatcher) == SOLARIS_OK);
    solaris_engine_snapshot_t snapshot;
    CHECK(solaris_engine_get_snapshot(fixture->engine, &snapshot, NULL) == SOLARIS_OK && snapshot.io_buffer_bytes == 0u);
    CHECK(solaris_engine_destroy(fixture->engine, NULL) == SOLARIS_OK);
    for (size_t i = 0; i < 3u; ++i) {
        CHECK(atomic_load(&fixture->slots[i].references) == 1u);
        solaris_test_event_destroy(&fixture->slots[i].sent); solaris_test_event_destroy(&fixture->slots[i].received);
        solaris_test_event_destroy(&fixture->slots[i].closed);
    }
}
static solaris_status_t submit(slot_t *slot, const solaris_address_t *target, const char *text,
                                ticket_t *ticket, uint64_t *id)
{
    solaris_buffer_t *buffer;
    CHECK(solaris_buffer_copy(solaris_executor_budget(slot->fixture->workers[0]), text, strlen(text), &buffer) == SOLARIS_OK);
    solaris_slice_t slice = {buffer, 0u, strlen(text)};
    solaris_status_t rc = solaris_udp_submit(slot->fixture->dispatcher, &slot->key, target, &slice,
                                             &slot->reply, sent, ticket, id);
    solaris_buffer_release(buffer);
    return rc;
}
static void fence_task(void *context, solaris_status_t status)
{ CHECK(status == SOLARIS_OK); solaris_test_event_signal(context); }
static void fence(solaris_executor_t *owner)
{
    solaris_test_event_t event; CHECK(solaris_test_event_init(&event, 0) == 0);
    CHECK(solaris_executor_post(owner, fence_task, &event) == SOLARIS_OK);
    solaris_test_event_wait(&event); solaris_test_event_destroy(&event);
}
typedef struct gate { solaris_test_event_t entered, release; } gate_t;
static void gate_task(void *context, solaris_status_t status)
{
    gate_t *gate = context; CHECK(status == SOLARIS_OK);
    solaris_test_event_signal(&gate->entered); solaris_test_event_wait(&gate->release);
}
typedef struct producer { slot_t *slot; ticket_t ticket; solaris_status_t result; uint64_t id; } producer_t;
static void produce(void *context)
{
    producer_t *producer = context;
    producer->result = submit(producer->slot, &producer->slot->fixture->a, "C", &producer->ticket, &producer->id);
}

int main(int argc, char **argv)
{
    CHECK(argc == 5);
    uint16_t ports[4];
    for (size_t i = 0; i < 4u; ++i) { long port = strtol(argv[i + 1u], NULL, 10); CHECK(port > 0 && port <= 65535); ports[i] = (uint16_t)port; }
    fixture_t first, second; fixture_start(&first, ports); fixture_start(&second, ports);
    gate_t gates[2];
    for (size_t i = 0; i < 2u; ++i) {
        CHECK(solaris_test_event_init(&gates[i].entered, 0) == 0 && solaris_test_event_init(&gates[i].release, 0) == 0);
        CHECK(solaris_executor_post(first.workers[i], gate_task, &gates[i]) == SOLARIS_OK);
        solaris_test_event_wait(&gates[i].entered);
    }
    slot_t *a = &first.slots[0], *b = &first.slots[1], *fresh = &first.slots[2], *engine = &second.slots[0];
    ticket_t ticket_a = {a, SOLARIS_OK}, ticket_new = {fresh, SOLARIS_OK}, ticket_engine = {engine, SOLARIS_OK};
    const char *data[] = {"A", "B", "A2", "overflow"};
    solaris_datagram_message_t messages[4] = {0};
    solaris_buffer_t *buffers[4];
    for (size_t i = 0; i < 4u; ++i) {
        CHECK(solaris_buffer_copy(solaris_executor_budget(first.workers[0]), data[i], strlen(data[i]), &buffers[i]) == SOLARIS_OK);
        messages[i].destination = i == 1u ? first.b : first.a;
        messages[i].data = (solaris_slice_t){buffers[i], 0u, strlen(data[i])}; messages[i].done = sent; messages[i].context = &ticket_a;
    }
    size_t accepted;
    CHECK(solaris_udp_submit_batch(first.dispatcher, &a->key, messages, 4u, &a->reply, &accepted) == SOLARIS_EAGAIN && accepted == 3u);
    for (size_t i = 0; i < 4u; ++i) solaris_buffer_release(buffers[i]);
    producer_t producers[8]; uv_thread_t threads[8];
    for (size_t i = 0; i < 8u; ++i) {
        producers[i] = (producer_t){.slot = b, .ticket = {b, SOLARIS_OK}};
        CHECK(uv_thread_create(&threads[i], produce, &producers[i]) == 0);
    }
    unsigned concurrent_accepted = 0u; uint64_t concurrent_id = 0u;
    for (size_t i = 0; i < 8u; ++i) {
        CHECK(uv_thread_join(&threads[i]) == 0);
        if (producers[i].result == SOLARIS_OK) {
            if (concurrent_id != 0u) CHECK(concurrent_id == producers[i].id);
            concurrent_id = producers[i].id; concurrent_accepted++;
        } else CHECK(producers[i].result == SOLARIS_EAGAIN && producers[i].id == 0u);
    }
    CHECK(concurrent_accepted == 3u && atomic_load(&a->selections) == 0u && atomic_load(&b->selections) == 0u);
    CHECK(solaris_udp_dispatcher_destroy(first.dispatcher) == SOLARIS_EBUSY);
    for (size_t i = 0; i < 2u; ++i) solaris_test_event_signal(&gates[i].release);
    for (size_t i = 0; i < 3u; ++i) { solaris_test_event_wait(&a->sent); solaris_test_event_wait(&b->sent); solaris_test_event_wait(&b->received); }
    for (size_t i = 0; i < 5u; ++i) solaris_test_event_wait(&a->received);
    fence(a->owner); fence(b->owner);
    CHECK(atomic_load(&a->selections) == 1u && atomic_load(&b->selections) == 1u && a->alternatives == 1u && a->empty4 == 1u);
    solaris_udp_snapshot_t before, after, b_stats, engine_stats, new_stats;
    CHECK(solaris_udp_association_snapshot(first.dispatcher, &a->key, &before) == SOLARIS_OK);
    solaris_udp_key_t padded = a->key;
    padded.source.scope_id = 99u; padded.source.ip[15] = 0xffu; memcpy(padded.source.host, "ignored", 8u);
    CHECK(solaris_udp_association_snapshot(first.dispatcher, &padded, &after) == SOLARIS_OK && after.id == before.id);
    solaris_executor_t *next_owner = a->owner == first.workers[0] ? first.workers[1] : first.workers[0];
    CHECK(solaris_udp_dispatcher_set_workers(first.dispatcher, &next_owner, 1u) == SOLARIS_OK);
    CHECK(submit(a, &first.a, "PIN", &ticket_a, NULL) == SOLARIS_OK);
    CHECK(submit(fresh, &first.a, "NEW", &ticket_new, NULL) == SOLARIS_OK);
    CHECK(submit(engine, &second.a, "ENG", &ticket_engine, NULL) == SOLARIS_OK);
    solaris_test_event_wait(&a->sent); solaris_test_event_wait(&a->received);
    solaris_test_event_wait(&fresh->sent); solaris_test_event_wait(&fresh->received);
    solaris_test_event_wait(&engine->sent); solaris_test_event_wait(&engine->received);
    CHECK(fresh->owner == next_owner);
    solaris_address_t domain;
    CHECK(solaris_address_parse("localhost", ports[0], &domain) == SOLARIS_OK);
    CHECK(submit(a, &domain, "DNS", &ticket_a, NULL) == SOLARIS_OK);
    CHECK(submit(a, &first.ipv6, "", &ticket_a, NULL) == SOLARIS_OK);
    for (size_t i = 0; i < 2u; ++i) { solaris_test_event_wait(&a->sent); solaris_test_event_wait(&a->received); }
    fence(a->owner); fence(fresh->owner); fence(engine->owner);
    CHECK(solaris_udp_association_snapshot(first.dispatcher, &a->key, &after) == SOLARIS_OK);
    CHECK(after.id == before.id && after.worker_id == before.worker_id && after.ipv4_local_port == before.ipv4_local_port);
    CHECK(after.sent == 6u && after.received == 8u && a->empty6 == 1u && after.pending_packets == 0u);
    CHECK(after.mapping_mode == SOLARIS_UDP_ASSOCIATION_LANES && after.mappings == 4u && after.active_lanes == 2u);
    CHECK(solaris_udp_association_snapshot(first.dispatcher, &b->key, &b_stats) == SOLARIS_OK);
    CHECK(after.queue_rejections == 1u && b_stats.queue_rejections == 5u);
    CHECK(solaris_udp_association_snapshot(first.dispatcher, &fresh->key, &new_stats) == SOLARIS_OK);
    CHECK(solaris_udp_association_snapshot(second.dispatcher, &engine->key, &engine_stats) == SOLARIS_OK);
    ticket_t full = {a, SOLARIS_EAGAIN}; solaris_address_t fifth;
    CHECK(solaris_address_parse("127.0.0.2", ports[0], &fifth) == SOLARIS_OK);
    CHECK(submit(a, &fifth, "no mapping", &full, NULL) == SOLARIS_OK);
    solaris_test_event_wait(&a->sent);
    solaris_buffer_t *large;
    CHECK(solaris_buffer_allocate(solaris_executor_budget(first.workers[0]), 65528u, &large) == SOLARIS_OK);
    CHECK(solaris_buffer_set_length(large, 65528u) == SOLARIS_OK);
    solaris_slice_t oversized = {large, 0u, 65528u}; ticket_t too_large = {a, SOLARIS_EMSGSIZE};
    CHECK(solaris_udp_submit(first.dispatcher, &a->key, &first.a, &oversized, &a->reply, sent, &too_large, NULL) == SOLARIS_EMSGSIZE);
    oversized.length = 65508u;
    CHECK(solaris_udp_submit(first.dispatcher, &a->key, &first.a, &oversized, &a->reply, sent, &too_large, NULL) == SOLARIS_OK);
    solaris_buffer_release(large); solaris_test_event_wait(&a->sent);
    CHECK(solaris_udp_association_close(first.dispatcher, &a->key, after.id + 100u) == SOLARIS_ECLOSED);
    CHECK(solaris_udp_association_close(first.dispatcher, &a->key, after.id) == SOLARIS_OK);
    CHECK(solaris_udp_association_close(first.dispatcher, &a->key, after.id) == SOLARIS_OK);
    solaris_test_event_wait(&a->closed);
    CHECK(a->final.sent == 6u && a->final.failed == 2u && a->final.accepted == 8u);
    fixture_stop(&first); fixture_stop(&second);
    for (size_t i = 0; i < 2u; ++i) { solaris_test_event_destroy(&gates[i].entered); solaris_test_event_destroy(&gates[i].release); }
    printf("{\"first_port\":%u,\"second_port\":%u,\"engine_port\":%u,\"new_port\":%u,\"ipv6_port\":%u}\n",
        (unsigned)after.ipv4_local_port, (unsigned)b_stats.ipv4_local_port, (unsigned)engine_stats.ipv4_local_port,
        (unsigned)new_stats.ipv4_local_port, (unsigned)after.ipv6_local_port);
    return 0;
}
