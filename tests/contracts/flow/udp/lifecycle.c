#include <solaris/core.h>
#include "contracts/flow/udp.h"
#include "runtime/engine/internal.h"
#include "support/runtime/event.h"
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)
enum { OPEN_LATE, DNS_LATE, DNS_CANCEL, INITIAL_STOP, IDLE, SINGLE_DESTINATION, PLAN_DENIED, RESOURCE_LIMIT };
typedef struct environment environment_t;
typedef struct mock_channel {
    environment_t *environment;
    solaris_datagram_t datagram;
    solaris_datagram_callbacks_t callbacks;
    void *context;
    solaris_deferred_t opened, finished, written;
    solaris_address_t destination;
    solaris_io_done_fn done;
    void *user;
    const solaris_buffer_t *buffer;
    int delivered_open, closing, busy, backpressure, bound;
} mock_channel_t;
struct environment {
    int mode, block_writes;
    solaris_engine_t *engine;
    solaris_executor_t *owner;
    solaris_udp_dispatcher_t *dispatcher;
    solaris_outbound_t outbound;
    solaris_scope_t reservation;
    solaris_udp_key_t key;
    solaris_address_t target;
    solaris_udp_reply_endpoint_t reply;
    uv_mutex_t clock_mutex;
    uint64_t now;
    solaris_test_event_t sent, closed, opened, cancelled, resolving, fence, entered, release;
    solaris_deferred_t resolution;
    solaris_resolve_fn resolved;
    void *resolve_context;
    mock_channel_t channels[8];
    size_t opens, selections, releases, sends, closes, cancels;
    solaris_status_t results[32], close_status;
    solaris_address_t last_peer;
    solaris_udp_snapshot_t final;
    atomic_uint references;
};

static uint64_t now_ns(void *context)
{
    environment_t *environment = context;
    uv_mutex_lock(&environment->clock_mutex);
    uint64_t result = environment->now;
    uv_mutex_unlock(&environment->clock_mutex);
    return result;
}
static void advance(environment_t *environment, uint64_t milliseconds)
{
    uv_mutex_lock(&environment->clock_mutex);
    environment->now = milliseconds * UINT64_C(1000000);
    uv_mutex_unlock(&environment->clock_mutex);
    solaris_executor_wake(environment->owner);
}
static void post_deferred(environment_t *environment, solaris_deferred_t *node, void (*run)(void *), void *context)
{
    node->run = run; node->context = context;
    CHECK(solaris_executor_defer(environment->owner, node) == SOLARIS_OK);
}
static void deliver_open(void *context)
{
    mock_channel_t *channel = context;
    CHECK(!channel->delivered_open); channel->delivered_open = 1;
    channel->callbacks.on_open(channel->context, &channel->datagram,
                               channel->closing ? SOLARIS_ECANCELLED : SOLARIS_OK);
}
static void deliver_close(void *context)
{
    mock_channel_t *channel = context;
    CHECK(!channel->busy);
    if (!channel->delivered_open) {
        channel->delivered_open = 1;
        /* A transport completing after cancellation must not revive the association. */
        channel->callbacks.on_open(channel->context, &channel->datagram, SOLARIS_OK);
    }
    channel->callbacks.on_close(channel->context, &channel->datagram, SOLARIS_ECANCELLED);
}
static void deliver_write(void *context)
{
    mock_channel_t *channel = context;
    channel->busy = 0;
    const solaris_buffer_t *buffer = channel->buffer; channel->buffer = NULL;
    channel->done(channel->user, channel->closing ? SOLARIS_ECANCELLED : SOLARIS_OK);
    solaris_buffer_release(buffer);
    if (channel->backpressure && !channel->closing) {
        channel->backpressure = 0;
        channel->callbacks.on_writable(channel->context, &channel->datagram);
    }
}
static solaris_status_t mock_send(void *context, const solaris_address_t *target, const solaris_slice_t *payload,
                                   solaris_io_done_fn done, void *user)
{
    mock_channel_t *channel = context;
    if (channel->closing) return SOLARIS_ECLOSED;
    if (channel->busy || channel->environment->block_writes) { channel->backpressure = 1; return SOLARIS_EAGAIN; }
    if (channel->environment->mode == SINGLE_DESTINATION && channel->bound)
        CHECK(solaris_address_equal(target, &channel->destination));
    channel->destination = *target; channel->bound = 1;
    channel->done = done; channel->user = user; channel->buffer = payload->buffer;
    solaris_buffer_retain(payload->buffer); channel->busy = 1;
    post_deferred(channel->environment, &channel->written, deliver_write, channel);
    return SOLARIS_OK;
}
static solaris_status_t mock_read(void *context, int enabled) { (void)context; (void)enabled; return SOLARIS_OK; }
static solaris_status_t mock_close(void *context)
{
    mock_channel_t *channel = context;
    if (!channel->closing) {
        channel->closing = 1;
        solaris_test_event_signal(&channel->environment->cancelled);
        if (channel->environment->mode != OPEN_LATE)
            post_deferred(channel->environment, &channel->finished, deliver_close, channel);
    }
    return SOLARIS_OK;
}
static solaris_status_t mock_snapshot(void *context, solaris_io_snapshot_t *out)
{ (void)context; memset(out, 0, sizeof(*out)); out->max_message_bytes = 65507u; return SOLARIS_OK; }
static solaris_status_t mock_local(void *context, solaris_address_t *out)
{ (void)context; return solaris_address_parse("127.0.0.1", 40000u, out); }
static const solaris_datagram_ops_t mock_datagram_ops = {mock_send, mock_read, mock_close, mock_snapshot, mock_local};
static uint32_t mock_caps(void *context)
{
    environment_t *environment = context;
    return SOLARIS_OUTBOUND_DATAGRAM | (environment->mode == SINGLE_DESTINATION ? 0u : SOLARIS_OUTBOUND_DATAGRAM_MULTI);
}
static solaris_status_t mock_stream(void *context, const solaris_address_t *target,
                                     const solaris_stream_callbacks_t *callbacks, void *user, solaris_stream_t **out)
{ (void)context; (void)target; (void)callbacks; (void)user; (void)out; return SOLARIS_ENOTSUP; }
static solaris_status_t mock_open(void *context, uint32_t family, const solaris_datagram_callbacks_t *callbacks,
                                   void *user, solaris_datagram_t **out)
{
    environment_t *environment = context;
    CHECK(family == SOLARIS_ADDRESS_IPV4 && environment->opens < 8u);
    mock_channel_t *channel = &environment->channels[environment->opens++];
    channel->environment = environment; channel->callbacks = *callbacks; channel->context = user;
    channel->datagram = (solaris_datagram_t){&mock_datagram_ops, channel, environment->owner};
    *out = &channel->datagram;
    if (environment->mode != OPEN_LATE) post_deferred(environment, &channel->opened, deliver_open, channel);
    solaris_test_event_signal(&environment->opened);
    return SOLARIS_OK;
}
static void mock_retire(void *context) { (void)context; }
static const solaris_outbound_ops_t mock_outbound_ops = {mock_caps, mock_stream, mock_open, mock_retire};
static void release_plan(void *context)
{
    environment_t *environment = context;
    CHECK(solaris_executor_is_owner(environment->owner)); environment->releases++;
}
static solaris_status_t select_plan(void *context, solaris_executor_t *owner, const solaris_udp_key_t *key,
                                     const solaris_address_t *target, solaris_udp_plan_t *out)
{
    (void)key; (void)target;
    environment_t *environment = context;
    CHECK(owner == environment->owner && solaris_executor_is_owner(owner)); environment->selections++;
    if (environment->mode == PLAN_DENIED) return SOLARIS_EACCESS;
    *out = (solaris_udp_plan_t){.outbound = &environment->outbound, .context = environment, .release = release_plan};
    return SOLARIS_OK;
}
static void retain_reply(void *context) { atomic_fetch_add(&((environment_t *)context)->references, 1u); }
static void release_reply(void *context) { CHECK(atomic_fetch_sub(&((environment_t *)context)->references, 1u) > 1u); }
static solaris_status_t reply(void *context, uint64_t generation, const solaris_udp_key_t *key,
                               const solaris_address_t *peer, const solaris_buffer_t *payload)
{
    environment_t *environment = context;
    CHECK(generation == 1u && key->inbound_id == 1u && solaris_buffer_length(payload) == 0u);
    CHECK(solaris_executor_is_owner(environment->owner)); environment->last_peer = *peer;
    return environment->mode == IDLE ? SOLARIS_EAGAIN : SOLARIS_OK;
}
static void sent(void *context, solaris_status_t status)
{
    environment_t *environment = context;
    CHECK(solaris_executor_is_owner(environment->owner) && environment->sends < 32u);
    environment->results[environment->sends++] = status;
    solaris_test_event_signal(&environment->sent);
}
static void closed(void *context, const solaris_udp_key_t *key, const solaris_udp_snapshot_t *snapshot, solaris_status_t status)
{
    (void)key;
    environment_t *environment = context;
    CHECK(solaris_executor_is_owner(environment->owner) && snapshot->pending_packets == 0u);
    environment->final = *snapshot; environment->close_status = status; environment->closes++;
    solaris_test_event_signal(&environment->closed);
}
static solaris_status_t resolve(void *context, solaris_executor_t *owner, const solaris_address_t *target,
                                 uint64_t timeout_ms, solaris_resolve_fn callback, void *user, void **request)
{
    environment_t *environment = context;
    CHECK(owner == environment->owner && target->family == SOLARIS_ADDRESS_DOMAIN && timeout_ms == 10u);
    environment->resolved = callback; environment->resolve_context = user; *request = environment;
    solaris_test_event_signal(&environment->resolving);
    return SOLARIS_OK;
}
static void cancel_resolve(void *context, void *request)
{
    environment_t *environment = context;
    CHECK(request == environment && solaris_executor_is_owner(environment->owner)); environment->cancels++;
    solaris_test_event_signal(&environment->cancelled);
}
static void deliver_resolution(void *context)
{
    environment_t *environment = context;
    environment->resolved(environment->resolve_context, SOLARIS_OK, &environment->target, 1u);
}
static void fence_task(void *context, solaris_status_t status)
{ CHECK(status == SOLARIS_OK); solaris_test_event_signal(&((environment_t *)context)->fence); }
static void fence(environment_t *environment)
{
    CHECK(solaris_executor_post(environment->owner, fence_task, environment) == SOLARIS_OK);
    solaris_test_event_wait(&environment->fence);
}
static void start_with_budget(environment_t *environment, int mode, solaris_budget_t *budget)
{
    memset(environment, 0, sizeof(*environment)); environment->mode = mode;
    CHECK(uv_mutex_init(&environment->clock_mutex) == 0);
    solaris_test_event_t *events[] = {&environment->sent, &environment->closed, &environment->opened,
        &environment->cancelled, &environment->resolving, &environment->fence, &environment->entered, &environment->release};
    for (size_t i = 0; i < sizeof(events) / sizeof(events[0]); ++i) CHECK(solaris_test_event_init(events[i], 0) == 0);
    solaris_runtime_services_t services; solaris_runtime_services_init(&services);
    services.context = environment; services.now_ns = now_ns;
    solaris_engine_options_t engine_options; solaris_engine_options_init(&engine_options);
    if (mode == RESOURCE_LIMIT) engine_options.io_resource_limit = 1u;
    CHECK(solaris_runtime_create(&engine_options, NULL, &services, &environment->engine, NULL) == SOLARIS_OK);
    uint64_t operation;
    CHECK(solaris_engine_start(environment->engine, &operation, NULL) == SOLARIS_OK);
    CHECK(solaris_engine_flush(environment->engine, 5000u, NULL) == SOLARIS_OK);
    environment->owner = solaris_runtime_executor(environment->engine, 0u);
    environment->outbound = (solaris_outbound_t){&mock_outbound_ops, environment, environment->owner};
    environment->key.inbound_id = 1u; environment->key.inbound_generation = 1u; environment->key.client_id = 1u;
    CHECK(solaris_address_parse("10.0.0.1", 12345u, &environment->key.source) == SOLARIS_OK);
    CHECK(solaris_address_parse("127.0.0.1", 12346u, &environment->target) == SOLARIS_OK);
    environment->reply = (solaris_udp_reply_endpoint_t){environment, 1u, retain_reply, release_reply, reply};
    atomic_init(&environment->references, 1u);
    solaris_udp_dispatcher_options_t options = {
        .workers = &environment->owner, .worker_count = 1u, .budget = budget == NULL ? solaris_executor_budget(environment->owner) : budget,
        .association_limit = 1u, .pending_packet_limit = 3u, .pending_byte_limit = 16u,
        .idle_timeout_ms = 100u, .open_timeout_ms = 10u, .dns_timeout_ms = 10u,
        .context = environment, .select = select_plan, .on_close = closed, .resolve = resolve, .cancel_resolve = cancel_resolve
    };
    CHECK(solaris_udp_dispatcher_create(&options, &environment->dispatcher) == SOLARIS_OK);
}
static void start(environment_t *environment, int mode) { start_with_budget(environment, mode, NULL); }
static solaris_status_t submit(environment_t *environment, const solaris_address_t *target, uint64_t *id)
{
    solaris_buffer_t *buffer;
    CHECK(solaris_buffer_copy(solaris_executor_budget(environment->owner), "x", 1u, &buffer) == SOLARIS_OK);
    solaris_slice_t payload = {buffer, 0u, 1u};
    solaris_status_t rc = solaris_udp_submit(environment->dispatcher, &environment->key, target,
                                             &payload, &environment->reply, sent, environment, id);
    solaris_buffer_release(buffer);
    return rc;
}
static void stop_engine(environment_t *environment)
{
    uint64_t operation;
    CHECK(solaris_engine_stop(environment->engine, &operation, NULL) == SOLARIS_OK);
    uint64_t started = uv_hrtime();
    while (solaris_executor_accepting(environment->owner)) {
        CHECK(uv_hrtime() - started < UINT64_C(5000000000)); uv_sleep(1u);
    }
}
static void finish(environment_t *environment)
{
    CHECK(solaris_udp_dispatcher_close(environment->dispatcher) == SOLARIS_OK);
    stop_engine(environment);
    CHECK(solaris_engine_flush(environment->engine, 5000u, NULL) == SOLARIS_OK);
    CHECK(solaris_udp_dispatcher_destroy(environment->dispatcher) == SOLARIS_OK);
    solaris_engine_snapshot_t snapshot;
    CHECK(solaris_engine_get_snapshot(environment->engine, &snapshot, NULL) == SOLARIS_OK && snapshot.io_buffer_bytes == 0u);
    CHECK(solaris_engine_destroy(environment->engine, NULL) == SOLARIS_OK);
    CHECK(atomic_load(&environment->references) == 1u);
    solaris_test_event_t *events[] = {&environment->sent, &environment->closed, &environment->opened,
        &environment->cancelled, &environment->resolving, &environment->fence, &environment->entered, &environment->release};
    for (size_t i = 0; i < sizeof(events) / sizeof(events[0]); ++i) solaris_test_event_destroy(events[i]);
    uv_mutex_destroy(&environment->clock_mutex);
}
static void late_open_before_timer(void *context, solaris_status_t status)
{
    environment_t *environment = context; CHECK(status == SOLARIS_OK);
    advance(environment, 11u);
    /* Same owner turn: no timer callback can have observed the new clock yet. */
    deliver_open(&environment->channels[0]);
}
static void open_timeout(int completion_first)
{
    environment_t environment; start(&environment, OPEN_LATE);
    CHECK(submit(&environment, &environment.target, NULL) == SOLARIS_OK);
    solaris_test_event_wait(&environment.opened);
    if (completion_first)
        CHECK(solaris_executor_post(environment.owner, late_open_before_timer, &environment) == SOLARIS_OK);
    else advance(&environment, 11u);
    solaris_test_event_wait(&environment.cancelled); solaris_test_event_wait(&environment.sent);
    CHECK(environment.results[0] == SOLARIS_ETIMEDOUT);
    stop_engine(&environment);
    CHECK(solaris_engine_flush(environment.engine, 0u, NULL) == SOLARIS_ETIMEDOUT);
    CHECK(solaris_udp_dispatcher_destroy(environment.dispatcher) == SOLARIS_EBUSY);
    post_deferred(&environment, &environment.channels[0].finished, deliver_close, &environment.channels[0]);
    solaris_test_event_wait(&environment.closed);
    CHECK(environment.close_status == SOLARIS_ETIMEDOUT && environment.final.failed == 1u);
    finish(&environment);
}
static void dns_case(int mode)
{
    environment_t environment; start(&environment, mode);
    solaris_address_t domain; CHECK(solaris_address_parse("example.invalid", 12346u, &domain) == SOLARIS_OK);
    CHECK(submit(&environment, &domain, NULL) == SOLARIS_OK);
    solaris_test_event_wait(&environment.resolving);
    if (mode == DNS_CANCEL) {
        stop_engine(&environment);
        solaris_test_event_wait(&environment.cancelled); solaris_test_event_wait(&environment.sent);
        CHECK(environment.results[0] == SOLARIS_ECANCELLED);
        CHECK(solaris_engine_flush(environment.engine, 0u, NULL) == SOLARIS_ETIMEDOUT);
    } else advance(&environment, 11u);
    post_deferred(&environment, &environment.resolution, deliver_resolution, &environment);
    if (mode == DNS_LATE) solaris_test_event_wait(&environment.sent);
    solaris_test_event_wait(&environment.closed);
    CHECK(environment.close_status == (mode == DNS_LATE ? SOLARIS_ETIMEDOUT : SOLARIS_ECANCELLED));
    CHECK(environment.opens == 0u && environment.final.failed == 1u);
    finish(&environment);
}
static void gate_task(void *context, solaris_status_t status)
{
    environment_t *environment = context; CHECK(status == SOLARIS_OK);
    solaris_test_event_signal(&environment->entered); solaris_test_event_wait(&environment->release);
}
static void initial_stop(void)
{
    environment_t environment; start(&environment, INITIAL_STOP);
    CHECK(solaris_executor_post(environment.owner, gate_task, &environment) == SOLARIS_OK);
    solaris_test_event_wait(&environment.entered);
    CHECK(submit(&environment, &environment.target, NULL) == SOLARIS_OK);
    stop_engine(&environment);
    CHECK(solaris_engine_flush(environment.engine, 0u, NULL) == SOLARIS_ETIMEDOUT);
    solaris_test_event_signal(&environment.release);
    solaris_test_event_wait(&environment.sent); solaris_test_event_wait(&environment.closed);
    CHECK(environment.selections == 0u && environment.results[0] == SOLARIS_ECANCELLED);
    finish(&environment);
}
static void block_writes(void *context, solaris_status_t status)
{
    environment_t *environment = context; CHECK(status == SOLARIS_OK); environment->block_writes = 1;
    solaris_test_event_signal(&environment->fence);
}
static void alternate_packet(void *context, solaris_status_t status)
{
    environment_t *environment = context; CHECK(status == SOLARIS_OK);
    solaris_buffer_t *buffer;
    CHECK(solaris_buffer_copy(solaris_executor_budget(environment->owner), NULL, 0u, &buffer) == SOLARIS_OK);
    solaris_address_t peer; CHECK(solaris_address_parse("192.168.10.17", 54321u, &peer) == SOLARIS_OK);
    mock_channel_t *channel = &environment->channels[0];
    channel->callbacks.on_packet(channel->context, &channel->datagram, &peer, buffer);
    solaris_buffer_release(buffer);
    solaris_test_event_signal(&environment->fence);
}
static void idle_timeout(void)
{
    environment_t environment; start(&environment, IDLE);
    CHECK(submit(&environment, &environment.target, NULL) == SOLARIS_OK);
    solaris_test_event_wait(&environment.sent); CHECK(environment.results[0] == SOLARIS_OK);
    CHECK(solaris_executor_post(environment.owner, block_writes, &environment) == SOLARIS_OK);
    solaris_test_event_wait(&environment.fence);
    advance(&environment, 99u); fence(&environment); CHECK(environment.closes == 0u);
    CHECK(solaris_executor_post(environment.owner, alternate_packet, &environment) == SOLARIS_OK);
    solaris_test_event_wait(&environment.fence);
    environment.key.inbound_id++;
    CHECK(submit(&environment, &environment.target, NULL) == SOLARIS_EAGAIN); /* association cap */
    environment.key.inbound_id--;
    for (size_t i = 0; i < 3u; ++i) CHECK(submit(&environment, &environment.target, NULL) == SOLARIS_OK);
    CHECK(submit(&environment, &environment.target, NULL) == SOLARIS_EAGAIN);
    advance(&environment, 100u);
    for (size_t i = 0; i < 3u; ++i) solaris_test_event_wait(&environment.sent);
    solaris_test_event_wait(&environment.closed);
    CHECK(environment.close_status == SOLARIS_ETIMEDOUT && environment.final.sent == 1u && environment.final.failed == 3u);
    CHECK(environment.final.reply_dropped == 1u); /* rejected reply did not refresh idle */
    CHECK(environment.final.queue_rejections == 1u);
    for (size_t i = 1u; i < 4u; ++i) CHECK(environment.results[i] == SOLARIS_ETIMEDOUT);
    finish(&environment);
}
static void single_destination_and_replacement(void)
{
    environment_t environment; start(&environment, SINGLE_DESTINATION);
    uint64_t id;
    CHECK(submit(&environment, &environment.target, &id) == SOLARIS_OK);
    solaris_test_event_wait(&environment.sent);
    solaris_address_t other = environment.target; other.port++;
    CHECK(submit(&environment, &other, NULL) == SOLARIS_OK);
    solaris_test_event_wait(&environment.sent);
    CHECK(submit(&environment, &environment.target, NULL) == SOLARIS_OK);
    solaris_test_event_wait(&environment.sent); fence(&environment);
    CHECK(environment.opens == 2u && environment.selections == 1u);
    solaris_udp_snapshot_t snapshot;
    CHECK(solaris_udp_association_snapshot(environment.dispatcher, &environment.key, &snapshot) == SOLARIS_OK);
    CHECK(snapshot.mapping_mode == SOLARIS_UDP_DESTINATION_LANES && snapshot.mappings == 2u && snapshot.active_lanes == 2u);
    CHECK(snapshot.ipv4_local_port == 0u);
    CHECK(solaris_executor_post(environment.owner, alternate_packet, &environment) == SOLARIS_OK);
    solaris_test_event_wait(&environment.fence);
    solaris_address_t expected; CHECK(solaris_address_parse("192.168.10.17", 54321u, &expected) == SOLARIS_OK);
    CHECK(solaris_address_equal(&expected, &environment.last_peer));
    environment.reply.generation++;
    CHECK(submit(&environment, &environment.target, NULL) == SOLARIS_EBUSY);
    environment.reply.generation--;
    CHECK(solaris_udp_association_close(environment.dispatcher, &environment.key, id) == SOLARIS_OK);
    solaris_test_event_wait(&environment.closed); fence(&environment);
    uint64_t replacement;
    CHECK(submit(&environment, &environment.target, &replacement) == SOLARIS_OK && replacement != id);
    CHECK(solaris_udp_association_close(environment.dispatcher, &environment.key, id) == SOLARIS_ECLOSED);
    solaris_test_event_wait(&environment.sent);
    CHECK(solaris_udp_association_close(environment.dispatcher, &environment.key, replacement) == SOLARIS_OK);
    solaris_test_event_wait(&environment.closed);
    CHECK(environment.selections == 2u && environment.releases == 2u && environment.opens == 3u);
    finish(&environment);
}
static void reserve_scope(void *context, solaris_status_t status)
{
    environment_t *environment = context; CHECK(status == SOLARIS_OK);
    CHECK(solaris_scope_init(&environment->reservation, environment->owner, NULL, NULL, NULL) == SOLARIS_OK);
    solaris_test_event_signal(&environment->fence);
}
static void rejected_initialization(int mode)
{
    environment_t environment; start(&environment, mode);
    if (mode == RESOURCE_LIMIT) {
        CHECK(solaris_executor_post(environment.owner, reserve_scope, &environment) == SOLARIS_OK);
        solaris_test_event_wait(&environment.fence);
    }
    CHECK(submit(&environment, &environment.target, NULL) == SOLARIS_OK);
    solaris_test_event_wait(&environment.sent); solaris_test_event_wait(&environment.closed);
    CHECK(environment.results[0] == (mode == PLAN_DENIED ? SOLARIS_EACCESS : SOLARIS_EAGAIN));
    CHECK(environment.opens == 0u && environment.releases == 0u);
    finish(&environment);
}
typedef struct fault_allocator { atomic_uint remaining, live; } fault_allocator_t;
static void *fault_allocate(void *context, size_t size)
{
    fault_allocator_t *fault = context;
    if (atomic_load(&fault->remaining) != 0u && atomic_fetch_sub(&fault->remaining, 1u) == 1u) return NULL;
    void *memory = malloc(size);
    if (memory != NULL) atomic_fetch_add(&fault->live, 1u);
    return memory;
}
static void fault_free(void *context, void *memory)
{
    fault_allocator_t *fault = context;
    if (memory != NULL) { atomic_fetch_sub(&fault->live, 1u); free(memory); }
}
static void allocation_failures(void)
{
    fault_allocator_t fault = {0};
    solaris_runtime_services_t services; solaris_runtime_services_init(&services);
    services.context = &fault; services.allocate = fault_allocate; services.deallocate = fault_free;
    solaris_budget_t *budget;
    CHECK(solaris_budget_create(1024u * 1024u, &services, &budget) == SOLARIS_OK);
    environment_t environment; start_with_budget(&environment, IDLE, budget);
    size_t baseline = solaris_budget_used(budget);
    for (unsigned index = 1u; index <= 2u; ++index) {
        atomic_store(&fault.remaining, index);
        uint64_t id = 999u;
        CHECK(submit(&environment, &environment.target, &id) == SOLARIS_ENOMEM && id == 0u);
        CHECK(solaris_budget_used(budget) == baseline && atomic_load(&environment.references) == 1u);
    }
    atomic_store(&fault.remaining, 3u); /* association + packet succeed; destination map fails */
    CHECK(submit(&environment, &environment.target, NULL) == SOLARIS_OK);
    solaris_test_event_wait(&environment.sent); solaris_test_event_wait(&environment.closed); fence(&environment);
    CHECK(environment.results[0] == SOLARIS_ENOMEM && environment.opens == 0u && solaris_budget_used(budget) == baseline);
    finish(&environment);
    CHECK(solaris_budget_used(budget) == 0u);
    solaris_budget_release(budget); CHECK(atomic_load(&fault.live) == 0u);
}
int main(void)
{
    open_timeout(0); open_timeout(1); dns_case(DNS_LATE); dns_case(DNS_CANCEL); initial_stop(); idle_timeout();
    single_destination_and_replacement();
    rejected_initialization(PLAN_DENIED); rejected_initialization(RESOURCE_LIMIT); allocation_failures();
    puts("UDP association deadlines, late completion, stop barriers, single-destination lanes and replacement passed");
    return 0;
}
