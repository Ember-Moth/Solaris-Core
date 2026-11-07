#include "observe/connections/tracker.h"
#include "contracts/runtime/traffic.h"
#include "support/runtime/event.h"
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x)                                                                                                       \
    do {                                                                                                               \
        if (!(x)) {                                                                                                    \
            fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x);                                                    \
            abort();                                                                                                   \
        }                                                                                                              \
    } while (0)
enum {
    NORMAL,
    PROBE,
    ADMIN,
    CLOSE_ALL,
    STOP,
    BEFORE_OPEN,
    REJECT,
    OPEN_FAIL,
    OBSERVE_MEMORY,
    CHANNEL_MEMORY,
    WRITE_MEMORY,
    RESOURCE,
    HISTORY
};
typedef struct environment environment_t;
typedef struct mock_stream {
    environment_t *env;
    solaris_stream_t stream;
    solaris_stream_callbacks_t callbacks;
    void *context;
    solaris_deferred_t opened, written, closed;
    solaris_slice_t slice;
    solaris_io_done_fn done;
    void *user;
    int busy, closing;
} mock_stream_t;
struct environment {
    solaris_executor_t *owner;
    solaris_budget_t *budget;
    solaris_tracker_t *tracker;
    solaris_outbound_t outbound;
    solaris_stream_t *channel;
    solaris_address_t target;
    solaris_dial_plan_t plan;
    mock_stream_t mock;
    solaris_deferred_t late, history_step;
    unsigned history_count;
    uint64_t history_first;
    solaris_test_event_t ready, pending, entered, gate, cancelled, complete;
    atomic_uint releases, closes, stop_reader;
    int mode, fail_next;
    unsigned int target_writes, submitted, completed, received, opened;
    uint64_t id;
    solaris_status_t open_status, close_status, submit_status;
};
static void queue(environment_t *env, solaris_deferred_t *node, void (*run)(void *), void *context)
{
    node->run = run;
    node->context = context;
    CHECK(solaris_executor_defer(env->owner, node) == SOLARIS_OK);
}
static void *allocate(void *context, size_t size)
{
    environment_t *env = context;
    if (env->fail_next) {
        env->fail_next = 0;
        return NULL;
    }
    return malloc(size);
}
static void released(void *context)
{
    environment_t *env = context;
    CHECK(solaris_executor_is_owner(env->owner));
    atomic_fetch_add(&env->releases, 1u);
}
static solaris_dial_plan_t source(environment_t *env)
{
    return (solaris_dial_plan_t){
        .outbound = &env->outbound, .context = env, .release = released, .node_id = 17u, .selection_revision = 9u};
}
static void mock_opened(void *context)
{
    mock_stream_t *mock = context;
    mock->callbacks.on_open(mock->context, &mock->stream, mock->env->mode == OPEN_FAIL ? SOLARIS_EACCESS : SOLARIS_OK);
}
static void mock_closed(void *context)
{
    mock_stream_t *mock = context;
    CHECK(!mock->busy);
    mock->callbacks.on_close(mock->context, &mock->stream, SOLARIS_OK);
}
static void mock_written(void *context)
{
    mock_stream_t *mock = context;
    CHECK(mock->busy);
    mock->busy = 0;
    const solaris_buffer_t *buffer = mock->slice.buffer;
    mock->slice.buffer = NULL;
    mock->done(mock->user, mock->closing ? SOLARIS_ECANCELLED : SOLARIS_OK);
    if (!mock->closing)
        mock->callbacks.on_data(mock->context, &mock->stream, buffer);
    solaris_buffer_release(buffer);
    if (mock->closing && !mock->closed.queued)
        queue(mock->env, &mock->closed, mock_closed, mock);
}
static solaris_status_t mock_write(void *context, const solaris_slice_t *slice, solaris_io_done_fn done, void *user)
{
    mock_stream_t *mock = context;
    if (mock->closing)
        return SOLARIS_ECLOSED;
    if (mock->busy)
        return SOLARIS_EAGAIN;
    mock->busy = 1;
    mock->slice = *slice;
    solaris_buffer_retain(slice->buffer);
    mock->done = done;
    mock->user = user;
    if (mock->env->mode != ADMIN && mock->env->mode != CLOSE_ALL && mock->env->mode != STOP)
        queue(mock->env, &mock->written, mock_written, mock);
    return SOLARIS_OK;
}
static solaris_status_t mock_shutdown(void *state, solaris_io_done_fn done, void *context)
{
    (void)state;
    (void)done;
    (void)context;
    return SOLARIS_ENOTSUP;
}
static solaris_status_t mock_read(void *state, int enabled)
{
    (void)state;
    (void)enabled;
    return SOLARIS_OK;
}
static solaris_status_t mock_close(void *context)
{
    mock_stream_t *mock = context;
    if (!mock->closing) {
        mock->closing = 1;
        solaris_test_event_signal(&mock->env->cancelled);
        if (!mock->busy && !mock->closed.queued)
            queue(mock->env, &mock->closed, mock_closed, mock);
    }
    return SOLARIS_OK;
}
static solaris_status_t mock_snapshot(void *state, solaris_io_snapshot_t *out)
{
    (void)state;
    memset(out, 0, sizeof(*out));
    out->max_message_bytes = 3u;
    return SOLARIS_OK;
}
static const solaris_stream_ops_t mock_ops = {mock_write, mock_shutdown, mock_read, mock_close, mock_snapshot, NULL};
static uint32_t capabilities(void *state)
{
    (void)state;
    return SOLARIS_OUTBOUND_STREAM;
}
static solaris_status_t open_stream(void *state, const solaris_address_t *target,
                                    const solaris_stream_callbacks_t *callbacks, void *context, solaris_stream_t **out)
{
    environment_t *env = state;
    CHECK(solaris_address_equal(target, &env->target));
    *out = NULL;
    if (env->mode == REJECT)
        return SOLARIS_EACCESS;
    mock_stream_t *mock = &env->mock;
    mock->env = env;
    mock->callbacks = *callbacks;
    mock->context = context;
    mock->stream = (solaris_stream_t){&mock_ops, mock, env->owner};
    *out = &mock->stream;
    queue(env, &mock->opened, mock_opened, mock);
    return SOLARIS_OK;
}
static solaris_status_t open_datagram(void *state, uint32_t family, const solaris_datagram_callbacks_t *callbacks,
                                      void *context, solaris_datagram_t **out)
{
    (void)state;
    (void)family;
    (void)callbacks;
    (void)context;
    *out = NULL;
    return SOLARIS_ENOTSUP;
}
static void retire(void *state)
{
    (void)state;
}
static const solaris_outbound_ops_t outbound_ops = {capabilities, open_stream, open_datagram, retire};
static void pump(environment_t *env);
static void completed(void *context, solaris_status_t status)
{
    environment_t *env = context;
    CHECK(status ==
          ((env->mode == ADMIN || env->mode == CLOSE_ALL || env->mode == STOP) ? SOLARIS_ECANCELLED : SOLARIS_OK));
    env->completed++;
}
static void opened(void *context, solaris_stream_t *stream, solaris_status_t status)
{
    environment_t *env = context;
    CHECK(stream == env->channel && ++env->opened == 1u);
    env->open_status = status;
    if (status != SOLARIS_OK)
        return;
    pump(env);
}
static void data(void *context, solaris_stream_t *stream, const solaris_buffer_t *buffer)
{
    environment_t *env = context;
    CHECK(stream == env->channel && solaris_buffer_length(buffer) == 3u &&
          memcmp(solaris_buffer_data(buffer), "abc", 3u) == 0);
    env->received++;
    if (env->received == env->target_writes)
        CHECK(solaris_stream_close(stream) == SOLARIS_OK);
    else
        pump(env);
}
static void closed(void *context, solaris_stream_t *stream, solaris_status_t status)
{
    environment_t *env = context;
    CHECK(stream == env->channel && atomic_fetch_add(&env->closes, 1u) == 0u);
    env->close_status = status;
    CHECK(env->completed == env->submitted);
    solaris_io_snapshot_t snapshot;
    CHECK(solaris_stream_get_snapshot(stream, &snapshot) == SOLARIS_OK && snapshot.pending_requests == 0u);
    CHECK(solaris_tracker_destroy(env->tracker) == SOLARIS_EBUSY);
    solaris_test_event_signal(&env->complete);
}
static const solaris_stream_callbacks_t callbacks = {opened, data, NULL, NULL, closed};
static void pump(environment_t *env)
{
    solaris_buffer_t *buffer;
    CHECK(solaris_buffer_copy(env->budget, "abc", 3u, &buffer) == SOLARIS_OK);
    solaris_slice_t slice = {buffer, 0u, 3u};
    if (env->mode == WRITE_MEMORY)
        env->fail_next = 1;
    solaris_status_t rc = solaris_stream_write(env->channel, &slice, completed, env);
    if (env->mode == WRITE_MEMORY) {
        CHECK(rc == SOLARIS_ENOMEM);
        CHECK(solaris_stream_close(env->channel) == SOLARIS_OK);
    } else {
        CHECK(rc == SOLARIS_OK);
        env->submitted++;
        CHECK(solaris_stream_write(env->channel, &slice, completed, env) == SOLARIS_EAGAIN);
    }
    if (env->mode == ADMIN || env->mode == CLOSE_ALL || env->mode == STOP)
        solaris_test_event_signal(&env->pending);
    solaris_buffer_release(buffer);
}
static void history_next(void *context)
{
    environment_t *env = context;
    if (env->history_count == 2) {
        solaris_connection_snapshot_t snapshot;
        CHECK(solaris_tracker_snapshot(env->tracker, env->history_first, &snapshot) == SOLARIS_ECLOSED);
        solaris_test_event_signal(&env->complete);
        return;
    }
    solaris_observe_options_t options = {
        .kind = SOLARIS_FLOW_STREAM, .purpose = SOLARIS_FLOW_USER, .target = env->target};
    solaris_dial_plan_t input = source(env);
    CHECK(solaris_observe_plan(env->tracker, &input, &options, &env->plan, &env->id) == SOLARIS_OK);
    CHECK(env->id > env->history_first &&
          solaris_tracker_close_connection(env->tracker, env->history_first) == SOLARIS_ECLOSED);
    env->history_count++;
    CHECK(solaris_dial_plan_release(&env->plan) == SOLARIS_OK);
    /* A closing record consumes its active slot through final source release.
     * Advance after the already-queued full destructor, not on the same stack. */
    queue(env, &env->history_step, history_next, env);
}
static void start(void *context, solaris_status_t status)
{
    environment_t *env = context;
    CHECK(status == SOLARIS_OK);
    solaris_observe_options_t options = {.kind = SOLARIS_FLOW_STREAM,
                                         .purpose = env->mode == PROBE ? SOLARIS_FLOW_PROBE : SOLARIS_FLOW_USER,
                                         .target = env->target};
    solaris_dial_plan_t input = source(env);
    if (env->mode == OBSERVE_MEMORY)
        env->fail_next = 1;
    env->submit_status = solaris_observe_plan(env->tracker, &input, &options, &env->plan, &env->id);
    if (env->mode == OBSERVE_MEMORY) {
        CHECK(env->submit_status == SOLARIS_ENOMEM && input.outbound == &env->outbound && env->plan.outbound == NULL);
        CHECK(solaris_dial_plan_release(&input) == SOLARIS_OK);
        solaris_test_event_signal(&env->complete);
    } else {
        CHECK(env->submit_status == SOLARIS_OK && input.outbound == NULL);
        solaris_dial_plan_t nested;
        CHECK(solaris_observe_plan(env->tracker, &env->plan, &options, &nested, NULL) == SOLARIS_EINVAL &&
              env->plan.outbound != NULL);
        if (env->mode == HISTORY) {
            env->history_first = env->id;
            CHECK(solaris_dial_plan_release(&env->plan) == SOLARIS_OK);
            queue(env, &env->history_step, history_next, env);
        } else {
            input = source(env);
            solaris_dial_plan_t refused;
            CHECK(solaris_observe_plan(env->tracker, &input, &options, &refused, NULL) == SOLARIS_EAGAIN &&
                  input.outbound != NULL);
            CHECK(solaris_dial_plan_release(&input) == SOLARIS_OK);
            if (env->mode == CHANNEL_MEMORY)
                env->fail_next = 1;
            env->submit_status =
                solaris_outbound_open_stream(env->plan.outbound, &env->target, &callbacks, env, &env->channel);
            CHECK(solaris_dial_plan_release(&env->plan) == SOLARIS_OK);
            if (env->submit_status != SOLARIS_OK) {
                CHECK(env->channel == NULL &&
                      (env->mode == REJECT || env->mode == CHANNEL_MEMORY || env->mode == RESOURCE));
                solaris_test_event_signal(&env->complete);
            } else if (env->mode == BEFORE_OPEN)
                CHECK(solaris_stream_close(env->channel) == SOLARIS_OK);
        }
    }
    solaris_test_event_signal(&env->ready);
}
static void no_op(void *context, solaris_status_t status)
{
    (void)context;
    CHECK(status == SOLARIS_OK);
}
static void gate(void *context, solaris_status_t status)
{
    environment_t *env = context;
    CHECK(status == SOLARIS_OK);
    solaris_test_event_signal(&env->entered);
    solaris_test_event_wait(&env->gate);
    solaris_buffer_t *buffer;
    CHECK(solaris_buffer_copy(env->budget, "abc", 3u, &buffer) == SOLARIS_OK);
    solaris_slice_t slice = {buffer, 0u, 3u};
    CHECK(solaris_stream_write(env->channel, &slice, completed, env) == SOLARIS_ECLOSED);
    solaris_buffer_release(buffer);
    if (env->mode == CLOSE_ALL) {
        solaris_dial_plan_t input = source(env), refused;
        solaris_observe_options_t options = {.kind = SOLARIS_FLOW_STREAM, .target = env->target};
        CHECK(solaris_observe_plan(env->tracker, &input, &options, &refused, NULL) == SOLARIS_ECLOSED &&
              input.outbound != NULL);
        CHECK(solaris_dial_plan_release(&input) == SOLARIS_OK);
    }
}
static void reader(void *context)
{
    environment_t *env = context;
    while (!atomic_load_explicit(&env->stop_reader, memory_order_acquire)) {
        solaris_connection_snapshot_t entries[2];
        size_t count;
        CHECK(solaris_tracker_list(env->tracker, 1, entries, 2u, &count) == SOLARIS_OK && count <= 2u);
        for (size_t i = 0u; i < count; ++i)
            CHECK(entries[i].pending_bytes == entries[i].pending_requests * 3u && entries[i].active_channels <= 1u);
        solaris_tracker_totals_t totals;
        CHECK(solaris_tracker_totals(env->tracker, SOLARIS_FLOW_USER, &totals) == SOLARIS_OK && totals.active <= 1u);
        uv_sleep(1u);
    }
}
static void run(int mode)
{
    environment_t env = {.mode = mode, .target_writes = mode == NORMAL || mode == PROBE ? 200u : 1u};
    atomic_init(&env.releases, 0u);
    atomic_init(&env.closes, 0u);
    atomic_init(&env.stop_reader, 0u);
    solaris_runtime_services_t services;
    solaris_runtime_services_init(&services);
    services.context = &env;
    services.allocate = allocate;
    CHECK(solaris_budget_create(4u * 1024u * 1024u, &services, &env.budget) == SOLARIS_OK);
    CHECK(solaris_tracker_create(env.budget, 1u, 1u, &env.tracker) == SOLARIS_OK);
    solaris_test_event_t *events[] = {&env.ready, &env.pending, &env.entered, &env.gate, &env.cancelled, &env.complete};
    for (size_t i = 0u; i < 6u; ++i)
        CHECK(solaris_test_event_init(events[i], 0u) == 0);
    solaris_executor_options_t options = {
        .id = 3u, .queue_capacity = 1u, .resource_limit = mode == RESOURCE ? 1u : 64u, .budget = env.budget};
    CHECK(solaris_executor_create(&options, &env.owner) == SOLARIS_OK &&
          solaris_executor_activate(env.owner, 7u) == SOLARIS_OK);
    env.outbound = (solaris_outbound_t){&outbound_ops, &env, env.owner};
    CHECK(solaris_address_parse("127.0.0.1", 80u, &env.target) == SOLARIS_OK);
    uv_thread_t query;
    CHECK(uv_thread_create(&query, reader, &env) == 0);
    CHECK(solaris_executor_post(env.owner, start, &env) == SOLARIS_OK);
    solaris_test_event_wait(&env.ready);
    if (mode == ADMIN || mode == CLOSE_ALL || mode == STOP) {
        solaris_test_event_wait(&env.pending);
        if (mode == ADMIN || mode == CLOSE_ALL) {
            CHECK(solaris_executor_post(env.owner, gate, &env) == SOLARIS_OK);
            solaris_test_event_wait(&env.entered);
            CHECK(solaris_executor_post(env.owner, no_op, NULL) == SOLARIS_OK &&
                  solaris_executor_post(env.owner, no_op, NULL) == SOLARIS_EAGAIN);
            if (mode == CLOSE_ALL)
                CHECK(solaris_tracker_close_all(env.tracker) == SOLARIS_OK);
            else
                CHECK(solaris_tracker_close_connection(env.tracker, env.id) == SOLARIS_OK &&
                      solaris_tracker_close_connection(env.tracker, env.id) == SOLARIS_OK);
            solaris_test_event_signal(&env.gate);
        } else
            CHECK(solaris_executor_begin_quiesce(env.owner) == SOLARIS_OK);
        solaris_test_event_wait(&env.cancelled);
        CHECK(atomic_load(&env.closes) == 0u && solaris_tracker_destroy(env.tracker) == SOLARIS_EBUSY);
        queue(&env, &env.late, mock_written, &env.mock);
    }
    solaris_test_event_wait(&env.complete);
    CHECK(solaris_executor_quiesce(env.owner) == SOLARIS_OK && solaris_executor_destroy(env.owner) == SOLARIS_OK);
    atomic_store_explicit(&env.stop_reader, 1u, memory_order_release);
    CHECK(uv_thread_join(&query) == 0);
    solaris_tracker_totals_t totals;
    uint32_t purpose = mode == PROBE ? SOLARIS_FLOW_PROBE : SOLARIS_FLOW_USER;
    CHECK(solaris_tracker_totals(env.tracker, purpose, &totals) == SOLARIS_OK && totals.active == 0u);
    CHECK(totals.created == (mode == OBSERVE_MEMORY ? 0u
                             : mode == HISTORY      ? 3u
                                                    : 1u) &&
          totals.closed == totals.created);
    CHECK(atomic_load(&env.releases) == (mode == OBSERVE_MEMORY ? 1u : mode == HISTORY || mode == CLOSE_ALL ? 3u : 2u));
    if (mode == NORMAL || mode == PROBE)
        CHECK(env.completed == 200u && env.received == 200u && totals.bytes_written == 600u &&
              totals.bytes_read == 600u && totals.rejections == 200u);
    if (mode == ADMIN || mode == CLOSE_ALL || mode == STOP)
        CHECK(env.close_status == SOLARIS_ECANCELLED && totals.write_failures == 1u && totals.bytes_written == 0u);
    if (totals.created != 0u) {
        solaris_connection_snapshot_t snapshot;
        CHECK(solaris_tracker_snapshot(env.tracker, env.id, &snapshot) == SOLARIS_OK);
        CHECK(snapshot.state == SOLARIS_CONNECTION_CLOSED && snapshot.node_id == 17u &&
              snapshot.selection_revision == 9u && snapshot.generation == 7u && snapshot.worker_id == 3u);
        size_t count;
        CHECK(solaris_tracker_list(env.tracker, 1, NULL, 0u, &count) == SOLARIS_EMSGSIZE && count == 1u);
        CHECK(solaris_tracker_close_connection(env.tracker, env.id) == SOLARIS_ECLOSED);
    }
    CHECK(solaris_tracker_close_all(env.tracker) == SOLARIS_OK && solaris_tracker_destroy(env.tracker) == SOLARIS_OK);
    for (size_t i = 0u; i < 6u; ++i)
        solaris_test_event_destroy(events[i]);
    CHECK(solaris_budget_used(env.budget) == 0u);
    solaris_budget_release(env.budget);
}
static void traffic(void)
{
    solaris_budget_t *budget;
    CHECK(solaris_budget_create(4096u, NULL, &budget) == SOLARIS_OK);
    solaris_traffic_counter_t *counter;
    CHECK(solaris_traffic_counter_create(budget, &counter) == SOLARIS_OK);
    solaris_traffic_counter_retain(counter);
    solaris_traffic_counter_release(counter);
    solaris_traffic_record_read(counter, SOLARIS_TRAFFIC_STREAM, UINT64_MAX);
    solaris_traffic_record_read(counter, SOLARIS_TRAFFIC_STREAM, 1u);
    solaris_traffic_record_write(counter, SOLARIS_TRAFFIC_DATAGRAM, 0u);
    solaris_traffic_snapshot_t snapshot;
    CHECK(solaris_traffic_counter_snapshot(counter, &snapshot) == SOLARIS_OK && snapshot.stream_read == UINT64_MAX &&
          snapshot.saturated && snapshot.packets_written == 1u && snapshot.datagram_written == 0u);
    solaris_traffic_counter_release(counter);
    CHECK(solaris_budget_used(budget) == 0u);
    solaris_budget_release(budget);
}
int main(void)
{
    for (int mode = NORMAL; mode <= HISTORY; ++mode)
        run(mode);
    traffic();
    puts("Observation: logical counts, history/limits, concurrent snapshots, cross-thread close, cancellation barriers "
         "and traffic counters passed");
    return 0;
}
