#include "transport/stream/bridge.h"
#include "support/runtime/event.h"
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)
typedef struct environment environment_t;
typedef struct endpoint_test endpoint_test_t;
typedef struct completion {
    endpoint_test_t *endpoint;
    unsigned int index;
    int shutdown;
} completion_t;
struct endpoint_test {
    environment_t *env;
    unsigned int index;
    solaris_executor_t *owner;
    solaris_stream_t *stream;
    solaris_scope_t blocker;
    solaris_test_event_t action, opened, data, eof, done, closed, entered, release;
    completion_t completions[8];
    unsigned int opens, closes, received, finished, eof_count, writable;
    size_t received_bytes;
    solaris_status_t attach_status, open_status, close_status, done_status[8];
    int reading, writes, block_data, close_data, fail_view, fill_resources;
};
struct environment {
    solaris_runtime_services_t services;
    solaris_budget_t *budget;
    solaris_stream_bridge_t *bridge;
    endpoint_test_t sides[2];
    atomic_int fail_next;
};
static void *allocate(void *context, size_t size)
{ return atomic_exchange(&((environment_t *)context)->fail_next, 0) ? NULL : malloc(size); }
static void opened(void *context, solaris_stream_t *stream, solaris_status_t status)
{
    endpoint_test_t *side = context;
    CHECK(solaris_executor_is_owner(side->owner) && side->stream == stream && side->opens++ == 0u);
    side->open_status = status;
    if (status == SOLARIS_OK) CHECK(solaris_stream_set_reading(stream, side->reading) == SOLARIS_OK);
    solaris_test_event_signal(&side->opened);
}
static void data(void *context, solaris_stream_t *stream, const solaris_buffer_t *buffer)
{
    endpoint_test_t *side = context;
    CHECK(solaris_executor_is_owner(side->owner) && side->stream == stream && side->opens == 1u && side->eof_count == 0u);
    CHECK(solaris_buffer_length(buffer) == 8u && memcmp(solaris_buffer_data(buffer), "abcdefgh", 8u) == 0);
    CHECK(solaris_buffer_mutable_data((solaris_buffer_t *)buffer) == NULL);
    side->received++; side->received_bytes += 8u;
    if (side->block_data) {
        solaris_test_event_signal(&side->entered);
        solaris_test_event_wait(&side->release);
    }
    if (side->close_data) CHECK(solaris_stream_close(stream) == SOLARIS_OK);
    solaris_test_event_signal(&side->data);
}
static void eof(void *context, solaris_stream_t *stream)
{
    endpoint_test_t *side = context;
    CHECK(solaris_executor_is_owner(side->owner) && side->stream == stream && side->eof_count++ == 0u);
    solaris_io_snapshot_t stats;
    CHECK(solaris_stream_get_snapshot(stream, &stats) == SOLARIS_OK && stats.read_eof);
    solaris_test_event_signal(&side->eof);
}
static void writable(void *context, solaris_stream_t *stream)
{
    endpoint_test_t *side = context;
    CHECK(solaris_executor_is_owner(side->owner) && side->stream == stream);
    side->writable++;
}
static void closed(void *context, solaris_stream_t *stream, solaris_status_t status)
{
    endpoint_test_t *side = context;
    CHECK(solaris_executor_is_owner(side->owner) && side->stream == stream && side->opens == 1u && side->closes++ == 0u);
    solaris_io_snapshot_t stats;
    CHECK(solaris_stream_get_snapshot(stream, &stats) == SOLARIS_OK && stats.pending_bytes == 0u && stats.pending_requests == 0u);
    side->stream = NULL; side->close_status = status;
    solaris_test_event_signal(&side->closed);
}
static void done(void *context, solaris_status_t status)
{
    completion_t *completion = context; endpoint_test_t *side = completion->endpoint;
    CHECK(solaris_executor_is_owner(side->owner) && side->closes == 0u);
    CHECK(completion->index == side->finished && side->finished < 8u);
    side->done_status[side->finished++] = status;
    if (completion->shutdown && status == SOLARIS_OK) {
        solaris_io_snapshot_t stats;
        CHECK(solaris_stream_get_snapshot(side->stream, &stats) == SOLARIS_OK && stats.write_shutdown);
    }
    solaris_test_event_signal(&side->done);
}
static const solaris_stream_callbacks_t callbacks = {opened, data, eof, writable, closed};
static void attach(void *context, solaris_status_t status)
{
    endpoint_test_t *side = context; CHECK(status == SOLARIS_OK);
    if (side->fill_resources) CHECK(solaris_scope_init(&side->blocker, side->owner, NULL, NULL, NULL) == SOLARIS_OK);
    side->attach_status = solaris_stream_bridge_attach(side->env->bridge, side->index,
        side->owner, &callbacks, side, &side->stream);
    if (side->fill_resources) solaris_scope_cancel(&side->blocker);
    solaris_test_event_signal(&side->action);
}
static void read_change(void *context, solaris_status_t status)
{
    endpoint_test_t *side = context; CHECK(status == SOLARIS_OK);
    CHECK(solaris_stream_set_reading(side->stream, side->reading) == SOLARIS_OK);
    solaris_test_event_signal(&side->action);
}
static void write_chunks(void *context, solaris_status_t status)
{
    endpoint_test_t *side = context; CHECK(status == SOLARIS_OK);
    solaris_buffer_t *buffer;
    CHECK(solaris_buffer_copy(side->env->budget, "!abcdefgh?", 10u, &buffer) == SOLARIS_OK);
    solaris_slice_t slice = {buffer, 1u, 8u};
    unsigned int first = side->finished;
    solaris_slice_t oversized = {buffer, 0u, 10u};
    CHECK(solaris_stream_write(side->stream, &oversized, done, &side->completions[first]) == SOLARIS_EMSGSIZE);
    if (side->fail_view) {
        atomic_store(&side->env->fail_next, 1);
        CHECK(solaris_stream_write(side->stream, &slice, done, &side->completions[first]) == SOLARIS_ENOMEM);
        solaris_io_snapshot_t stats;
        CHECK(solaris_stream_get_snapshot(side->stream, &stats) == SOLARIS_OK && stats.pending_requests == 0u);
    } else {
        for (int i = 0; i < side->writes; ++i)
            CHECK(solaris_stream_write(side->stream, &slice, done, &side->completions[first + (unsigned int)i]) == SOLARIS_OK);
        if (side->writes == 2) {
            CHECK(solaris_stream_write(side->stream, &slice, done, &side->completions[first + 2u]) == SOLARIS_EAGAIN);
            CHECK(solaris_stream_shutdown_write(side->stream, done, &side->completions[first + 2u]) == SOLARIS_EAGAIN);
            solaris_io_snapshot_t stats;
            CHECK(solaris_stream_get_snapshot(side->stream, &stats) == SOLARIS_OK && stats.pending_requests == 2u && stats.pending_bytes == 16u);
        }
    }
    CHECK(side->finished == first); /* Completion cannot run inline on sender. */
    solaris_buffer_release(buffer);
    solaris_test_event_signal(&side->action);
}
static void reject_without_credit(void *context, solaris_status_t status)
{
    endpoint_test_t *side = context; CHECK(status == SOLARIS_OK);
    solaris_buffer_t *buffer;
    CHECK(solaris_buffer_copy(side->env->budget, "abcdefgh", 8u, &buffer) == SOLARIS_OK);
    solaris_slice_t slice = {buffer, 0u, 8u};
    CHECK(solaris_stream_write(side->stream, &slice, done, &side->completions[0]) == SOLARIS_EAGAIN);
    solaris_io_snapshot_t stats;
    CHECK(solaris_stream_get_snapshot(side->stream, &stats) == SOLARIS_OK && stats.pending_bytes == 0u && stats.pending_requests == 0u);
    solaris_buffer_release(buffer); solaris_test_event_signal(&side->action);
}
static void shutdown_write(void *context, solaris_status_t status)
{
    endpoint_test_t *side = context; CHECK(status == SOLARIS_OK);
    completion_t *completion = &side->completions[side->finished]; completion->shutdown = 1;
    CHECK(solaris_stream_shutdown_write(side->stream, done, completion) == SOLARIS_OK);
    CHECK(solaris_stream_shutdown_write(side->stream, done, completion) == SOLARIS_ECLOSED);
    solaris_test_event_signal(&side->action);
}
static void queue_shutdown(void *context, solaris_status_t status)
{
    endpoint_test_t *side = context; CHECK(status == SOLARIS_OK && side->finished == 0u);
    side->completions[1].shutdown = 1;
    CHECK(solaris_stream_shutdown_write(side->stream, done, &side->completions[1]) == SOLARIS_OK);
    solaris_test_event_signal(&side->action);
}
static void close_pair(void *context, solaris_status_t status)
{
    endpoint_test_t *side = context; CHECK(status == SOLARIS_OK);
    CHECK(solaris_stream_close(side->stream) == SOLARIS_OK);
    CHECK(solaris_stream_close(side->stream) == SOLARIS_OK);
    solaris_test_event_signal(&side->action);
}
static void check_raw(void *context, solaris_status_t status)
{
    endpoint_test_t *side = context; CHECK(status == SOLARIS_OK);
    uint32_t capabilities = UINT32_MAX;
    CHECK(solaris_stream_raw_capabilities(side->stream, &capabilities) == SOLARIS_OK && capabilities == 0u);
    CHECK(solaris_stream_read_raw(side->stream) == SOLARIS_ENOTSUP);
    CHECK(solaris_stream_write_raw(side->stream, done, &side->completions[0]) == SOLARIS_ENOTSUP);
    solaris_test_event_signal(&side->action);
}
static void hold_owner(void *context, solaris_status_t status)
{
    endpoint_test_t *side = context; CHECK(status == SOLARIS_OK);
    solaris_test_event_signal(&side->entered); solaris_test_event_wait(&side->release);
}
static void queued_task(void *context, solaris_status_t status)
{
    endpoint_test_t *side = context; CHECK(status == SOLARIS_ECANCELLED);
    solaris_test_event_signal(&side->action);
}
static void invoke(endpoint_test_t *side, solaris_task_fn task)
{ CHECK(solaris_executor_post(side->owner, task, side) == SOLARIS_OK); solaris_test_event_wait(&side->action); }
static void create_pair(environment_t *env)
{
    solaris_stream_bridge_options_t options = {env->budget, 16u, 2u, 8u};
    CHECK(solaris_stream_bridge_create(&options, &env->bridge) == SOLARIS_OK);
}
static void init(environment_t *env, size_t resources)
{
    memset(env, 0, sizeof(*env)); atomic_init(&env->fail_next, 0);
    solaris_runtime_services_init(&env->services); env->services.context = env; env->services.allocate = allocate;
    CHECK(solaris_budget_create(1024u * 1024u, &env->services, &env->budget) == SOLARIS_OK);
    for (unsigned int i = 0; i < 2u; ++i) {
        endpoint_test_t *side = &env->sides[i]; side->env = env; side->index = i; side->reading = 1;
        CHECK(solaris_test_event_init(&side->action, 0u) == 0 && solaris_test_event_init(&side->opened, 0u) == 0 &&
            solaris_test_event_init(&side->data, 0u) == 0 && solaris_test_event_init(&side->eof, 0u) == 0 &&
            solaris_test_event_init(&side->done, 0u) == 0 && solaris_test_event_init(&side->closed, 0u) == 0 &&
            solaris_test_event_init(&side->entered, 0u) == 0 && solaris_test_event_init(&side->release, 0u) == 0);
        for (unsigned int j = 0; j < 8u; ++j) side->completions[j] = (completion_t){side, j, 0};
        solaris_executor_options_t options = {.id = i, .budget = env->budget, .services = &env->services,
            .queue_capacity = 1u, .resource_limit = resources};
        CHECK(solaris_executor_create(&options, &side->owner) == SOLARIS_OK);
        CHECK(solaris_executor_activate(side->owner, 1u) == SOLARIS_OK);
    }
    create_pair(env);
}
static void connect_pair(environment_t *env)
{
    invoke(&env->sides[0], attach); invoke(&env->sides[1], attach);
    for (unsigned int i = 0; i < 2u; ++i) {
        solaris_test_event_wait(&env->sides[i].opened);
        CHECK(env->sides[i].attach_status == SOLARIS_OK && env->sides[i].open_status == SOLARIS_OK);
    }
}
static void disconnect_pair(environment_t *env)
{
    invoke(&env->sides[0], close_pair);
    for (unsigned int i = 0; i < 2u; ++i) solaris_test_event_wait(&env->sides[i].closed);
}
static void destroy(environment_t *env)
{
    solaris_stream_bridge_release(env->bridge); env->bridge = NULL;
    for (unsigned int i = 0; i < 2u; ++i) {
        endpoint_test_t *side = &env->sides[i];
        CHECK(solaris_executor_quiesce(side->owner) == SOLARIS_OK && solaris_executor_destroy(side->owner) == SOLARIS_OK);
        solaris_test_event_destroy(&side->action); solaris_test_event_destroy(&side->opened);
        solaris_test_event_destroy(&side->data); solaris_test_event_destroy(&side->eof);
        solaris_test_event_destroy(&side->done); solaris_test_event_destroy(&side->closed);
        solaris_test_event_destroy(&side->entered); solaris_test_event_destroy(&side->release);
    }
    CHECK(solaris_budget_used(env->budget) == 0u); solaris_budget_release(env->budget);
}
static void ordered_credit(void)
{
    environment_t env; init(&env, 8u); connect_pair(&env);
    endpoint_test_t *a = &env.sides[0], *b = &env.sides[1];
    invoke(a, check_raw);
    b->reading = 0; invoke(b, read_change);
    a->writes = 2; invoke(a, write_chunks); /* Previously granted credit survives pause. */
    b->reading = 1; invoke(b, read_change);
    solaris_test_event_wait(&a->done); solaris_test_event_wait(&a->done);
    invoke(a, shutdown_write); solaris_test_event_wait(&b->eof); solaris_test_event_wait(&a->done);
    b->writes = 1; invoke(b, write_chunks); solaris_test_event_wait(&b->done);
    disconnect_pair(&env);
    CHECK(a->finished == 3u && b->finished == 1u && a->received == 1u && b->received == 2u && b->eof_count == 1u);
    CHECK(a->done_status[0] == SOLARIS_OK && a->done_status[1] == SOLARIS_OK && a->done_status[2] == SOLARIS_OK);
    CHECK(a->writable > 0u); destroy(&env);
}
static void initially_paused(void)
{
    environment_t env; init(&env, 8u); env.sides[1].reading = 0; connect_pair(&env);
    endpoint_test_t *a = &env.sides[0], *b = &env.sides[1];
    invoke(a, reject_without_credit); b->reading = 1; invoke(b, read_change);
    a->writes = 1; invoke(a, write_chunks); solaris_test_event_wait(&a->done);
    disconnect_pair(&env);
    CHECK(a->finished == 1u && a->writable == 1u && b->received == 1u); destroy(&env);
}
static void simultaneous_stop(void)
{
    environment_t env; init(&env, 8u); connect_pair(&env);
    for (unsigned int i = 0; i < 2u; ++i) { env.sides[i].reading = 0; invoke(&env.sides[i], read_change); }
    for (unsigned int i = 0; i < 2u; ++i) { env.sides[i].writes = 2; invoke(&env.sides[i], write_chunks); }
    for (unsigned int i = 0; i < 2u; ++i) CHECK(solaris_executor_begin_quiesce(env.sides[i].owner) == SOLARIS_OK);
    for (unsigned int i = 0; i < 2u; ++i) {
        CHECK(solaris_executor_wait_quiescent(env.sides[i].owner) == SOLARIS_OK);
        CHECK(env.sides[i].closes == 1u && env.sides[i].finished == 2u && env.sides[i].received == 0u);
        CHECK(env.sides[i].done_status[0] == SOLARIS_ECANCELLED && env.sides[i].done_status[1] == SOLARIS_ECANCELLED);
    }
    destroy(&env);
}
static void cancelled_shutdown(void)
{
    environment_t env; init(&env, 8u); connect_pair(&env);
    endpoint_test_t *a = &env.sides[0], *b = &env.sides[1];
    b->reading = 0; invoke(b, read_change);
    a->writes = 1; invoke(a, write_chunks); invoke(a, queue_shutdown);
    disconnect_pair(&env);
    CHECK(a->finished == 2u && a->done_status[0] == SOLARIS_ECANCELLED && a->done_status[1] == SOLARIS_ECANCELLED);
    CHECK(b->received == 0u && b->eof_count == 0u); destroy(&env);
}
static void late_delivery_and_restart(void)
{
    environment_t env; init(&env, 8u); env.sides[1].block_data = 1; connect_pair(&env);
    endpoint_test_t *a = &env.sides[0], *b = &env.sides[1];
    a->writes = 1; invoke(a, write_chunks); solaris_test_event_wait(&b->entered);
    CHECK(solaris_executor_begin_quiesce(a->owner) == SOLARIS_OK && solaris_executor_begin_quiesce(b->owner) == SOLARIS_OK);
    CHECK(!solaris_executor_is_quiescent(a->owner) && !solaris_executor_is_quiescent(b->owner));
    solaris_test_event_signal(&b->release);
    CHECK(solaris_executor_wait_quiescent(a->owner) == SOLARIS_OK && solaris_executor_wait_quiescent(b->owner) == SOLARIS_OK);
    CHECK(a->finished == 1u && a->done_status[0] == SOLARIS_OK && b->received == 1u);
    CHECK(solaris_executor_activate(a->owner, 2u) == SOLARIS_OK && solaris_executor_activate(b->owner, 2u) == SOLARIS_OK);
    invoke(a, attach); CHECK(a->attach_status == SOLARIS_ECLOSED && a->stream == NULL && a->opens == 1u);
    solaris_stream_bridge_release(env.bridge); env.bridge = NULL;
    for (unsigned int i = 0; i < 2u; ++i) {
        endpoint_test_t *side = &env.sides[i]; solaris_test_event_wait(&side->closed);
        side->opens = side->closes = side->received = side->finished = 0u; side->block_data = 0;
    }
    create_pair(&env); connect_pair(&env); disconnect_pair(&env); destroy(&env);
}
static void full_command_queue(void)
{
    environment_t env; init(&env, 8u); connect_pair(&env);
    endpoint_test_t *a = &env.sides[0], *b = &env.sides[1];
    CHECK(solaris_executor_post(b->owner, hold_owner, b) == SOLARIS_OK); solaris_test_event_wait(&b->entered);
    CHECK(solaris_executor_post(b->owner, queued_task, b) == SOLARIS_OK);
    CHECK(solaris_executor_post(b->owner, queued_task, b) == SOLARIS_EAGAIN);
    a->writes = 1; invoke(a, write_chunks);
    CHECK(solaris_executor_begin_quiesce(a->owner) == SOLARIS_OK && solaris_executor_begin_quiesce(b->owner) == SOLARIS_OK);
    solaris_test_event_signal(&b->release);
    CHECK(solaris_executor_wait_quiescent(a->owner) == SOLARIS_OK && solaris_executor_wait_quiescent(b->owner) == SOLARIS_OK);
    CHECK(a->finished == 1u && a->done_status[0] == SOLARIS_ECANCELLED && b->received == 0u);
    destroy(&env);
}
static void incomplete_and_failed_attach(void)
{
    environment_t env; init(&env, 1u);
    invoke(&env.sides[0], attach);
    solaris_stream_bridge_release(env.bridge); env.bridge = NULL;
    solaris_test_event_wait(&env.sides[0].closed);
    CHECK(env.sides[0].open_status == SOLARIS_ECANCELLED && env.sides[1].opens == 0u);
    destroy(&env);
    init(&env, 1u); invoke(&env.sides[0], attach);
    env.sides[1].fill_resources = 1; invoke(&env.sides[1], attach);
    solaris_test_event_wait(&env.sides[0].closed);
    CHECK(env.sides[1].attach_status == SOLARIS_EAGAIN && env.sides[1].opens == 0u);
    CHECK(env.sides[0].open_status == SOLARIS_EAGAIN && env.sides[0].close_status == SOLARIS_EAGAIN);
    destroy(&env);
}
static void allocation_and_reentrant_close(void)
{
    environment_t env; init(&env, 8u);
    solaris_stream_bridge_options_t options = {env.budget, 16u, 2u, 8u}; solaris_stream_bridge_t *rejected = NULL;
    size_t before = solaris_budget_used(env.budget); atomic_store(&env.fail_next, 1);
    CHECK(solaris_stream_bridge_create(&options, &rejected) == SOLARIS_ENOMEM && rejected == NULL);
    CHECK(solaris_budget_used(env.budget) == before);
    connect_pair(&env); env.sides[0].fail_view = 1; invoke(&env.sides[0], write_chunks);
    env.sides[0].fail_view = 0; env.sides[0].writes = 1; env.sides[1].close_data = 1;
    invoke(&env.sides[0], write_chunks);
    solaris_test_event_wait(&env.sides[0].closed); solaris_test_event_wait(&env.sides[1].closed);
    CHECK(env.sides[0].finished == 1u && env.sides[0].done_status[0] == SOLARIS_OK && env.sides[1].received == 1u);
    destroy(&env);
}
int main(void)
{
    ordered_credit(); initially_paused(); simultaneous_stop(); cancelled_shutdown(); late_delivery_and_restart(); full_command_queue();
    incomplete_and_failed_attach(); allocation_and_reentrant_close();
    puts("bridge: two-owner ordered DATA/EOF, credit, cancellation ACKs, restart and allocation failures passed");
    return 0;
}
