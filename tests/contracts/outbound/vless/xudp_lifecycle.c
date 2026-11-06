#include "adapters/outbound/vless/datagram.h"
#include "support/runtime/event.h"
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)
enum { RECOVER, CANCEL_REOPEN, STOP_REOPEN, LATE_WRITE, END_FRAME, BAD_FRAME, PARTIAL_FRAME, BAD_VLESS, ALLOCATE, REJECT, ZERO_ID };
typedef struct environment environment_t;
typedef struct mock_stream {
    environment_t *env;
    solaris_stream_t stream;
    solaris_stream_callbacks_t callbacks;
    void *context;
    solaris_deferred_t opened, written, readable, closed, broken;
    solaris_slice_t slice;
    solaris_io_done_fn done;
    void *user;
    unsigned int generation, writes;
    int opening, closing, busy, reading, response_sent;
} mock_stream_t;
struct environment {
    solaris_executor_t *owner;
    solaris_budget_t *budget;
    solaris_datagram_t *channel;
    solaris_test_event_t ready, pending, cancelled, complete;
    solaris_deferred_t resume;
    mock_stream_t mocks[4];
    atomic_uint closed;
    unsigned int physical, opens, sends, completions, packets, waiting;
    int mode, fail_at, fail_count;
    solaris_status_t submit_status, close_status;
    uint8_t identity[8];
};
static void queue(environment_t *env, solaris_deferred_t *node, void (*run)(void *), void *context)
{ node->run = run; node->context = context; CHECK(solaris_executor_defer(env->owner, node) == SOLARIS_OK); }
static void *allocate(void *context, size_t size)
{
    environment_t *env = context;
    if (env->fail_at > 0 && ++env->fail_count == env->fail_at) { env->fail_at = 0; return NULL; }
    return malloc(size);
}
static solaris_status_t random_bytes(void *context, uint8_t *out, size_t size)
{ environment_t *env = context; memset(out, env->mode == ZERO_ID ? 0 : 73, size); return SOLARIS_OK; }
static void mock_opened(void *context)
{
    mock_stream_t *mock = context; CHECK(!mock->opening); mock->opening = 1;
    mock->callbacks.on_open(mock->context, &mock->stream, SOLARIS_OK);
}
static void mock_closed(void *context)
{
    mock_stream_t *mock = context; CHECK(!mock->busy);
    if (!mock->opening) mock_opened(mock);
    mock->callbacks.on_close(mock->context, &mock->stream, SOLARIS_OK);
}
static void deliver(mock_stream_t *mock, const uint8_t *bytes, size_t size)
{
    solaris_buffer_t *buffer;
    CHECK(solaris_buffer_copy(mock->env->budget, bytes, size, &buffer) == SOLARIS_OK);
    mock->callbacks.on_data(mock->context, &mock->stream, buffer); solaris_buffer_release(buffer);
}
static void mock_readable(void *context)
{
    mock_stream_t *mock = context;
    if (!mock->reading || mock->closing || mock->response_sent) return;
    mock->response_sent = 1;
    const uint8_t response[] = {0,0,0,4,0,0,2,1,0,1,42};
    const uint8_t bad[] = {1,0};
    if (mock->env->mode == BAD_VLESS && mock->generation == 2u) deliver(mock, bad, sizeof(bad));
    else deliver(mock, response, sizeof(response));
}
static void mock_broken(void *context)
{
    mock_stream_t *mock = context; environment_t *env = mock->env;
    if (mock->closing) return;
    if (env->mode == END_FRAME || env->mode == BAD_FRAME || env->mode == PARTIAL_FRAME) {
        uint8_t frame[] = {0,4,0,0,3,0};
        if (env->mode == BAD_FRAME) frame[5] = 8u;
        deliver(mock, frame, env->mode == PARTIAL_FRAME ? 1u : sizeof(frame));
    }
    mock->callbacks.on_eof(mock->context, &mock->stream);
}
static void mock_written(void *context)
{
    mock_stream_t *mock = context; CHECK(mock->busy); mock->busy = 0; mock->writes++;
    const solaris_buffer_t *buffer = mock->slice.buffer; mock->slice.buffer = NULL;
    /* A successful completion may arrive after local cancellation. */
    mock->done(mock->user, SOLARIS_OK); solaris_buffer_release(buffer);
    if (mock->closing) queue(mock->env, &mock->closed, mock_closed, mock);
    else if (mock->writes >= 2u && mock->reading) queue(mock->env, &mock->readable, mock_readable, mock);
}
static solaris_status_t mock_write(void *context, const solaris_slice_t *slice, solaris_io_done_fn done, void *user)
{
    mock_stream_t *mock = context; environment_t *env = mock->env;
    if (mock->closing) return SOLARIS_ECLOSED;
    CHECK(!mock->busy);
    if (mock->writes == 1u) {
        const uint8_t *wire = solaris_buffer_data(slice->buffer) + slice->offset;
        size_t metadata = ((size_t)wire[0] << 8u) | wire[1];
        CHECK(metadata == 20u && wire[4] == 1u);
        if (mock->generation == 1u) memcpy(env->identity, wire + 14u, 8u);
        CHECK(memcmp(env->identity, wire + 14u, 8u) == 0 && env->identity[0] == 73u);
    }
    mock->slice = *slice; solaris_buffer_retain(slice->buffer); mock->done = done; mock->user = user; mock->busy = 1;
    if (env->mode == LATE_WRITE && mock->writes == 2u) {
        solaris_test_event_signal(&env->pending);
        queue(env, &mock->broken, mock_broken, mock);
    } else queue(env, &mock->written, mock_written, mock);
    return SOLARIS_OK;
}
static solaris_status_t mock_shutdown(void *state, solaris_io_done_fn done, void *context)
{ (void)state; (void)done; (void)context; return SOLARIS_ENOTSUP; }
static solaris_status_t mock_reading(void *context, int enabled)
{
    mock_stream_t *mock = context; mock->reading = enabled;
    if (enabled && !mock->closing && mock->writes >= 2u && !mock->response_sent && !mock->readable.queued)
        queue(mock->env, &mock->readable, mock_readable, mock);
    return SOLARIS_OK;
}
static solaris_status_t mock_close(void *context)
{
    mock_stream_t *mock = context;
    if (!mock->closing) {
        mock->closing = 1;
        if (mock->generation == 2u) solaris_test_event_signal(&mock->env->cancelled);
        if (!mock->busy && !(mock->generation == 2u &&
            (mock->env->mode == CANCEL_REOPEN || mock->env->mode == STOP_REOPEN)))
            queue(mock->env, &mock->closed, mock_closed, mock);
    }
    return SOLARIS_OK;
}
static solaris_status_t mock_snapshot(void *state, solaris_io_snapshot_t *out)
{ (void)state; memset(out, 0, sizeof(*out)); return SOLARIS_OK; }
static const solaris_stream_ops_t mock_ops = {mock_write, mock_shutdown, mock_reading, mock_close, mock_snapshot, NULL};
static solaris_status_t mock_open(void *context, solaris_executor_t *owner, const solaris_dialer_options_t *options,
    const solaris_address_t *peer, const solaris_stream_callbacks_t *callbacks, void *user, solaris_stream_t **out)
{
    (void)options; (void)peer; environment_t *env = context; *out = NULL;
    if (env->mode == REJECT) return SOLARIS_EACCESS;
    CHECK(env->physical < 4u); mock_stream_t *mock = &env->mocks[env->physical++];
    mock->env = env; mock->generation = env->physical;
    mock->stream = (solaris_stream_t){&mock_ops, mock, owner}; mock->callbacks = *callbacks;
    mock->context = user; mock->reading = 1; *out = &mock->stream;
    if (mock->generation == 2u) {
        solaris_test_event_signal(&env->pending);
        if (env->mode == CANCEL_REOPEN || env->mode == STOP_REOPEN) return SOLARIS_OK;
    }
    queue(env, &mock->opened, mock_opened, mock); return SOLARIS_OK;
}
static void send_next(environment_t *env);
static void sent(void *context, solaris_status_t status)
{
    environment_t *env = context;
    CHECK(status == SOLARIS_OK || env->mode == LATE_WRITE); env->completions++;
}
static void opened(void *context, solaris_datagram_t *channel, solaris_status_t status)
{
    environment_t *env = context; CHECK(channel == env->channel && ++env->opens == 1u);
    if (env->mode == ALLOCATE) { (void)solaris_datagram_close(channel); return; }
    CHECK(status == SOLARIS_OK); send_next(env);
}
static void packet(void *context, solaris_datagram_t *channel, const solaris_address_t *source, const solaris_buffer_t *buffer)
{
    (void)source; environment_t *env = context; CHECK(channel == env->channel);
    CHECK(solaris_buffer_length(buffer) == 1u && solaris_buffer_data(buffer)[0] == 42u); env->packets++;
    if (env->packets == 2u) { CHECK(solaris_datagram_close(channel) == SOLARIS_OK); return; }
    if (env->mode == LATE_WRITE) send_next(env);
    else queue(env, &env->mocks[0].broken, mock_broken, &env->mocks[0]);
}
static void writable(void *context, solaris_datagram_t *channel)
{ environment_t *env = context; CHECK(channel == env->channel); if (env->waiting) send_next(env); }
static void closed(void *context, solaris_datagram_t *channel, solaris_status_t status)
{
    environment_t *env = context; CHECK(channel == env->channel && atomic_fetch_add(&env->closed, 1u) == 0u);
    env->close_status = status;
    solaris_io_snapshot_t stats; CHECK(solaris_datagram_get_snapshot(channel, &stats) == SOLARIS_OK);
    CHECK(stats.pending_requests == 0u && stats.pending_bytes == 0u && env->sends == env->completions);
    solaris_test_event_signal(&env->complete);
}
static const solaris_datagram_callbacks_t callbacks = {opened, packet, writable, closed};
static void send_next(environment_t *env)
{
    solaris_buffer_t *buffer; CHECK(solaris_buffer_copy(env->budget, "x", 1u, &buffer) == SOLARIS_OK);
    solaris_address_t target; CHECK(solaris_address_parse("127.0.0.1", 53u, &target) == SOLARIS_OK);
    solaris_slice_t slice = {buffer, 0u, 1u};
    solaris_status_t rc = solaris_datagram_send(env->channel, &target, &slice, sent, env);
    solaris_buffer_release(buffer); CHECK(rc == SOLARIS_OK || rc == SOLARIS_EAGAIN);
    env->waiting = rc == SOLARIS_EAGAIN; if (rc == SOLARIS_OK) env->sends++;
}
static void submit(void *context, solaris_status_t status)
{ CHECK(status == SOLARIS_OK); send_next(context); }
static void cancel(void *context, solaris_status_t status)
{ environment_t *env = context; CHECK(status == SOLARIS_OK && solaris_datagram_close(env->channel) == SOLARIS_OK); solaris_test_event_signal(&env->cancelled); }
static void start_case(void *context, solaris_status_t status)
{
    environment_t *env = context; CHECK(status == SOLARIS_OK);
    solaris_vless_datagram_parameters_t p = {.crypto = {.context = env, .random = random_bytes}};
    p.transport.carrier = (solaris_stream_factory_t){env, mock_open};
    p.transport.dialer.pending_request_limit = 1u;
    CHECK(solaris_address_parse("127.0.0.1", 443u, &p.transport.server) == SOLARIS_OK);
    env->fail_count = 0;
    env->submit_status = solaris_vless_datagram_open(env->owner, &p, &callbacks, env, &env->channel);
    if (env->submit_status != SOLARIS_OK) { CHECK(env->channel == NULL); solaris_test_event_signal(&env->complete); }
    solaris_test_event_signal(&env->ready);
}
static void run(int mode, int fail_at)
{
    environment_t env = {.mode = mode}; atomic_init(&env.closed, 0u);
    CHECK(solaris_test_event_init(&env.ready, 0u) == 0 && solaris_test_event_init(&env.pending, 0u) == 0 &&
        solaris_test_event_init(&env.cancelled, 0u) == 0 && solaris_test_event_init(&env.complete, 0u) == 0);
    solaris_runtime_services_t services; solaris_runtime_services_init(&services); services.context = &env; services.allocate = allocate;
    CHECK(solaris_budget_create(8u * 1024u * 1024u, &services, &env.budget) == SOLARIS_OK);
    solaris_executor_options_t options = {.id = (uint32_t)mode % 2u, .queue_capacity = 8u, .resource_limit = 64u, .budget = env.budget};
    CHECK(solaris_executor_create(&options, &env.owner) == SOLARIS_OK && solaris_executor_activate(env.owner, 1u) == SOLARIS_OK);
    env.fail_at = fail_at;
    CHECK(solaris_executor_post(env.owner, start_case, &env) == SOLARIS_OK); solaris_test_event_wait(&env.ready);
    if (mode == RECOVER || mode == BAD_VLESS) {
        solaris_test_event_wait(&env.pending);
        CHECK(solaris_executor_post(env.owner, submit, &env) == SOLARIS_OK);
    } else if (mode == CANCEL_REOPEN || mode == STOP_REOPEN || mode == LATE_WRITE) {
        solaris_test_event_wait(&env.pending);
        if (mode == STOP_REOPEN) CHECK(solaris_executor_begin_quiesce(env.owner) == SOLARIS_OK);
        else CHECK(solaris_executor_post(env.owner, cancel, &env) == SOLARIS_OK);
        solaris_test_event_wait(&env.cancelled);
        CHECK(atomic_load(&env.closed) == 0u);
        mock_stream_t *mock = &env.mocks[mode == LATE_WRITE ? 0 : 1];
        queue(&env, &env.resume, mode == LATE_WRITE ? mock_written : mock_closed, mock);
    }
    solaris_test_event_wait(&env.complete);
    CHECK(solaris_executor_quiesce(env.owner) == SOLARIS_OK && solaris_executor_destroy(env.owner) == SOLARIS_OK);
    if (env.submit_status == SOLARIS_OK) {
        CHECK(env.opens == 1u && atomic_load(&env.closed) == 1u);
        if (mode == RECOVER) CHECK(env.physical == 2u && env.packets == 2u && env.close_status == SOLARIS_OK);
        if (mode == END_FRAME) CHECK(env.physical == 1u && env.close_status == SOLARIS_ECLOSED);
        if (mode == BAD_FRAME || mode == PARTIAL_FRAME) CHECK(env.physical == 1u && env.close_status == SOLARIS_EIO);
        if (mode == BAD_VLESS) CHECK(env.physical == 2u && env.close_status == SOLARIS_EIO);
        if (mode == CANCEL_REOPEN || mode == STOP_REOPEN) CHECK(env.physical == 2u && env.packets == 1u);
        if (mode == STOP_REOPEN) CHECK(env.close_status == SOLARIS_ECANCELLED);
        if (mode == LATE_WRITE) CHECK(env.physical == 1u && env.completions == 2u);
    } else CHECK(env.opens == 0u && atomic_load(&env.closed) == 0u && (mode == ALLOCATE || mode == REJECT || mode == ZERO_ID));
    CHECK(solaris_budget_used(env.budget) == 0u); solaris_budget_release(env.budget);
    solaris_test_event_destroy(&env.ready); solaris_test_event_destroy(&env.pending);
    solaris_test_event_destroy(&env.cancelled); solaris_test_event_destroy(&env.complete);
}
int main(void)
{
    for (int mode = RECOVER; mode <= ZERO_ID; ++mode) run(mode, 0);
    for (int failure = 1; failure <= 64; ++failure) run(ALLOCATE, failure);
    puts("XUDP lifecycle: generation barrier, cancellation, stop, late completion, no replay, protocol failures and allocation rollback passed");
    return 0;
}
