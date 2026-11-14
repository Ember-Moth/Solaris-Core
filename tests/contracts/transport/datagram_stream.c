#include "support/runtime/files.h"
#include "transport/datagram/stream.h"
#include "codec/uot/codec.h"
#include "codec/xudp/codec.h"
#include "support/runtime/event.h"
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)
enum { NORMAL, PARTIAL_EOF, BAD_TYPE, READ_MEMORY, CANCEL_BEFORE, LATE_OPEN, CANCEL_WRITE, STOP_WRITE, REJECT, LATE_SUCCESS, ALLOCATE, TERMINAL };
static const solaris_datagram_codec_ops_t *codec = &solaris_uot_v2_codec;
typedef struct environment environment_t;
typedef struct mock_stream {
    environment_t *env;
    solaris_stream_t stream;
    solaris_stream_callbacks_t callbacks;
    void *context;
    solaris_deferred_t opened, written, readable, writable, closed;
    solaris_slice_t slice;
    solaris_io_done_fn done;
    void *user;
    int opening, closing, busy, reading, backpressure;
    unsigned int writes;
    size_t input_offset;
} mock_stream_t;
struct environment {
    solaris_executor_t *owner;
    solaris_budget_t *budget;
    solaris_datagram_t *channel;
    solaris_runtime_services_t services;
    solaris_test_event_t ready, pending, cancelled, complete;
    solaris_deferred_t resume, late;
    mock_stream_t mock;
    atomic_uint closed;
    atomic_uint_fast64_t clock;
    int mode, fail_at, fail_count, initial_failure;
    unsigned int opens, sends, packets, completions, writable;
    solaris_status_t open_status, close_status, submit_status;
    uint8_t input[128];
    size_t input_size;
};
static void queue(environment_t *env, solaris_deferred_t *node, void (*fn)(void *), void *context)
{ node->run = fn; node->context = context; CHECK(solaris_executor_defer(env->owner, node) == SOLARIS_OK); }
static uint64_t now_ns(void *context) { return atomic_load(&((environment_t *)context)->clock); }
static void *allocate(void *context, size_t size)
{
    environment_t *env = context;
    if (env->fail_at > 0 && ++env->fail_count == env->fail_at) { env->fail_at = 0; return NULL; }
    return malloc(size);
}
static void mock_opened(void *context)
{
    mock_stream_t *mock = context; CHECK(!mock->opening); mock->opening = 1;
    if (mock->env->mode == LATE_SUCCESS) atomic_store(&mock->env->clock, UINT64_C(11000000));
    mock->callbacks.on_open(mock->context, &mock->stream, mock->closing ? SOLARIS_ECANCELLED : SOLARIS_OK);
}
static void mock_closed(void *context)
{
    mock_stream_t *mock = context; CHECK(!mock->busy);
    if (!mock->opening) {
        mock->opening = 1;
        mock->callbacks.on_open(mock->context, &mock->stream, SOLARIS_OK);
    }
    mock->callbacks.on_close(mock->context, &mock->stream, SOLARIS_ECANCELLED);
}
static void mock_readable(void *context)
{
    mock_stream_t *mock = context; environment_t *env = mock->env;
    if (!mock->reading || mock->closing || mock->input_offset == env->input_size) return;
    size_t length = env->input_size - mock->input_offset;
    if (length > 3u) length = 3u;
    solaris_buffer_t *buffer;
    CHECK(solaris_buffer_copy(env->budget, env->input + mock->input_offset, length, &buffer) == SOLARIS_OK);
    mock->input_offset += length;
    if (env->mode == READ_MEMORY && mock->input_offset == env->input_size) { env->fail_at = 1; env->fail_count = 0; }
    mock->callbacks.on_data(mock->context, &mock->stream, buffer);
    solaris_buffer_release(buffer);
    if (env->mode == PARTIAL_EOF && mock->input_offset == env->input_size)
        mock->callbacks.on_eof(mock->context, &mock->stream);
}
static void mock_written(void *context)
{
    mock_stream_t *mock = context; CHECK(mock->busy); mock->busy = 0; mock->writes++;
    const solaris_buffer_t *buffer = mock->slice.buffer; mock->slice.buffer = NULL;
    mock->done(mock->user, mock->closing ? SOLARIS_ECANCELLED : SOLARIS_OK); solaris_buffer_release(buffer);
    if (mock->closing) queue(mock->env, &mock->closed, mock_closed, mock);
    else if (mock->writes >= 2u && mock->reading) queue(mock->env, &mock->readable, mock_readable, mock);
}
static void mock_writable(void *context)
{
    mock_stream_t *mock = context;
    if (!mock->closing) mock->callbacks.on_writable(mock->context, &mock->stream);
}
static solaris_status_t mock_write(void *state, const solaris_slice_t *slice, solaris_io_done_fn done, void *context)
{
    mock_stream_t *mock = state;
    if (mock->closing) return SOLARIS_ECLOSED;
    if (!mock->backpressure) {
        mock->backpressure = 1; queue(mock->env, &mock->writable, mock_writable, mock); return SOLARIS_EAGAIN;
    }
    CHECK(!mock->busy); mock->slice = *slice; solaris_buffer_retain(slice->buffer);
    mock->busy = 1; mock->done = done; mock->user = context;
    if (mock->env->mode == CANCEL_WRITE || mock->env->mode == STOP_WRITE)
        solaris_test_event_signal(&mock->env->pending);
    else queue(mock->env, &mock->written, mock_written, mock);
    return SOLARIS_OK;
}
static solaris_status_t mock_shutdown(void *state, solaris_io_done_fn done, void *context)
{ (void)state; (void)done; (void)context; return SOLARIS_ENOTSUP; }
static solaris_status_t mock_read(void *state, int enabled)
{
    mock_stream_t *mock = state; mock->reading = enabled;
    if (enabled && !mock->closing && mock->writes >= 2u && mock->input_offset < mock->env->input_size && !mock->readable.queued)
        queue(mock->env, &mock->readable, mock_readable, mock);
    return SOLARIS_OK;
}
static solaris_status_t mock_close(void *state)
{
    mock_stream_t *mock = state;
    if (!mock->closing) {
        mock->closing = 1; solaris_test_event_signal(&mock->env->cancelled);
        if (!mock->busy && mock->env->mode != LATE_OPEN) queue(mock->env, &mock->closed, mock_closed, mock);
    }
    return SOLARIS_OK;
}
static solaris_status_t mock_snapshot(void *state, solaris_io_snapshot_t *out)
{ (void)state; memset(out, 0, sizeof(*out)); return SOLARIS_OK; }
static const solaris_stream_ops_t mock_ops = {mock_write, mock_shutdown, mock_read, mock_close, mock_snapshot, NULL};
static solaris_status_t mock_open(void *context, solaris_executor_t *owner, const solaris_dialer_options_t *options,
    const solaris_address_t *peer, const solaris_stream_callbacks_t *callbacks, void *user, solaris_stream_t **out)
{
    (void)peer; environment_t *env = context; *out = NULL;
    CHECK(owner == env->owner && options->pending_request_limit == 1u && options->pending_byte_limit >= codec->frame_limit);
    if (env->mode == REJECT) return SOLARIS_EACCESS;
    mock_stream_t *mock = &env->mock; mock->env = env; mock->stream = (solaris_stream_t){&mock_ops, mock, owner};
    mock->callbacks = *callbacks; mock->context = user; mock->reading = 1; *out = &mock->stream;
    if (env->mode != LATE_OPEN) queue(env, &mock->opened, mock_opened, mock);
    return SOLARIS_OK;
}
static void finish(environment_t *env)
{
    if (env->mode == NORMAL && env->packets == 2u && env->completions == 2u)
        CHECK(solaris_datagram_close(env->channel) == SOLARIS_OK);
}
static void sent(void *context, solaris_status_t status)
{
    environment_t *env = context;
    CHECK(status == ((env->mode == CANCEL_WRITE || env->mode == STOP_WRITE) ? SOLARIS_ECANCELLED : SOLARIS_OK));
    env->completions++; finish(env);
}
static void opened(void *context, solaris_datagram_t *channel, solaris_status_t status)
{
    environment_t *env = context; CHECK(channel == env->channel && ++env->opens == 1u); env->open_status = status;
    if (env->mode == ALLOCATE) { CHECK(solaris_datagram_close(channel) == SOLARIS_OK); return; }
    if (status != SOLARIS_OK) return;
    solaris_buffer_t *buffer; CHECK(solaris_buffer_copy(env->budget, "payload", 7u, &buffer) == SOLARIS_OK);
    solaris_address_t target; CHECK(solaris_address_parse("127.0.0.1", 53u, &target) == SOLARIS_OK);
    solaris_datagram_message_t messages[3];
    for (size_t i = 0u; i < 3u; ++i) messages[i] = (solaris_datagram_message_t){target, {buffer, 0u, 7u}, sent, env};
    size_t accepted;
    CHECK(solaris_datagram_send_batch(channel, messages, 3u, &accepted) == SOLARIS_EAGAIN && accepted == 2u);
    env->sends = 2u; CHECK(env->completions == 0u && solaris_buffer_mutable_data(buffer) == NULL);
    solaris_buffer_release(buffer);
}
static void resume(void *context)
{ environment_t *env = context; CHECK(solaris_datagram_set_reading(env->channel, 1) == SOLARIS_OK); }
static void packet(void *context, solaris_datagram_t *channel, const solaris_address_t *source, const solaris_buffer_t *buffer)
{
    environment_t *env = context; CHECK((env->mode == NORMAL || env->mode == TERMINAL) && channel == env->channel);
    solaris_address_t expected; CHECK(solaris_address_parse("127.0.0.1", 53u, &expected) == SOLARIS_OK);
    CHECK(solaris_address_equal(source, &expected)); CHECK(solaris_buffer_mutable_data((solaris_buffer_t *)buffer) == NULL);
    size_t length = solaris_buffer_length(buffer); CHECK(length == (env->packets == 0u ? 0u : 17u));
    for (size_t n = 0u; n < length; ++n) CHECK(solaris_buffer_data(buffer)[n] == (uint8_t)(n * 17u));
    env->packets++;
    if (env->packets == 1u && env->mode == NORMAL) {
        CHECK(solaris_datagram_set_reading(channel, 0) == SOLARIS_OK);
        queue(env, &env->resume, resume, env);
    }
    finish(env);
}
static void writable(void *context, solaris_datagram_t *channel)
{ environment_t *env = context; CHECK(channel == env->channel); env->writable++; }
static void closed(void *context, solaris_datagram_t *channel, solaris_status_t status)
{
    environment_t *env = context; CHECK(channel == env->channel && atomic_fetch_add(&env->closed, 1u) == 0u);
    env->close_status = status; solaris_io_snapshot_t stats;
    CHECK(solaris_datagram_get_snapshot(channel, &stats) == SOLARIS_OK && stats.pending_requests == 0u && stats.pending_bytes == 0u);
    if (env->mode == NORMAL) CHECK(stats.packets_read == 2u && stats.bytes_read == 17u && stats.packets_written == 2u && stats.bytes_written == 14u);
    solaris_test_event_signal(&env->complete);
}
static const solaris_datagram_callbacks_t callbacks = {opened, packet, writable, closed};
static void start(void *context, solaris_status_t status)
{
    environment_t *env = context; CHECK(status == SOLARIS_OK);
    solaris_stream_factory_t factory = {.context = env, .open = mock_open};
    solaris_dialer_options_t options = {.pending_byte_limit = 14u, .pending_request_limit = 2u, .open_timeout_ms = 10u};
    solaris_address_t peer; CHECK(solaris_address_parse("127.0.0.1", 123u, &peer) == SOLARIS_OK);
    env->fail_at = env->initial_failure; env->fail_count = 0;
    env->submit_status = solaris_datagram_stream_open(env->owner, &factory, &options, &peer, codec,
        NULL, &callbacks, env, &env->channel);
    if (env->submit_status != SOLARIS_OK) { CHECK(env->channel == NULL); solaris_test_event_signal(&env->complete); }
    else if (env->mode == CANCEL_BEFORE) CHECK(solaris_datagram_close(env->channel) == SOLARIS_OK);
    solaris_test_event_signal(&env->ready);
}
static void cancel(void *context, solaris_status_t status)
{ environment_t *env = context; CHECK(status == SOLARIS_OK && solaris_datagram_close(env->channel) == SOLARIS_OK); }
static size_t load(const char *directory, unsigned int id, uint8_t *out, size_t capacity)
{
    char path[1024]; CHECK(snprintf(path, sizeof(path), "%s/frame-%u.bin", directory, id) > 0);
    FILE *file = solaris_test_fopen(path, "rb"); CHECK(file != NULL);
    size_t n = fread(out, 1u, capacity, file); CHECK(feof(file)); fclose(file); return n;
}
static void run(const char *directory, int mode, int failure)
{
    environment_t env = {.mode = mode, .initial_failure = failure}; atomic_init(&env.closed, 0u); atomic_init(&env.clock, 0u);
    CHECK(solaris_test_event_init(&env.ready, 0u) == 0 && solaris_test_event_init(&env.pending, 0u) == 0 &&
        solaris_test_event_init(&env.cancelled, 0u) == 0 && solaris_test_event_init(&env.complete, 0u) == 0);
    solaris_runtime_services_init(&env.services); env.services.context = &env; env.services.allocate = allocate; env.services.now_ns = now_ns;
    CHECK(solaris_budget_create(4u * 1024u * 1024u, &env.services, &env.budget) == SOLARIS_OK);
    solaris_executor_options_t options = {.id = (uint32_t)mode % 2u, .queue_capacity = 1u, .resource_limit = 32u,
        .budget = env.budget, .services = &env.services};
    CHECK(solaris_executor_create(&options, &env.owner) == SOLARIS_OK && solaris_executor_activate(env.owner, 1u) == SOLARIS_OK);
    env.input_size = load(directory, 3u, env.input, sizeof(env.input));
    if (mode == NORMAL) env.input_size += load(directory, 0u, env.input + env.input_size, sizeof(env.input) - env.input_size);
    else if (mode == PARTIAL_EOF) env.input_size = 2u;
    else if (mode == BAD_TYPE) { env.input[0] = 255u; env.input_size = codec == &solaris_xudp_codec ? 2u : 1u; }
    if (mode == TERMINAL) {
        static const uint8_t end[] = {0,4,0,0,3,1,0,0};
        memcpy(env.input, end, sizeof(end)); env.input_size = sizeof(end);
    }
    CHECK(solaris_executor_post(env.owner, start, &env) == SOLARIS_OK); solaris_test_event_wait(&env.ready);
    if (mode == LATE_OPEN) {
        atomic_store(&env.clock, UINT64_C(11000000)); solaris_executor_wake(env.owner);
        solaris_test_event_wait(&env.cancelled); CHECK(atomic_load(&env.closed) == 0u);
        queue(&env, &env.late, mock_closed, &env.mock);
    } else if (mode == CANCEL_WRITE || mode == STOP_WRITE) {
        solaris_test_event_wait(&env.pending);
        if (mode == STOP_WRITE) CHECK(solaris_executor_begin_quiesce(env.owner) == SOLARIS_OK);
        else CHECK(solaris_executor_post(env.owner, cancel, &env) == SOLARIS_OK);
        solaris_test_event_wait(&env.cancelled); CHECK(atomic_load(&env.closed) == 0u);
        queue(&env, &env.late, mock_written, &env.mock);
    }
    solaris_test_event_wait(&env.complete);
    CHECK(solaris_executor_quiesce(env.owner) == SOLARIS_OK && solaris_executor_destroy(env.owner) == SOLARIS_OK);
    if (env.submit_status == SOLARIS_OK) {
        CHECK(env.opens == 1u && atomic_load(&env.closed) == 1u && env.completions == env.sends);
        if (mode == LATE_OPEN || mode == LATE_SUCCESS) CHECK(env.open_status == SOLARIS_ETIMEDOUT && env.close_status == SOLARIS_ETIMEDOUT);
        else if (mode == CANCEL_BEFORE) CHECK(env.open_status == SOLARIS_ECANCELLED && env.close_status == SOLARIS_OK);
        else if (mode == READ_MEMORY) CHECK(env.close_status == SOLARIS_ENOMEM);
        else if (mode == BAD_TYPE || mode == PARTIAL_EOF) CHECK(env.close_status == SOLARIS_EIO);
        else if (mode == STOP_WRITE) CHECK(env.close_status == SOLARIS_ECANCELLED);
        else if (mode == TERMINAL) CHECK(env.close_status == SOLARIS_ECLOSED && env.packets == 1u);
        else CHECK(env.close_status == SOLARIS_OK);
        if (mode == NORMAL) CHECK(env.packets == 2u && env.writable == 1u);
    } else CHECK(env.opens == 0u && atomic_load(&env.closed) == 0u && (mode == REJECT || mode == ALLOCATE));
    CHECK(solaris_budget_used(env.budget) == 0u); solaris_budget_release(env.budget);
    solaris_test_event_destroy(&env.ready); solaris_test_event_destroy(&env.pending);
    solaris_test_event_destroy(&env.cancelled); solaris_test_event_destroy(&env.complete);
}
int main(int argc, char **argv)
{
    CHECK(argc == 2 || argc == 3);
    if (argc == 3) { CHECK(strcmp(argv[2], "xudp") == 0); codec = &solaris_xudp_codec; }
    for (int mode = NORMAL; mode < ALLOCATE; ++mode) run(argv[1], mode, 0);
    for (int allocation = 1; allocation <= 6; ++allocation) run(argv[1], ALLOCATE, allocation);
    if (argc == 3) run(argv[1], TERMINAL, 0);
    puts("Datagram stream: framing/pause, batch/backpressure, allocation, EOF, deadline, cancellation and stop barriers passed");
    return 0;
}
