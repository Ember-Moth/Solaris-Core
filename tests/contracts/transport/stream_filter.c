#include "transport/stream/filter.h"
#include "support/runtime/event.h"
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)
enum { NORMAL, ACK_EARLY, PAUSED, DELAY, FINAL_DELAY, CANCEL_DELAY, STOP_DELAY,
    CANCEL_WRITE, STOP_WRITE, TIMEOUT, LATE_ACK, PARTIAL_EOF, BAD_ACK, REJECT,
    RAW_OWN, RAW_CARRIER, RAW_CANCEL, RAW_STOP, RAW_UNSUPPORTED, ALLOCATE };
typedef struct environment environment_t;
typedef struct mock_stream {
    environment_t *env;
    solaris_stream_t stream;
    solaris_stream_callbacks_t callbacks;
    void *context;
    solaris_deferred_t opened, written, readable, writable, closed;
    solaris_deferred_t raw_done;
    solaris_slice_t slice;
    solaris_io_done_fn done;
    void *user;
    solaris_io_done_fn raw_callback;
    void *raw_context;
    int raw_busy;
    int closing, busy, reading, pressured, saw_open;
    unsigned int writes;
    size_t input_offset;
} mock_stream_t;
struct environment {
    solaris_executor_t *owner;
    solaris_budget_t *budget;
    solaris_stream_t *channel;
    solaris_runtime_services_t services;
    solaris_test_event_t started, pending, cancelled, complete;
    solaris_deferred_t late, resume;
    mock_stream_t mock;
    atomic_uint closed;
    atomic_uint_fast64_t clock;
    int mode, fail_at, fail_count, initial_failure;
    unsigned int opens, successes, data, writes, completions;
    unsigned int codec_read, codec_write, carrier_read, carrier_write, barrier_done;
    solaris_status_t open_status, close_status, submit_status;
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
typedef struct codec_state { environment_t *env; solaris_budget_t *budget; int ready, next; uint32_t requests; } codec_state_t;
static int carrier_raw_mode(int mode) { return mode == RAW_CARRIER || mode == RAW_CANCEL || mode == RAW_STOP || mode == RAW_UNSUPPORTED; }
static solaris_status_t create(const void *parameters, solaris_budget_t *budget, void **out)
{
    codec_state_t *codec = solaris_memory_allocate(budget, sizeof(*codec));
    if (codec == NULL) return SOLARIS_ENOMEM;
    *codec = (codec_state_t){.env = (environment_t *)parameters, .budget = budget}; *out = codec; return SOLARIS_OK;
}
static solaris_status_t begin(void *state, solaris_buffer_t **out)
{ codec_state_t *codec = state; return solaris_buffer_copy(codec->budget, "hello", 5u, out); }
static solaris_status_t next(void *state, solaris_buffer_t **out, uint64_t *delay)
{
    codec_state_t *codec = state; environment_t *env = codec->env; *out = NULL; *delay = 0u;
    if (codec->next++ != 0) return SOLARIS_OK;
    if (env->mode == DELAY || env->mode == CANCEL_DELAY || env->mode == STOP_DELAY || env->mode == FINAL_DELAY) {
        *delay = 5u; solaris_test_event_signal(&env->pending);
    }
    if (env->mode == FINAL_DELAY) return SOLARIS_OK;
    return solaris_buffer_copy(codec->budget, "padding", 7u, out);
}
static solaris_status_t encode(void *state, const solaris_slice_t *plain, solaris_buffer_t **out)
{
    codec_state_t *codec = state;
    solaris_status_t rc = solaris_buffer_copy(codec->budget, solaris_buffer_data(plain->buffer) + plain->offset, plain->length, out);
    if (rc == SOLARIS_OK && carrier_raw_mode(codec->env->mode)) codec->requests |= SOLARIS_STREAM_RAW_WRITE;
    return rc;
}
static solaris_status_t decode(void *state, const uint8_t *wire, size_t size, size_t *used, solaris_buffer_t **out)
{
    codec_state_t *codec = state; *used = 0u; *out = NULL;
    if (!codec->ready) {
        if (size < 4u) return SOLARIS_EAGAIN;
        if (memcmp(wire, "ACK!", 4u) != 0) return SOLARIS_EACCESS;
        codec->ready = 1; *used = 4u;
        if (carrier_raw_mode(codec->env->mode)) codec->requests |= SOLARIS_STREAM_RAW_READ;
        return SOLARIS_OK;
    }
    if (size < 5u) return SOLARIS_EAGAIN;
    CHECK(memcmp(wire, "reply", 5u) == 0);
    solaris_status_t rc = solaris_buffer_copy(codec->budget, wire, 5u, out);
    if (rc == SOLARIS_OK) *used = 5u;
    return rc;
}
static int ready(void *state) { return ((codec_state_t *)state)->ready; }
static solaris_status_t finish_codec(void *state) { return ready(state) ? SOLARIS_OK : SOLARIS_EIO; }
static void destroy_codec(void *state) { solaris_memory_free(state); }
static solaris_status_t codec_read_raw(void *state)
{ ((codec_state_t *)state)->env->codec_read++; return SOLARIS_OK; }
static solaris_status_t codec_write_raw(void *state)
{
    environment_t *env = ((codec_state_t *)state)->env; CHECK(env->mock.writes == 3u && env->completions == 1u);
    env->codec_write++; return SOLARIS_OK;
}
static uint32_t codec_requests(void *state) { return ((codec_state_t *)state)->requests; }
static void codec_applied(void *state, uint32_t directions) { ((codec_state_t *)state)->requests &= ~directions; }
static const solaris_stream_codec_raw_ops_t codec_raw_ops = {codec_read_raw, codec_write_raw};
static const solaris_stream_codec_carrier_raw_t codec_carrier_raw = {
    SOLARIS_STREAM_RAW_READ | SOLARIS_STREAM_RAW_WRITE, codec_requests, codec_applied
};
static const solaris_stream_codec_ops_t codec = {
    .receive_limit = 32768u, .create = create, .start = begin, .encode = encode,
    .decode = decode, .finish = finish_codec, .destroy = destroy_codec, .ready = ready, .next_preface = next, .raw = &codec_raw_ops
};
static const solaris_stream_codec_ops_t carrier_codec = {
    .receive_limit = 32768u, .create = create, .start = begin, .encode = encode,
    .decode = decode, .finish = finish_codec, .destroy = destroy_codec, .ready = ready, .next_preface = next,
    .carrier_raw = &codec_carrier_raw
};
static void mock_opened(void *context)
{
    mock_stream_t *mock = context; mock->saw_open = 1;
    mock->callbacks.on_open(mock->context, &mock->stream, mock->closing ? SOLARIS_ECANCELLED : SOLARIS_OK);
}
static void mock_closed(void *context)
{
    mock_stream_t *mock = context; CHECK(!mock->busy && !mock->raw_busy && mock->saw_open);
    mock->callbacks.on_close(mock->context, &mock->stream, SOLARIS_ECANCELLED);
}
static void mock_readable(void *context)
{
    mock_stream_t *mock = context; environment_t *env = mock->env;
    if (!mock->reading || mock->closing) return;
    const char *input = env->mode == BAD_ACK ? "NAK!reply" : "ACK!reply";
    size_t total = env->mode == PARTIAL_EOF ? 2u : 9u;
    if (mock->input_offset >= total) return;
    size_t length = total - mock->input_offset;
    if (length > 2u) length = 2u;
    solaris_buffer_t *buffer;
    CHECK(solaris_buffer_copy(env->budget, input + mock->input_offset, length, &buffer) == SOLARIS_OK);
    mock->input_offset += length;
    if (env->mode == LATE_ACK && mock->input_offset == 4u) atomic_store(&env->clock, UINT64_C(11000000));
    mock->callbacks.on_data(mock->context, &mock->stream, buffer); solaris_buffer_release(buffer);
    if (env->mode == PARTIAL_EOF && mock->input_offset == total) mock->callbacks.on_eof(mock->context, &mock->stream);
    if (env->mode == ACK_EARLY && mock->input_offset == 4u) solaris_test_event_signal(&env->pending);
}
static void mock_written(void *context)
{
    mock_stream_t *mock = context; CHECK(mock->busy); mock->busy = 0; mock->writes++;
    const solaris_buffer_t *buffer = mock->slice.buffer; mock->slice.buffer = NULL;
    mock->done(mock->user, mock->closing ? SOLARIS_ECANCELLED : SOLARIS_OK); solaris_buffer_release(buffer);
    if (mock->closing) queue(mock->env, &mock->closed, mock_closed, mock);
}
static void mock_writable(void *context)
{ mock_stream_t *mock = context; if (!mock->closing) mock->callbacks.on_writable(mock->context, &mock->stream); }
static solaris_status_t mock_write(void *state, const solaris_slice_t *slice, solaris_io_done_fn done, void *context)
{
    mock_stream_t *mock = state; environment_t *env = mock->env;
    if (mock->closing) return SOLARIS_ECLOSED;
    if (!mock->pressured) { mock->pressured = 1; queue(env, &mock->writable, mock_writable, mock); return SOLARIS_EAGAIN; }
    CHECK(!mock->busy); mock->busy = 1; mock->slice = *slice; solaris_buffer_retain(slice->buffer); mock->done = done; mock->user = context;
    const char *expected = mock->writes == 0u ? "hello" : mock->writes == 1u && env->mode != FINAL_DELAY ? "padding" : "data";
    CHECK(slice->length == strlen(expected) && memcmp(solaris_buffer_data(slice->buffer) + slice->offset, expected, slice->length) == 0);
    if (env->mode == CANCEL_WRITE || env->mode == STOP_WRITE) solaris_test_event_signal(&env->pending);
    else if (env->mode != ACK_EARLY || mock->writes != 1u) queue(env, &mock->written, mock_written, mock);
    return SOLARIS_OK;
}
static solaris_status_t mock_shutdown(void *state, solaris_io_done_fn done, void *context)
{ (void)state; (void)done; (void)context; return SOLARIS_ENOTSUP; }
static solaris_status_t mock_read(void *state, int enabled)
{
    mock_stream_t *mock = state; environment_t *env = mock->env; mock->reading = enabled;
    int allowed = env->mode != TIMEOUT && env->mode != ALLOCATE;
    if (env->mode == ACK_EARLY) allowed = mock->writes >= 1u;
    if (enabled && allowed && !mock->closing && !mock->readable.queued) queue(env, &mock->readable, mock_readable, mock);
    if (env->mode == TIMEOUT && mock->writes >= 2u) solaris_test_event_signal(&env->pending);
    return SOLARIS_OK;
}
static solaris_status_t mock_close(void *state)
{
    mock_stream_t *mock = state;
    if (!mock->closing) {
        mock->closing = 1; solaris_test_event_signal(&mock->env->cancelled);
        if (!mock->busy && !mock->raw_busy) queue(mock->env, &mock->closed, mock_closed, mock);
    }
    return SOLARIS_OK;
}
static solaris_status_t mock_snapshot(void *state, solaris_io_snapshot_t *out)
{ (void)state; memset(out, 0, sizeof(*out)); return SOLARIS_OK; }
static uint32_t mock_raw_capabilities(void *state)
{ return ((mock_stream_t *)state)->env->mode == RAW_UNSUPPORTED ? 0u : SOLARIS_STREAM_RAW_READ | SOLARIS_STREAM_RAW_WRITE; }
static solaris_status_t mock_read_raw(void *state)
{ ((mock_stream_t *)state)->env->carrier_read++; return SOLARIS_OK; }
static void mock_raw_completed(void *context)
{
    mock_stream_t *mock = context; CHECK(mock->raw_busy); mock->raw_busy = 0;
    mock->raw_callback(mock->raw_context, mock->closing ? SOLARIS_ECANCELLED : SOLARIS_OK);
    if (mock->closing) queue(mock->env, &mock->closed, mock_closed, mock);
}
static solaris_status_t mock_write_raw(void *state, solaris_io_done_fn done, void *context)
{
    mock_stream_t *mock = state; CHECK(!mock->busy && !mock->raw_busy && mock->writes == 3u);
    mock->raw_busy = 1; mock->raw_callback = done; mock->raw_context = context; mock->env->carrier_write++;
    if (mock->env->mode == RAW_CANCEL || mock->env->mode == RAW_STOP) solaris_test_event_signal(&mock->env->pending);
    else queue(mock->env, &mock->raw_done, mock_raw_completed, mock);
    return SOLARIS_OK;
}
static const solaris_stream_raw_ops_t mock_raw_ops = {mock_raw_capabilities, mock_read_raw, mock_write_raw};
static const solaris_stream_ops_t mock_ops = {mock_write, mock_shutdown, mock_read, mock_close, mock_snapshot, &mock_raw_ops};
static solaris_status_t mock_open(void *context, solaris_executor_t *owner, const solaris_dialer_options_t *options,
    const solaris_address_t *peer, const solaris_stream_callbacks_t *callbacks, void *user, solaris_stream_t **out)
{
    (void)options; (void)peer; environment_t *env = context; *out = NULL;
    if (env->mode == REJECT) return SOLARIS_EACCESS;
    mock_stream_t *mock = &env->mock; mock->env = env; mock->stream = (solaris_stream_t){&mock_ops, mock, owner};
    mock->callbacks = *callbacks; mock->context = user; mock->reading = 1; *out = &mock->stream;
    queue(env, &mock->opened, mock_opened, mock); return SOLARIS_OK;
}
static void maybe_finish(environment_t *env)
{ if (env->data == 1u && env->completions == (env->mode == RAW_OWN ? 2u : 1u)) CHECK(solaris_stream_close(env->channel) == SOLARIS_OK); }
static void sent(void *context, solaris_status_t status)
{
    environment_t *env = context;
    CHECK(status == ((env->mode == RAW_CANCEL || env->mode == RAW_STOP) ? SOLARIS_ECANCELLED : SOLARIS_OK));
    if (env->mode == RAW_OWN && env->completions == 1u) CHECK(env->barrier_done == 1u);
    if (env->mode == RAW_CARRIER) CHECK(env->carrier_write == 1u && !env->mock.raw_busy);
    env->completions++; maybe_finish(env);
}
static void barrier_done(void *context, solaris_status_t status)
{
    environment_t *env = context; CHECK(status == SOLARIS_OK && env->codec_write == 1u && env->completions == 1u);
    env->barrier_done++;
}
static void resume(void *context)
{ environment_t *env = context; CHECK(env->data == 0u); CHECK(solaris_stream_set_reading(env->channel, 1) == SOLARIS_OK); }
static void opened(void *context, solaris_stream_t *channel, solaris_status_t status)
{
    environment_t *env = context; CHECK(channel == env->channel && ++env->opens == 1u); env->open_status = status;
    if (status != SOLARIS_OK) return;
    env->successes++; CHECK(env->mock.writes >= (env->mode == FINAL_DELAY ? 1u : 2u));
    if (env->mode == PAUSED) queue(env, &env->resume, resume, env);
    solaris_buffer_t *buffer; CHECK(solaris_buffer_copy(env->budget, "data", 4u, &buffer) == SOLARIS_OK);
    solaris_slice_t slice = {buffer, 0u, 4u};
    CHECK(solaris_stream_write(channel, &slice, sent, env) == SOLARIS_OK); env->writes++;
    if (env->mode == RAW_OWN) {
        uint32_t caps; CHECK(solaris_stream_raw_capabilities(channel, &caps) == SOLARIS_OK && caps == 3u);
        CHECK(solaris_stream_read_raw(channel) == SOLARIS_OK && solaris_stream_read_raw(channel) == SOLARIS_OK);
        CHECK(solaris_stream_write_raw(channel, barrier_done, env) == SOLARIS_OK);
        CHECK(solaris_stream_write_raw(channel, barrier_done, env) == SOLARIS_EBUSY);
        CHECK(solaris_stream_write(channel, &slice, sent, env) == SOLARIS_OK); env->writes++;
    }
    CHECK(solaris_stream_write(channel, &slice, sent, env) == SOLARIS_EAGAIN);
    solaris_buffer_release(buffer);
}
static void data(void *context, solaris_stream_t *channel, const solaris_buffer_t *buffer)
{
    environment_t *env = context; CHECK(channel == env->channel && env->successes == 1u);
    CHECK(solaris_buffer_length(buffer) == 5u && memcmp(solaris_buffer_data(buffer), "reply", 5u) == 0);
    CHECK(solaris_buffer_mutable_data((solaris_buffer_t *)buffer) == NULL); env->data++; maybe_finish(env);
}
static void closed(void *context, solaris_stream_t *channel, solaris_status_t status)
{
    environment_t *env = context; CHECK(channel == env->channel && atomic_fetch_add(&env->closed, 1u) == 0u);
    env->close_status = status; solaris_test_event_signal(&env->complete);
}
static const solaris_stream_callbacks_t callbacks = {opened, data, NULL, NULL, closed};
static void start(void *context, solaris_status_t status)
{
    environment_t *env = context; CHECK(status == SOLARIS_OK);
    solaris_stream_factory_t factory = {.context = env, .open = mock_open};
    solaris_dialer_options_t options = {.pending_byte_limit = 4u, .pending_request_limit = 1u, .open_timeout_ms = 10u};
    if (env->mode == RAW_OWN) { options.pending_byte_limit = 8u; options.pending_request_limit = 2u; }
    solaris_address_t peer; CHECK(solaris_address_parse("127.0.0.1", 123u, &peer) == SOLARIS_OK);
    env->fail_at = env->initial_failure; env->fail_count = 0;
    env->submit_status = solaris_filter_open(env->owner, &factory, &options, &peer,
        carrier_raw_mode(env->mode) ? &carrier_codec : &codec, env, &callbacks, env, &env->channel);
    if (env->submit_status != SOLARIS_OK) { CHECK(env->channel == NULL); solaris_test_event_signal(&env->complete); }
    else if (env->mode == PAUSED) CHECK(solaris_stream_set_reading(env->channel, 0) == SOLARIS_OK);
    else if (env->mode == ALLOCATE) CHECK(solaris_stream_close(env->channel) == SOLARIS_OK);
    solaris_test_event_signal(&env->started);
}
static void cancel(void *context, solaris_status_t status)
{ environment_t *env = context; CHECK(status == SOLARIS_OK && solaris_stream_close(env->channel) == SOLARIS_OK); }
static void release_write(void *context, solaris_status_t status)
{ environment_t *env = context; CHECK(status == SOLARIS_OK && env->opens == 0u); mock_written(&env->mock); }
static void advance_clock(void *context, solaris_status_t status)
{
    environment_t *env = context; CHECK(status == SOLARIS_OK && env->opens == 0u);
    /* This owner task follows the pump that installed the padding timer. */
    atomic_store(&env->clock, env->mode == TIMEOUT ? UINT64_C(11000000) : UINT64_C(6000000));
    solaris_executor_wake(env->owner);
}
static void run(int mode, int failure)
{
    fprintf(stderr, "stream filter mode %d allocation %d\n", mode, failure);
    environment_t env = {.mode = mode, .initial_failure = failure}; atomic_init(&env.closed, 0u); atomic_init(&env.clock, 0u);
    CHECK(solaris_test_event_init(&env.started, 0u) == 0 && solaris_test_event_init(&env.pending, 0u) == 0 &&
        solaris_test_event_init(&env.cancelled, 0u) == 0 && solaris_test_event_init(&env.complete, 0u) == 0);
    solaris_runtime_services_init(&env.services); env.services.context = &env; env.services.allocate = allocate; env.services.now_ns = now_ns;
    CHECK(solaris_budget_create(4u * 1024u * 1024u, &env.services, &env.budget) == SOLARIS_OK);
    solaris_executor_options_t options = {.id = (uint32_t)mode % 2u, .queue_capacity = 1u, .resource_limit = 32u,
        .budget = env.budget, .services = &env.services};
    CHECK(solaris_executor_create(&options, &env.owner) == SOLARIS_OK && solaris_executor_activate(env.owner, 1u) == SOLARIS_OK);
    CHECK(solaris_executor_post(env.owner, start, &env) == SOLARIS_OK); solaris_test_event_wait(&env.started);
    if (mode == ACK_EARLY) {
        solaris_test_event_wait(&env.pending); CHECK(solaris_executor_post(env.owner, release_write, &env) == SOLARIS_OK);
    } else if (mode == DELAY || mode == FINAL_DELAY || mode == TIMEOUT) {
        solaris_test_event_wait(&env.pending);
        CHECK(solaris_executor_post(env.owner, advance_clock, &env) == SOLARIS_OK);
    } else if (mode == CANCEL_DELAY || mode == STOP_DELAY || mode == CANCEL_WRITE || mode == STOP_WRITE || mode == RAW_CANCEL || mode == RAW_STOP) {
        solaris_test_event_wait(&env.pending);
        if (mode == STOP_DELAY || mode == STOP_WRITE || mode == RAW_STOP) CHECK(solaris_executor_begin_quiesce(env.owner) == SOLARIS_OK);
        else CHECK(solaris_executor_post(env.owner, cancel, &env) == SOLARIS_OK);
        solaris_test_event_wait(&env.cancelled);
        if (mode == CANCEL_WRITE || mode == STOP_WRITE) {
            CHECK(atomic_load(&env.closed) == 0u); queue(&env, &env.late, mock_written, &env.mock);
        } else if (mode == RAW_CANCEL || mode == RAW_STOP) {
            CHECK(atomic_load(&env.closed) == 0u); queue(&env, &env.late, mock_raw_completed, &env.mock);
        }
    }
    solaris_test_event_wait(&env.complete);
    CHECK(solaris_executor_quiesce(env.owner) == SOLARIS_OK && solaris_executor_destroy(env.owner) == SOLARIS_OK);
    if (env.submit_status == SOLARIS_OK) {
        CHECK(env.opens == 1u && atomic_load(&env.closed) == 1u && env.completions == env.writes);
        if (mode == NORMAL || mode == ACK_EARLY || mode == PAUSED || mode == DELAY || mode == FINAL_DELAY || mode == RAW_OWN || mode == RAW_CARRIER)
            CHECK(env.successes == 1u && env.data == 1u && env.close_status == SOLARIS_OK);
        else if (mode == RAW_CANCEL || mode == RAW_STOP)
            CHECK(env.successes == 1u && env.close_status == (mode == RAW_STOP ? SOLARIS_ECANCELLED : SOLARIS_OK));
        else {
            CHECK(env.successes == 0u && env.data == 0u);
            if (mode == TIMEOUT || mode == LATE_ACK) CHECK(env.open_status == SOLARIS_ETIMEDOUT && env.close_status == SOLARIS_ETIMEDOUT);
            else if (mode == PARTIAL_EOF) CHECK(env.close_status == SOLARIS_EIO);
            else if (mode == BAD_ACK) CHECK(env.close_status == SOLARIS_EACCESS);
            else if (mode == RAW_UNSUPPORTED) CHECK(env.close_status == SOLARIS_ENOTSUP && env.mock.writes == 0u);
            else if (mode == STOP_DELAY || mode == STOP_WRITE) CHECK(env.close_status == SOLARIS_ECANCELLED);
            else CHECK(env.close_status == SOLARIS_OK);
        }
        if (mode == RAW_OWN) CHECK(env.codec_read == 1u && env.codec_write == 1u && env.barrier_done == 1u);
        if (mode == RAW_CARRIER || mode == RAW_CANCEL || mode == RAW_STOP) CHECK(env.carrier_read == 1u && env.carrier_write == 1u);
    } else CHECK(env.opens == 0u && atomic_load(&env.closed) == 0u && (mode == REJECT || mode == ALLOCATE));
    CHECK(solaris_budget_used(env.budget) == 0u); solaris_budget_release(env.budget);
    solaris_test_event_destroy(&env.started); solaris_test_event_destroy(&env.pending);
    solaris_test_event_destroy(&env.cancelled); solaris_test_event_destroy(&env.complete);
}
int main(void)
{
    for (int mode = NORMAL; mode < ALLOCATE; ++mode) run(mode, 0);
    for (int allocation = 1; allocation <= 6; ++allocation) run(ALLOCATE, allocation);
    puts("Stream filter: authenticated open, delayed preface, read pause, EOF, deadline and cancellation barriers passed"); return 0;
}
