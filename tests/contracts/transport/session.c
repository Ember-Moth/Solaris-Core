#include "transport/session/pool.h"
#include "support/runtime/event.h"
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)
enum { MULTIPLEX, REUSE, BLAST, CANCEL_PART, STOP_PART, ALLOCATE, LATE_OPEN, IDLE, LATEST };
typedef struct environment environment_t;
typedef struct channel {
    environment_t *env;
    solaris_stream_t *stream;
    unsigned int opens, closes, writes, bytes, writable;
    solaris_status_t open_status, close_status;
} channel_t;
typedef struct mock {
    environment_t *env;
    solaris_stream_t stream;
    solaris_stream_callbacks_t callbacks;
    void *context;
    solaris_deferred_t opened, written, readable, writable, closed;
    solaris_io_done_fn done;
    void *user;
    solaris_slice_t slice;
    int opening, reading, busy, closing, pressure;
    uint8_t input[256], output[256];
    size_t input_size, output_size;
    unsigned int syn, data, fin;
} mock_t;
struct environment {
    solaris_executor_t *owner;
    solaris_budget_t *budget;
    solaris_runtime_services_t services;
    solaris_session_pool_t *pool;
    solaris_test_event_t ready, pending, cancelled, complete, idle_ready;
    solaris_deferred_t release;
    atomic_uint_fast64_t clock;
    atomic_uint closed;
    mock_t mocks[4];
    channel_t channels[4];
    int mode, fail_at, fail_count, failure;
    unsigned int carriers, opens, closes, callbacks, rounds;
    solaris_status_t submit;
};
static void queue(environment_t *e, solaris_deferred_t *d, void (*run)(void *), void *context)
{ d->run = run; d->context = context; CHECK(solaris_executor_defer(e->owner, d) == SOLARIS_OK); }
static uint64_t clock_now(void *context) { return atomic_load(&((environment_t *)context)->clock); }
static void *allocate(void *context, size_t size)
{ environment_t *e = context; if (e->fail_at > 0 && ++e->fail_count == e->fail_at) { e->fail_at = 0; return NULL; } return malloc(size); }
/* Deliberately unrelated test protocol: three-byte headers and two carrier
 * writes for DATA, split inside the header. This exercises session semantics
 * independently of AnyTLS parsing and padding. */
typedef struct codec { solaris_budget_t *budget; environment_t *env; } codec_t;
static solaris_status_t codec_create(void *parameters, solaris_budget_t *budget, void **out)
{ codec_t *c = solaris_memory_allocate(budget, sizeof(*c)); if (c == NULL) return SOLARIS_ENOMEM; c->budget = budget; c->env = parameters; *out = c; return SOLARIS_OK; }
static solaris_status_t add(codec_t *c, const uint8_t *p, size_t n, solaris_session_batch_t *batch)
{ solaris_status_t rc = solaris_buffer_copy(c->budget, p, n, &batch->buffers[batch->count]); if (rc == SOLARIS_OK) batch->count++; return rc; }
static solaris_status_t codec_start(void *state, solaris_session_batch_t *out)
{ const uint8_t p[3] = {0, 0, 0}; return add(state, p, 3u, out); }
static solaris_status_t codec_open(void *state, uint32_t id, const solaris_address_t *peer, int *ack, solaris_session_batch_t *out)
{ (void)peer; codec_t *c = state; uint8_t p[3] = {1, (uint8_t)id, 0}; *ack = c->env->mode == LATE_OPEN; return add(c, p, 3u, out); }
static solaris_status_t codec_write(void *state, uint32_t id, const solaris_slice_t *data, solaris_session_batch_t *out)
{
    codec_t *c = state; CHECK(data->length == 7u); uint8_t p[10] = {2, (uint8_t)id, 7};
    memcpy(p + 3, solaris_buffer_data(data->buffer) + data->offset, 7u);
    solaris_status_t rc = add(c, p, 2u, out); return rc == SOLARIS_OK ? add(c, p + 2, 8u, out) : rc;
}
static solaris_status_t codec_end(void *state, uint32_t id, solaris_session_batch_t *out)
{ uint8_t p[3] = {3, (uint8_t)id, 0}; return add(state, p, 3u, out); }
static solaris_status_t codec_decode(void *state, const uint8_t *p, size_t n, size_t *used, solaris_session_event_t *event)
{
    codec_t *c = state; *used = 0u;
    if (n != 0u && p[0] == 255u) return SOLARIS_EIO;
    if (n < 3u || n < (size_t)p[2] + 3u) return SOLARIS_EAGAIN;
    CHECK(p[0] == 2u); event->kind = SOLARIS_SESSION_DATA; event->id = p[1];
    solaris_status_t rc = solaris_buffer_copy(c->budget, p + 3, p[2], &event->data);
    if (rc == SOLARIS_OK) *used = 3u + p[2]; return rc;
}
static void codec_destroy(void *state) { solaris_memory_free(state); }
static const solaris_session_codec_t codec = {258u, codec_create, codec_start, codec_open, codec_write, codec_end, codec_decode, codec_destroy};
static void mock_closed(void *context)
{
    mock_t *m = context; CHECK(!m->busy);
    if (!m->opening) { m->opening = 1; m->callbacks.on_open(m->context, &m->stream, SOLARIS_ECANCELLED); }
    m->callbacks.on_close(m->context, &m->stream, SOLARIS_ECANCELLED);
}
static void mock_opened(void *context)
{
    mock_t *m = context; m->opening = 1;
    if (m->env->mode == LATE_OPEN) atomic_store(&m->env->clock, UINT64_C(11000000));
    m->callbacks.on_open(m->context, &m->stream, m->closing ? SOLARIS_ECANCELLED : SOLARIS_OK);
}
static void mock_readable(void *context)
{
    mock_t *m = context;
    if (!m->reading || m->closing || m->input_size == 0u) return;
    size_t n = m->input_size > 4u ? 4u : m->input_size;
    solaris_buffer_t *b; CHECK(solaris_buffer_copy(m->env->budget, m->input, n, &b) == SOLARIS_OK);
    memmove(m->input, m->input + n, m->input_size - n); m->input_size -= n;
    m->callbacks.on_data(m->context, &m->stream, b); solaris_buffer_release(b);
}
static void mock_written(void *context)
{
    mock_t *m = context; CHECK(m->busy); m->busy = 0;
    if (!m->closing) {
        CHECK(m->output_size + m->slice.length <= sizeof(m->output));
        memcpy(m->output + m->output_size, solaris_buffer_data(m->slice.buffer) + m->slice.offset, m->slice.length); m->output_size += m->slice.length;
        while (m->output_size >= 3u && m->output_size >= 3u + (size_t)m->output[2]) {
            size_t size = 3u + m->output[2];
            CHECK(m->output[0] <= 3u);
            if (m->output[0] == 1u) { m->syn++; CHECK(m->output[1] == m->syn); }
            if (m->output[0] == 2u) {
                m->data++; CHECK(size == 10u && memcmp(m->output + 3, "payload", 7u) == 0);
                if (m->env->mode == MULTIPLEX || m->env->mode == REUSE || m->env->mode == IDLE || m->env->mode == LATEST) {
                    CHECK(m->input_size + size <= sizeof(m->input)); memcpy(m->input + m->input_size, m->output, size); m->input_size += size;
                }
            }
            if (m->output[0] == 3u) m->fin++;
            memmove(m->output, m->output + size, m->output_size - size); m->output_size -= size;
        }
        if (m->env->mode == BLAST && m->syn == 2u) { m->input[0] = 255u; m->input_size = 1u; }
    }
    const solaris_buffer_t *b = m->slice.buffer; m->slice.buffer = NULL;
    m->done(m->user, m->closing ? SOLARIS_ECANCELLED : SOLARIS_OK); solaris_buffer_release(b);
    if (m->closing) queue(m->env, &m->closed, mock_closed, m);
    else if (m->reading && m->input_size != 0u && !m->readable.queued) queue(m->env, &m->readable, mock_readable, m);
}
static void mock_writable(void *context)
{ mock_t *m = context; if (!m->closing) m->callbacks.on_writable(m->context, &m->stream); }
static solaris_status_t mock_write(void *state, const solaris_slice_t *slice, solaris_io_done_fn done, void *context)
{
    mock_t *m = state; if (m->closing) return SOLARIS_ECLOSED;
    if (!m->pressure) { m->pressure = 1; queue(m->env, &m->writable, mock_writable, m); return SOLARIS_EAGAIN; }
    CHECK(!m->busy); m->busy = 1; m->slice = *slice; solaris_buffer_retain(slice->buffer); m->done = done; m->user = context;
    if ((m->env->mode == CANCEL_PART || m->env->mode == STOP_PART) && slice->length == 2u)
        solaris_test_event_signal(&m->env->pending);
    else queue(m->env, &m->written, mock_written, m);
    return SOLARIS_OK;
}
static solaris_status_t mock_shutdown(void *state, solaris_io_done_fn done, void *context) { (void)state; (void)done; (void)context; return SOLARIS_ENOTSUP; }
static solaris_status_t mock_read(void *state, int enabled)
{
    mock_t *m = state; m->reading = enabled;
    if (enabled && !m->closing && m->input_size != 0u && !m->readable.queued) queue(m->env, &m->readable, mock_readable, m);
    return SOLARIS_OK;
}
static solaris_status_t mock_close(void *state)
{ mock_t *m = state; if (!m->closing) { m->closing = 1; solaris_test_event_signal(&m->env->cancelled); if (!m->busy) queue(m->env, &m->closed, mock_closed, m); } return SOLARIS_OK; }
static solaris_status_t mock_snapshot(void *state, solaris_io_snapshot_t *out) { (void)state; memset(out, 0, sizeof(*out)); return SOLARIS_OK; }
static const solaris_stream_ops_t mock_ops = {mock_write, mock_shutdown, mock_read, mock_close, mock_snapshot, NULL};
static solaris_status_t mock_factory(void *context, solaris_executor_t *owner, const solaris_dialer_options_t *options,
    const solaris_address_t *peer, const solaris_stream_callbacks_t *callbacks, void *user, solaris_stream_t **out)
{
    (void)options; (void)peer; environment_t *e = context; CHECK(e->carriers < 4u); mock_t *m = &e->mocks[e->carriers++];
    m->env = e; m->stream = (solaris_stream_t){&mock_ops, m, owner}; m->callbacks = *callbacks; m->context = user; m->reading = 1;
    *out = &m->stream; queue(e, &m->opened, mock_opened, m); return SOLARIS_OK;
}
static void pool_closed(void *context)
{ environment_t *e = context; e->pool = NULL; solaris_test_event_signal(&e->complete); }
static void sent(void *context, solaris_status_t status)
{
    channel_t *c = context; environment_t *e = c->env; c->writes++; e->callbacks++;
    if (status != SOLARIS_OK) fprintf(stderr, "mode=%d sent status=%d\n", e->mode, status);
    CHECK(status == ((e->mode == CANCEL_PART || e->mode == STOP_PART || e->mode == BLAST) ? SOLARIS_ECANCELLED : SOLARIS_OK) || (e->mode == BLAST && status == SOLARIS_EIO));
}
static void opened(void *context, solaris_stream_t *stream, solaris_status_t status)
{
    channel_t *c = context; environment_t *e = c->env; CHECK(stream == c->stream); c->opens++; e->opens++; c->open_status = status;
    if (status != SOLARIS_OK) return;
    if (e->mode == ALLOCATE) { CHECK(solaris_stream_close(stream) == SOLARIS_OK); return; }
    if (e->mode == BLAST) return;
    solaris_buffer_t *b; CHECK(solaris_buffer_copy(e->budget, "payload", 7u, &b) == SOLARIS_OK);
    solaris_slice_t slice = {b, 0u, 7u}; CHECK(solaris_stream_write(stream, &slice, sent, c) == SOLARIS_OK);
    CHECK(solaris_stream_write(stream, &slice, sent, c) == SOLARIS_EAGAIN); solaris_buffer_release(b);
}
static void data(void *context, solaris_stream_t *stream, const solaris_buffer_t *buffer)
{
    channel_t *c = context; CHECK(stream == c->stream && solaris_buffer_length(buffer) == 7u && memcmp(solaris_buffer_data(buffer), "payload", 7u) == 0);
    CHECK(solaris_buffer_mutable_data((solaris_buffer_t *)buffer) == NULL); c->bytes += 7u;
    CHECK(solaris_stream_close(stream) == SOLARIS_OK);
}
static void writable(void *context, solaris_stream_t *stream) { channel_t *c = context; CHECK(stream == c->stream); c->writable++; }
static void open_next(environment_t *e, unsigned int index);
static void closed(void *context, solaris_stream_t *stream, solaris_status_t status)
{
    channel_t *c = context; environment_t *e = c->env; CHECK(stream == c->stream); c->closes++; e->closes++; c->close_status = status;
    solaris_io_snapshot_t stats; CHECK(solaris_stream_get_snapshot(stream, &stats) == SOLARIS_OK && stats.pending_requests == 0u && stats.pending_bytes == 0u);
    atomic_fetch_add(&e->closed, 1u);
    if (e->mode == LATEST && e->closes == 2u) { open_next(e, 2u); return; }
    if (e->mode == REUSE && e->closes < 3u) { open_next(e, e->closes); return; }
    if (e->mode == IDLE && e->closes == 1u) { solaris_test_event_signal(&e->idle_ready); return; }
    if (e->closes == e->rounds) solaris_session_pool_retire(e->pool);
}
static const solaris_stream_callbacks_t callbacks = {opened, data, NULL, writable, closed};
static void open_next(environment_t *e, unsigned int index)
{
    channel_t *c = &e->channels[index]; c->env = e; solaris_address_t target;
    CHECK(solaris_address_parse("127.0.0.1", 53u, &target) == SOLARIS_OK);
    e->submit = solaris_session_pool_open(e->pool, NULL, &target, &callbacks, c, &c->stream);
    if (e->submit != SOLARIS_OK) { CHECK(c->stream == NULL && e->mode == ALLOCATE); solaris_session_pool_retire(e->pool); }
}
static void start(void *context, solaris_status_t status)
{
    environment_t *e = context; CHECK(status == SOLARIS_OK);
    solaris_session_pool_options_t options = {.carrier = {.context = e, .open = mock_factory}, .codec = &codec, .parameters = e,
        .dialer = {.pending_byte_limit = 7u, .pending_request_limit = 1u, .open_timeout_ms = 10u},
        .session_limit = 4u, .streams_per_session = e->mode == LATEST ? 1u : 2u, .idle_timeout_ms = 10u, .on_close = pool_closed, .context = e};
    CHECK(solaris_address_parse("127.0.0.1", 443u, &options.peer) == SOLARIS_OK);
    CHECK(solaris_session_pool_create(e->owner, &options, &e->pool) == SOLARIS_OK);
    e->fail_at = e->failure; e->fail_count = 0;
    open_next(e, 0u);
    e->fail_at = 0;
    if (e->mode == MULTIPLEX || e->mode == BLAST || e->mode == LATEST) open_next(e, 1u);
    solaris_test_event_signal(&e->ready);
}
static void cancel(void *context, solaris_status_t status)
{ environment_t *e = context; CHECK(status == SOLARIS_OK && solaris_stream_close(e->channels[0].stream) == SOLARIS_OK); solaris_test_event_signal(&e->cancelled); }
static void idle_next(void *context, solaris_status_t status)
{ CHECK(status == SOLARIS_OK); open_next(context, 1u); }
static void run(int mode, int failure)
{
    environment_t e = {.mode = mode, .failure = failure}; atomic_init(&e.clock, 0u); atomic_init(&e.closed, 0u);
    e.rounds = (mode == REUSE || mode == LATEST) ? 3u : mode == MULTIPLEX || mode == BLAST || mode == IDLE ? 2u : 1u;
    CHECK(solaris_test_event_init(&e.ready, 0u) == 0 && solaris_test_event_init(&e.pending, 0u) == 0 &&
        solaris_test_event_init(&e.cancelled, 0u) == 0 && solaris_test_event_init(&e.complete, 0u) == 0 && solaris_test_event_init(&e.idle_ready, 0u) == 0);
    solaris_runtime_services_init(&e.services); e.services.context = &e; e.services.allocate = allocate; e.services.now_ns = clock_now;
    CHECK(solaris_budget_create(8u*1024u*1024u, &e.services, &e.budget) == SOLARIS_OK);
    solaris_executor_options_t options = {.id = (uint32_t)mode % 2u, .budget = e.budget, .services = &e.services, .queue_capacity = 8u, .resource_limit = 64u};
    CHECK(solaris_executor_create(&options, &e.owner) == SOLARIS_OK && solaris_executor_activate(e.owner, 1u) == SOLARIS_OK);
    CHECK(solaris_executor_post(e.owner, start, &e) == SOLARIS_OK); solaris_test_event_wait(&e.ready);
    if (mode == CANCEL_PART || mode == STOP_PART) {
        solaris_test_event_wait(&e.pending);
        if (mode == CANCEL_PART) { CHECK(solaris_executor_post(e.owner, cancel, &e) == SOLARIS_OK); solaris_test_event_wait(&e.cancelled); }
        else { CHECK(solaris_executor_begin_quiesce(e.owner) == SOLARIS_OK); solaris_test_event_wait(&e.cancelled); }
        CHECK(atomic_load(&e.closed) == 0u);
        queue(&e, &e.release, mock_written, &e.mocks[0]);
    } else if (mode == IDLE) {
        solaris_test_event_wait(&e.idle_ready); atomic_store(&e.clock, UINT64_C(21000000));
        CHECK(solaris_executor_post(e.owner, idle_next, &e) == SOLARIS_OK);
    }
    solaris_test_event_wait(&e.complete);
    CHECK(solaris_executor_quiesce(e.owner) == SOLARIS_OK && solaris_executor_destroy(e.owner) == SOLARIS_OK);
    if (e.submit == SOLARIS_OK) {
        CHECK(e.opens == e.rounds && e.closes == e.rounds);
        if (mode == MULTIPLEX || mode == REUSE || mode == IDLE) CHECK(e.callbacks == e.rounds);
        if (mode == REUSE) CHECK(e.carriers == 1u && e.mocks[0].syn == 3u && e.mocks[0].fin == 3u);
        if (mode == MULTIPLEX) CHECK(e.carriers == 1u && e.mocks[0].data == 2u);
        if (mode == IDLE) CHECK(e.carriers == 2u);
        if (mode == LATEST) CHECK(e.carriers == 2u && e.mocks[0].syn == 1u && e.mocks[1].syn == 2u);
        if (mode == CANCEL_PART) CHECK(e.mocks[0].data == 1u && e.mocks[0].fin == 1u && e.mocks[0].output_size == 0u && e.callbacks == 1u);
        if (mode == STOP_PART) CHECK(e.channels[0].close_status == SOLARIS_ECANCELLED && e.callbacks == 1u);
        if (mode == BLAST) CHECK(e.channels[0].close_status == SOLARIS_EIO && e.channels[1].close_status == SOLARIS_EIO);
        if (mode == LATE_OPEN) CHECK(e.channels[0].open_status == SOLARIS_ETIMEDOUT && e.channels[0].close_status == SOLARIS_ETIMEDOUT);
    } else CHECK(mode == ALLOCATE && e.opens == 0u && e.closes == 0u);
    CHECK(solaris_budget_used(e.budget) == 0u); solaris_budget_release(e.budget);
    solaris_test_event_destroy(&e.ready); solaris_test_event_destroy(&e.pending); solaris_test_event_destroy(&e.cancelled);
    solaris_test_event_destroy(&e.complete); solaris_test_event_destroy(&e.idle_ready);
}
int main(void)
{
    for (int mode = MULTIPLEX; mode <= LATEST; ++mode) if (mode != ALLOCATE) run(mode, 0);
    for (int failure = 1; failure <= 16; ++failure) run(ALLOCATE, failure);
    puts("session: multiplex, reuse, idle expiry, failure blast, split-write cancel/stop, allocation and deadlines passed"); return 0;
}
