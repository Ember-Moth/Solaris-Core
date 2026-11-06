#include "contracts/flow/tcp.h"
#include "support/runtime/event.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)
enum { TRANSFER, CANCEL_INBOUND_OPEN, CANCEL_OUTBOUND_OPEN, CANCEL_WRITE, CANCEL_SHUTDOWN,
    STOP_WRITE, STOP_SHUTDOWN, REJECT_OPEN, REJECT_WRITE, REJECT_SHUTDOWN, PAUSE_FAILURE, OVERSIZED, REJECT_PREPARE, ALLOC_PREPARE, CLOSE_ON_CONNECT, CLOSE_ON_CONNECT_FAILURE };
typedef struct environment environment_t;
typedef struct mock {
    environment_t *env;
    unsigned int index;
    solaris_stream_t stream;
    solaris_stream_callbacks_t callbacks;
    void *context;
    solaris_deferred_t open, read, write, shutdown, writable, close;
    solaris_slice_t slice;
    solaris_io_done_fn write_done, shutdown_done;
    void *write_context, *shutdown_context;
    int accepted, opened, closing, reading, data_sent, eof_sent, busy, shutting;
    int hold_open, hold_write, hold_shutdown, write_granted, shutdown_granted;
    unsigned int opens, closes, close_calls, writes, write_callbacks, shutdowns, shutdown_callbacks, rejected, pauses, pressure;
    uint8_t output[128]; size_t output_size;
} mock_t;
struct environment {
    solaris_executor_t *owner;
    solaris_budget_t *budget;
    solaris_runtime_services_t services;
    solaris_outbound_t outbound;
    solaris_tcp_relay_t *relay;
    mock_t mocks[2];
    solaris_deferred_t release;
    solaris_test_event_t ready, pending, cancelled, done;
    int mode, allocation_failure;
    unsigned int factory_calls, plan_releases, relay_closes, connects;
    solaris_status_t connect_status;
    solaris_status_t status;
};
static const uint8_t inputs[2][23] = {
    "client payload of 23b!", "server reply of 23byte"
};
static void queue(environment_t *e, solaris_deferred_t *d)
{ if (!d->queued) CHECK(solaris_executor_defer(e->owner, d) == SOLARIS_OK); }
static void *allocate(void *context, size_t size)
{ environment_t *e = context; if (e->allocation_failure) { e->allocation_failure = 0; return NULL; } return malloc(size); }
static void maybe_closed(mock_t *m)
{ if (m->closing && m->opened && !m->busy && !m->shutting && !m->closes) queue(m->env, &m->close); }
static void mock_open(void *context)
{
    mock_t *m = context; CHECK(m->accepted && !m->opened); m->opened = 1; m->opens++;
    /* Deliberately report late success after cancellation. The relay must
     * close it without opening a new peer or enabling reads. */
    m->callbacks.on_open(m->context, &m->stream, SOLARIS_OK);
    maybe_closed(m);
}
static void mock_read(void *context)
{
    mock_t *m = context; environment_t *e = m->env;
    if (!m->reading || m->closing || !m->opened) return;
    if (!m->data_sent && e->mode != CANCEL_SHUTDOWN && e->mode != STOP_SHUTDOWN && e->mode != REJECT_SHUTDOWN) {
        m->data_sent = 1;
        uint8_t large[33] = {0}; size_t length = e->mode == OVERSIZED ? sizeof(large) : sizeof(inputs[m->index]);
        solaris_buffer_t *buffer;
        CHECK(solaris_buffer_copy(e->budget, e->mode == OVERSIZED ? large : inputs[m->index], length, &buffer) == SOLARIS_OK);
        solaris_buffer_publish(buffer); m->callbacks.on_data(m->context, &m->stream, buffer); solaris_buffer_release(buffer);
        CHECK(!m->reading || m->closing);
    } else if (!m->eof_sent) {
        m->eof_sent = 1; m->callbacks.on_eof(m->context, &m->stream);
    }
}
static void mock_written(void *context)
{
    mock_t *m = context; CHECK(m->busy && m->slice.buffer != NULL);
    solaris_slice_t slice = m->slice; solaris_io_done_fn done = m->write_done; void *user = m->write_context;
    m->busy = 0; m->slice.buffer = NULL; m->write_callbacks++;
    if (!m->closing) {
        CHECK(m->output_size + slice.length <= sizeof(m->output));
        memcpy(m->output + m->output_size, solaris_buffer_data(slice.buffer) + slice.offset, slice.length); m->output_size += slice.length;
    }
    done(user, SOLARIS_OK); solaris_buffer_release(slice.buffer);
    maybe_closed(m);
}
static void mock_shutdown_done(void *context)
{
    mock_t *m = context; CHECK(m->shutting); m->shutting = 0; m->shutdown_callbacks++;
    m->shutdown_done(m->shutdown_context, SOLARIS_OK);
    /* Two FINs deliberately do not auto-close this valid stream backend. */
    maybe_closed(m);
}
static void mock_writable(void *context)
{ mock_t *m = context; if (!m->closing) m->callbacks.on_writable(m->context, &m->stream); }
static void mock_closed(void *context)
{
    mock_t *m = context;
    CHECK(m->accepted && m->opened && m->closing && !m->busy && !m->shutting && ++m->closes == 1u);
    m->callbacks.on_close(m->context, &m->stream, SOLARIS_OK);
}
static solaris_status_t write_stream(void *state, const solaris_slice_t *slice, solaris_io_done_fn done, void *context)
{
    mock_t *m = state; environment_t *e = m->env;
    if (m->closing) return SOLARIS_ECLOSED;
    CHECK(m->opened && !m->busy && !e->mocks[1u - m->index].reading);
    if (e->mode == REJECT_WRITE) { m->rejected++; return SOLARIS_EIO; }
    if (!m->write_granted) { m->write_granted = 1; m->pressure++; queue(e, &m->writable); return SOLARIS_EAGAIN; }
    CHECK(slice->length <= (m->index == 0u ? 3u : 5u) && slice->length != 0u);
    m->write_granted = 0; m->busy = 1; m->writes++; m->slice = *slice; solaris_buffer_retain(slice->buffer);
    m->write_done = done; m->write_context = context;
    if (m->hold_write) solaris_test_event_signal(&e->pending); else queue(e, &m->write);
    return SOLARIS_OK;
}
static solaris_status_t shutdown_stream(void *state, solaris_io_done_fn done, void *context)
{
    mock_t *m = state; environment_t *e = m->env;
    if (m->closing) return SOLARIS_ECLOSED;
    CHECK(!m->busy && !m->shutting);
    if (e->mode == REJECT_SHUTDOWN) { m->rejected++; return SOLARIS_ENOTSUP; }
    if (!m->shutdown_granted) { m->shutdown_granted = 1; m->pressure++; queue(e, &m->writable); return SOLARIS_EAGAIN; }
    m->shutting = 1; m->shutdowns++; m->shutdown_done = done; m->shutdown_context = context;
    if (m->hold_shutdown) solaris_test_event_signal(&e->pending); else queue(e, &m->shutdown);
    return SOLARIS_OK;
}
static solaris_status_t reading_stream(void *state, int enabled)
{
    mock_t *m = state;
    if (m->closing) return SOLARIS_ECLOSED;
    if (!enabled) {
        m->pauses++;
        if (m->env->mode == PAUSE_FAILURE && m->index == 0u) return SOLARIS_EIO;
    }
    m->reading = enabled;
    if (enabled && !m->eof_sent) queue(m->env, &m->read);
    return SOLARIS_OK;
}
static solaris_status_t close_stream(void *state)
{
    mock_t *m = state;
    if (!m->closing) { m->closing = 1; m->reading = 0; m->close_calls++; solaris_test_event_signal(&m->env->cancelled); }
    maybe_closed(m); return SOLARIS_OK;
}
static solaris_status_t snapshot_stream(void *state, solaris_io_snapshot_t *out)
{
    mock_t *m = state; memset(out, 0, sizeof(*out)); out->max_message_bytes = m->index == 0u ? 3u : 5u;
    out->pending_requests = m->busy ? 1u : 0u; out->pending_bytes = m->busy ? m->slice.length : 0u; return SOLARIS_OK;
}
static const solaris_stream_ops_t stream_ops = {write_stream, shutdown_stream, reading_stream, close_stream, snapshot_stream, NULL};
static uint32_t capabilities(void *state) { (void)state; return SOLARIS_OUTBOUND_STREAM | SOLARIS_OUTBOUND_HALF_CLOSE; }
static solaris_status_t open_stream(void *state, const solaris_address_t *peer,
    const solaris_stream_callbacks_t *callbacks, void *context, solaris_stream_t **out)
{
    environment_t *e = state; CHECK(peer->port == 443u); e->factory_calls++;
    if (e->mode == REJECT_OPEN || e->mode == CLOSE_ON_CONNECT_FAILURE) return SOLARIS_EACCESS;
    mock_t *m = &e->mocks[1]; m->callbacks = *callbacks; m->context = context; m->accepted = 1; *out = &m->stream;
    if (m->hold_open) solaris_test_event_signal(&e->pending); else queue(e, &m->open);
    return SOLARIS_OK;
}
static const solaris_outbound_ops_t outbound_ops = {capabilities, open_stream, NULL, NULL};
static void plan_released(void *context)
{
    environment_t *e = context; CHECK(solaris_executor_is_owner(e->owner) && ++e->plan_releases == 1u);
    for (size_t i = 0u; i < 2u; ++i) CHECK(e->mocks[i].closes == (unsigned int)e->mocks[i].accepted);
}
static void relay_closed(void *context, solaris_status_t status)
{
    environment_t *e = context; CHECK(e->plan_releases == 1u && ++e->relay_closes == 1u);
    e->status = status; e->relay = NULL; solaris_test_event_signal(&e->done);
}
static void release_pending(void *context)
{
    environment_t *e = context;
    CHECK(e->relay_closes == 0u && e->plan_releases == 0u);
    for (size_t i = 0u; i < 2u; ++i) {
        mock_t *m = &e->mocks[i]; m->hold_open = m->hold_write = m->hold_shutdown = 0;
        if (m->accepted && !m->opened) queue(e, &m->open);
        if (m->busy) queue(e, &m->write);
        if (m->shutting) queue(e, &m->shutdown);
    }
}
static void relay_connected(void *context, solaris_status_t status)
{
    environment_t *e = context;
    CHECK(++e->connects == 1 && !e->relay_closes && !e->plan_releases);
    e->connect_status = status;
    if (e->mode == CLOSE_ON_CONNECT || e->mode == CLOSE_ON_CONNECT_FAILURE) solaris_tcp_relay_close(e->relay);
}
static void start(void *context, solaris_status_t status)
{
    environment_t *e = context; CHECK(status == SOLARIS_OK);
    e->outbound = (solaris_outbound_t){&outbound_ops, e, e->owner};
    for (unsigned int i = 0u; i < 2u; ++i) {
        mock_t *m = &e->mocks[i]; m->env = e; m->index = i; m->stream = (solaris_stream_t){&stream_ops, m, e->owner};
        m->open = (solaris_deferred_t){.run = mock_open, .context = m};
        m->read = (solaris_deferred_t){.run = mock_read, .context = m};
        m->write = (solaris_deferred_t){.run = mock_written, .context = m};
        m->shutdown = (solaris_deferred_t){.run = mock_shutdown_done, .context = m};
        m->writable = (solaris_deferred_t){.run = mock_writable, .context = m};
        m->close = (solaris_deferred_t){.run = mock_closed, .context = m};
        m->hold_open = (e->mode == CANCEL_INBOUND_OPEN && i == 0u) || (e->mode == CANCEL_OUTBOUND_OPEN && i == 1u);
        m->hold_write = e->mode == CANCEL_WRITE || e->mode == STOP_WRITE;
        m->hold_shutdown = e->mode == CANCEL_SHUTDOWN || e->mode == STOP_SHUTDOWN;
    }
    solaris_dial_plan_t plan = {.outbound = &e->outbound, .context = e, .release = plan_released};
    solaris_tcp_relay_options_t options = {.owner = e->owner, .pending_byte_limit = 32u, .context = e, .on_close = relay_closed, .on_connect = relay_connected};
    CHECK(solaris_address_parse("1.2.3.4", 443u, &options.destination) == SOLARIS_OK);
    if (e->mode == REJECT_PREPARE) options.pending_byte_limit = 0u;
    if (e->mode == ALLOC_PREPARE) e->allocation_failure = 1;
    solaris_status_t rc = solaris_tcp_relay_prepare(&options, &plan, &e->mocks[0].callbacks, &e->mocks[0].context, &e->relay);
    if (e->mode == REJECT_PREPARE || e->mode == ALLOC_PREPARE) {
        CHECK(rc == (e->mode == REJECT_PREPARE ? SOLARIS_EINVAL : SOLARIS_ENOMEM) && e->relay == NULL && plan.outbound == &e->outbound);
        CHECK(solaris_dial_plan_release(&plan) == SOLARIS_OK); solaris_test_event_signal(&e->done);
    } else {
        CHECK(rc == SOLARIS_OK && plan.outbound == NULL && plan.release == NULL);
        e->mocks[0].accepted = 1;
        if (e->mocks[0].hold_open) solaris_test_event_signal(&e->pending); else queue(e, &e->mocks[0].open);
    }
    solaris_test_event_signal(&e->ready);
}
static void cancel_relay(void *context, solaris_status_t status)
{
    environment_t *e = context; CHECK(status == SOLARIS_OK);
    solaris_tcp_relay_close(e->relay); solaris_test_event_signal(&e->cancelled);
}
static void run(int mode)
{
    environment_t e; memset(&e, 0, sizeof(e)); e.mode = mode;
    CHECK(solaris_test_event_init(&e.ready, 0u) == 0 && solaris_test_event_init(&e.pending, 0u) == 0 &&
        solaris_test_event_init(&e.cancelled, 0u) == 0 && solaris_test_event_init(&e.done, 0u) == 0);
    solaris_runtime_services_init(&e.services); e.services.context = &e; e.services.allocate = allocate;
    CHECK(solaris_budget_create(4u * 1024u * 1024u, &e.services, &e.budget) == SOLARIS_OK);
    solaris_executor_options_t options = {.budget = e.budget, .services = &e.services, .queue_capacity = 8u, .resource_limit = 64u};
    CHECK(solaris_executor_create(&options, &e.owner) == SOLARIS_OK && solaris_executor_activate(e.owner, 1u) == SOLARIS_OK);
    e.release = (solaris_deferred_t){.run = release_pending, .context = &e};
    CHECK(solaris_executor_post(e.owner, start, &e) == SOLARIS_OK); solaris_test_event_wait(&e.ready);
    if (mode >= CANCEL_INBOUND_OPEN && mode <= STOP_SHUTDOWN) {
        solaris_test_event_wait(&e.pending);
        if (mode == STOP_WRITE || mode == STOP_SHUTDOWN) CHECK(solaris_executor_begin_quiesce(e.owner) == SOLARIS_OK);
        else CHECK(solaris_executor_post(e.owner, cancel_relay, &e) == SOLARIS_OK);
        solaris_test_event_wait(&e.cancelled);
        CHECK(e.relay_closes == 0u && e.plan_releases == 0u);
        CHECK(solaris_executor_defer(e.owner, &e.release) == SOLARIS_OK);
    }
    solaris_test_event_wait(&e.done);
    CHECK(solaris_executor_quiesce(e.owner) == SOLARIS_OK && solaris_executor_destroy(e.owner) == SOLARIS_OK);
    CHECK(e.plan_releases == 1u);
    if (mode == REJECT_PREPARE || mode == ALLOC_PREPARE) CHECK(e.relay_closes == 0u && e.factory_calls == 0u);
    else {
        solaris_status_t expected = mode == TRANSFER ? SOLARIS_OK : mode == CLOSE_ON_CONNECT ? SOLARIS_ECANCELLED : mode >= CANCEL_INBOUND_OPEN && mode <= STOP_SHUTDOWN ? SOLARIS_ECANCELLED :
            (mode == REJECT_OPEN || mode == CLOSE_ON_CONNECT_FAILURE) ? SOLARIS_EACCESS : mode == REJECT_SHUTDOWN ? SOLARIS_ENOTSUP : mode == OVERSIZED ? SOLARIS_EOVERFLOW : SOLARIS_EIO;
        CHECK(e.relay_closes == 1u && e.status == expected && e.connects == 1);
        solaris_status_t connect_status = mode == CANCEL_INBOUND_OPEN || mode == CANCEL_OUTBOUND_OPEN ? SOLARIS_ECANCELLED :
            mode == PAUSE_FAILURE ? SOLARIS_EIO : mode == REJECT_OPEN || mode == CLOSE_ON_CONNECT_FAILURE ? SOLARIS_EACCESS : SOLARIS_OK;
        CHECK(e.connect_status == connect_status);
        CHECK(e.factory_calls == (mode == CANCEL_INBOUND_OPEN || mode == PAUSE_FAILURE ? 0u : 1u));
        for (size_t i = 0u; i < 2u; ++i) {
            mock_t *m = &e.mocks[i];
            CHECK(m->opens == (unsigned int)m->accepted && m->closes == m->opens && m->close_calls == m->closes);
            CHECK(m->write_callbacks == m->writes && m->shutdown_callbacks == m->shutdowns && !m->busy && !m->shutting);
            if (mode == TRANSFER) {
                CHECK(m->output_size == sizeof(inputs[1u - i]) && memcmp(m->output, inputs[1u - i], m->output_size) == 0);
                CHECK(m->writes == (i == 0u ? 8u : 5u) && m->pauses >= 2u && m->shutdowns == 1u && m->pressure == m->writes + 1u);
            }
            if (mode == REJECT_WRITE) CHECK(m->write_callbacks == 0u);
            if (mode == REJECT_SHUTDOWN) CHECK(m->shutdown_callbacks == 0u);
        }
    }
    CHECK(solaris_budget_used(e.budget) == 0u); solaris_budget_release(e.budget);
    solaris_test_event_destroy(&e.ready); solaris_test_event_destroy(&e.pending); solaris_test_event_destroy(&e.cancelled); solaris_test_event_destroy(&e.done);
}
int main(void)
{
    for (int mode = TRANSFER; mode <= CLOSE_ON_CONNECT_FAILURE; ++mode) run(mode);
    puts("TCP relay: chunked bidirectional transfer, pause/backpressure, dual FIN, late open/write/shutdown after cancel/stop, rejection and plan barriers passed"); return 0;
}
