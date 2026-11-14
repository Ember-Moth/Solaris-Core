#include "transport/stream/filter.h"
#include <assert.h>
#include <string.h>

#define FILTER_READ_BYTES 16384u
#define FILTER_STEPS 32u
enum { FILTER_WRITE, FILTER_SHUTDOWN, FILTER_RAW };

typedef struct filter_request {
    struct filter_request *next;
    solaris_slice_t plain;
    solaris_buffer_t *encoded;
    solaris_io_done_fn done;
    void *context;
    int kind;
} filter_request_t;

typedef struct stream_filter {
    solaris_stream_t stream, *carrier;
    solaris_scope_t scope;
    solaris_deferred_t pump;
    solaris_deadline_t *deadline, *preface_delay;
    uint64_t open_deadline_ns;
    solaris_dialer_options_t options;
    solaris_stream_callbacks_t callbacks;
    void *context, *codec_state;
    const solaris_stream_codec_ops_t *codec;
    uint8_t *receive;
    size_t begin, end;
    filter_request_t *head, *tail;
    solaris_buffer_t *preface;
    solaris_io_snapshot_t stats;
    solaris_status_t close_status;
    int accepted, connected, opened, preface_done, preface_terminal, reading, writing, shutting;
    int close_requested, writable_requested, shutdown_requested, carrier_eof, carrier_gone;
    int raw_requested, carrier_switching;
} stream_filter_t;

static void schedule(stream_filter_t *filter);
static void close_status(stream_filter_t *filter, solaris_status_t status);

static void finish_request(stream_filter_t *filter, solaris_status_t status)
{
    filter_request_t *request = filter->head;
    filter->head = request->next;
    if (filter->head == NULL) filter->tail = NULL;
    if (request->kind == FILTER_WRITE) {
        filter->stats.pending_requests--; filter->stats.pending_bytes -= request->plain.length;
        if (status == SOLARIS_OK) filter->stats.bytes_written += request->plain.length;
    } else if (status == SOLARIS_OK && request->kind == FILTER_SHUTDOWN) filter->stats.write_shutdown = 1u;
    request->done(request->context, status);
    solaris_buffer_release(request->plain.buffer); solaris_buffer_release(request->encoded);
    solaris_memory_free(request);
    if (filter->writable_requested && !filter->scope.cancelled && !filter->shutdown_requested) {
        filter->writable_requested = 0;
        if (filter->callbacks.on_writable != NULL)
            filter->callbacks.on_writable(filter->context, &filter->stream);
    }
}

static void cancelled(void *context)
{
    stream_filter_t *filter = context;
    if (!filter->close_requested) { filter->close_requested = 1; filter->close_status = SOLARIS_ECANCELLED; }
    if (filter->deadline != NULL) solaris_deadline_cancel(filter->deadline);
    if (filter->preface_delay != NULL) solaris_deadline_cancel(filter->preface_delay);
    if (filter->carrier != NULL) (void)solaris_stream_close(filter->carrier);
    if (filter->accepted) schedule(filter);
}
static void destroyed(void *context)
{
    stream_filter_t *filter = context;
    assert(filter->head == NULL && filter->carrier == NULL);
    if (filter->accepted) filter->callbacks.on_close(filter->context, &filter->stream, filter->close_status);
    if (filter->codec_state != NULL) filter->codec->destroy(filter->codec_state);
    solaris_buffer_release(filter->preface);
    solaris_memory_free(filter->receive); solaris_memory_free(filter);
}
static void close_status(stream_filter_t *filter, solaris_status_t status)
{
    if (filter->close_requested) return;
    /* Stop can close executor admission while a codec is preparing the next
     * preface timer. The refused child operation belongs to the owner's stop. */
    if (status == SOLARIS_ECLOSED && !solaris_executor_accepting(filter->scope.owner))
        status = SOLARIS_ECANCELLED;
    filter->close_requested = 1; filter->close_status = status;
    solaris_scope_cancel(&filter->scope);
}
static void timed_out(void *context, solaris_status_t status)
{
    stream_filter_t *filter = context; filter->deadline = NULL;
    if (status == SOLARIS_OK && !filter->opened) close_status(filter, SOLARIS_ETIMEDOUT);
    solaris_scope_release(&filter->scope);
}
static int codec_ready(stream_filter_t *filter)
{ return filter->codec->ready == NULL || filter->codec->ready(filter->codec_state); }
static void maybe_open(stream_filter_t *filter)
{
    if (filter->scope.cancelled || filter->opened || !filter->preface_done || !codec_ready(filter)) return;
    if (solaris_executor_now_ns(filter->scope.owner) >= filter->open_deadline_ns) {
        close_status(filter, SOLARIS_ETIMEDOUT); return;
    }
    filter->opened = 1;
    if (filter->deadline != NULL) solaris_deadline_cancel(filter->deadline);
    filter->callbacks.on_open(filter->context, &filter->stream, SOLARIS_OK);
}
static void preface_delayed(void *context, solaris_status_t status)
{
    stream_filter_t *filter = context; filter->preface_delay = NULL;
    if (!filter->scope.cancelled && status == SOLARIS_OK) {
        if (filter->preface_terminal) filter->preface_done = 1;
        schedule(filter);
    }
    solaris_scope_release(&filter->scope);
}
static void advance_preface(stream_filter_t *filter)
{
    uint64_t delay_ms = 0u;
    solaris_status_t rc = SOLARIS_OK;
    if (filter->codec->next_preface != NULL)
        rc = filter->codec->next_preface(filter->codec_state, &filter->preface, &delay_ms);
    if (rc != SOLARIS_OK) { close_status(filter, rc); return; }
    filter->preface_terminal = filter->preface == NULL;
    if (delay_ms == 0u) { filter->preface_done = filter->preface_terminal; return; }
    solaris_scope_retain(&filter->scope);
    rc = solaris_deadline_start(filter->scope.owner, delay_ms, preface_delayed, filter, &filter->preface_delay);
    if (rc != SOLARIS_OK) { solaris_scope_release(&filter->scope); close_status(filter, rc); }
}
static void carrier_opened(void *context, solaris_stream_t *carrier, solaris_status_t status)
{
    (void)carrier;
    stream_filter_t *filter = context;
    if (filter->scope.cancelled) return;
    if (status == SOLARIS_OK) {
        filter->connected = 1;
        if (filter->codec->carrier_raw != NULL) {
            uint32_t caps; status = solaris_stream_raw_capabilities(carrier, &caps);
            if (status == SOLARIS_OK && (caps & filter->codec->carrier_raw->required) != filter->codec->carrier_raw->required)
                status = SOLARIS_ENOTSUP;
        }
        if (status == SOLARIS_OK) status = filter->codec->start(filter->codec_state, &filter->preface);
        if (status == SOLARIS_OK) schedule(filter);
    }
    if (status != SOLARIS_OK) close_status(filter, status);
}
static void carrier_data(void *context, solaris_stream_t *carrier, const solaris_buffer_t *buffer)
{
    stream_filter_t *filter = context;
    if (filter->scope.cancelled) return;
    size_t count = solaris_buffer_length(buffer), remaining = filter->end - filter->begin;
    if (count > filter->codec->receive_limit - remaining) { close_status(filter, SOLARIS_EMSGSIZE); return; }
    if (count > filter->codec->receive_limit - filter->end) {
        memmove(filter->receive, filter->receive + filter->begin, remaining);
        filter->begin = 0u; filter->end = remaining;
    }
    memcpy(filter->receive + filter->end, solaris_buffer_data(buffer), count); filter->end += count;
    (void)solaris_stream_set_reading(carrier, 0);
    schedule(filter);
}
static void carrier_eof(void *context, solaris_stream_t *carrier)
{ (void)carrier; stream_filter_t *filter = context; filter->carrier_eof = 1; if (!filter->scope.cancelled) schedule(filter); }
static void carrier_writable(void *context, solaris_stream_t *carrier)
{ (void)carrier; if (!((stream_filter_t *)context)->scope.cancelled) schedule(context); }
static void carrier_closed(void *context, solaris_stream_t *carrier, solaris_status_t status)
{
    (void)carrier;
    stream_filter_t *filter = context; filter->carrier = NULL; filter->carrier_gone = 1;
    if (!filter->scope.cancelled) {
        if (status == SOLARIS_OK && filter->carrier_eof) schedule(filter);
        else close_status(filter, status == SOLARIS_OK ? SOLARIS_EIO : status);
    }
    solaris_scope_release(&filter->scope);
}
static const solaris_stream_callbacks_t carrier_callbacks = {
    carrier_opened, carrier_data, carrier_eof, carrier_writable, carrier_closed
};
static uint32_t carrier_requests(stream_filter_t *filter)
{ return filter->codec->carrier_raw == NULL ? 0u : filter->codec->carrier_raw->requested(filter->codec_state); }
static void carrier_raw_written(void *context, solaris_status_t status)
{
    stream_filter_t *filter = context; filter->carrier_switching = 0;
    if (!filter->scope.cancelled) {
        if (status == SOLARIS_OK) {
            filter->codec->carrier_raw->applied(filter->codec_state, SOLARIS_STREAM_RAW_WRITE);
            filter->stats.raw_write = 1u;
            finish_request(filter, SOLARIS_OK); schedule(filter);
        } else close_status(filter, status);
    }
    solaris_scope_release(&filter->scope);
}
static void wire_written(void *context, solaris_status_t status)
{
    stream_filter_t *filter = context; filter->writing = 0;
    if (!filter->scope.cancelled) {
        if (status != SOLARIS_OK) close_status(filter, status);
        else {
            if (!filter->preface_done) {
                solaris_buffer_release(filter->preface); filter->preface = NULL;
            } else if ((carrier_requests(filter) & SOLARIS_STREAM_RAW_WRITE) != 0u) {
                solaris_status_t rc = solaris_stream_write_raw(filter->carrier, carrier_raw_written, filter);
                if (rc == SOLARIS_OK) { filter->carrier_switching = 1; solaris_scope_retain(&filter->scope); }
                else close_status(filter, rc);
            } else finish_request(filter, SOLARIS_OK);
            schedule(filter);
        }
    }
    solaris_scope_release(&filter->scope);
}
static void wire_shutdown(void *context, solaris_status_t status)
{
    stream_filter_t *filter = context; filter->shutting = 0;
    if (!filter->scope.cancelled) {
        finish_request(filter, status);
        if (status != SOLARIS_OK || filter->stats.read_eof) close_status(filter, status);
    }
    solaris_scope_release(&filter->scope);
}
static void write_buffer(stream_filter_t *filter, solaris_buffer_t *buffer)
{
    solaris_slice_t slice = {buffer, 0u, solaris_buffer_length(buffer)};
    solaris_status_t status = solaris_stream_write(filter->carrier, &slice, wire_written, filter);
    if (status == SOLARIS_OK) { filter->writing = 1; solaris_scope_retain(&filter->scope); }
    else if (status != SOLARIS_EAGAIN) close_status(filter, status);
}
static void pump(void *context)
{
    stream_filter_t *filter = context;
    if (!filter->scope.cancelled && !filter->opened &&
        solaris_executor_now_ns(filter->scope.owner) >= filter->open_deadline_ns)
        close_status(filter, SOLARIS_ETIMEDOUT);
    if (!filter->scope.cancelled && filter->connected && filter->carrier != NULL && !filter->writing && !filter->carrier_switching) {
        if (!filter->preface_done && filter->preface_delay == NULL) {
            if (filter->preface == NULL) advance_preface(filter);
            if (filter->preface != NULL && filter->preface_delay == NULL && !filter->scope.cancelled)
                write_buffer(filter, filter->preface);
        }
        maybe_open(filter);
        if (filter->opened && !filter->scope.cancelled && filter->head != NULL && !filter->shutting) {
            filter_request_t *request = filter->head;
            if (request->kind == FILTER_RAW) {
                solaris_status_t rc = filter->codec->raw->write(filter->codec_state);
                if (rc != SOLARIS_OK) close_status(filter, rc);
                else { filter->stats.raw_write = 1u; finish_request(filter, SOLARIS_OK); schedule(filter); }
            } else if (request->kind == FILTER_SHUTDOWN) {
                solaris_status_t rc = solaris_stream_shutdown_write(filter->carrier, wire_shutdown, filter);
                if (rc == SOLARIS_OK) { filter->shutting = 1; solaris_scope_retain(&filter->scope); }
                else close_status(filter, rc);
            } else {
                solaris_status_t rc = SOLARIS_OK;
                if (request->encoded == NULL) rc = filter->codec->encode(filter->codec_state, &request->plain, &request->encoded);
                if (rc != SOLARIS_OK) close_status(filter, rc);
                else if (request->encoded != NULL) write_buffer(filter, request->encoded);
                else { finish_request(filter, SOLARIS_OK); schedule(filter); }
            }
        }
    }
    int needs_input = filter->begin == filter->end;
    unsigned int steps = 0u;
    while (!filter->scope.cancelled && filter->connected &&
           ((filter->opened && filter->reading) || (!filter->opened && !codec_ready(filter))) &&
           !filter->stats.read_eof && filter->begin < filter->end && steps++ < FILTER_STEPS) {
        size_t consumed = 0u;
        solaris_buffer_t *plain = NULL;
        solaris_status_t rc = filter->codec->decode(filter->codec_state, filter->receive + filter->begin,
            filter->end - filter->begin, &consumed, &plain);
        assert(consumed <= filter->end - filter->begin);
        filter->begin += consumed;
        if (rc == SOLARIS_EAGAIN) {
            assert(plain == NULL);
            needs_input = 1; break;
        }
        if (rc != SOLARIS_OK) { solaris_buffer_release(plain); close_status(filter, rc); break; }
        /* Handshake decode steps cannot deliver application data before the
         * open callback, including when the final preface write is pending. */
        if (plain != NULL && !filter->opened) {
            solaris_buffer_release(plain); close_status(filter, SOLARIS_EIO); break;
        }
        if ((carrier_requests(filter) & SOLARIS_STREAM_RAW_READ) != 0u) {
            solaris_status_t raw = solaris_stream_read_raw(filter->carrier);
            if (raw != SOLARIS_OK) { solaris_buffer_release(plain); close_status(filter, raw); break; }
            filter->codec->carrier_raw->applied(filter->codec_state, SOLARIS_STREAM_RAW_READ);
            filter->stats.raw_read = 1u;
        }
        maybe_open(filter);
        if (plain != NULL) {
            solaris_buffer_publish(plain);
            if (!filter->scope.cancelled) {
                filter->stats.bytes_read += solaris_buffer_length(plain);
                filter->callbacks.on_data(filter->context, &filter->stream, plain);
            }
            solaris_buffer_release(plain);
        }
        if (consumed == 0u && plain == NULL) { close_status(filter, SOLARIS_EIO); break; }
        needs_input = filter->begin == filter->end;
    }
    if (!filter->scope.cancelled && filter->carrier_eof && !filter->opened && !codec_ready(filter) && needs_input)
        close_status(filter, SOLARIS_EIO);
    if (!filter->scope.cancelled && filter->carrier_eof && filter->reading && filter->opened && !filter->stats.read_eof && needs_input) {
        solaris_status_t rc = filter->begin != filter->end ? SOLARIS_EIO : filter->codec->finish(filter->codec_state);
        if (rc != SOLARIS_OK) close_status(filter, rc);
        else {
            filter->stats.read_eof = 1u;
            if (filter->callbacks.on_eof != NULL) filter->callbacks.on_eof(filter->context, &filter->stream);
            if ((filter->stats.write_shutdown || filter->carrier_gone) && !filter->scope.cancelled)
                close_status(filter, SOLARIS_OK);
        }
    }
    if (!filter->scope.cancelled && filter->carrier_gone && filter->stats.read_eof)
        close_status(filter, SOLARIS_OK);
    if (filter->scope.cancelled) {
        solaris_status_t status = filter->close_status == SOLARIS_OK ? SOLARIS_ECANCELLED : filter->close_status;
        if (!filter->opened) { filter->opened = 1; filter->callbacks.on_open(filter->context, &filter->stream, status); }
        while (filter->head != NULL) finish_request(filter, status);
    } else {
        if (filter->begin == filter->end) filter->begin = filter->end = 0u;
        if (filter->carrier != NULL && !filter->carrier_eof) {
            int want = ((filter->opened && filter->reading) || (!filter->opened && !codec_ready(filter))) && needs_input;
            if (want && filter->codec->receive_limit - (filter->end - filter->begin) < FILTER_READ_BYTES)
                close_status(filter, SOLARIS_EMSGSIZE);
            else {
                solaris_status_t rc = solaris_stream_set_reading(filter->carrier, want);
                if (rc != SOLARIS_OK) close_status(filter, rc);
            }
        }
        if (steps > FILTER_STEPS && !filter->scope.cancelled) schedule(filter);
    }
    solaris_scope_release(&filter->scope);
}
static void schedule(stream_filter_t *filter)
{
    if (filter->pump.queued) return;
    solaris_scope_retain(&filter->scope);
    solaris_status_t rc = solaris_executor_defer(filter->scope.owner, &filter->pump);
    assert(rc == SOLARIS_OK); (void)rc;
}
static solaris_status_t enqueue(stream_filter_t *filter, const solaris_slice_t *slice,
    int kind, solaris_io_done_fn done, void *context)
{
    if (filter->scope.cancelled || filter->carrier_gone || filter->shutdown_requested || !solaris_executor_accepting(filter->scope.owner))
        return SOLARIS_ECLOSED;
    if (!filter->opened) return SOLARIS_EBUSY;
    if (kind == FILTER_RAW && filter->raw_requested) return SOLARIS_EBUSY;
    if (slice != NULL) {
        if (slice->length > filter->options.pending_byte_limit) return SOLARIS_EMSGSIZE;
        if (filter->stats.pending_requests >= filter->options.pending_request_limit ||
            filter->stats.pending_bytes > filter->options.pending_byte_limit - slice->length) {
            filter->writable_requested = 1; return SOLARIS_EAGAIN;
        }
    }
    filter_request_t *request = solaris_memory_allocate(solaris_executor_budget(filter->scope.owner), sizeof(*request));
    if (request == NULL) return SOLARIS_ENOMEM;
    memset(request, 0, sizeof(*request)); request->done = done; request->context = context; request->kind = kind;
    if (slice != NULL) {
        request->plain = *slice; solaris_buffer_retain(slice->buffer);
        filter->stats.pending_requests++; filter->stats.pending_bytes += slice->length;
    } else if (kind == FILTER_SHUTDOWN) filter->shutdown_requested = 1;
    else filter->raw_requested = 1;
    if (filter->tail != NULL) filter->tail->next = request;
    else filter->head = request;
    filter->tail = request; schedule(filter); return SOLARIS_OK;
}
static solaris_status_t write_stream(void *state, const solaris_slice_t *slice, solaris_io_done_fn done, void *context)
{ return enqueue(state, slice, FILTER_WRITE, done, context); }
static solaris_status_t shutdown_stream(void *state, solaris_io_done_fn done, void *context)
{ return enqueue(state, NULL, FILTER_SHUTDOWN, done, context); }
static uint32_t raw_capabilities(void *state)
{
    stream_filter_t *filter = state;
    if (filter->scope.cancelled || filter->codec->raw == NULL) return 0u;
    return (filter->codec->raw->read != NULL ? SOLARIS_STREAM_RAW_READ : 0u) |
           (filter->codec->raw->write != NULL ? SOLARIS_STREAM_RAW_WRITE : 0u);
}
static solaris_status_t read_raw(void *state)
{
    stream_filter_t *filter = state;
    if (filter->scope.cancelled) return SOLARIS_ECLOSED;
    if (filter->codec->raw == NULL || filter->codec->raw->read == NULL) return SOLARIS_ENOTSUP;
    if (!filter->opened) return SOLARIS_EBUSY;
    if (filter->stats.raw_read) return SOLARIS_OK;
    solaris_status_t rc = filter->codec->raw->read(filter->codec_state);
    if (rc == SOLARIS_OK) { filter->stats.raw_read = 1u; schedule(filter); }
    return rc;
}
static solaris_status_t write_raw(void *state, solaris_io_done_fn done, void *context)
{
    stream_filter_t *filter = state;
    if (filter->codec->raw == NULL || filter->codec->raw->write == NULL) return SOLARIS_ENOTSUP;
    return enqueue(filter, NULL, FILTER_RAW, done, context);
}
static solaris_status_t reading(void *state, int enabled)
{
    stream_filter_t *filter = state;
    if (filter->scope.cancelled || (enabled && filter->stats.read_eof)) return SOLARIS_ECLOSED;
    filter->reading = enabled;
    if (!enabled && filter->carrier != NULL) (void)solaris_stream_set_reading(filter->carrier, 0);
    schedule(filter); return SOLARIS_OK;
}
static solaris_status_t close_stream(void *state) { close_status(state, SOLARIS_OK); return SOLARIS_OK; }
static solaris_status_t snapshot(void *state, solaris_io_snapshot_t *out)
{ *out = ((stream_filter_t *)state)->stats; return SOLARIS_OK; }
static const solaris_stream_raw_ops_t raw_operations = {raw_capabilities, read_raw, write_raw};
static const solaris_stream_ops_t operations = {write_stream, shutdown_stream, reading, close_stream, snapshot, &raw_operations};

solaris_status_t solaris_filter_open(solaris_executor_t *owner,
    const solaris_stream_factory_t *carrier, const solaris_dialer_options_t *options,
    const solaris_address_t *peer, const solaris_stream_codec_ops_t *codec,
    const void *parameters, const solaris_stream_callbacks_t *callbacks,
    void *context, solaris_stream_t **out)
{
    if (out == NULL) return SOLARIS_EINVAL;
    *out = NULL;
    if (owner == NULL || peer == NULL || codec == NULL || codec->receive_limit < 2u * FILTER_READ_BYTES ||
        codec->receive_limit > 1024u * 1024u || codec->create == NULL || codec->start == NULL || codec->encode == NULL ||
        codec->decode == NULL || codec->finish == NULL || codec->destroy == NULL || callbacks == NULL ||
        callbacks->on_open == NULL || callbacks->on_data == NULL || callbacks->on_close == NULL) return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(owner)) return SOLARIS_ETHREAD;
    stream_filter_t *filter = solaris_memory_allocate(solaris_executor_budget(owner), sizeof(*filter));
    if (filter == NULL) return SOLARIS_ENOMEM;
    memset(filter, 0, sizeof(*filter)); filter->codec = codec;
    filter->callbacks = *callbacks; filter->context = context; filter->reading = 1;
    filter->stream = (solaris_stream_t){&operations, filter, owner};
    filter->pump.run = pump; filter->pump.context = filter;
    solaris_status_t rc = solaris_dialer_options_normalize(options, &filter->options);
    if (rc != SOLARIS_OK) { destroyed(filter); return rc; }
    filter->stats.max_message_bytes = filter->options.pending_byte_limit;
    filter->receive = solaris_memory_allocate(solaris_executor_budget(owner), codec->receive_limit);
    if (filter->receive == NULL) { destroyed(filter); return SOLARIS_ENOMEM; }
    rc = codec->create(parameters, solaris_executor_budget(owner), &filter->codec_state);
    if (rc != SOLARIS_OK) { destroyed(filter); return rc; }
    rc = solaris_scope_init(&filter->scope, owner, cancelled, destroyed, filter);
    if (rc != SOLARIS_OK) { destroyed(filter); return rc; }
    uint64_t now = solaris_executor_now_ns(owner), duration = filter->options.open_timeout_ms * UINT64_C(1000000);
    if (duration > UINT64_MAX - now) { close_status(filter, SOLARIS_EOVERFLOW); return SOLARIS_EOVERFLOW; }
    filter->open_deadline_ns = now + duration;
    solaris_scope_retain(&filter->scope);
    rc = solaris_deadline_start(owner, filter->options.open_timeout_ms, timed_out, filter, &filter->deadline);
    if (rc != SOLARIS_OK) { solaris_scope_release(&filter->scope); close_status(filter, rc); return rc; }
    solaris_dialer_options_t wire_options = filter->options;
    /* Record framing may expand data. Encoders remain budgeted; one encoded
     * write is in flight, and the underlying queue is independently bounded. */
    if (wire_options.pending_byte_limit > (UINT32_MAX - 65536u) / 2u) {
        close_status(filter, SOLARIS_EINVAL); return SOLARIS_EINVAL;
    }
    wire_options.pending_byte_limit = wire_options.pending_byte_limit * 2u + 65536u;
    wire_options.pending_request_limit = 1u; wire_options.read_chunk_size = FILTER_READ_BYTES;
    rc = solaris_carrier_open(carrier, owner, &wire_options, peer, &carrier_callbacks, filter, &filter->carrier);
    if (rc != SOLARIS_OK) { close_status(filter, rc); return rc; }
    solaris_scope_retain(&filter->scope);
    filter->accepted = 1; *out = &filter->stream; return SOLARIS_OK;
}
