#include "adapters/outbound/socks5/internal.h"
#include <assert.h>
#include <string.h>

#define SOCKS5_RECEIVE 32768u
typedef struct socks5_write {
    struct socks5_write *next;
    solaris_slice_t slice;
    solaris_io_done_fn done;
    void *context;
    int shutdown;
} socks5_write_t;
typedef struct socks5_stream {
    solaris_stream_t stream, *carrier;
    solaris_scope_t scope;
    solaris_deferred_t pump;
    solaris_deadline_t *deadline;
    solaris_socks5_handshake_t handshake;
    solaris_socks5_open_info_t *info;
    solaris_buffer_t *handshake_wire;
    solaris_dialer_options_t options;
    solaris_stream_callbacks_t callbacks;
    void *context;
    socks5_write_t *head, *tail;
    solaris_io_snapshot_t stats;
    uint64_t expires;
    uint8_t receive[SOCKS5_RECEIVE];
    size_t begin, end;
    solaris_status_t status;
    int accepted, connected, opened, closing, reading, writing, handshake_writing;
    int shutting, shutdown_requested, writable, carrier_eof, carrier_gone;
} socks5_stream_t;
static void schedule(socks5_stream_t *stream);
static void close_status(socks5_stream_t *stream, solaris_status_t status);
static void finish_request(socks5_stream_t *stream, solaris_status_t status)
{
    socks5_write_t *request = stream->head; stream->head = request->next; if (stream->head == NULL) stream->tail = NULL;
    if (!request->shutdown) {
        stream->stats.pending_requests--; stream->stats.pending_bytes -= request->slice.length;
        if (status == SOLARIS_OK) stream->stats.bytes_written += request->slice.length;
    } else if (status == SOLARIS_OK) stream->stats.write_shutdown = 1u;
    request->done(request->context, status); solaris_buffer_release(request->slice.buffer); solaris_memory_free(request);
    if (stream->writable && !stream->scope.cancelled && !stream->shutdown_requested) {
        stream->writable = 0; if (stream->callbacks.on_writable != NULL) stream->callbacks.on_writable(stream->context, &stream->stream);
    }
}
static void cancelled(void *context)
{
    socks5_stream_t *stream = context;
    if (!stream->closing) { stream->closing = 1; stream->status = SOLARIS_ECANCELLED; }
    if (stream->deadline != NULL) solaris_deadline_cancel(stream->deadline);
    if (stream->carrier != NULL) (void)solaris_stream_close(stream->carrier);
    if (stream->accepted) schedule(stream);
}
static void destroyed(void *context)
{
    socks5_stream_t *stream = context; assert(stream->carrier == NULL && stream->head == NULL);
    if (stream->accepted) stream->callbacks.on_close(stream->context, &stream->stream, stream->status);
    solaris_buffer_release(stream->handshake_wire); solaris_socks5_clear(stream, sizeof(*stream)); solaris_memory_free(stream);
}
static void close_status(socks5_stream_t *stream, solaris_status_t status)
{ if (!stream->closing) { stream->closing = 1; stream->status = status; solaris_scope_cancel(&stream->scope); } }
static void timed_out(void *context, solaris_status_t status)
{
    socks5_stream_t *stream = context; stream->deadline = NULL;
    if (status == SOLARIS_OK && !stream->opened) close_status(stream, SOLARIS_ETIMEDOUT);
    solaris_scope_release(&stream->scope);
}
static void carrier_opened(void *context, solaris_stream_t *carrier, solaris_status_t status)
{
    (void)carrier; socks5_stream_t *stream = context;
    if (stream->scope.cancelled) return;
    if (status == SOLARIS_OK) {
        stream->connected = 1; if (stream->info != NULL) stream->info->carrier_connected = 1; schedule(stream);
    } else close_status(stream, status);
}
static void carrier_data(void *context, solaris_stream_t *carrier, const solaris_buffer_t *buffer)
{
    socks5_stream_t *stream = context; if (stream->scope.cancelled) return;
    size_t count = solaris_buffer_length(buffer);
    if (stream->opened && stream->reading && stream->begin == stream->end) {
        stream->stats.bytes_read += count; stream->callbacks.on_data(stream->context, &stream->stream, buffer); return;
    }
    size_t remaining = stream->end - stream->begin;
    if (count > sizeof(stream->receive) - remaining) { close_status(stream, SOLARIS_EMSGSIZE); return; }
    if (count > sizeof(stream->receive) - stream->end) {
        memmove(stream->receive, stream->receive + stream->begin, remaining); stream->begin = 0u; stream->end = remaining;
    }
    memcpy(stream->receive + stream->end, solaris_buffer_data(buffer), count); stream->end += count;
    (void)solaris_stream_set_reading(carrier, 0); schedule(stream);
}
static void carrier_eof(void *context, solaris_stream_t *carrier)
{ (void)carrier; socks5_stream_t *stream = context; stream->carrier_eof = 1; if (!stream->scope.cancelled) schedule(stream); }
static void carrier_writable(void *context, solaris_stream_t *carrier)
{ (void)carrier; socks5_stream_t *stream = context; if (!stream->scope.cancelled) schedule(stream); }
static void carrier_closed(void *context, solaris_stream_t *carrier, solaris_status_t status)
{
    (void)carrier; socks5_stream_t *stream = context; stream->carrier = NULL; stream->carrier_gone = 1;
    if (!stream->scope.cancelled) {
        /* A terminal socket error can arrive in the same I/O turn as a
         * complete authentication denial, before the handshake pump runs. */
        if (status == SOLARIS_EIO && !stream->opened && stream->begin < stream->end) {
            solaris_socks5_handshake_t pending = stream->handshake;
            size_t consumed = 0;
            solaris_status_t reply = solaris_socks5_handshake_read(&pending,
                stream->receive + stream->begin, stream->end - stream->begin, &consumed);
            if (reply != SOLARIS_OK && reply != SOLARIS_EAGAIN && reply != SOLARIS_EBUSY)
                status = reply;
        }
        if (status == SOLARIS_OK && stream->carrier_eof) schedule(stream);
        else close_status(stream, status == SOLARIS_OK ? SOLARIS_EIO : status);
    }
    solaris_scope_release(&stream->scope);
}
static const solaris_stream_callbacks_t carrier_callbacks = {carrier_opened, carrier_data, carrier_eof, carrier_writable, carrier_closed};
static void written(void *context, solaris_status_t status)
{
    socks5_stream_t *stream = context; stream->writing = 0;
    if (stream->handshake_writing) { solaris_buffer_release(stream->handshake_wire); stream->handshake_wire = NULL; }
    if (!stream->scope.cancelled) {
        if (status != SOLARIS_OK) close_status(stream, status);
        else { if (!stream->handshake_writing) finish_request(stream, SOLARIS_OK); schedule(stream); }
    }
    stream->handshake_writing = 0; solaris_scope_release(&stream->scope);
}
static void shutdown_done(void *context, solaris_status_t status)
{
    socks5_stream_t *stream = context; stream->shutting = 0;
    if (!stream->scope.cancelled) {
        finish_request(stream, status);
        if (status != SOLARIS_OK || stream->stats.read_eof) close_status(stream, status);
    }
    solaris_scope_release(&stream->scope);
}
static void write_slice(socks5_stream_t *stream, const solaris_slice_t *slice, int handshake)
{
    solaris_status_t rc = solaris_stream_write(stream->carrier, slice, written, stream);
    if (rc == SOLARIS_OK) { stream->writing = 1; stream->handshake_writing = handshake; solaris_scope_retain(&stream->scope); }
    else if (rc != SOLARIS_EAGAIN) close_status(stream, rc);
}
static void pump(void *context)
{
    socks5_stream_t *stream = context;
    if (!stream->scope.cancelled && !stream->opened && solaris_executor_now_ns(stream->scope.owner) >= stream->expires)
        close_status(stream, SOLARIS_ETIMEDOUT);
    int need_input = stream->begin == stream->end;
    for (unsigned int step = 0u; !stream->scope.cancelled && stream->connected && !stream->opened && !stream->writing && step < 8u; ++step) {
        if (stream->handshake_wire == NULL && solaris_socks5_handshake_wants_write(&stream->handshake)) {
            solaris_status_t rc = solaris_socks5_handshake_write(&stream->handshake, solaris_executor_budget(stream->scope.owner), &stream->handshake_wire);
            if (rc != SOLARIS_OK) { close_status(stream, rc); break; }
        }
        if (stream->handshake_wire != NULL) {
            solaris_slice_t slice = {stream->handshake_wire, 0u, solaris_buffer_length(stream->handshake_wire)};
            if (stream->carrier == NULL) close_status(stream, SOLARIS_EIO); else write_slice(stream, &slice, 1);
            break;
        }
        if (stream->handshake.stage == SOLARIS_SOCKS5_READY) {
            if (stream->carrier == NULL) { close_status(stream, SOLARIS_EIO); break; }
            if (solaris_executor_now_ns(stream->scope.owner) >= stream->expires) { close_status(stream, SOLARIS_ETIMEDOUT); break; }
            stream->opened = 1; if (stream->deadline != NULL) solaris_deadline_cancel(stream->deadline);
            if (stream->info != NULL) stream->info->bound = stream->handshake.bound;
            stream->callbacks.on_open(stream->context, &stream->stream, SOLARIS_OK); break;
        }
        if (stream->begin == stream->end) { need_input = 1; break; }
        size_t used = 0u;
        solaris_status_t rc = solaris_socks5_handshake_read(&stream->handshake, stream->receive + stream->begin, stream->end - stream->begin, &used);
        assert(used <= stream->end - stream->begin); stream->begin += used;
        if (rc == SOLARIS_EAGAIN) { need_input = 1; break; }
        if (rc != SOLARIS_OK) { close_status(stream, rc); break; }
        if (solaris_socks5_handshake_wants_write(&stream->handshake) && stream->begin != stream->end) {
            close_status(stream, SOLARIS_EIO); break; /* reply to an unsent next request */
        }
        need_input = stream->begin == stream->end;
    }
    if (!stream->scope.cancelled && stream->carrier_eof && !stream->opened && !stream->writing &&
        stream->handshake_wire == NULL && stream->handshake.stage != SOLARIS_SOCKS5_READY && need_input)
        close_status(stream, SOLARIS_EIO);
    if (!stream->scope.cancelled && stream->opened && stream->carrier != NULL && !stream->writing && !stream->shutting && stream->head != NULL) {
        if (stream->head->shutdown) {
            solaris_status_t rc = solaris_stream_shutdown_write(stream->carrier, shutdown_done, stream);
            if (rc == SOLARIS_OK) { stream->shutting = 1; solaris_scope_retain(&stream->scope); } else close_status(stream, rc);
        } else write_slice(stream, &stream->head->slice, 0);
    }
    if (!stream->scope.cancelled && stream->opened && stream->reading && stream->begin < stream->end) {
        solaris_buffer_t *buffer;
        solaris_status_t rc = solaris_buffer_copy(solaris_executor_budget(stream->scope.owner), stream->receive + stream->begin, stream->end - stream->begin, &buffer);
        if (rc != SOLARIS_OK) close_status(stream, rc);
        else {
            stream->begin = stream->end; stream->stats.bytes_read += solaris_buffer_length(buffer);
            stream->callbacks.on_data(stream->context, &stream->stream, buffer); solaris_buffer_release(buffer);
        }
    }
    if (!stream->scope.cancelled && stream->opened && stream->reading && stream->begin == stream->end && stream->carrier_eof && !stream->stats.read_eof) {
        stream->stats.read_eof = 1u;
        if (stream->callbacks.on_eof != NULL) stream->callbacks.on_eof(stream->context, &stream->stream);
        if (!stream->scope.cancelled && (stream->stats.write_shutdown || stream->carrier_gone)) close_status(stream, SOLARIS_OK);
    }
    if (stream->scope.cancelled) {
        solaris_status_t status = stream->status == SOLARIS_OK ? SOLARIS_ECANCELLED : stream->status;
        if (!stream->opened) { stream->opened = 1; stream->callbacks.on_open(stream->context, &stream->stream, status); }
        while (stream->head != NULL) finish_request(stream, status);
    } else {
        if (stream->begin == stream->end) stream->begin = stream->end = 0u;
        if (stream->carrier != NULL && !stream->carrier_eof) {
            int wanted = stream->opened ? stream->reading && stream->begin == stream->end : need_input;
            solaris_status_t rc = solaris_stream_set_reading(stream->carrier, wanted); if (rc != SOLARIS_OK) close_status(stream, rc);
        }
        if (stream->writable && stream->opened && !stream->writing && stream->head == NULL && !stream->shutdown_requested && !stream->scope.cancelled) {
            stream->writable = 0; if (stream->callbacks.on_writable != NULL) stream->callbacks.on_writable(stream->context, &stream->stream);
        }
    }
    solaris_scope_release(&stream->scope);
}
static void schedule(socks5_stream_t *stream)
{
    if (stream->pump.queued) return;
    solaris_scope_retain(&stream->scope); solaris_status_t rc = solaris_executor_defer(stream->scope.owner, &stream->pump); assert(rc == SOLARIS_OK); (void)rc;
}
static solaris_status_t enqueue(socks5_stream_t *stream, const solaris_slice_t *slice, solaris_io_done_fn done, void *context)
{
    if (stream->scope.cancelled || stream->carrier_gone || stream->shutdown_requested || !solaris_executor_accepting(stream->scope.owner)) return SOLARIS_ECLOSED;
    if (!stream->opened) return SOLARIS_EBUSY;
    if (slice != NULL) {
        if (slice->length > stream->options.pending_byte_limit) return SOLARIS_EMSGSIZE;
        if (stream->stats.pending_requests >= stream->options.pending_request_limit || stream->stats.pending_bytes > stream->options.pending_byte_limit - slice->length) {
            stream->writable = 1; return SOLARIS_EAGAIN;
        }
    }
    socks5_write_t *request = solaris_memory_allocate(solaris_executor_budget(stream->scope.owner), sizeof(*request));
    if (request == NULL) return SOLARIS_ENOMEM;
    memset(request, 0, sizeof(*request)); request->done = done; request->context = context;
    if (slice != NULL) {
        request->slice = *slice; solaris_buffer_retain(slice->buffer); stream->stats.pending_requests++; stream->stats.pending_bytes += slice->length;
    } else { request->shutdown = 1; stream->shutdown_requested = 1; }
    if (stream->tail != NULL) stream->tail->next = request; else stream->head = request;
    stream->tail = request; schedule(stream); return SOLARIS_OK;
}
static solaris_status_t write_stream(void *state, const solaris_slice_t *slice, solaris_io_done_fn done, void *context)
{ return enqueue(state, slice, done, context); }
static solaris_status_t shutdown_stream(void *state, solaris_io_done_fn done, void *context) { return enqueue(state, NULL, done, context); }
static solaris_status_t reading(void *state, int enabled)
{
    socks5_stream_t *stream = state;
    if (stream->scope.cancelled || (enabled && stream->stats.read_eof)) return SOLARIS_ECLOSED;
    stream->reading = enabled;
    if (!enabled && stream->opened && stream->carrier != NULL) (void)solaris_stream_set_reading(stream->carrier, 0);
    schedule(stream); return SOLARIS_OK;
}
static solaris_status_t close_stream(void *state) { close_status(state, SOLARIS_OK); return SOLARIS_OK; }
static solaris_status_t snapshot(void *state, solaris_io_snapshot_t *out) { *out = ((socks5_stream_t *)state)->stats; return SOLARIS_OK; }
static const solaris_stream_ops_t operations = {write_stream, shutdown_stream, reading, close_stream, snapshot, NULL};
solaris_status_t solaris_socks5_stream_open(solaris_executor_t *owner,
    const solaris_stream_factory_t *carrier, const solaris_dialer_options_t *options,
    const solaris_address_t *server, const solaris_socks5_credentials_t *credentials,
    uint8_t command, const solaris_address_t *target, solaris_socks5_open_info_t *info,
    const solaris_stream_callbacks_t *callbacks, void *context, solaris_stream_t **out)
{
    if (out == NULL) return SOLARIS_EINVAL;
    *out = NULL;
    if (owner == NULL || server == NULL || server->port == 0u || credentials == NULL || target == NULL || callbacks == NULL ||
        callbacks->on_open == NULL || callbacks->on_data == NULL || callbacks->on_close == NULL) return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(owner)) return SOLARIS_ETHREAD;
    socks5_stream_t *stream = solaris_memory_allocate(solaris_executor_budget(owner), sizeof(*stream)); if (stream == NULL) return SOLARIS_ENOMEM;
    memset(stream, 0, sizeof(*stream)); stream->callbacks = *callbacks; stream->context = context; stream->info = info; stream->reading = 1;
    stream->stream = (solaris_stream_t){&operations, stream, owner}; stream->pump = (solaris_deferred_t){.run = pump, .context = stream};
    if (info != NULL) memset(info, 0, sizeof(*info));
    solaris_status_t rc = solaris_dialer_options_normalize(options, &stream->options);
    if (rc == SOLARIS_OK) rc = solaris_socks5_handshake_init(&stream->handshake, credentials, command, target);
    if (rc != SOLARIS_OK) { destroyed(stream); return rc; }
    stream->stats.max_message_bytes = stream->options.pending_byte_limit;
    rc = solaris_scope_init(&stream->scope, owner, cancelled, destroyed, stream); if (rc != SOLARIS_OK) { destroyed(stream); return rc; }
    uint64_t now = solaris_executor_now_ns(owner), duration = stream->options.open_timeout_ms * UINT64_C(1000000);
    if (now > UINT64_MAX - duration) { close_status(stream, SOLARIS_EOVERFLOW); return SOLARIS_EOVERFLOW; }
    stream->expires = now + duration;
    rc = solaris_deadline_start(owner, stream->options.open_timeout_ms, timed_out, stream, &stream->deadline);
    if (rc != SOLARIS_OK) { close_status(stream, rc); return rc; }
    solaris_scope_retain(&stream->scope);
    solaris_dialer_options_t wire = stream->options;
    if (wire.pending_byte_limit < 1024u) wire.pending_byte_limit = 1024u;
    wire.read_chunk_size = 16384u;
    rc = solaris_carrier_open(carrier, owner, &wire, server, &carrier_callbacks, stream, &stream->carrier);
    if (rc != SOLARIS_OK) { close_status(stream, rc); return rc; }
    solaris_scope_retain(&stream->scope); stream->accepted = 1; *out = &stream->stream; return SOLARIS_OK;
}
