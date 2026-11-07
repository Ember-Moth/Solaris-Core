#include "observe/connections/internal.h"
#include <assert.h>
#include <string.h>

enum { REQUEST_WRITE, REQUEST_SHUTDOWN, REQUEST_RAW };
typedef struct tracked_stream {
    solaris_tracked_channel_t channel;
    solaris_stream_t stream, *lower;
    solaris_stream_callbacks_t callbacks;
    void *context;
    solaris_io_snapshot_t stats;
    solaris_status_t status;
    int closing, opened;
} tracked_stream_t;
typedef struct stream_request {
    tracked_stream_t *stream;
    solaris_io_done_fn done;
    void *context;
    size_t length;
    int kind;
} stream_request_t;
static void close_status(solaris_tracked_channel_t *channel, solaris_status_t status)
{
    tracked_stream_t *stream = (tracked_stream_t *)channel;
    if (stream->closing) return;
    stream->closing = 1; stream->status = status; solaris_scope_cancel(&channel->scope);
}
static void cancelled(void *context)
{
    tracked_stream_t *stream = context;
    if (!stream->closing) { stream->closing = 1; stream->status = SOLARIS_ECANCELLED; }
    if (stream->lower != NULL) (void)solaris_stream_close(stream->lower);
}
static void destroyed(void *context)
{
    tracked_stream_t *stream = context; assert(stream->lower == NULL && stream->stats.pending_requests == 0u);
    if (stream->channel.accepted) {
        if (!stream->opened) stream->callbacks.on_open(stream->context, &stream->stream, SOLARIS_ECANCELLED);
        stream->callbacks.on_close(stream->context, &stream->stream, stream->status);
    }
    solaris_track_remove(&stream->channel, stream->status); solaris_memory_free(stream);
}
static void refresh(tracked_stream_t *stream)
{
    if (stream->lower == NULL) return;
    solaris_io_snapshot_t stats;
    if (solaris_stream_get_snapshot(stream->lower, &stats) == SOLARIS_OK) {
        stream->stats.max_message_bytes = stats.max_message_bytes; stream->stats.last_system_error = stats.last_system_error;
        stream->stats.raw_read = stats.raw_read; stream->stats.raw_write = stats.raw_write;
    }
}
static void opened(void *context, solaris_stream_t *lower, solaris_status_t status)
{
    (void)lower; tracked_stream_t *stream = context; assert(!stream->opened); stream->opened = 1;
    if (stream->channel.scope.cancelled) status = stream->status == SOLARIS_OK ? SOLARIS_ECANCELLED : stream->status;
    refresh(stream); solaris_track_open(stream->channel.plan, status);
    if (status != SOLARIS_OK) close_status(&stream->channel, status);
    stream->callbacks.on_open(stream->context, &stream->stream, status);
}
static void data(void *context, solaris_stream_t *lower, const solaris_buffer_t *buffer)
{
    (void)lower; tracked_stream_t *stream = context; if (stream->channel.scope.cancelled) return;
    size_t length = solaris_buffer_length(buffer); stream->stats.bytes_read += length;
    solaris_track_read(stream->channel.plan, length, NULL); stream->callbacks.on_data(stream->context, &stream->stream, buffer);
}
static void stream_eof(void *context, solaris_stream_t *lower)
{
    (void)lower; tracked_stream_t *stream = context;
    if (stream->channel.scope.cancelled || stream->stats.read_eof) return;
    stream->stats.read_eof = 1u;
    if (stream->callbacks.on_eof != NULL) stream->callbacks.on_eof(stream->context, &stream->stream);
}
static void writable(void *context, solaris_stream_t *lower)
{
    (void)lower; tracked_stream_t *stream = context;
    if (!stream->channel.scope.cancelled && stream->callbacks.on_writable != NULL) stream->callbacks.on_writable(stream->context, &stream->stream);
}
static void closed(void *context, solaris_stream_t *lower, solaris_status_t status)
{
    (void)lower; tracked_stream_t *stream = context; refresh(stream); stream->lower = NULL;
    close_status(&stream->channel, status); solaris_scope_release(&stream->channel.scope);
}
static const solaris_stream_callbacks_t lower_callbacks = {opened, data, stream_eof, writable, closed};
static void completed(void *context, solaris_status_t status)
{
    stream_request_t *request = context; tracked_stream_t *stream = request->stream;
    if (request->kind == REQUEST_WRITE) {
        stream->stats.pending_requests--; stream->stats.pending_bytes -= request->length;
        if (status == SOLARIS_OK) stream->stats.bytes_written += request->length;
        solaris_track_written(stream->channel.plan, request->length, 0, status);
    } else if (status == SOLARIS_OK) {
        if (request->kind == REQUEST_SHUTDOWN) stream->stats.write_shutdown = 1u;
        else stream->stats.raw_write = 1u;
    }
    request->done(request->context, status); solaris_memory_free(request); solaris_scope_release(&stream->channel.scope);
}
static solaris_status_t submit(tracked_stream_t *stream, const solaris_slice_t *slice, int kind,
    solaris_io_done_fn done, void *context)
{
    if (stream->channel.scope.cancelled || atomic_load_explicit(&stream->channel.plan->close_requested, memory_order_acquire) ||
        stream->lower == NULL || !solaris_executor_accepting(stream->stream.owner)) return SOLARIS_ECLOSED;
    stream_request_t *request = solaris_memory_allocate(solaris_executor_budget(stream->stream.owner), sizeof(*request));
    if (request == NULL) { if (kind == REQUEST_WRITE) solaris_track_reject(stream->channel.plan, SOLARIS_ENOMEM); return SOLARIS_ENOMEM; }
    *request = (stream_request_t){stream, done, context, slice != NULL ? slice->length : 0u, kind};
    solaris_status_t rc = kind == REQUEST_WRITE ? solaris_stream_write(stream->lower, slice, completed, request) :
        kind == REQUEST_SHUTDOWN ? solaris_stream_shutdown_write(stream->lower, completed, request) :
        solaris_stream_write_raw(stream->lower, completed, request);
    if (rc != SOLARIS_OK) {
        if (kind == REQUEST_WRITE) solaris_track_reject(stream->channel.plan, rc);
        solaris_memory_free(request); return rc;
    }
    solaris_scope_retain(&stream->channel.scope);
    if (kind == REQUEST_WRITE) {
        stream->stats.pending_requests++; stream->stats.pending_bytes += slice->length;
        solaris_track_submit(stream->channel.plan, slice->length, NULL);
    }
    return SOLARIS_OK;
}
static solaris_status_t write_stream(void *state, const solaris_slice_t *slice, solaris_io_done_fn done, void *context)
{ return submit(state, slice, REQUEST_WRITE, done, context); }
static solaris_status_t shutdown_stream(void *state, solaris_io_done_fn done, void *context)
{ return submit(state, NULL, REQUEST_SHUTDOWN, done, context); }
static solaris_status_t reading(void *state, int enabled)
{
    tracked_stream_t *stream = state;
    if (stream->channel.scope.cancelled || stream->lower == NULL) return SOLARIS_ECLOSED;
    return solaris_stream_set_reading(stream->lower, enabled);
}
static solaris_status_t close_stream(void *state) { close_status(&((tracked_stream_t *)state)->channel, SOLARIS_OK); return SOLARIS_OK; }
static solaris_status_t snapshot(void *state, solaris_io_snapshot_t *out)
{ tracked_stream_t *stream = state; refresh(stream); *out = stream->stats; return SOLARIS_OK; }
static uint32_t raw_capabilities(void *state)
{
    tracked_stream_t *stream = state; uint32_t caps = 0u;
    if (!stream->channel.scope.cancelled && stream->lower != NULL) (void)solaris_stream_raw_capabilities(stream->lower, &caps);
    return caps;
}
static solaris_status_t read_raw(void *state)
{
    tracked_stream_t *stream = state;
    if (stream->channel.scope.cancelled || stream->lower == NULL) return SOLARIS_ECLOSED;
    solaris_status_t rc = solaris_stream_read_raw(stream->lower); if (rc == SOLARIS_OK) stream->stats.raw_read = 1u; return rc;
}
static solaris_status_t write_raw(void *state, solaris_io_done_fn done, void *context)
{ return submit(state, NULL, REQUEST_RAW, done, context); }
static const solaris_stream_raw_ops_t raw_operations = {raw_capabilities, read_raw, write_raw};
static const solaris_stream_ops_t operations = {write_stream, shutdown_stream, reading, close_stream, snapshot, &raw_operations};
solaris_status_t solaris_tracked_stream_open(solaris_observed_plan_t *plan, const solaris_address_t *target,
    const solaris_stream_callbacks_t *callbacks, void *context, solaris_stream_t **out)
{
    *out = NULL;
    if (callbacks->on_open == NULL || callbacks->on_data == NULL || callbacks->on_close == NULL) return SOLARIS_EINVAL;
    tracked_stream_t *stream = solaris_memory_allocate(solaris_executor_budget(plan->outbound.owner), sizeof(*stream));
    if (stream == NULL) return SOLARIS_ENOMEM;
    memset(stream, 0, sizeof(*stream)); stream->callbacks = *callbacks; stream->context = context;
    stream->stream = (solaris_stream_t){&operations, stream, plan->outbound.owner}; stream->channel.close = close_status;
    solaris_status_t rc = solaris_scope_init(&stream->channel.scope, plan->outbound.owner, cancelled, destroyed, stream);
    if (rc != SOLARIS_OK) { solaris_memory_free(stream); return rc; }
    solaris_track_link(plan, &stream->channel);
    rc = solaris_outbound_open_stream(plan->source.outbound, target, &lower_callbacks, stream, &stream->lower);
    if (rc != SOLARIS_OK) { close_status(&stream->channel, rc); return rc; }
    solaris_scope_retain(&stream->channel.scope); solaris_track_accept(&stream->channel); *out = &stream->stream; return SOLARIS_OK;
}
