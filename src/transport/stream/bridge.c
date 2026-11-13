#include "transport/stream/bridge.h"
#include <assert.h>
#include <stdatomic.h>
#include <string.h>
#include <uv.h>

enum { MESSAGE_FREE, MESSAGE_QUEUED, MESSAGE_DELIVERING, MESSAGE_ACK, MESSAGE_COMPLETING };
typedef struct bridge_message {
    solaris_slice_t slice;
    solaris_buffer_t *view;
    solaris_io_done_fn done;
    void *context;
    solaris_status_t status;
    unsigned int state;
    int shutdown;
} bridge_message_t;
typedef struct bridge_endpoint {
    solaris_stream_bridge_t *bridge;
    solaris_stream_t stream;
    solaris_scope_t scope;
    solaris_deferred_t wake;
    solaris_stream_callbacks_t callbacks;
    void *context;
    solaris_io_snapshot_t stats; /* owner-only */
    bridge_message_t *messages;
    size_t head, count, bytes, pumps, credit_bytes, credit_requests;
    uint64_t generation;
    unsigned int side;
    int attached, opened, reading, shutdown, wanted, scheduled, close_seen, finalizing;
} bridge_endpoint_t;
struct solaris_stream_bridge {
    atomic_size_t references, external;
    uv_mutex_t mutex;
    solaris_stream_bridge_options_t options;
    bridge_endpoint_t endpoints[2];
    size_t outstanding, callbacks_running;
    int closing;
    solaris_status_t status;
    bridge_message_t messages[];
};

static void pump(void *context);
static void drop(solaris_stream_bridge_t *bridge)
{
    if (atomic_fetch_sub_explicit(&bridge->references, 1u, memory_order_acq_rel) == 1u) {
        assert(bridge->outstanding == 0u);
        uv_mutex_destroy(&bridge->mutex);
        solaris_memory_free(bridge);
    }
}
/* A persistent owner-local scope reference pins this node, including while
 * quiescing. No foreign thread retains/releases a scope. */
static void schedule_locked(bridge_endpoint_t *endpoint)
{
    if (!endpoint->attached || endpoint->finalizing || endpoint->scheduled) return;
    endpoint->scheduled = 1;
    endpoint->pumps++;
    solaris_status_t rc = solaris_executor_defer(endpoint->stream.owner, &endpoint->wake);
    assert(rc == SOLARIS_OK); (void)rc;
}
static void wake_both_locked(solaris_stream_bridge_t *bridge)
{
    schedule_locked(&bridge->endpoints[0]);
    schedule_locked(&bridge->endpoints[1]);
}
static void abort_locked(solaris_stream_bridge_t *bridge, solaris_status_t status)
{
    if (!bridge->closing) { bridge->closing = 1; bridge->status = status; }
    wake_both_locked(bridge);
}
static void cancelled(void *context)
{
    bridge_endpoint_t *endpoint = context;
    solaris_stream_bridge_t *bridge = endpoint->bridge;
    uv_mutex_lock(&bridge->mutex);
    endpoint->close_seen = 1;
    abort_locked(bridge, SOLARIS_ECANCELLED);
    uv_mutex_unlock(&bridge->mutex);
}
static void closed(void *context)
{
    bridge_endpoint_t *endpoint = context;
    solaris_stream_bridge_t *bridge = endpoint->bridge;
    assert(endpoint->opened && endpoint->count == 0u && endpoint->pumps == 0u);
    endpoint->callbacks.on_close(endpoint->context, &endpoint->stream, bridge->status);
    drop(bridge);
}
static int has_credit_locked(bridge_endpoint_t *sender, size_t size)
{
    solaris_stream_bridge_t *bridge = sender->bridge;
    bridge_endpoint_t *peer = &bridge->endpoints[sender->side ^ 1u];
    return !bridge->closing && peer->attached && !sender->shutdown && sender->credit_requests &&
        size <= sender->credit_bytes &&
        sender->count < bridge->options.request_limit && size <= bridge->options.byte_limit - sender->bytes;
}
static void grant_locked(bridge_endpoint_t *sender)
{
    solaris_stream_bridge_t *bridge = sender->bridge;
    if (bridge->endpoints[sender->side ^ 1u].reading && !bridge->closing) {
        sender->credit_bytes = bridge->options.byte_limit - sender->bytes;
        sender->credit_requests = bridge->options.request_limit - sender->count;
    }
}
static bridge_message_t *queued_locked(bridge_endpoint_t *sender)
{
    for (size_t i = 0; i < sender->count; ++i) {
        bridge_message_t *message = &sender->messages[(sender->head + i) % sender->bridge->options.request_limit];
        if (message->state == MESSAGE_QUEUED) return message;
    }
    return NULL;
}
static int deliver_ack(bridge_endpoint_t *endpoint)
{
    solaris_stream_bridge_t *bridge = endpoint->bridge;
    uv_mutex_lock(&bridge->mutex);
    bridge_message_t *message = endpoint->count ? &endpoint->messages[endpoint->head] : NULL;
    if (!message || message->state != MESSAGE_ACK) { uv_mutex_unlock(&bridge->mutex); return 0; }
    message->state = MESSAGE_COMPLETING;
    uv_mutex_unlock(&bridge->mutex);
    if (!message->shutdown) {
        endpoint->stats.pending_requests--;
        endpoint->stats.pending_bytes -= message->slice.length;
        if (message->status == SOLARIS_OK) endpoint->stats.bytes_written += message->slice.length;
    } else if (message->status == SOLARIS_OK) endpoint->stats.write_shutdown = 1u;
    message->done(message->context, message->status);
    solaris_buffer_release(message->slice.buffer);
    solaris_buffer_release(message->view);
    uv_mutex_lock(&bridge->mutex);
    endpoint->bytes -= message->slice.length;
    memset(message, 0, sizeof(*message));
    endpoint->head = (endpoint->head + 1u) % bridge->options.request_limit;
    endpoint->count--;
    bridge->outstanding--;
    grant_locked(endpoint);
    /* Acknowledgement includes return from the sender callback. */
    wake_both_locked(bridge);
    uv_mutex_unlock(&bridge->mutex);
    return 1;
}
static int deliver_input(bridge_endpoint_t *endpoint)
{
    solaris_stream_bridge_t *bridge = endpoint->bridge;
    bridge_endpoint_t *sender = &bridge->endpoints[endpoint->side ^ 1u];
    uv_mutex_lock(&bridge->mutex);
    bridge_message_t *message = queued_locked(sender);
    if (!message || (!bridge->closing && !endpoint->reading)) {
        uv_mutex_unlock(&bridge->mutex); return 0;
    }
    const int deliver = !bridge->closing;
    message->state = MESSAGE_DELIVERING;
    uv_mutex_unlock(&bridge->mutex);
    if (deliver) {
        if (message->shutdown) {
            endpoint->stats.read_eof = 1u;
            if (endpoint->callbacks.on_eof) endpoint->callbacks.on_eof(endpoint->context, &endpoint->stream);
        } else {
            endpoint->stats.bytes_read += message->slice.length;
            endpoint->callbacks.on_data(endpoint->context, &endpoint->stream,
                message->view ? message->view : message->slice.buffer);
        }
    }
    uv_mutex_lock(&bridge->mutex);
    message->status = deliver ? SOLARIS_OK : SOLARIS_ECANCELLED;
    message->state = MESSAGE_ACK;
    schedule_locked(sender);
    uv_mutex_unlock(&bridge->mutex);
    return 1;
}
static void pump(void *context)
{
    bridge_endpoint_t *endpoint = context;
    solaris_stream_bridge_t *bridge = endpoint->bridge;
    assert(solaris_executor_is_owner(endpoint->stream.owner));
    uv_mutex_lock(&bridge->mutex);
    endpoint->scheduled = 0;
    if (solaris_executor_generation(endpoint->stream.owner) != endpoint->generation)
        abort_locked(bridge, SOLARIS_ECANCELLED);
    int need_cancel = bridge->closing && !endpoint->close_seen;
    int notify_open = !endpoint->opened && (bridge->closing ||
        (bridge->endpoints[0].attached && bridge->endpoints[1].attached));
    solaris_status_t open_status = bridge->closing ?
        (bridge->status == SOLARIS_OK ? SOLARIS_ECANCELLED : bridge->status) : SOLARIS_OK;
    if (notify_open) { endpoint->opened = 1; bridge->callbacks_running++; }
    uv_mutex_unlock(&bridge->mutex);
    if (need_cancel) solaris_scope_cancel(&endpoint->scope);
    if (notify_open) {
        endpoint->callbacks.on_open(endpoint->context, &endpoint->stream, open_status);
        uv_mutex_lock(&bridge->mutex);
        bridge->callbacks_running--; wake_both_locked(bridge);
        uv_mutex_unlock(&bridge->mutex);
    }
    if (endpoint->opened) {
        for (unsigned int steps = 0; steps < 32u; ++steps) {
            int progressed = deliver_ack(endpoint);
            progressed |= deliver_input(endpoint);
            if (!progressed) break;
        }
    }
    uv_mutex_lock(&bridge->mutex);
    int writable = endpoint->opened && endpoint->wanted && has_credit_locked(endpoint, bridge->options.max_chunk_size);
    if (writable) { endpoint->wanted = 0; bridge->callbacks_running++; }
    uv_mutex_unlock(&bridge->mutex);
    if (writable) {
        if (endpoint->callbacks.on_writable) endpoint->callbacks.on_writable(endpoint->context, &endpoint->stream);
        uv_mutex_lock(&bridge->mutex);
        bridge->callbacks_running--; wake_both_locked(bridge);
        uv_mutex_unlock(&bridge->mutex);
    }
    uv_mutex_lock(&bridge->mutex);
    bridge_endpoint_t *peer = &bridge->endpoints[endpoint->side ^ 1u];
    int finished = bridge->closing && endpoint->close_seen && (!peer->attached || peer->close_seen) &&
        bridge->outstanding == 0u && bridge->callbacks_running == 0u && endpoint->pumps == 1u;
    if (finished) endpoint->finalizing = 1;
    else if ((endpoint->count && endpoint->messages[endpoint->head].state == MESSAGE_ACK) ||
             ((bridge->closing || endpoint->reading) && queued_locked(peer))) schedule_locked(endpoint);
    assert(endpoint->pumps > 0u);
    endpoint->pumps--;
    uv_mutex_unlock(&bridge->mutex);
    if (finished) solaris_scope_release(&endpoint->scope); /* persistent pair/ACK lease */
}
static solaris_status_t enqueue(bridge_endpoint_t *endpoint, const solaris_slice_t *slice,
    solaris_io_done_fn done, void *context, int shutdown)
{
    solaris_stream_bridge_t *bridge = endpoint->bridge;
    size_t length = shutdown ? 0u : slice->length;
    if (length > bridge->options.max_chunk_size) return SOLARIS_EMSGSIZE;
    uv_mutex_lock(&bridge->mutex);
    if (bridge->closing || endpoint->shutdown || !solaris_executor_accepting(endpoint->stream.owner)) {
        uv_mutex_unlock(&bridge->mutex); return SOLARIS_ECLOSED;
    }
    if (!endpoint->opened || !has_credit_locked(endpoint, length)) {
        endpoint->wanted = 1; uv_mutex_unlock(&bridge->mutex); return SOLARIS_EAGAIN;
    }
    solaris_buffer_t *view = NULL;
    if (!shutdown && (slice->offset != 0u || slice->length != solaris_buffer_length(slice->buffer))) {
        solaris_status_t rc = solaris_buffer_copy(bridge->options.budget,
            solaris_buffer_data(slice->buffer) + slice->offset, length, &view);
        if (rc != SOLARIS_OK) { uv_mutex_unlock(&bridge->mutex); return rc; }
    }
    bridge_message_t *message = &endpoint->messages[(endpoint->head + endpoint->count) % bridge->options.request_limit];
    assert(message->state == MESSAGE_FREE);
    *message = (bridge_message_t){.view = view, .done = done, .context = context,
                                 .state = MESSAGE_QUEUED, .shutdown = shutdown};
    if (!shutdown) { message->slice = *slice; solaris_buffer_retain(slice->buffer); }
    endpoint->count++; endpoint->bytes += length; bridge->outstanding++;
    endpoint->credit_requests--; endpoint->credit_bytes -= length;
    if (shutdown) endpoint->shutdown = 1;
    else { endpoint->stats.pending_requests++; endpoint->stats.pending_bytes += length; }
    schedule_locked(&bridge->endpoints[endpoint->side ^ 1u]);
    uv_mutex_unlock(&bridge->mutex);
    return SOLARIS_OK;
}
static solaris_status_t write_stream(void *state, const solaris_slice_t *slice, solaris_io_done_fn done, void *context)
{ return enqueue(state, slice, done, context, 0); }
static solaris_status_t shutdown_stream(void *state, solaris_io_done_fn done, void *context)
{ return enqueue(state, NULL, done, context, 1); }
static solaris_status_t reading(void *state, int enabled)
{
    bridge_endpoint_t *endpoint = state; solaris_stream_bridge_t *bridge = endpoint->bridge;
    uv_mutex_lock(&bridge->mutex);
    solaris_status_t rc = bridge->closing ? SOLARIS_ECLOSED : SOLARIS_OK;
    if (rc == SOLARIS_OK) {
        endpoint->reading = enabled;
        if (enabled) grant_locked(&bridge->endpoints[endpoint->side ^ 1u]);
        wake_both_locked(bridge);
    }
    uv_mutex_unlock(&bridge->mutex); return rc;
}
static solaris_status_t close_stream(void *state)
{
    bridge_endpoint_t *endpoint = state; solaris_stream_bridge_t *bridge = endpoint->bridge;
    uv_mutex_lock(&bridge->mutex); abort_locked(bridge, SOLARIS_OK); uv_mutex_unlock(&bridge->mutex);
    solaris_scope_cancel(&endpoint->scope); return SOLARIS_OK;
}
static solaris_status_t snapshot(void *state, solaris_io_snapshot_t *out)
{ *out = ((bridge_endpoint_t *)state)->stats; return SOLARIS_OK; }
static const solaris_stream_ops_t operations = {write_stream, shutdown_stream, reading, close_stream, snapshot, NULL};

solaris_status_t solaris_stream_bridge_create(const solaris_stream_bridge_options_t *options,
                                             solaris_stream_bridge_t **out)
{
    if (!out) return SOLARIS_EINVAL;
    *out = NULL;
    if (!options || !options->budget || !options->byte_limit || !options->request_limit ||
        !options->max_chunk_size || options->max_chunk_size > options->byte_limit ||
        options->request_limit > 65536u || options->byte_limit > 16777216u ||
        options->max_chunk_size > 65536u) return SOLARIS_EINVAL;
    solaris_stream_bridge_t *bridge = solaris_memory_allocate(options->budget,
        sizeof(*bridge) + 2u * options->request_limit * sizeof(bridge_message_t));
    if (!bridge) return SOLARIS_ENOMEM;
    memset(bridge, 0, sizeof(*bridge) + 2u * options->request_limit * sizeof(bridge_message_t));
    if (uv_mutex_init(&bridge->mutex) != 0) { solaris_memory_free(bridge); return SOLARIS_ENOMEM; }
    bridge->options = *options;
    atomic_init(&bridge->references, 1u); atomic_init(&bridge->external, 1u);
    for (unsigned int i = 0; i < 2u; ++i) {
        bridge_endpoint_t *endpoint = &bridge->endpoints[i];
        endpoint->bridge = bridge; endpoint->side = i;
        endpoint->messages = bridge->messages + i * options->request_limit;
        endpoint->wake = (solaris_deferred_t){.run = pump, .context = endpoint};
    }
    *out = bridge; return SOLARIS_OK;
}
void solaris_stream_bridge_retain(solaris_stream_bridge_t *bridge)
{
    if (!bridge) return;
    atomic_fetch_add_explicit(&bridge->references, 1u, memory_order_relaxed);
    atomic_fetch_add_explicit(&bridge->external, 1u, memory_order_relaxed);
}
void solaris_stream_bridge_release(solaris_stream_bridge_t *bridge)
{
    if (!bridge) return;
    if (atomic_fetch_sub_explicit(&bridge->external, 1u, memory_order_acq_rel) == 1u) {
        uv_mutex_lock(&bridge->mutex);
        if (!bridge->endpoints[0].attached || !bridge->endpoints[1].attached) abort_locked(bridge, SOLARIS_ECANCELLED);
        uv_mutex_unlock(&bridge->mutex);
    }
    drop(bridge);
}
solaris_status_t solaris_stream_bridge_attach(solaris_stream_bridge_t *bridge, unsigned int side,
    solaris_executor_t *owner, const solaris_stream_callbacks_t *callbacks,
    void *context, solaris_stream_t **out)
{
    if (!out) return SOLARIS_EINVAL;
    *out = NULL;
    if (!bridge || side > 1u || !owner || !callbacks || !callbacks->on_open || !callbacks->on_data || !callbacks->on_close)
        return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(owner)) return SOLARIS_ETHREAD;
    uv_mutex_lock(&bridge->mutex);
    bridge_endpoint_t *endpoint = &bridge->endpoints[side];
    solaris_status_t rc = bridge->closing ? SOLARIS_ECLOSED : endpoint->attached ? SOLARIS_EBUSY : SOLARIS_OK;
    if (rc == SOLARIS_OK) {
        rc = solaris_scope_init(&endpoint->scope, owner, cancelled, closed, endpoint);
        if (rc == SOLARIS_OK) {
            endpoint->stream = (solaris_stream_t){&operations, endpoint, owner};
            endpoint->generation = solaris_executor_generation(owner);
            endpoint->callbacks = *callbacks; endpoint->context = context; endpoint->attached = 1;
            solaris_scope_retain(&endpoint->scope);
            atomic_fetch_add_explicit(&bridge->references, 1u, memory_order_relaxed);
            *out = &endpoint->stream;
            wake_both_locked(bridge);
        } else abort_locked(bridge, rc);
    }
    uv_mutex_unlock(&bridge->mutex);
    return rc;
}
