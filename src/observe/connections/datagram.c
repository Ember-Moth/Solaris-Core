#include "observe/connections/internal.h"
#include <assert.h>
#include <string.h>

typedef struct tracked_datagram {
    solaris_tracked_channel_t channel;
    solaris_datagram_t datagram, *lower;
    solaris_datagram_callbacks_t callbacks;
    void *context;
    solaris_io_snapshot_t stats;
    solaris_status_t status;
    int closing, opened;
} tracked_datagram_t;
typedef struct datagram_request {
    tracked_datagram_t *datagram;
    solaris_io_done_fn done;
    void *context;
    size_t length;
} datagram_request_t;
static void close_status(solaris_tracked_channel_t *channel, solaris_status_t status)
{
    tracked_datagram_t *datagram = (tracked_datagram_t *)channel;
    if (datagram->closing) return;
    datagram->closing = 1; datagram->status = status; solaris_scope_cancel(&channel->scope);
}
static void cancelled(void *context)
{
    tracked_datagram_t *datagram = context;
    if (!datagram->closing) { datagram->closing = 1; datagram->status = SOLARIS_ECANCELLED; }
    if (datagram->lower != NULL) (void)solaris_datagram_close(datagram->lower);
}
static void destroyed(void *context)
{
    tracked_datagram_t *datagram = context; assert(datagram->lower == NULL && datagram->stats.pending_requests == 0u);
    if (datagram->channel.accepted) {
        if (!datagram->opened) datagram->callbacks.on_open(datagram->context, &datagram->datagram, SOLARIS_ECANCELLED);
        datagram->callbacks.on_close(datagram->context, &datagram->datagram, datagram->status);
    }
    solaris_track_remove(&datagram->channel, datagram->status); solaris_memory_free(datagram);
}
static void refresh(tracked_datagram_t *datagram)
{
    if (datagram->lower == NULL) return;
    solaris_io_snapshot_t stats;
    if (solaris_datagram_get_snapshot(datagram->lower, &stats) == SOLARIS_OK) {
        datagram->stats.max_message_bytes = stats.max_message_bytes; datagram->stats.last_system_error = stats.last_system_error;
        datagram->stats.dropped_packets = stats.dropped_packets;
    }
}
static void opened(void *context, solaris_datagram_t *lower, solaris_status_t status)
{
    (void)lower; tracked_datagram_t *datagram = context; assert(!datagram->opened); datagram->opened = 1;
    if (datagram->channel.scope.cancelled) status = datagram->status == SOLARIS_OK ? SOLARIS_ECANCELLED : datagram->status;
    refresh(datagram); solaris_track_open(datagram->channel.plan, status);
    if (status != SOLARIS_OK) close_status(&datagram->channel, status);
    datagram->callbacks.on_open(datagram->context, &datagram->datagram, status);
}
static void packet(void *context, solaris_datagram_t *lower, const solaris_address_t *source, const solaris_buffer_t *buffer)
{
    (void)lower; tracked_datagram_t *datagram = context; if (datagram->channel.scope.cancelled) return;
    size_t length = solaris_buffer_length(buffer); datagram->stats.bytes_read += length; datagram->stats.packets_read++;
    solaris_track_read(datagram->channel.plan, length, source);
    datagram->callbacks.on_packet(datagram->context, &datagram->datagram, source, buffer);
}
static void writable(void *context, solaris_datagram_t *lower)
{
    (void)lower; tracked_datagram_t *datagram = context;
    if (!datagram->channel.scope.cancelled && datagram->callbacks.on_writable != NULL)
        datagram->callbacks.on_writable(datagram->context, &datagram->datagram);
}
static void closed(void *context, solaris_datagram_t *lower, solaris_status_t status)
{
    (void)lower; tracked_datagram_t *datagram = context; refresh(datagram); datagram->lower = NULL;
    close_status(&datagram->channel, status); solaris_scope_release(&datagram->channel.scope);
}
static const solaris_datagram_callbacks_t lower_callbacks = {opened, packet, writable, closed};
static void completed(void *context, solaris_status_t status)
{
    datagram_request_t *request = context; tracked_datagram_t *datagram = request->datagram;
    datagram->stats.pending_requests--; datagram->stats.pending_bytes -= request->length;
    if (status == SOLARIS_OK) { datagram->stats.bytes_written += request->length; datagram->stats.packets_written++; }
    solaris_track_written(datagram->channel.plan, request->length, 1, status);
    request->done(request->context, status); solaris_memory_free(request); solaris_scope_release(&datagram->channel.scope);
}
static solaris_status_t send_packet(void *state, const solaris_address_t *target, const solaris_slice_t *slice, solaris_io_done_fn done, void *context)
{
    tracked_datagram_t *datagram = state;
    if (datagram->channel.scope.cancelled || atomic_load_explicit(&datagram->channel.plan->close_requested, memory_order_acquire) ||
        datagram->lower == NULL || !solaris_executor_accepting(datagram->datagram.owner)) return SOLARIS_ECLOSED;
    datagram_request_t *request = solaris_memory_allocate(solaris_executor_budget(datagram->datagram.owner), sizeof(*request));
    if (request == NULL) { solaris_track_reject(datagram->channel.plan, SOLARIS_ENOMEM); return SOLARIS_ENOMEM; }
    *request = (datagram_request_t){datagram, done, context, slice->length};
    solaris_status_t rc = solaris_datagram_send(datagram->lower, target, slice, completed, request);
    if (rc != SOLARIS_OK) { solaris_memory_free(request); solaris_track_reject(datagram->channel.plan, rc); return rc; }
    solaris_scope_retain(&datagram->channel.scope);
    datagram->stats.pending_requests++; datagram->stats.pending_bytes += slice->length;
    solaris_track_submit(datagram->channel.plan, slice->length, target); return SOLARIS_OK;
}
static solaris_status_t reading(void *state, int enabled)
{
    tracked_datagram_t *datagram = state;
    if (datagram->channel.scope.cancelled || datagram->lower == NULL) return SOLARIS_ECLOSED;
    return solaris_datagram_set_reading(datagram->lower, enabled);
}
static solaris_status_t close_datagram(void *state) { close_status(&((tracked_datagram_t *)state)->channel, SOLARIS_OK); return SOLARIS_OK; }
static solaris_status_t snapshot(void *state, solaris_io_snapshot_t *out)
{ tracked_datagram_t *datagram = state; refresh(datagram); *out = datagram->stats; return SOLARIS_OK; }
static solaris_status_t local_address(void *state, solaris_address_t *out)
{
    tracked_datagram_t *datagram = state;
    return datagram->lower == NULL ? SOLARIS_ECLOSED : solaris_datagram_local_address(datagram->lower, out);
}
static const solaris_datagram_ops_t operations = {send_packet, reading, close_datagram, snapshot, local_address};
solaris_status_t solaris_tracked_datagram_open(solaris_observed_plan_t *plan, uint32_t family,
    const solaris_datagram_callbacks_t *callbacks, void *context, solaris_datagram_t **out)
{
    *out = NULL;
    if (callbacks->on_open == NULL || callbacks->on_packet == NULL || callbacks->on_close == NULL) return SOLARIS_EINVAL;
    tracked_datagram_t *datagram = solaris_memory_allocate(solaris_executor_budget(plan->outbound.owner), sizeof(*datagram));
    if (datagram == NULL) return SOLARIS_ENOMEM;
    memset(datagram, 0, sizeof(*datagram)); datagram->callbacks = *callbacks; datagram->context = context;
    datagram->datagram = (solaris_datagram_t){&operations, datagram, plan->outbound.owner}; datagram->channel.close = close_status;
    solaris_status_t rc = solaris_scope_init(&datagram->channel.scope, plan->outbound.owner, cancelled, destroyed, datagram);
    if (rc != SOLARIS_OK) { solaris_memory_free(datagram); return rc; }
    solaris_track_link(plan, &datagram->channel);
    rc = solaris_outbound_open_datagram(plan->source.outbound, family, &lower_callbacks, datagram, &datagram->lower);
    if (rc != SOLARIS_OK) { close_status(&datagram->channel, rc); return rc; }
    solaris_scope_retain(&datagram->channel.scope); solaris_track_accept(&datagram->channel); *out = &datagram->datagram; return SOLARIS_OK;
}
