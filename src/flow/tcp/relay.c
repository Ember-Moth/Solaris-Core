#include "contracts/flow/tcp.h"
#include <assert.h>
#include <string.h>

typedef struct relay_side {
    struct solaris_tcp_relay *relay;
    struct relay_side *peer;
    solaris_stream_t *stream;
    const solaris_buffer_t *pending;
    size_t offset, writing;
    int opened, eof, inflight, shutdown_pending, shutdown_done;
} relay_side_t;
struct solaris_tcp_relay {
    solaris_scope_t scope;
    solaris_tcp_relay_options_t options;
    solaris_dial_plan_t plan;
    relay_side_t side[2];
    solaris_status_t status;
};
static void pump(relay_side_t *side);
static void fail(solaris_tcp_relay_t *relay, solaris_status_t status)
{
    if (!relay->scope.cancelled) {
        relay->status = status;
        solaris_scope_cancel(&relay->scope);
    }
}
static void cancel(void *context)
{
    solaris_tcp_relay_t *relay = context;
    for (size_t i = 0; i < 2; ++i) {
        relay_side_t *side = &relay->side[i];
        if (side->stream) (void)solaris_stream_close(side->stream);
        if (!side->inflight) { solaris_buffer_release(side->pending); side->pending = NULL; }
    }
}
static void finished(void *context)
{
    solaris_tcp_relay_t *relay = context;
    (void)solaris_dial_plan_release(&relay->plan);
    relay->options.on_close(relay->options.context, relay->status);
    solaris_memory_free(relay);
}
static void wrote(void *context, solaris_status_t status)
{
    relay_side_t *side = context;
    solaris_tcp_relay_t *relay = side->relay;
    side->inflight = 0;
    if (status != SOLARIS_OK) fail(relay, status);
    if (relay->scope.cancelled) {
        solaris_buffer_release(side->pending); side->pending = NULL;
    } else {
        side->offset += side->writing;
        if (side->offset == solaris_buffer_length(side->pending)) {
            solaris_buffer_release(side->pending); side->pending = NULL; side->offset = 0;
        }
        pump(side);
    }
    solaris_scope_release(&relay->scope);
}
static void shut(void *context, solaris_status_t status)
{
    relay_side_t *side = context;
    side->shutdown_pending = 0; side->shutdown_done = 1;
    if (status != SOLARIS_OK) fail(side->relay, status);
    else {
        solaris_tcp_relay_t *relay = side->relay;
        if (relay->side[0].eof && relay->side[1].eof &&
            relay->side[0].shutdown_done && relay->side[1].shutdown_done &&
            !relay->side[0].pending && !relay->side[1].pending)
            fail(relay, SOLARIS_OK);
    }
    solaris_scope_release(&side->relay->scope);
}
static void pump(relay_side_t *side)
{
    solaris_tcp_relay_t *relay = side->relay;
    relay_side_t *peer = side->peer;
    if (relay->scope.cancelled || !peer->opened || !peer->stream || side->inflight) return;
    if (side->pending) {
        solaris_io_snapshot_t stats;
        solaris_status_t rc = solaris_stream_get_snapshot(peer->stream, &stats);
        if (rc != SOLARIS_OK) { fail(relay, rc); return; }
        size_t length = solaris_buffer_length(side->pending) - side->offset;
        if (stats.max_message_bytes && length > stats.max_message_bytes) length = stats.max_message_bytes;
        solaris_slice_t slice = { side->pending, side->offset, length };
        rc = solaris_stream_write(peer->stream, &slice, wrote, side);
        if (rc == SOLARIS_OK) {
            side->inflight = 1; side->writing = length;
            solaris_scope_retain(&relay->scope);
        } else if (rc != SOLARIS_EAGAIN) fail(relay, rc);
        return;
    }
    if (side->eof) {
        if (!side->shutdown_pending && !side->shutdown_done) {
            solaris_status_t rc = solaris_stream_shutdown_write(peer->stream, shut, side);
            if (rc == SOLARIS_OK) { side->shutdown_pending = 1; solaris_scope_retain(&relay->scope); }
            else if (rc != SOLARIS_EAGAIN) fail(relay, rc);
        }
    } else if (side->stream && side->opened) {
        solaris_status_t rc = solaris_stream_set_reading(side->stream, 1);
        if (rc != SOLARIS_OK) fail(relay, rc);
    }
}
static void opened(void *context, solaris_stream_t *stream, solaris_status_t status);
static void received(void *context, solaris_stream_t *stream, const solaris_buffer_t *buffer)
{
    relay_side_t *side = context; (void)stream;
    if (side->relay->scope.cancelled) return;
    if (side->pending || solaris_buffer_length(buffer) > side->relay->options.pending_byte_limit) {
        fail(side->relay, SOLARIS_EOVERFLOW); return;
    }
    if (!solaris_buffer_length(buffer)) return;
    solaris_status_t rc = solaris_stream_set_reading(side->stream, 0);
    if (rc != SOLARIS_OK) { fail(side->relay, rc); return; }
    side->pending = buffer; side->offset = 0; solaris_buffer_retain(buffer);
    pump(side);
}
static void eof(void *context, solaris_stream_t *stream)
{
    relay_side_t *side = context; (void)stream;
    side->eof = 1; pump(side);
}
static void writable(void *context, solaris_stream_t *stream)
{
    relay_side_t *side = context; (void)stream;
    pump(side->peer);
}
static void closed(void *context, solaris_stream_t *stream, solaris_status_t status)
{
    relay_side_t *side = context; (void)stream;
    side->stream = NULL;
    fail(side->relay, status);
    solaris_scope_release(&side->relay->scope);
}
static const solaris_stream_callbacks_t callbacks = { opened, received, eof, writable, closed };
static void opened(void *context, solaris_stream_t *stream, solaris_status_t status)
{
    relay_side_t *side = context;
    solaris_tcp_relay_t *relay = side->relay;
    side->stream = stream; side->opened = status == SOLARIS_OK;
    if (relay->scope.cancelled) { (void)solaris_stream_close(stream); return; }
    if (status != SOLARIS_OK) { fail(relay, status); return; }
    solaris_status_t paused = solaris_stream_set_reading(stream, 0);
    if (paused != SOLARIS_OK) { fail(relay, paused); return; }
    if (side == &relay->side[0]) {
        solaris_status_t rc = solaris_outbound_open_stream(relay->plan.outbound, &relay->options.destination,
            &callbacks, &relay->side[1], &relay->side[1].stream);
        if (rc != SOLARIS_OK) { fail(relay, rc); return; }
        solaris_scope_retain(&relay->scope);
    } else { pump(side); pump(side->peer); }
}
solaris_status_t solaris_tcp_relay_prepare(const solaris_tcp_relay_options_t *options,
    solaris_dial_plan_t *plan, solaris_stream_callbacks_t *inbound_callbacks, void **context,
    solaris_tcp_relay_t **out)
{
    if (!out) return SOLARIS_EINVAL;
    *out = NULL;
    if (!options || !options->owner || !options->on_close || !options->pending_byte_limit ||
        !plan || !plan->outbound || !inbound_callbacks || !context || !options->destination.port)
        return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(options->owner)) return SOLARIS_ETHREAD;
    if (plan->outbound->owner != options->owner) return SOLARIS_ETHREAD;
    solaris_tcp_relay_t *relay = solaris_memory_allocate(solaris_executor_budget(options->owner), sizeof(*relay));
    if (!relay) return SOLARIS_ENOMEM;
    memset(relay, 0, sizeof(*relay)); relay->options = *options;
    solaris_status_t rc = solaris_scope_init(&relay->scope, options->owner, cancel, finished, relay);
    if (rc != SOLARIS_OK) { solaris_memory_free(relay); return rc; }
    relay->plan = *plan; memset(plan, 0, sizeof(*plan));
    relay->side[0].relay = relay; relay->side[1].relay = relay;
    relay->side[0].peer = &relay->side[1]; relay->side[1].peer = &relay->side[0];
    relay->status = SOLARIS_ECANCELLED;
    solaris_scope_retain(&relay->scope); /* promised inbound lifecycle */
    *inbound_callbacks = callbacks; *context = &relay->side[0]; *out = relay;
    return SOLARIS_OK;
}
void solaris_tcp_relay_close(solaris_tcp_relay_t *relay)
{ if (relay && solaris_executor_is_owner(relay->scope.owner)) fail(relay, SOLARIS_ECANCELLED); }
