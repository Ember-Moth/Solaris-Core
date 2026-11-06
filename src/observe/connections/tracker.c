#include "observe/connections/internal.h"
#include <assert.h>
#include <string.h>

#define ADD(plan, name, n) ((void)atomic_fetch_add_explicit(&(plan)->totals->name, (uint64_t)(n), memory_order_relaxed))
static void finalize(solaris_observed_plan_t *plan)
{
    if (!plan->released || plan->channels != NULL || !plan->registered) return;
    solaris_tracker_t *tracker = plan->tracker; uv_mutex_lock(&tracker->mutex);
    if (plan->close_pending) { uv_mutex_unlock(&tracker->mutex); return; }
    uv_mutex_lock(&plan->mutex);
    plan->info.state = SOLARIS_CONNECTION_CLOSED; plan->info.closed_ns = solaris_executor_now_ns(plan->outbound.owner);
    if (tracker->history_limit != 0u) {
        tracker->history[tracker->history_next] = plan->info;
        tracker->history_next = (tracker->history_next + 1u) % tracker->history_limit;
        if (tracker->history_count < tracker->history_limit) tracker->history_count++;
    }
    uv_mutex_unlock(&plan->mutex);
    if (plan->previous != NULL) plan->previous->next = plan->next; else tracker->head = plan->next;
    if (plan->next != NULL) plan->next->previous = plan->previous;
    tracker->active_count--; plan->registered = 0;
    uv_mutex_unlock(&tracker->mutex);
    ADD(plan, closed, 1u); (void)atomic_fetch_sub_explicit(&plan->totals->active, 1u, memory_order_relaxed);
    solaris_scope_release(&plan->scope); /* registered-entry/close-command lease */
}
static void cancelled(void *context) { ((solaris_observed_plan_t *)context)->retired = 1; }
static void destroyed(void *context)
{
    solaris_observed_plan_t *plan = context; assert(!plan->registered && plan->channels == NULL);
    if (plan->source.outbound != NULL) { solaris_status_t rc = solaris_dial_plan_release(&plan->source); assert(rc == SOLARIS_OK); (void)rc; }
    solaris_tracker_t *tracker = plan->reference ? plan->tracker : NULL;
    uv_mutex_destroy(&plan->mutex); solaris_memory_free(plan);
    if (tracker != NULL) (void)atomic_fetch_sub_explicit(&tracker->references, 1u, memory_order_release);
}
static void release_plan(void *context)
{
    solaris_observed_plan_t *plan = context; assert(!plan->released); plan->released = 1;
    solaris_scope_cancel(&plan->scope); finalize(plan); solaris_scope_release(&plan->scope); /* caller's plan lease */
}
static void close_entry(void *context)
{
    solaris_observed_plan_t *plan = context;
    uv_mutex_lock(&plan->tracker->mutex); plan->close_pending = 0; uv_mutex_unlock(&plan->tracker->mutex);
    plan->retired = 1;
    uv_mutex_lock(&plan->mutex); plan->info.state = SOLARIS_CONNECTION_CLOSING;
    if (plan->info.status == SOLARIS_OK) plan->info.status = SOLARIS_ECANCELLED;
    uv_mutex_unlock(&plan->mutex);
    for (solaris_tracked_channel_t *channel = plan->channels; channel != NULL; channel = channel->next)
        channel->close(channel, SOLARIS_ECANCELLED);
    solaris_scope_cancel(&plan->scope); finalize(plan);
}
static solaris_status_t request_close(solaris_observed_plan_t *plan)
{
    if (atomic_load_explicit(&plan->close_requested, memory_order_relaxed)) return SOLARIS_OK;
    atomic_store_explicit(&plan->close_requested, 1, memory_order_release); plan->close_pending = 1;
    solaris_status_t rc = solaris_executor_defer(plan->outbound.owner, &plan->close_task);
    if (rc != SOLARIS_OK) { atomic_store(&plan->close_requested, 0); plan->close_pending = 0; }
    return rc;
}
solaris_status_t solaris_tracker_create(solaris_budget_t *budget, size_t active_limit, size_t history_limit, solaris_tracker_t **out)
{
    if (out == NULL) return SOLARIS_EINVAL;
    *out = NULL;
    if (budget == NULL || active_limit == 0u || active_limit > 65536u || history_limit > 65536u) return SOLARIS_EINVAL;
    solaris_tracker_t *tracker = solaris_memory_allocate(budget, sizeof(*tracker) + history_limit * sizeof(*tracker->history));
    if (tracker == NULL) return SOLARIS_ENOMEM;
    memset(tracker, 0, sizeof(*tracker) + history_limit * sizeof(*tracker->history)); atomic_init(&tracker->references, 1u);
    if (uv_mutex_init(&tracker->mutex) != 0) { solaris_memory_free(tracker); return SOLARIS_EIO; }
    tracker->budget = budget; tracker->active_limit = active_limit; tracker->history_limit = history_limit; *out = tracker; return SOLARIS_OK;
}
solaris_status_t solaris_tracker_snapshot(solaris_tracker_t *tracker, uint64_t id, solaris_connection_snapshot_t *out)
{
    if (tracker == NULL || id == 0u || out == NULL) return SOLARIS_EINVAL;
    uv_mutex_lock(&tracker->mutex);
    for (solaris_observed_plan_t *plan = tracker->head; plan != NULL; plan = plan->next) if (plan->info.id == id) {
        uv_mutex_lock(&plan->mutex); *out = plan->info; uv_mutex_unlock(&plan->mutex); uv_mutex_unlock(&tracker->mutex); return SOLARIS_OK;
    }
    for (size_t i = 0u; i < tracker->history_count; ++i) if (tracker->history[i].id == id) {
        *out = tracker->history[i]; uv_mutex_unlock(&tracker->mutex); return SOLARIS_OK;
    }
    uv_mutex_unlock(&tracker->mutex); return SOLARIS_ECLOSED;
}
solaris_status_t solaris_tracker_list(solaris_tracker_t *tracker, int include_closed,
    solaris_connection_snapshot_t *out, size_t capacity, size_t *count)
{
    if (tracker == NULL || count == NULL || (out == NULL && capacity != 0u)) return SOLARIS_EINVAL;
    uv_mutex_lock(&tracker->mutex); *count = tracker->active_count + (include_closed ? tracker->history_count : 0u); size_t used = 0u;
    for (solaris_observed_plan_t *plan = tracker->head; plan != NULL && used < capacity; plan = plan->next) {
        uv_mutex_lock(&plan->mutex); out[used++] = plan->info; uv_mutex_unlock(&plan->mutex);
    }
    if (include_closed) for (size_t i = 0u; i < tracker->history_count && used < capacity; ++i)
        out[used++] = tracker->history[(tracker->history_next + tracker->history_limit - 1u - i) % tracker->history_limit];
    solaris_status_t rc = capacity < *count ? SOLARIS_EMSGSIZE : SOLARIS_OK;
    uv_mutex_unlock(&tracker->mutex); return rc;
}
solaris_status_t solaris_tracker_totals(solaris_tracker_t *tracker, uint32_t purpose, solaris_tracker_totals_t *out)
{
    if (tracker == NULL || out == NULL || purpose >= SOLARIS_FLOW_PURPOSE_COUNT) return SOLARIS_EINVAL;
    memset(out, 0, sizeof(*out)); uv_mutex_lock(&tracker->mutex);
    for (size_t i = 0u; i < tracker->worker_count; ++i) {
#define LOAD(name) out->name += atomic_load_explicit(&tracker->workers[i].totals[purpose].name, memory_order_relaxed);
        SOLARIS_TRACKER_COUNTERS(LOAD)
#undef LOAD
    }
    uv_mutex_unlock(&tracker->mutex); return SOLARIS_OK;
}
solaris_status_t solaris_tracker_close_connection(solaris_tracker_t *tracker, uint64_t id)
{
    if (tracker == NULL || id == 0u) return SOLARIS_EINVAL;
    uv_mutex_lock(&tracker->mutex); solaris_status_t rc = SOLARIS_ECLOSED;
    for (solaris_observed_plan_t *plan = tracker->head; plan != NULL; plan = plan->next) if (plan->info.id == id) { rc = request_close(plan); break; }
    uv_mutex_unlock(&tracker->mutex); return rc;
}
solaris_status_t solaris_tracker_close_all(solaris_tracker_t *tracker)
{
    if (tracker == NULL) return SOLARIS_EINVAL;
    uv_mutex_lock(&tracker->mutex); tracker->closing = 1; solaris_status_t status = SOLARIS_OK;
    for (solaris_observed_plan_t *plan = tracker->head; plan != NULL; plan = plan->next) {
        solaris_status_t rc = request_close(plan); if (rc != SOLARIS_OK) status = rc;
    }
    uv_mutex_unlock(&tracker->mutex); return status;
}
solaris_status_t solaris_tracker_destroy(solaris_tracker_t *tracker)
{
    if (tracker == NULL) return SOLARIS_EINVAL;
    uv_mutex_lock(&tracker->mutex);
    if (tracker->active_count != 0u || atomic_load_explicit(&tracker->references, memory_order_acquire) != 1u) {
        uv_mutex_unlock(&tracker->mutex); return SOLARIS_EBUSY;
    }
    tracker->closing = 1; uv_mutex_unlock(&tracker->mutex); uv_mutex_destroy(&tracker->mutex); solaris_memory_free(tracker); return SOLARIS_OK;
}
static int accepting(solaris_observed_plan_t *plan)
{ return !plan->retired && !atomic_load_explicit(&plan->close_requested, memory_order_acquire) && solaris_executor_accepting(plan->outbound.owner); }
static uint32_t capabilities(void *state)
{
    solaris_observed_plan_t *plan = state; uint32_t caps = 0u;
    if (accepting(plan)) (void)solaris_outbound_capabilities(plan->source.outbound, &caps);
    return caps & (plan->info.kind == SOLARIS_FLOW_STREAM ?
        SOLARIS_OUTBOUND_STREAM | SOLARIS_OUTBOUND_STREAM_DOMAIN | SOLARIS_OUTBOUND_HALF_CLOSE :
        SOLARIS_OUTBOUND_DATAGRAM | SOLARIS_OUTBOUND_DATAGRAM_MULTI | SOLARIS_OUTBOUND_DATAGRAM_DOMAIN);
}
static solaris_status_t open_stream(void *state, const solaris_address_t *target,
    const solaris_stream_callbacks_t *callbacks, void *context, solaris_stream_t **out)
{
    solaris_observed_plan_t *plan = state;
    if (!accepting(plan)) return SOLARIS_ECLOSED;
    if (plan->info.kind != SOLARIS_FLOW_STREAM) return SOLARIS_ENOTSUP;
    if (!solaris_address_equal(target, &plan->info.target)) return SOLARIS_EINVAL;
    if (plan->stream_attempted) return SOLARIS_EBUSY;
    plan->stream_attempted = 1;
    solaris_status_t rc = solaris_tracked_stream_open(plan, target, callbacks, context, out);
    if (rc != SOLARIS_OK) solaris_track_open(plan, rc);
    return rc;
}
static solaris_status_t open_datagram(void *state, uint32_t family,
    const solaris_datagram_callbacks_t *callbacks, void *context, solaris_datagram_t **out)
{
    solaris_observed_plan_t *plan = state;
    if (!accepting(plan)) return SOLARIS_ECLOSED;
    if (plan->info.kind != SOLARIS_FLOW_DATAGRAM) return SOLARIS_ENOTSUP;
    if (plan->channel_count >= plan->channel_limit) return SOLARIS_EAGAIN;
    solaris_status_t rc = solaris_tracked_datagram_open(plan, family, callbacks, context, out);
    if (rc != SOLARIS_OK) solaris_track_open(plan, rc);
    return rc;
}
static void retire(void *state) { solaris_scope_cancel(&((solaris_observed_plan_t *)state)->scope); }
static const solaris_outbound_ops_t operations = {capabilities, open_stream, open_datagram, retire};
solaris_status_t solaris_observe_plan(solaris_tracker_t *tracker, solaris_dial_plan_t *source,
    const solaris_observe_options_t *options, solaris_dial_plan_t *out, uint64_t *connection_id)
{
    if (out == NULL || out == source) return SOLARIS_EINVAL;
    memset(out, 0, sizeof(*out)); if (connection_id != NULL) *connection_id = 0u;
    if (tracker == NULL || source == NULL || source->outbound == NULL || source->release == NULL || source->node_id == 0u ||
        (source->flags & SOLARIS_PLAN_OBSERVED) != 0u || options == NULL || options->purpose >= SOLARIS_FLOW_PURPOSE_COUNT ||
        (options->kind != SOLARIS_FLOW_STREAM && options->kind != SOLARIS_FLOW_DATAGRAM) || options->channel_limit > 1024u) return SOLARIS_EINVAL;
    solaris_executor_t *owner = source->outbound->owner;
    if (!solaris_executor_is_owner(owner)) return SOLARIS_ETHREAD;
    solaris_observed_plan_t *plan = solaris_memory_allocate(tracker->budget, sizeof(*plan));
    if (plan == NULL) return SOLARIS_ENOMEM;
    memset(plan, 0, sizeof(*plan)); atomic_init(&plan->close_requested, 0);
    if (uv_mutex_init(&plan->mutex) != 0) { solaris_memory_free(plan); return SOLARIS_EIO; }
    plan->tracker = tracker; plan->outbound = (solaris_outbound_t){&operations, plan, owner};
    plan->channel_limit = options->channel_limit == 0u ? 32u : options->channel_limit;
    plan->close_task = (solaris_deferred_t){.run = close_entry, .context = plan};
    solaris_status_t rc = solaris_scope_init(&plan->scope, owner, cancelled, destroyed, plan);
    if (rc != SOLARIS_OK) { uv_mutex_destroy(&plan->mutex); solaris_memory_free(plan); return rc; }
    plan->info = (solaris_connection_snapshot_t){.node_id = source->node_id, .selection_revision = source->selection_revision,
        .generation = solaris_executor_generation(owner), .worker_id = solaris_executor_id(owner), .kind = options->kind,
        .purpose = options->purpose, .target = options->target, .created_ns = solaris_executor_now_ns(owner)};
    uv_mutex_lock(&tracker->mutex);
    if (tracker->closing) rc = SOLARIS_ECLOSED;
    else if (tracker->active_count >= tracker->active_limit) rc = SOLARIS_EAGAIN;
    else if (tracker->next_id == UINT64_MAX) rc = SOLARIS_EOVERFLOW;
    size_t worker = 0u;
    while (worker < tracker->worker_count && tracker->workers[worker].owner != owner) worker++;
    if (rc == SOLARIS_OK && worker == tracker->worker_count) {
        if (worker == 32u) rc = SOLARIS_EAGAIN;
        else {
            tracker->workers[worker].owner = owner;
            for (size_t purpose = 0u; purpose < SOLARIS_FLOW_PURPOSE_COUNT; ++purpose) {
#define INIT(name) atomic_init(&tracker->workers[worker].totals[purpose].name, 0u);
                SOLARIS_TRACKER_COUNTERS(INIT)
#undef INIT
            }
            tracker->worker_count++;
        }
    }
    if (rc == SOLARIS_OK) {
        plan->totals = &tracker->workers[worker].totals[options->purpose];
        plan->info.id = ++tracker->next_id; plan->source = *source;
        plan->next = tracker->head; if (tracker->head != NULL) tracker->head->previous = plan;
        tracker->head = plan; tracker->active_count++; plan->registered = plan->reference = 1;
        (void)atomic_fetch_add_explicit(&tracker->references, 1u, memory_order_relaxed);
        solaris_scope_retain(&plan->scope); solaris_scope_retain(&plan->scope); /* caller and registry leases */
        ADD(plan, created, 1u); ADD(plan, active, 1u);
    }
    uv_mutex_unlock(&tracker->mutex);
    if (rc != SOLARIS_OK) { solaris_scope_cancel(&plan->scope); return rc; }
    *out = (solaris_dial_plan_t){.outbound = &plan->outbound, .context = plan, .release = release_plan,
        .node_id = source->node_id, .selection_revision = source->selection_revision, .flags = source->flags | SOLARIS_PLAN_OBSERVED};
    memset(source, 0, sizeof(*source)); if (connection_id != NULL) *connection_id = plan->info.id; return SOLARIS_OK;
}
void solaris_track_link(solaris_observed_plan_t *plan, solaris_tracked_channel_t *channel)
{
    channel->plan = plan; channel->next = plan->channels;
    if (plan->channels != NULL) plan->channels->previous = channel;
    plan->channels = channel; plan->channel_count++; solaris_scope_retain(&plan->scope);
}
void solaris_track_accept(solaris_tracked_channel_t *channel)
{
    channel->accepted = 1; uv_mutex_lock(&channel->plan->mutex); channel->plan->info.active_channels++; uv_mutex_unlock(&channel->plan->mutex);
}
void solaris_track_remove(solaris_tracked_channel_t *channel, solaris_status_t status)
{
    solaris_observed_plan_t *plan = channel->plan;
    uv_mutex_lock(&plan->mutex);
    if (channel->accepted) plan->info.active_channels--;
    if (plan->info.status == SOLARIS_OK && status != SOLARIS_OK) plan->info.status = status;
    uv_mutex_unlock(&plan->mutex);
    if (channel->previous != NULL) channel->previous->next = channel->next; else plan->channels = channel->next;
    if (channel->next != NULL) channel->next->previous = channel->previous;
    plan->channel_count--; finalize(plan); solaris_scope_release(&plan->scope);
}
void solaris_track_open(solaris_observed_plan_t *plan, solaris_status_t status)
{
    uv_mutex_lock(&plan->mutex);
    if (status == SOLARIS_OK) {
        if (!plan->opened_once) { plan->opened_once = 1; plan->info.opened_ns = solaris_executor_now_ns(plan->outbound.owner); ADD(plan, opened, 1u); }
        if (!atomic_load(&plan->close_requested)) plan->info.state = SOLARIS_CONNECTION_OPEN;
    } else { ADD(plan, open_failures, 1u); if (plan->info.status == SOLARIS_OK) plan->info.status = status; }
    uv_mutex_unlock(&plan->mutex);
}
void solaris_track_reject(solaris_observed_plan_t *plan, solaris_status_t status)
{ (void)status; uv_mutex_lock(&plan->mutex); plan->info.rejections++; ADD(plan, rejections, 1u); uv_mutex_unlock(&plan->mutex); }
void solaris_track_submit(solaris_observed_plan_t *plan, size_t bytes, const solaris_address_t *target)
{
    uv_mutex_lock(&plan->mutex); plan->info.pending_bytes += bytes; plan->info.pending_requests++; plan->info.accepted_writes++;
    if (target != NULL) plan->info.last_destination = *target;
    ADD(plan, accepted_writes, 1u); uv_mutex_unlock(&plan->mutex);
}
void solaris_track_written(solaris_observed_plan_t *plan, size_t bytes, int datagram, solaris_status_t status)
{
    uv_mutex_lock(&plan->mutex); plan->info.pending_bytes -= bytes; plan->info.pending_requests--;
    if (status == SOLARIS_OK) {
        plan->info.bytes_written += bytes; ADD(plan, bytes_written, bytes);
        if (datagram) { plan->info.packets_written++; ADD(plan, packets_written, 1u); }
    } else { plan->info.write_failures++; ADD(plan, write_failures, 1u); }
    uv_mutex_unlock(&plan->mutex);
}
void solaris_track_read(solaris_observed_plan_t *plan, size_t bytes, const solaris_address_t *peer)
{
    uv_mutex_lock(&plan->mutex); plan->info.bytes_read += bytes; ADD(plan, bytes_read, bytes);
    if (peer != NULL) { plan->info.last_peer = *peer; plan->info.packets_read++; ADD(plan, packets_read, 1u); }
    uv_mutex_unlock(&plan->mutex);
}
