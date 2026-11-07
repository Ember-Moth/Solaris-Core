#include "observe/connections/internal.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define ADD(plan, name, n) ((void)atomic_fetch_add_explicit(&(plan)->totals->name, (uint64_t)(n), memory_order_relaxed))
typedef struct close_request close_request_t;
struct solaris_close_link {
    solaris_close_link_t *next;
    close_request_t *request;
};
struct close_request {
    solaris_tracker_t *tracker;
    solaris_tracker_close_fn done;
    void *context;
    size_t remaining;
    uint64_t matched;
    solaris_close_link_t links[];
};
static void finalize(solaris_observed_plan_t *plan)
{
    if (!plan->finished || (plan->attached && !plan->released) || plan->channels || !plan->registered ||
        plan->finalizing)
        return;
    solaris_tracker_t *tracker = plan->tracker;
    uv_mutex_lock(&tracker->mutex);
    if (plan->close_pending) {
        uv_mutex_unlock(&tracker->mutex);
        return;
    }
    plan->finalizing = 1;
    uv_mutex_lock(&plan->mutex);
    plan->info.state = SOLARIS_CONNECTION_CLOSING;
    uv_mutex_unlock(&plan->mutex);
    uv_mutex_unlock(&tracker->mutex);
    solaris_scope_release(&plan->scope); /* registry lease; unlink only after full destruction */
}
static void close_outer(solaris_observed_plan_t *plan)
{
    if (!plan->finished && !plan->close_called && plan->close_flow) {
        plan->close_called = 1;
        plan->close_flow(plan->close_context);
    }
}
static void close_channels(solaris_observed_plan_t *plan)
{
    for (solaris_tracked_channel_t *channel = plan->channels; channel; channel = channel->next)
        channel->close(channel, SOLARIS_ECANCELLED);
}
static void cancelled(void *context)
{
    solaris_observed_plan_t *plan = context;
    plan->retired = 1;
    if (!plan->finished) {
        close_outer(plan);
        close_channels(plan);
    }
}
static void notify_waiters(solaris_close_link_t *link)
{
    while (link) {
        solaris_close_link_t *next = link->next;
        close_request_t *request = link->request;
        solaris_tracker_t *tracker = request->tracker;
        uv_mutex_lock(&tracker->mutex);
        assert(request->remaining);
        int ready = --request->remaining == 0;
        uv_mutex_unlock(&tracker->mutex);
        if (ready) {
            request->done(request->context, SOLARIS_OK, request->matched);
            solaris_memory_free(request);
            (void)atomic_fetch_sub_explicit(&tracker->references, 1u, memory_order_release);
        }
        link = next;
    }
}
static void destroyed(void *context)
{
    solaris_observed_plan_t *plan = context;
    assert(!plan->channels);
    if (plan->source.outbound) {
        solaris_status_t rc = solaris_dial_plan_release(&plan->source);
        assert(rc == SOLARIS_OK);
        (void)rc;
    }
    solaris_tracker_t *tracker = plan->reference ? plan->tracker : NULL;
    solaris_close_link_t *waiters = NULL;
    if (plan->registered) {
        assert(plan->finalizing);
        uv_mutex_lock(&tracker->mutex);
        uv_mutex_lock(&plan->mutex);
        plan->info.state = SOLARIS_CONNECTION_CLOSED;
        plan->info.closed_ns = solaris_executor_now_ns(plan->outbound.owner);
        if (tracker->history_limit) {
            tracker->history[tracker->history_next] = plan->info;
            tracker->history_next = (tracker->history_next + 1) % tracker->history_limit;
            if (tracker->history_count < tracker->history_limit)
                tracker->history_count++;
        }
        uv_mutex_unlock(&plan->mutex);
        if (plan->previous)
            plan->previous->next = plan->next;
        else
            tracker->head = plan->next;
        if (plan->next)
            plan->next->previous = plan->previous;
        tracker->active_count--;
        plan->registered = 0;
        waiters = plan->waiters;
        uv_mutex_unlock(&tracker->mutex);
        ADD(plan, closed, 1u);
        (void)atomic_fetch_sub_explicit(&plan->totals->active, 1u, memory_order_relaxed);
    }
    uv_mutex_destroy(&plan->mutex);
    solaris_memory_free(plan);
    notify_waiters(waiters);
    if (tracker)
        (void)atomic_fetch_sub_explicit(&tracker->references, 1u, memory_order_release);
}
void solaris_tracker_finish(solaris_tracked_flow_t *plan, solaris_status_t status)
{
    if (!plan)
        return;
    assert(solaris_executor_is_owner(plan->outbound.owner));
    if (plan->finished)
        return;
    plan->finished = 1;
    plan->retired = 1;
    plan->close_flow = NULL;
    plan->close_context = NULL;
    uv_mutex_lock(&plan->mutex);
    if (plan->info.status == SOLARIS_OK && status != SOLARIS_OK)
        plan->info.status = status;
    plan->info.state = SOLARIS_CONNECTION_CLOSING;
    uv_mutex_unlock(&plan->mutex);
    solaris_scope_cancel(&plan->scope);
    finalize(plan);
    if (plan->caller_reference) {
        plan->caller_reference = 0;
        solaris_scope_release(&plan->scope);
    }
}
static void release_plan(void *context)
{
    solaris_observed_plan_t *plan = context;
    assert(plan->attached && !plan->released);
    plan->released = 1;
    if (plan->auto_finish)
        solaris_tracker_finish(plan, SOLARIS_OK);
    finalize(plan);
    solaris_scope_release(&plan->scope); /* returned-plan lease */
}
static void close_entry(void *context)
{
    solaris_observed_plan_t *plan = context;
    uv_mutex_lock(&plan->tracker->mutex);
    plan->close_pending = 0;
    uv_mutex_unlock(&plan->tracker->mutex);
    plan->retired = 1;
    uv_mutex_lock(&plan->mutex);
    plan->info.state = SOLARIS_CONNECTION_CLOSING;
    if (plan->info.status == SOLARIS_OK)
        plan->info.status = SOLARIS_ECANCELLED;
    uv_mutex_unlock(&plan->mutex);
    close_outer(plan);
    close_channels(plan);
    solaris_scope_cancel(&plan->scope);
    finalize(plan);
}
static solaris_status_t request_close(solaris_observed_plan_t *plan)
{
    if (atomic_load_explicit(&plan->close_requested, memory_order_relaxed) || plan->finalizing)
        return SOLARIS_OK;
    atomic_store_explicit(&plan->close_requested, 1, memory_order_release);
    plan->close_pending = 1;
    solaris_status_t rc = solaris_executor_defer(plan->outbound.owner, &plan->close_task);
    if (rc != SOLARIS_OK) {
        atomic_store(&plan->close_requested, 0);
        plan->close_pending = 0;
    }
    return rc;
}
solaris_status_t solaris_tracker_create(solaris_budget_t *budget, size_t active_limit, size_t history_limit,
                                        solaris_tracker_t **out)
{
    if (!out)
        return SOLARIS_EINVAL;
    *out = NULL;
    if (!budget || !active_limit || active_limit > 65536 || history_limit > 65536)
        return SOLARIS_EINVAL;
    solaris_tracker_t *tracker =
        solaris_memory_allocate(budget, sizeof(*tracker) + history_limit * sizeof(*tracker->history));
    if (!tracker)
        return SOLARIS_ENOMEM;
    memset(tracker, 0, sizeof(*tracker) + history_limit * sizeof(*tracker->history));
    atomic_init(&tracker->references, 1u);
    if (uv_mutex_init(&tracker->mutex)) {
        solaris_memory_free(tracker);
        return SOLARIS_EIO;
    }
    tracker->budget = budget;
    tracker->active_limit = active_limit;
    tracker->history_limit = history_limit;
    *out = tracker;
    return SOLARIS_OK;
}
solaris_status_t solaris_tracker_snapshot(solaris_tracker_t *tracker, uint64_t id, solaris_connection_snapshot_t *out)
{
    if (!tracker || !id || !out)
        return SOLARIS_EINVAL;
    uv_mutex_lock(&tracker->mutex);
    for (solaris_observed_plan_t *plan = tracker->head; plan; plan = plan->next)
        if (plan->info.id == id) {
            uv_mutex_lock(&plan->mutex);
            *out = plan->info;
            uv_mutex_unlock(&plan->mutex);
            uv_mutex_unlock(&tracker->mutex);
            return SOLARIS_OK;
        }
    for (size_t i = 0; i < tracker->history_count; ++i)
        if (tracker->history[i].id == id) {
            *out = tracker->history[i];
            uv_mutex_unlock(&tracker->mutex);
            return SOLARIS_OK;
        }
    uv_mutex_unlock(&tracker->mutex);
    return SOLARIS_ECLOSED;
}
solaris_status_t solaris_tracker_snapshot_key(solaris_tracker_t *tracker, const solaris_connection_id_t *key,
                                              solaris_connection_snapshot_t *out)
{
    if (!key || !key->id || !key->generation)
        return SOLARIS_EINVAL;
    solaris_status_t rc = solaris_tracker_snapshot(tracker, key->id, out);
    return rc == SOLARIS_OK && out->generation != key->generation ? SOLARIS_EAGAIN : rc;
}
static void copy_locked(solaris_tracker_t *tracker, int closed, solaris_connection_snapshot_t *out, size_t capacity)
{
    size_t used = 0;
    for (solaris_observed_plan_t *plan = tracker->head; plan && used < capacity; plan = plan->next) {
        uv_mutex_lock(&plan->mutex);
        out[used++] = plan->info;
        uv_mutex_unlock(&plan->mutex);
    }
    if (closed)
        for (size_t i = 0; i < tracker->history_count && used < capacity; ++i)
            out[used++] =
                tracker->history[(tracker->history_next + tracker->history_limit - 1 - i) % tracker->history_limit];
}
solaris_status_t solaris_tracker_list(solaris_tracker_t *tracker, int include_closed,
                                      solaris_connection_snapshot_t *out, size_t capacity, size_t *count)
{
    if (!tracker || !count || (!out && capacity))
        return SOLARIS_EINVAL;
    uv_mutex_lock(&tracker->mutex);
    *count = tracker->active_count + (include_closed ? tracker->history_count : 0);
    copy_locked(tracker, include_closed, out, capacity);
    solaris_status_t rc = capacity < *count ? SOLARIS_EMSGSIZE : SOLARIS_OK;
    uv_mutex_unlock(&tracker->mutex);
    return rc;
}
solaris_status_t solaris_tracker_capture(solaris_tracker_t *tracker, int include_closed,
                                         solaris_connection_snapshot_t **out, size_t *count)
{
    if (!tracker || !out || !count || (include_closed != 0 && include_closed != 1))
        return SOLARIS_EINVAL;
    *out = NULL;
    *count = 0;
    uv_mutex_lock(&tracker->mutex);
    size_t n = tracker->active_count + (include_closed ? tracker->history_count : 0);
    solaris_connection_snapshot_t *copy = n ? malloc(n * sizeof(*copy)) : NULL;
    if (n && !copy) {
        uv_mutex_unlock(&tracker->mutex);
        return SOLARIS_ENOMEM;
    }
    copy_locked(tracker, include_closed, copy, n);
    uv_mutex_unlock(&tracker->mutex);
    *out = copy;
    *count = n;
    return SOLARIS_OK;
}
void solaris_tracker_capture_free(solaris_connection_snapshot_t *snapshot)
{
    free(snapshot);
}
solaris_status_t solaris_tracker_totals(solaris_tracker_t *tracker, uint32_t purpose, solaris_tracker_totals_t *out)
{
    if (!tracker || !out || purpose >= SOLARIS_FLOW_PURPOSE_COUNT)
        return SOLARIS_EINVAL;
    memset(out, 0, sizeof(*out));
    uv_mutex_lock(&tracker->mutex);
    for (size_t i = 0; i < tracker->worker_count; ++i) {
#define LOAD(name) out->name += atomic_load_explicit(&tracker->workers[i].totals[purpose].name, memory_order_relaxed);
        SOLARIS_TRACKER_COUNTERS(LOAD)
#undef LOAD
    }
    uv_mutex_unlock(&tracker->mutex);
    return SOLARIS_OK;
}
solaris_status_t solaris_tracker_close_connection(solaris_tracker_t *tracker, uint64_t id)
{
    if (!tracker || !id)
        return SOLARIS_EINVAL;
    uv_mutex_lock(&tracker->mutex);
    solaris_status_t rc = SOLARIS_ECLOSED;
    for (solaris_observed_plan_t *plan = tracker->head; plan; plan = plan->next)
        if (plan->info.id == id) {
            rc = request_close(plan);
            break;
        }
    uv_mutex_unlock(&tracker->mutex);
    return rc;
}
solaris_status_t solaris_tracker_close_all(solaris_tracker_t *tracker)
{
    if (!tracker)
        return SOLARIS_EINVAL;
    uv_mutex_lock(&tracker->mutex);
    tracker->closing = 1;
    solaris_status_t status = SOLARIS_OK;
    for (solaris_observed_plan_t *plan = tracker->head; plan; plan = plan->next) {
        solaris_status_t rc = request_close(plan);
        if (rc != SOLARIS_OK)
            status = rc;
    }
    uv_mutex_unlock(&tracker->mutex);
    return status;
}
solaris_status_t solaris_tracker_close_current(solaris_tracker_t *tracker, const solaris_connection_id_t *key,
                                               solaris_tracker_close_fn done, void *context)
{
    if (!tracker || !done || (key && (!key->id || !key->generation)))
        return SOLARIS_EINVAL;
    uv_mutex_lock(&tracker->mutex);
    size_t count = 0;
    solaris_observed_plan_t *selected = NULL;
    for (solaris_observed_plan_t *plan = tracker->head; plan; plan = plan->next) {
        if (!key)
            ++count;
        else if (plan->info.id == key->id) {
            selected = plan;
            count = 1;
            break;
        }
    }
    if (key && selected && selected->info.generation != key->generation) {
        uv_mutex_unlock(&tracker->mutex);
        return SOLARIS_EAGAIN;
    }
    if (key && !selected) {
        solaris_status_t rc = SOLARIS_ECLOSED;
        for (size_t i = 0; i < tracker->history_count; ++i)
            if (tracker->history[i].id == key->id && tracker->history[i].generation != key->generation)
                rc = SOLARIS_EAGAIN;
        uv_mutex_unlock(&tracker->mutex);
        return rc;
    }
    if (!count) {
        uv_mutex_unlock(&tracker->mutex);
        done(context, SOLARIS_OK, 0);
        return SOLARIS_OK;
    }
    close_request_t *request =
        solaris_memory_allocate(tracker->budget, sizeof(*request) + count * sizeof(*request->links));
    if (!request) {
        uv_mutex_unlock(&tracker->mutex);
        return SOLARIS_ENOMEM;
    }
    memset(request, 0, sizeof(*request) + count * sizeof(*request->links));
    request->tracker = tracker;
    request->done = done;
    request->context = context;
    request->remaining = count;
    request->matched = count;
    (void)atomic_fetch_add_explicit(&tracker->references, 1u, memory_order_relaxed);
    size_t i = 0;
    for (solaris_observed_plan_t *plan = tracker->head; plan; plan = plan->next) {
        if (key && plan != selected)
            continue;
        solaris_close_link_t *link = &request->links[i++];
        link->request = request;
        link->next = plan->waiters;
        plan->waiters = link;
        solaris_status_t rc = request_close(plan);
        assert(rc == SOLARIS_OK);
        (void)rc;
        if (key)
            break;
    }
    uv_mutex_unlock(&tracker->mutex);
    return SOLARIS_OK;
}
int solaris_tracker_drained(solaris_tracker_t *tracker)
{
    if (!tracker)
        return 1;
    uv_mutex_lock(&tracker->mutex);
    int drained = !tracker->active_count && atomic_load_explicit(&tracker->references, memory_order_acquire) == 1u;
    uv_mutex_unlock(&tracker->mutex);
    return drained;
}
solaris_status_t solaris_tracker_destroy(solaris_tracker_t *tracker)
{
    if (!tracker)
        return SOLARIS_OK;
    uv_mutex_lock(&tracker->mutex);
    if (tracker->active_count || atomic_load_explicit(&tracker->references, memory_order_acquire) != 1u) {
        uv_mutex_unlock(&tracker->mutex);
        return SOLARIS_EBUSY;
    }
    tracker->closing = 1;
    uv_mutex_unlock(&tracker->mutex);
    uv_mutex_destroy(&tracker->mutex);
    solaris_memory_free(tracker);
    return SOLARIS_OK;
}
static int accepting(solaris_observed_plan_t *plan)
{
    return plan->attached && !plan->released && !plan->retired &&
           !atomic_load_explicit(&plan->close_requested, memory_order_acquire) &&
           solaris_executor_accepting(plan->outbound.owner);
}
static uint32_t capabilities(void *state)
{
    solaris_observed_plan_t *plan = state;
    uint32_t caps = 0;
    if (accepting(plan))
        (void)solaris_outbound_capabilities(plan->source.outbound, &caps);
    return caps &
           ((plan->info.kind == SOLARIS_FLOW_STREAM
                 ? SOLARIS_OUTBOUND_STREAM | SOLARIS_OUTBOUND_STREAM_DOMAIN | SOLARIS_OUTBOUND_HALF_CLOSE
                 : SOLARIS_OUTBOUND_DATAGRAM | SOLARIS_OUTBOUND_DATAGRAM_MULTI | SOLARIS_OUTBOUND_DATAGRAM_DOMAIN) |
            SOLARIS_OUTBOUND_LOCAL_RESOLUTION);
}
static solaris_status_t open_stream(void *state, const solaris_address_t *target,
                                    const solaris_stream_callbacks_t *callbacks, void *context, solaris_stream_t **out)
{
    solaris_observed_plan_t *plan = state;
    if (!accepting(plan))
        return SOLARIS_ECLOSED;
    if (plan->info.kind != SOLARIS_FLOW_STREAM)
        return SOLARIS_ENOTSUP;
    if (!solaris_address_equal(target, &plan->info.dial_target))
        return SOLARIS_EINVAL;
    if (plan->stream_attempted)
        return SOLARIS_EBUSY;
    plan->stream_attempted = 1;
    solaris_status_t rc = solaris_tracked_stream_open(plan, target, callbacks, context, out);
    if (rc != SOLARIS_OK)
        solaris_track_open(plan, rc);
    return rc;
}
static solaris_status_t open_datagram(void *state, uint32_t family, const solaris_datagram_callbacks_t *callbacks,
                                      void *context, solaris_datagram_t **out)
{
    solaris_observed_plan_t *plan = state;
    if (!accepting(plan))
        return SOLARIS_ECLOSED;
    if (plan->info.kind != SOLARIS_FLOW_DATAGRAM)
        return SOLARIS_ENOTSUP;
    if (plan->channel_count >= plan->channel_limit)
        return SOLARIS_EAGAIN;
    solaris_status_t rc = solaris_tracked_datagram_open(plan, family, callbacks, context, out);
    if (rc != SOLARIS_OK)
        solaris_track_open(plan, rc);
    return rc;
}
static void retire(void *state)
{
    ((solaris_observed_plan_t *)state)->retired = 1;
}
static const solaris_outbound_ops_t operations = {capabilities, open_stream, open_datagram, retire};
solaris_status_t solaris_tracker_admit(solaris_tracker_t *tracker, solaris_executor_t *owner,
                                       const solaris_observe_options_t *options, void (*close)(void *), void *context,
                                       solaris_tracked_flow_t **out, uint64_t *connection_id)
{
    if (!out)
        return SOLARIS_EINVAL;
    *out = NULL;
    if (connection_id)
        *connection_id = 0;
    if (!tracker || !owner || !options || options->purpose >= SOLARIS_FLOW_PURPOSE_COUNT ||
        (options->kind != SOLARIS_FLOW_STREAM && options->kind != SOLARIS_FLOW_DATAGRAM) ||
        options->channel_limit > 1024)
        return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(owner))
        return SOLARIS_ETHREAD;
    solaris_observed_plan_t *plan = solaris_memory_allocate(tracker->budget, sizeof(*plan));
    if (!plan)
        return SOLARIS_ENOMEM;
    memset(plan, 0, sizeof(*plan));
    atomic_init(&plan->close_requested, 0);
    if (uv_mutex_init(&plan->mutex)) {
        solaris_memory_free(plan);
        return SOLARIS_EIO;
    }
    plan->tracker = tracker;
    plan->outbound = (solaris_outbound_t){&operations, plan, owner};
    plan->channel_limit = options->channel_limit ? options->channel_limit : 32;
    plan->close_flow = close;
    plan->close_context = context;
    plan->close_task = (solaris_deferred_t){.run = close_entry, .context = plan};
    solaris_status_t rc = solaris_scope_init(&plan->scope, owner, cancelled, destroyed, plan);
    if (rc != SOLARIS_OK) {
        uv_mutex_destroy(&plan->mutex);
        solaris_memory_free(plan);
        return rc;
    }
    plan->info = (solaris_connection_snapshot_t){.generation = solaris_executor_generation(owner),
                                                 .worker_id = solaris_executor_id(owner),
                                                 .kind = options->kind,
                                                 .purpose = options->purpose,
                                                 .source = options->source,
                                                 .target = options->target,
                                                 .dial_target = options->dial_target.family ? options->dial_target
                                                                                            : options->target,
                                                 .config_revision = options->config_revision,
                                                 .selection_revision = options->selection_revision,
                                                 .inbound_id = options->inbound_id,
                                                 .rule_index = options->rule_index,
                                                 .created_ns = solaris_executor_now_ns(owner)};
    uv_mutex_lock(&tracker->mutex);
    if (tracker->closing)
        rc = SOLARIS_ECLOSED;
    else if (tracker->active_count >= tracker->active_limit)
        rc = SOLARIS_EAGAIN;
    else if (tracker->next_id == UINT64_MAX)
        rc = SOLARIS_EOVERFLOW;
    size_t worker = 0;
    while (worker < tracker->worker_count && tracker->workers[worker].owner != owner)
        worker++;
    if (rc == SOLARIS_OK && worker == tracker->worker_count) {
        if (worker == 32)
            rc = SOLARIS_EAGAIN;
        else {
            tracker->workers[worker].owner = owner;
            for (size_t purpose = 0; purpose < SOLARIS_FLOW_PURPOSE_COUNT; ++purpose) {
#define INIT(name) atomic_init(&tracker->workers[worker].totals[purpose].name, 0u);
                SOLARIS_TRACKER_COUNTERS(INIT)
#undef INIT
            }
            tracker->worker_count++;
        }
    }
    if (rc == SOLARIS_OK) {
        plan->totals = &tracker->workers[worker].totals[options->purpose];
        plan->info.id = ++tracker->next_id;
        plan->next = tracker->head;
        if (tracker->head)
            tracker->head->previous = plan;
        tracker->head = plan;
        tracker->active_count++;
        plan->registered = plan->reference = plan->caller_reference = 1;
        atomic_fetch_add_explicit(&tracker->references, 1u, memory_order_relaxed);
        solaris_scope_retain(&plan->scope);
        solaris_scope_retain(&plan->scope); /* admission caller and registry */
        ADD(plan, created, 1);
        ADD(plan, active, 1);
    }
    uv_mutex_unlock(&tracker->mutex);
    if (rc != SOLARIS_OK) {
        plan->finished = 1;
        plan->close_flow = NULL;
        plan->close_context = NULL;
        solaris_scope_cancel(&plan->scope);
        return rc;
    }
    *out = plan;
    if (connection_id)
        *connection_id = plan->info.id;
    return SOLARIS_OK;
}
int solaris_tracker_flow_closing(solaris_tracked_flow_t *flow)
{
    return flow &&
           (flow->finished || flow->retired || atomic_load_explicit(&flow->close_requested, memory_order_acquire));
}
void solaris_tracker_flow_target(solaris_tracked_flow_t *flow, const solaris_address_t *target)
{
    if (!flow || !target)
        return;
    assert(solaris_executor_is_owner(flow->outbound.owner));
    uv_mutex_lock(&flow->mutex);
    flow->info.target = *target;
    uv_mutex_unlock(&flow->mutex);
}
void solaris_tracker_flow_open(solaris_tracked_flow_t *flow)
{
    if (flow && !solaris_tracker_flow_closing(flow))
        solaris_track_open(flow, SOLARIS_OK);
}
solaris_status_t solaris_tracker_attach_plan(solaris_tracked_flow_t *flow, solaris_dial_plan_t *source,
                                             const solaris_route_result_t *route, solaris_dial_plan_t *out)
{
    if (!out || out == source)
        return SOLARIS_EINVAL;
    memset(out, 0, sizeof(*out));
    if (!flow || !source || !source->outbound || !source->release || !source->node_id ||
        (source->flags & SOLARIS_PLAN_OBSERVED) || !route)
        return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(flow->outbound.owner) || source->outbound->owner != flow->outbound.owner)
        return SOLARIS_ETHREAD;
    if (solaris_tracker_flow_closing(flow) || !solaris_executor_accepting(flow->outbound.owner))
        return SOLARIS_ECLOSED;
    if (flow->attached)
        return SOLARIS_EBUSY;
    flow->attached = 1;
    flow->source = *source;
    uv_mutex_lock(&flow->mutex);
    flow->info.node_id = source->node_id;
    flow->info.selection_revision = source->selection_revision;
    flow->info.config_revision = route->metadata.config_revision;
    flow->info.inbound_id = route->metadata.inbound_id;
    flow->info.source = route->metadata.source;
    flow->info.target = route->metadata.destination;
    flow->info.dial_target = route->dial_target;
    flow->info.rule_index = route->rule_index;
    uv_mutex_unlock(&flow->mutex);
    solaris_scope_retain(&flow->scope);
    *out = (solaris_dial_plan_t){.outbound = &flow->outbound,
                                 .context = flow,
                                 .release = release_plan,
                                 .node_id = source->node_id,
                                 .selection_revision = source->selection_revision,
                                 .flags = source->flags | SOLARIS_PLAN_OBSERVED};
    memset(source, 0, sizeof(*source));
    return SOLARIS_OK;
}
solaris_status_t solaris_observe_plan(solaris_tracker_t *tracker, solaris_dial_plan_t *source,
                                      const solaris_observe_options_t *options, solaris_dial_plan_t *out,
                                      uint64_t *connection_id)
{
    if (!out || out == source)
        return SOLARIS_EINVAL;
    memset(out, 0, sizeof(*out));
    if (connection_id)
        *connection_id = 0;
    if (!source || !source->outbound || !source->release || !source->node_id ||
        (source->flags & SOLARIS_PLAN_OBSERVED) || !options)
        return SOLARIS_EINVAL;
    solaris_tracked_flow_t *flow;
    solaris_status_t rc = solaris_tracker_admit(tracker, source->outbound->owner, options, NULL, NULL, &flow, NULL);
    if (rc != SOLARIS_OK)
        return rc;
    solaris_route_result_t route = {.metadata = {.source = options->source,
                                                 .destination = options->target,
                                                 .config_revision = options->config_revision,
                                                 .selection_revision = source->selection_revision,
                                                 .inbound_id = options->inbound_id},
                                    .dial_target = options->dial_target.family ? options->dial_target : options->target,
                                    .rule_index = options->rule_index};
    rc = solaris_tracker_attach_plan(flow, source, &route, out);
    if (rc != SOLARIS_OK) {
        solaris_tracker_finish(flow, rc);
        return rc;
    }
    flow->auto_finish = 1;
    flow->caller_reference = 0;
    solaris_scope_release(&flow->scope);
    if (connection_id)
        *connection_id = flow->info.id;
    return SOLARIS_OK;
}

void solaris_track_link(solaris_observed_plan_t *plan, solaris_tracked_channel_t *channel)
{
    channel->plan = plan;
    channel->next = plan->channels;
    if (plan->channels != NULL)
        plan->channels->previous = channel;
    plan->channels = channel;
    plan->channel_count++;
    solaris_scope_retain(&plan->scope);
}
void solaris_track_accept(solaris_tracked_channel_t *channel)
{
    channel->accepted = 1;
    uv_mutex_lock(&channel->plan->mutex);
    channel->plan->info.active_channels++;
    uv_mutex_unlock(&channel->plan->mutex);
}
void solaris_track_remove(solaris_tracked_channel_t *channel, solaris_status_t status)
{
    solaris_observed_plan_t *plan = channel->plan;
    uv_mutex_lock(&plan->mutex);
    if (channel->accepted)
        plan->info.active_channels--;
    if (plan->info.status == SOLARIS_OK && status != SOLARIS_OK)
        plan->info.status = status;
    uv_mutex_unlock(&plan->mutex);
    if (channel->previous != NULL)
        channel->previous->next = channel->next;
    else
        plan->channels = channel->next;
    if (channel->next != NULL)
        channel->next->previous = channel->previous;
    plan->channel_count--;
    finalize(plan);
    solaris_scope_release(&plan->scope);
}
void solaris_track_open(solaris_observed_plan_t *plan, solaris_status_t status)
{
    uv_mutex_lock(&plan->mutex);
    if (status == SOLARIS_OK) {
        if (!plan->opened_once) {
            plan->opened_once = 1;
            plan->info.opened_ns = solaris_executor_now_ns(plan->outbound.owner);
            ADD(plan, opened, 1u);
        }
        if (!atomic_load(&plan->close_requested))
            plan->info.state = SOLARIS_CONNECTION_OPEN;
    } else {
        ADD(plan, open_failures, 1u);
        if (plan->info.status == SOLARIS_OK)
            plan->info.status = status;
    }
    uv_mutex_unlock(&plan->mutex);
}
void solaris_track_reject(solaris_observed_plan_t *plan, solaris_status_t status)
{
    (void)status;
    uv_mutex_lock(&plan->mutex);
    plan->info.rejections++;
    ADD(plan, rejections, 1u);
    uv_mutex_unlock(&plan->mutex);
}
void solaris_track_submit(solaris_observed_plan_t *plan, size_t bytes, const solaris_address_t *target)
{
    uv_mutex_lock(&plan->mutex);
    plan->info.pending_bytes += bytes;
    plan->info.pending_requests++;
    plan->info.accepted_writes++;
    if (target != NULL)
        plan->info.last_destination = *target;
    ADD(plan, accepted_writes, 1u);
    uv_mutex_unlock(&plan->mutex);
}
void solaris_track_written(solaris_observed_plan_t *plan, size_t bytes, int datagram, solaris_status_t status)
{
    uv_mutex_lock(&plan->mutex);
    plan->info.pending_bytes -= bytes;
    plan->info.pending_requests--;
    if (status == SOLARIS_OK) {
        plan->info.bytes_written += bytes;
        ADD(plan, bytes_written, bytes);
        if (datagram) {
            plan->info.packets_written++;
            ADD(plan, packets_written, 1u);
        }
    } else {
        plan->info.write_failures++;
        ADD(plan, write_failures, 1u);
    }
    uv_mutex_unlock(&plan->mutex);
}
void solaris_track_read(solaris_observed_plan_t *plan, size_t bytes, const solaris_address_t *peer)
{
    uv_mutex_lock(&plan->mutex);
    plan->info.bytes_read += bytes;
    ADD(plan, bytes_read, bytes);
    if (peer != NULL) {
        plan->info.last_peer = *peer;
        plan->info.packets_read++;
        ADD(plan, packets_read, 1u);
    }
    uv_mutex_unlock(&plan->mutex);
}
