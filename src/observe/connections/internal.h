#ifndef SOLARIS_CONNECTION_TRACKER_INTERNAL_H
#define SOLARIS_CONNECTION_TRACKER_INTERNAL_H
#include "observe/connections/tracker.h"
#include <stdatomic.h>
#include <uv.h>

#define SOLARIS_TRACKER_COUNTERS(X) \
    X(created) X(opened) X(closed) X(active) X(open_failures) \
    X(bytes_read) X(bytes_written) X(packets_read) X(packets_written) \
    X(accepted_writes) X(write_failures) X(rejections)
typedef struct solaris_tracker_atomic_totals {
#define COUNTER(name) atomic_uint_fast64_t name;
    SOLARIS_TRACKER_COUNTERS(COUNTER)
#undef COUNTER
} solaris_tracker_atomic_totals_t;
typedef struct solaris_tracker_worker {
    solaris_executor_t *owner;
    solaris_tracker_atomic_totals_t totals[SOLARIS_FLOW_PURPOSE_COUNT];
} solaris_tracker_worker_t;
typedef struct solaris_observed_plan solaris_observed_plan_t;
typedef struct solaris_tracked_channel {
    struct solaris_tracked_channel *next, *previous;
    solaris_observed_plan_t *plan;
    solaris_scope_t scope;
    void (*close)(struct solaris_tracked_channel *, solaris_status_t);
    int accepted;
} solaris_tracked_channel_t;
struct solaris_tracker {
    uv_mutex_t mutex;
    atomic_uint references;
    solaris_budget_t *budget;
    size_t active_limit, history_limit, active_count, history_count, history_next, worker_count;
    uint64_t next_id;
    int closing;
    solaris_observed_plan_t *head;
    solaris_tracker_worker_t workers[32];
    solaris_connection_snapshot_t history[];
};
struct solaris_observed_plan {
    solaris_outbound_t outbound;
    solaris_scope_t scope;
    solaris_deferred_t close_task;
    solaris_tracker_t *tracker;
    solaris_tracker_atomic_totals_t *totals;
    solaris_dial_plan_t source;
    uv_mutex_t mutex;
    solaris_connection_snapshot_t info;
    solaris_observed_plan_t *next, *previous;
    solaris_tracked_channel_t *channels;
    size_t channel_count, channel_limit;
    atomic_int close_requested;
    int retired, released, registered, reference, close_pending, opened_once, stream_attempted;
};

void solaris_track_link(solaris_observed_plan_t *plan, solaris_tracked_channel_t *channel);
void solaris_track_accept(solaris_tracked_channel_t *channel);
void solaris_track_remove(solaris_tracked_channel_t *channel, solaris_status_t status);
void solaris_track_open(solaris_observed_plan_t *plan, solaris_status_t status);
void solaris_track_reject(solaris_observed_plan_t *plan, solaris_status_t status);
void solaris_track_submit(solaris_observed_plan_t *plan, size_t bytes, const solaris_address_t *target);
void solaris_track_written(solaris_observed_plan_t *plan, size_t bytes, int datagram, solaris_status_t status);
void solaris_track_read(solaris_observed_plan_t *plan, size_t bytes, const solaris_address_t *peer);
solaris_status_t solaris_tracked_stream_open(solaris_observed_plan_t *plan, const solaris_address_t *target,
    const solaris_stream_callbacks_t *callbacks, void *context, solaris_stream_t **out);
solaris_status_t solaris_tracked_datagram_open(solaris_observed_plan_t *plan, uint32_t family,
    const solaris_datagram_callbacks_t *callbacks, void *context, solaris_datagram_t **out);

#endif
