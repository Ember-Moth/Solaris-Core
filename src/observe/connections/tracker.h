#ifndef SOLARIS_CONNECTION_TRACKER_H
#define SOLARIS_CONNECTION_TRACKER_H

#include "contracts/flow/plan.h"
#include "runtime/executor/executor.h"

typedef struct solaris_tracker solaris_tracker_t;
enum { SOLARIS_FLOW_STREAM = 1u, SOLARIS_FLOW_DATAGRAM = 2u };
enum { SOLARIS_FLOW_USER, SOLARIS_FLOW_PROBE, SOLARIS_FLOW_PURPOSE_COUNT };
enum { SOLARIS_CONNECTION_OPENING, SOLARIS_CONNECTION_OPEN, SOLARIS_CONNECTION_CLOSING, SOLARIS_CONNECTION_CLOSED };
typedef struct solaris_connection_snapshot {
    uint64_t id, node_id, selection_revision, generation;
    uint32_t worker_id, kind, purpose, state;
    solaris_address_t target, last_destination, last_peer;
    uint64_t created_ns, opened_ns, closed_ns;
    uint64_t bytes_read, bytes_written, packets_read, packets_written;
    uint64_t accepted_writes, write_failures, rejections;
    size_t pending_bytes, pending_requests, active_channels;
    solaris_status_t status;
} solaris_connection_snapshot_t;
typedef struct solaris_tracker_totals {
    uint64_t created, opened, closed, active, open_failures;
    uint64_t bytes_read, bytes_written, packets_read, packets_written;
    uint64_t accepted_writes, write_failures, rejections;
} solaris_tracker_totals_t;
typedef struct solaris_observe_options {
    uint32_t kind, purpose;
    solaris_address_t target; /* immutable first target, including UDP */
    size_t channel_limit;    /* zero selects 32 */
} solaris_observe_options_t;

/* Limits belong to this tracker, not each worker. Closed history is a bounded
 * newest-first ring. Counters are aggregated per worker and purpose; a live
 * totals snapshot is observational across workers, exact after owner fences.
 * Read/list/close methods are thread-safe. destroy requires all plans, channels
 * and callbacks to drain and returns EBUSY until then. */
solaris_status_t solaris_tracker_create(solaris_budget_t *budget, size_t active_limit,
    size_t history_limit, solaris_tracker_t **out);
solaris_status_t solaris_tracker_snapshot(solaris_tracker_t *tracker, uint64_t id, solaris_connection_snapshot_t *out);
/* Copies the available ordered prefix; count always reports the total needed. */
solaris_status_t solaris_tracker_list(solaris_tracker_t *tracker, int include_closed,
    solaris_connection_snapshot_t *out, size_t capacity, size_t *count);
solaris_status_t solaris_tracker_totals(solaris_tracker_t *tracker, uint32_t purpose, solaris_tracker_totals_t *out);
solaris_status_t solaris_tracker_close_connection(solaris_tracker_t *tracker, uint64_t id);
solaris_status_t solaris_tracker_close_all(solaris_tracker_t *tracker);
solaris_status_t solaris_tracker_destroy(solaris_tracker_t *tracker);

/* Owner-only. Success moves source into the returned plan and clears source;
 * failure leaves source owned by the caller. One plan is one logical flow;
 * UDP family lanes share its record. Nested observation is rejected to avoid
 * counting the same application bytes twice. Releasing the plan stops new
 * opens while accepted channels keep independent lifetimes. */
solaris_status_t solaris_observe_plan(solaris_tracker_t *tracker, solaris_dial_plan_t *source,
    const solaris_observe_options_t *options, solaris_dial_plan_t *out, uint64_t *connection_id);

#endif
