#ifndef SOLARIS_CONNECTION_TRACKER_H
#define SOLARIS_CONNECTION_TRACKER_H

#include <solaris/observe.h>
#include "contracts/flow/plan.h"
#include "contracts/policy/route.h"
#include "runtime/executor/executor.h"

typedef struct solaris_tracker solaris_tracker_t;
typedef struct solaris_observed_plan solaris_tracked_flow_t;
typedef struct solaris_connection_snapshot {
    uint64_t id, node_id, selection_revision, generation, config_revision, inbound_id, rule_index;
    uint32_t worker_id, kind, purpose, state;
    solaris_address_t source, target, dial_target, last_destination, last_peer;
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
    size_t channel_limit;     /* zero selects 32 */
    solaris_address_t source, dial_target;
    uint64_t config_revision, selection_revision, inbound_id, rule_index;
    uint32_t network;
} solaris_observe_options_t;

/* Limits belong to this tracker, not each worker. Closed history is a bounded
 * newest-first ring. Counters are aggregated per worker and purpose; a live
 * totals snapshot is observational across workers, exact after owner fences.
 * Read/list/close methods are thread-safe. destroy requires all plans, channels
 * and callbacks to drain and returns EBUSY until then. */
solaris_status_t solaris_tracker_create(solaris_budget_t *budget, size_t active_limit, size_t history_limit,
                                        solaris_tracker_t **out);
solaris_status_t solaris_tracker_snapshot(solaris_tracker_t *tracker, uint64_t id, solaris_connection_snapshot_t *out);
/* Copies the available ordered prefix; count always reports the total needed. */
solaris_status_t solaris_tracker_list(solaris_tracker_t *tracker, int include_closed,
                                      solaris_connection_snapshot_t *out, size_t capacity, size_t *count);
solaris_status_t solaris_tracker_totals(solaris_tracker_t *tracker, uint32_t purpose, solaris_tracker_totals_t *out);
solaris_status_t solaris_tracker_close_connection(solaris_tracker_t *tracker, uint64_t id);
solaris_status_t solaris_tracker_close_all(solaris_tracker_t *tracker);
solaris_status_t solaris_tracker_destroy(solaris_tracker_t *tracker);
/* Nonterminal readiness check, including final plan destruction/close waiters. */
int solaris_tracker_drained(solaris_tracker_t *tracker);
/* Owned default-allocator copy; remains independent of tracker lifetime.
 * Free the returned array with solaris_tracker_capture_free. */
solaris_status_t solaris_tracker_capture(solaris_tracker_t *tracker, int include_closed,
                                         solaris_connection_snapshot_t **out, size_t *count);
void solaris_tracker_capture_free(solaris_connection_snapshot_t *snapshot);
solaris_status_t solaris_tracker_snapshot_key(solaris_tracker_t *tracker, const solaris_connection_id_t *key,
                                              solaris_connection_snapshot_t *out);
/* Captures active IDs under one lock without closing future admission. NULL
 * key means all; existing ID with a mismatched generation is EAGAIN, missing
 * or closed-history IDs are ECLOSED. After accepted close, callback runs once
 * outside locks after all captured records are fully destroyed. With an empty
 * capture it may run inline; otherwise it runs on the last draining owner.
 * The caller marshals it to its public operation completion channel. */
typedef void (*solaris_tracker_close_fn)(void *context, solaris_status_t status, uint64_t matched);
solaris_status_t solaris_tracker_close_current(solaris_tracker_t *tracker, const solaris_connection_id_t *key,
                                               solaris_tracker_close_fn done, void *context);
/* Admission precedes authentication/routing and may have no target/node yet.
 * close runs on owner and cancels the entire outer TCP/UDP flow, including any
 * pending route. The owner keeps context alive until finish, which invalidates
 * the hook before returning. No extra context reference cycle is introduced. */
solaris_status_t solaris_tracker_admit(solaris_tracker_t *tracker, solaris_executor_t *owner,
                                       const solaris_observe_options_t *options, void (*close)(void *context),
                                       void *context, solaris_tracked_flow_t **out, uint64_t *connection_id);
int solaris_tracker_flow_closing(solaris_tracked_flow_t *flow);
void solaris_tracker_flow_target(solaris_tracked_flow_t *flow, const solaris_address_t *target);
void solaris_tracker_flow_open(solaris_tracked_flow_t *flow);
/* Success moves source into the same admitted record. Failure leaves source
 * owned by the caller. route supplies original and effective targets/revisions. */
solaris_status_t solaris_tracker_attach_plan(solaris_tracked_flow_t *flow, solaris_dial_plan_t *source,
                                             const solaris_route_result_t *route, solaris_dial_plan_t *out);
/* Owner-only full outer-flow barrier. No future close hook can use context.
 * The record persists until its plan and accepted channel callbacks also drain. */
void solaris_tracker_finish(solaris_tracked_flow_t *flow, solaris_status_t status);

/* Owner-only. Success moves source into the returned plan and clears source;
 * failure leaves source owned by the caller. One plan is one logical flow;
 * UDP family lanes share its record. Nested observation is rejected to avoid
 * counting the same application bytes twice. Releasing the plan stops new
 * opens while accepted channels keep independent lifetimes. */
solaris_status_t solaris_observe_plan(solaris_tracker_t *tracker, solaris_dial_plan_t *source,
                                      const solaris_observe_options_t *options, solaris_dial_plan_t *out,
                                      uint64_t *connection_id);

#endif
