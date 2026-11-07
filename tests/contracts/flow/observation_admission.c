#include "observe/connections/tracker.h"
#include "support/runtime/event.h"
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x)                                                                                                       \
    do {                                                                                                               \
        if (!(x)) {                                                                                                    \
            fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x);                                                    \
            abort();                                                                                                   \
        }                                                                                                              \
    } while (0)
typedef struct completion {
    solaris_test_event_t done;
    atomic_uint calls;
    uint64_t matched;
} completion_t;
typedef struct flow {
    solaris_tracker_t *tracker;
    solaris_executor_t *owner;
    solaris_tracked_flow_t *handle;
    solaris_connection_id_t key;
    solaris_test_event_t step, closed;
    atomic_uint close_calls;
    completion_t *after_finish;
} flow_t;
static atomic_int fail_allocate;
static void *allocate(void *context, size_t length)
{
    (void)context;
    return atomic_load(&fail_allocate) ? NULL : malloc(length);
}
static void completed(void *context, solaris_status_t status, uint64_t matched)
{
    completion_t *completion = context;
    CHECK(status == SOLARIS_OK && atomic_fetch_add(&completion->calls, 1) == 0);
    completion->matched = matched;
    solaris_test_event_signal(&completion->done);
}
static void completion_init(completion_t *completion)
{
    memset(completion, 0, sizeof(*completion));
    atomic_init(&completion->calls, 0);
    CHECK(!solaris_test_event_init(&completion->done, 0));
}
static void closed(void *context)
{
    flow_t *flow = context;
    CHECK(solaris_executor_is_owner(flow->owner) && atomic_fetch_add(&flow->close_calls, 1) == 0);
    solaris_test_event_signal(&flow->closed);
    /* Deliberately keep the outer flow alive until the host releases its gate. */
}
static void admit(void *context, solaris_status_t status)
{
    flow_t *flow = context;
    CHECK(status == SOLARIS_OK);
    solaris_observe_options_t options = {.kind = SOLARIS_FLOW_STREAM,
                                         .purpose = SOLARIS_FLOW_USER,
                                         .config_revision = 11,
                                         .selection_revision = 19,
                                         .inbound_id = 29,
                                         .rule_index = UINT64_MAX};
    CHECK(solaris_address_parse("127.0.0.1", 12345, &options.source) == SOLARIS_OK);
    CHECK(solaris_tracker_admit(flow->tracker, flow->owner, &options, closed, flow, &flow->handle, &flow->key.id) ==
          SOLARIS_OK);
    flow->key.generation = solaris_executor_generation(flow->owner);
    solaris_test_event_signal(&flow->step);
}
static void finish(void *context, solaris_status_t status)
{
    flow_t *flow = context;
    CHECK(status == SOLARIS_OK && flow->handle);
    solaris_tracker_finish(flow->handle, SOLARIS_OK);
    flow->handle = NULL;
    if (flow->after_finish) {
        CHECK(solaris_tracker_close_current(flow->tracker, &flow->key, completed, flow->after_finish) == SOLARIS_OK);
        CHECK(!atomic_load(&flow->after_finish->calls)); /* final destructor has not run */
    }
    solaris_test_event_signal(&flow->step);
}
static void flow_init(flow_t *flow, solaris_tracker_t *tracker, solaris_executor_t *owner)
{
    memset(flow, 0, sizeof(*flow));
    flow->tracker = tracker;
    flow->owner = owner;
    atomic_init(&flow->close_calls, 0);
    CHECK(!solaris_test_event_init(&flow->step, 0) && !solaris_test_event_init(&flow->closed, 0));
}
static void post(flow_t *flow, solaris_task_fn callback)
{
    CHECK(solaris_executor_post(flow->owner, callback, flow) == SOLARIS_OK);
    solaris_test_event_wait(&flow->step);
}
int main(void)
{
    atomic_init(&fail_allocate, 0);
    solaris_runtime_services_t services;
    solaris_runtime_services_init(&services);
    services.allocate = allocate;
    solaris_budget_t *budget;
    CHECK(solaris_budget_create(4 * 1024 * 1024, &services, &budget) == SOLARIS_OK);
    solaris_tracker_t *tracker;
    CHECK(solaris_tracker_create(budget, 8, 4, &tracker) == SOLARIS_OK);
    completion_t empty, all, one, finished, refused;
    completion_init(&empty);
    completion_init(&all);
    completion_init(&one);
    completion_init(&finished);
    completion_init(&refused);
    CHECK(solaris_tracker_close_current(tracker, NULL, completed, &empty) == SOLARIS_OK);
    CHECK(atomic_load(&empty.calls) == 1 && !empty.matched && solaris_tracker_drained(tracker));
    solaris_executor_t *owners[2];
    for (unsigned i = 0; i < 2; ++i) {
        solaris_executor_options_t options = {.id = i, .queue_capacity = 8, .resource_limit = 32, .budget = budget};
        CHECK(solaris_executor_create(&options, &owners[i]) == SOLARIS_OK);
        CHECK(solaris_executor_activate(owners[i], 7) == SOLARIS_OK);
    }
    flow_t flows[3];
    flow_init(&flows[0], tracker, owners[0]);
    flow_init(&flows[1], tracker, owners[1]);
    flow_init(&flows[2], tracker, owners[0]);
    post(&flows[0], admit);
    post(&flows[1], admit);
    solaris_connection_snapshot_t *captured;
    size_t count;
    CHECK(solaris_tracker_capture(tracker, 0, &captured, &count) == SOLARIS_OK && count == 2);
    CHECK(captured[0].state == SOLARIS_CONNECTION_OPENING && !captured[0].node_id && !captured[0].target.family &&
          captured[0].config_revision == 11 && captured[0].selection_revision == 19 &&
          captured[0].source.port == 12345);
    atomic_store(&fail_allocate, 1);
    CHECK(solaris_tracker_close_current(tracker, NULL, completed, &refused) == SOLARIS_ENOMEM);
    atomic_store(&fail_allocate, 0);
    CHECK(!atomic_load(&refused.calls) && !atomic_load(&flows[0].close_calls) && !atomic_load(&flows[1].close_calls));
    solaris_connection_id_t wrong = flows[0].key;
    wrong.generation++;
    CHECK(solaris_tracker_close_current(tracker, &wrong, completed, &refused) == SOLARIS_EAGAIN);
    CHECK(solaris_tracker_close_current(tracker, NULL, completed, &all) == SOLARIS_OK);
    CHECK(solaris_tracker_close_current(tracker, &flows[0].key, completed, &one) == SOLARIS_OK);
    solaris_test_event_wait(&flows[0].closed);
    solaris_test_event_wait(&flows[1].closed);
    CHECK(!atomic_load(&all.calls) && !atomic_load(&one.calls) && !solaris_tracker_drained(tracker));
    post(&flows[2], admit);
    CHECK(flows[2].key.id > flows[1].key.id && !atomic_load(&flows[2].close_calls));
    post(&flows[0], finish);
    solaris_test_event_wait(&one.done);
    CHECK(one.matched == 1 && !atomic_load(&all.calls));
    post(&flows[1], finish);
    solaris_test_event_wait(&all.done);
    CHECK(all.matched == 2);
    CHECK(!atomic_load(&flows[2].close_calls));
    flows[2].after_finish = &finished;
    post(&flows[2], finish);
    solaris_test_event_wait(&finished.done);
    CHECK(finished.matched == 1 && !atomic_load(&flows[2].close_calls));
    CHECK(solaris_tracker_close_current(tracker, &flows[0].key, completed, &refused) == SOLARIS_ECLOSED);
    CHECK(solaris_tracker_close_current(tracker, &wrong, completed, &refused) == SOLARIS_EAGAIN &&
          !atomic_load(&refused.calls));
    for (unsigned i = 0; i < 2; ++i) {
        CHECK(solaris_executor_quiesce(owners[i]) == SOLARIS_OK);
        CHECK(solaris_executor_destroy(owners[i]) == SOLARIS_OK);
    }
    CHECK(solaris_tracker_drained(tracker));
    solaris_tracker_totals_t totals;
    CHECK(solaris_tracker_totals(tracker, SOLARIS_FLOW_USER, &totals) == SOLARIS_OK);
    CHECK(totals.created == 3 && totals.closed == 3 && !totals.active && !totals.bytes_read && !totals.bytes_written);
    CHECK(solaris_tracker_destroy(tracker) == SOLARIS_OK);
    CHECK(count == 2 && captured[0].state == SOLARIS_CONNECTION_OPENING && captured[0].source.port == 12345);
    solaris_tracker_capture_free(captured);
    for (unsigned i = 0; i < 3; ++i) {
        solaris_test_event_destroy(&flows[i].step);
        solaris_test_event_destroy(&flows[i].closed);
    }
    completion_t *completions[] = {&empty, &all, &one, &finished, &refused};
    for (unsigned i = 0; i < 5; ++i)
        solaris_test_event_destroy(&completions[i]->done);
    CHECK(!solaris_budget_used(budget));
    solaris_budget_release(budget);
    puts("Observation admission: pending flows, bounded close allocation, captured cutoff, concurrent waiters, final "
         "destruction and detached copies passed");
    return 0;
}
