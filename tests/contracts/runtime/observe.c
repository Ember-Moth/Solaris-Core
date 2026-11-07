#include "runtime/config/manager.h"
#include "runtime/engine/internal.h"
#include "support/runtime/event.h"
#include <solaris/core.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x);                  \
      abort();                                                                 \
    }                                                                          \
  } while (0)
typedef struct fixture fixture_t;
typedef struct operation {
  fixture_t *fixture;
  solaris_status_t status;
  uint64_t matched;
  atomic_uint typed, generic;
  int block;
  solaris_test_event_t entered, release;
} operation_t;
struct fixture {
  solaris_engine_t *engine;
  solaris_tracker_t *tracker;
  operation_t *typed_operation;
  uv_thread_t control_owner;
};
typedef struct flow {
  solaris_tracker_t *tracker;
  solaris_executor_t *owner;
  solaris_tracked_flow_t *handle;
  solaris_connection_id_t key;
  solaris_test_event_t ready, closing, finished;
  solaris_deferred_t finish;
  atomic_uint closes;
} flow_t;
typedef struct gate {
  solaris_control_completion_t task;
  solaris_test_event_t entered, release;
} gate_t;
static void event(void *context, const solaris_event_t *result) {
  fixture_t *f = context;
  if (result->operation == SOLARIS_OPERATION_START)
    f->control_owner = uv_thread_self();
  if (result->operation != SOLARIS_OPERATION_CLOSE_CONNECTIONS)
    return;
  operation_t *operation = f->typed_operation;
  CHECK(operation && operation->typed == 1 && operation->generic == 0);
  CHECK(operation->status == result->status && !result->config_revision);
  operation->generic = 1;
  f->typed_operation = NULL;
}
static void close_done(void *context, solaris_status_t status, uint64_t matched,
                       const solaris_error_t *error) {
  operation_t *operation = context;
  fixture_t *f = operation->fixture;
  uv_thread_t current = uv_thread_self();
  CHECK(uv_thread_equal(&current, &f->control_owner));
  CHECK(!operation->typed && !operation->generic && !f->typed_operation &&
        error && error->code == status);
  CHECK(solaris_engine_flush(f->engine, 0, NULL) == SOLARIS_EDEADLOCK);
  operation->status = status;
  operation->matched = matched;
  operation->typed = 1;
  f->typed_operation = operation;
  solaris_test_event_signal(&operation->entered);
  if (operation->block)
    solaris_test_event_wait(&operation->release);
}
static void operation_init(operation_t *operation, fixture_t *f) {
  memset(operation, 0, sizeof(*operation));
  operation->fixture = f;
  atomic_init(&operation->typed, 0);
  atomic_init(&operation->generic, 0);
  CHECK(!solaris_test_event_init(&operation->entered, 0));
  CHECK(!solaris_test_event_init(&operation->release, 0));
}
static void operation_destroy(operation_t *operation) {
  CHECK(operation->typed == 1 && operation->generic == 1);
  solaris_test_event_destroy(&operation->entered);
  solaris_test_event_destroy(&operation->release);
}
static void close_flow(void *context) {
  flow_t *flow = context;
  CHECK(atomic_fetch_add(&flow->closes, 1) == 0);
  /* The simulated outer protocol still owns pending work. Its host-controlled
   * finish below is the deterministic late cleanup boundary under test. */
  solaris_test_event_signal(&flow->closing);
}
static void admit(void *context, solaris_status_t status) {
  flow_t *flow = context;
  CHECK(status == SOLARIS_OK);
  solaris_observe_options_t options = {.kind = SOLARIS_FLOW_STREAM,
                                       .purpose = SOLARIS_FLOW_USER,
                                       .config_revision = 7,
                                       .selection_revision = 9,
                                       .inbound_id = 11,
                                       .rule_index = UINT64_MAX};
  CHECK(solaris_address_parse("127.0.0.1", 12345, &options.source) ==
        SOLARIS_OK);
  CHECK(solaris_tracker_admit(flow->tracker, flow->owner, &options, close_flow,
                              flow, &flow->handle,
                              &flow->key.id) == SOLARIS_OK);
  flow->key.generation = solaris_executor_generation(flow->owner);
  solaris_test_event_signal(&flow->ready);
}
static void finish_flow(void *context) {
  flow_t *flow = context;
  solaris_tracker_finish(flow->handle, SOLARIS_ECANCELLED);
  flow->handle = NULL;
  solaris_test_event_signal(&flow->finished);
}
static void flow_init(flow_t *flow, fixture_t *f, uint64_t worker) {
  memset(flow, 0, sizeof(*flow));
  flow->tracker = f->tracker;
  flow->owner = solaris_runtime_executor(f->engine, worker);
  CHECK(flow->owner);
  atomic_init(&flow->closes, 0);
  CHECK(!solaris_test_event_init(&flow->ready, 0));
  CHECK(!solaris_test_event_init(&flow->closing, 0));
  CHECK(!solaris_test_event_init(&flow->finished, 0));
  flow->finish = (solaris_deferred_t){.run = finish_flow, .context = flow};
  CHECK(solaris_executor_post(flow->owner, admit, flow) == SOLARIS_OK);
  solaris_test_event_wait(&flow->ready);
}
static void flow_finish(flow_t *flow) {
  CHECK(solaris_executor_defer(flow->owner, &flow->finish) == SOLARIS_OK);
  solaris_test_event_wait(&flow->finished);
}
static void flow_destroy(flow_t *flow) {
  CHECK(!flow->handle && flow->closes == 1);
  solaris_test_event_destroy(&flow->ready);
  solaris_test_event_destroy(&flow->closing);
  solaris_test_event_destroy(&flow->finished);
}
static void gate_run(void *context) {
  gate_t *gate = context;
  solaris_test_event_signal(&gate->entered);
  solaris_test_event_wait(&gate->release);
}
static void flush(fixture_t *f) {
  CHECK(solaris_engine_flush(f->engine, 5000, NULL) == SOLARIS_OK);
}
int main(void) {
  fixture_t f = {0};
  solaris_engine_options_t options;
  solaris_engine_options_init(&options);
  options.io_workers = 2;
  solaris_host_t host = {.context = &f, .on_event = event};
  CHECK(solaris_engine_create(&options, &host, &f.engine, NULL) == SOLARIS_OK);
  uint64_t id;
  CHECK(solaris_engine_start(f.engine, &id, NULL) == SOLARIS_OK);
  flush(&f);
  solaris_config_manager_t *manager;
  CHECK(solaris_config_manager_ensure(f.engine, &manager) == SOLARIS_OK);
  f.tracker = solaris_config_manager_tracker(manager);
  CHECK(f.tracker);
  flow_t first, second, third;
  flow_init(&first, &f, 0);
  solaris_connection_info_t info;
  CHECK(solaris_engine_get_connection(f.engine, &first.key, &info, NULL) ==
        SOLARIS_OK);
  CHECK(info.state == SOLARIS_CONNECTION_OPENING && info.config_revision == 7 &&
        info.selection_revision == 9);
  CHECK(info.source.port == 12345 && !strcmp(info.source.host, "127.0.0.1"));
  solaris_connection_id_t wrong = first.key;
  ++wrong.generation;
  operation_t stale;
  operation_init(&stale, &f);
  CHECK(solaris_engine_close_connection(f.engine, &wrong, close_done, &stale,
                                        &id, NULL) == SOLARIS_OK);
  flush(&f);
  CHECK(stale.status == SOLARIS_EAGAIN && !stale.matched && !first.closes);
  operation_destroy(&stale);

  gate_t gate = {0};
  CHECK(!solaris_test_event_init(&gate.entered, 0));
  CHECK(!solaris_test_event_init(&gate.release, 0));
  gate.task = (solaris_control_completion_t){.run = gate_run, .context = &gate};
  CHECK(solaris_runtime_control_post(f.engine, &gate.task) == SOLARIS_OK);
  solaris_test_event_wait(&gate.entered);
  operation_t queued;
  operation_init(&queued, &f);
  CHECK(solaris_engine_close_connections(f.engine, close_done, &queued, &id,
                                         NULL) == SOLARIS_OK);
  CHECK(solaris_engine_cancel(f.engine, id, NULL) == SOLARIS_OK);
  solaris_test_event_signal(&gate.release);
  flush(&f);
  CHECK(queued.status == SOLARIS_ECANCELLED && !queued.matched &&
        !first.closes);
  operation_destroy(&queued);
  solaris_test_event_destroy(&gate.entered);
  solaris_test_event_destroy(&gate.release);

  operation_t cancelled;
  operation_init(&cancelled, &f);
  CHECK(solaris_engine_close_connection(f.engine, &first.key, close_done,
                                        &cancelled, &id, NULL) == SOLARIS_OK);
  solaris_test_event_wait(&first.closing);
  CHECK(solaris_engine_cancel(f.engine, id, NULL) == SOLARIS_OK);
  CHECK(solaris_engine_flush(f.engine, 1, NULL) == SOLARIS_ETIMEDOUT &&
        !cancelled.typed);
  flow_init(&second, &f, 1);
  CHECK(!second.closes);
  flow_finish(&first);
  flush(&f);
  CHECK(cancelled.status == SOLARIS_ECANCELLED && cancelled.matched == 1);
  operation_destroy(&cancelled);
  CHECK(solaris_engine_get_connection(f.engine, &first.key, &info, NULL) ==
            SOLARIS_OK &&
        info.state == SOLARIS_CONNECTION_CLOSED);
  CHECK(solaris_engine_get_connection(f.engine, &second.key, &info, NULL) ==
            SOLARIS_OK &&
        info.state == SOLARIS_CONNECTION_OPENING);

  operation_t all;
  operation_init(&all, &f);
  all.block = 1;
  CHECK(solaris_engine_close_connections(f.engine, close_done, &all, &id,
                                         NULL) == SOLARIS_OK);
  solaris_test_event_wait(&second.closing);
  flow_init(&third, &f, 0);
  CHECK(!third.closes);
  solaris_connection_list_t *owned;
  CHECK(solaris_engine_get_connections(f.engine, 1, &owned, NULL) ==
        SOLARIS_OK);
  size_t retained = solaris_connection_list_count(owned);
  CHECK(retained == 3);
  flow_finish(&second);
  solaris_test_event_wait(&all.entered);
  CHECK(solaris_engine_flush(f.engine, 1, NULL) == SOLARIS_ETIMEDOUT &&
        !all.generic);
  solaris_test_event_signal(&all.release);
  flush(&f);
  CHECK(all.status == SOLARIS_OK && all.matched == 1 && !third.closes);
  operation_destroy(&all);

  operation_t last;
  operation_init(&last, &f);
  CHECK(solaris_engine_close_connections(f.engine, close_done, &last, &id,
                                         NULL) == SOLARIS_OK);
  solaris_test_event_wait(&third.closing);
  flow_finish(&third);
  flush(&f);
  CHECK(last.status == SOLARIS_OK && last.matched == 1);
  operation_destroy(&last);
  CHECK(solaris_engine_destroy(f.engine, NULL) == SOLARIS_OK);
  CHECK(solaris_connection_list_count(owned) == retained &&
        solaris_connection_list_get(owned, 0, &info) == SOLARIS_OK);
  solaris_connection_list_release(owned);
  flow_destroy(&first);
  flow_destroy(&second);
  flow_destroy(&third);
  puts("Public close cancellation, captured-set drain, callback fence and "
       "owned snapshots passed");
  return 0;
}
