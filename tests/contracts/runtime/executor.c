#include <solaris/core.h>
#include "runtime/engine/internal.h"
#include "runtime/executor/executor.h"
#include "contracts/io/buffer.h"
#ifdef __linux__
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>
#include "support/runtime/event.h"

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)

typedef struct worker_case {
    solaris_engine_t *engine;
    solaris_executor_t *first, *second;
    solaris_scope_t scope;
    solaris_deferred_t late_completion;
    solaris_test_event_t entered, release, pinged, cancelled;
    uv_thread_t first_thread, second_thread;
    unsigned int cancellations, completions, queued_callbacks;
    uint64_t generation;
} worker_case_t;

static void scope_cancelled(void *context)
{
    worker_case_t *test = context;
    CHECK(solaris_executor_is_owner(test->first));
    test->cancellations++;
    solaris_test_event_signal(&test->cancelled);
}
static void scope_completed(void *context)
{
    worker_case_t *test = context;
    CHECK(solaris_executor_is_owner(test->first));
    test->completions++;
}
static void release_native_lease(void *context)
{
    worker_case_t *test = context;
    solaris_scope_release(&test->scope);
}
static void first_task(void *context, solaris_status_t status)
{
    worker_case_t *test = context;
    CHECK(status == SOLARIS_OK && solaris_executor_is_owner(test->first));
#ifdef __linux__
    sigset_t mask;
    CHECK(pthread_sigmask(SIG_SETMASK, NULL, &mask) == 0 && sigismember(&mask, SIGPIPE) == 1);
    int pipe_fds[2];
    CHECK(pipe(pipe_fds) == 0 && close(pipe_fds[0]) == 0);
    CHECK(write(pipe_fds[1], "x", 1) == -1 && errno == EPIPE);
    CHECK(close(pipe_fds[1]) == 0);
#endif
    test->first_thread = uv_thread_self();
    test->generation = solaris_executor_generation(test->first);
    CHECK(solaris_engine_flush(test->engine, 0u, NULL) == SOLARIS_EDEADLOCK);
    CHECK(solaris_engine_destroy(test->engine, NULL) == SOLARIS_EDEADLOCK);
    CHECK(solaris_scope_init(&test->scope, test->first, scope_cancelled, scope_completed, test) == SOLARIS_OK);
    solaris_scope_retain(&test->scope); /* outstanding asynchronous native operation */
    solaris_test_event_signal(&test->entered);
    solaris_test_event_wait(&test->release);
}
static void second_task(void *context, solaris_status_t status)
{
    worker_case_t *test = context;
    CHECK(status == SOLARIS_OK && solaris_executor_is_owner(test->second));
    test->second_thread = uv_thread_self();
    solaris_test_event_signal(&test->pinged);
}
static void cancelled_task(void *context, solaris_status_t status)
{
    worker_case_t *test = context;
    CHECK(status == SOLARIS_ECANCELLED && solaris_executor_is_owner(test->first));
    test->queued_callbacks++;
}
static void wait_for_closed_admission(solaris_executor_t *executor)
{
    uint64_t started = uv_hrtime();
    while (solaris_executor_accepting(executor)) {
        CHECK(uv_hrtime() - started < UINT64_C(5000000000));
        uv_sleep(1u);
    }
}

static void test_workers_and_shutdown_scope(void)
{
    worker_case_t test; memset(&test, 0, sizeof(test));
    CHECK(solaris_test_event_init(&test.entered, 0) == 0 && solaris_test_event_init(&test.release, 0) == 0);
    CHECK(solaris_test_event_init(&test.pinged, 0) == 0 && solaris_test_event_init(&test.cancelled, 0) == 0);
    solaris_engine_options_t options; solaris_engine_options_init(&options);
    options.io_workers = 2u; options.io_queue_capacity = 2u;
    CHECK(solaris_engine_create(&options, NULL, &test.engine, NULL) == SOLARIS_OK);
    test.first = solaris_runtime_executor(test.engine, 0u);
    test.second = solaris_runtime_executor(test.engine, 1u);
    CHECK(test.first != NULL && test.second != NULL && test.first != test.second);
    CHECK(test.first == solaris_runtime_executor(test.engine, 42u));
    CHECK(solaris_executor_post(test.first, first_task, &test) == SOLARIS_ECLOSED);
    uint64_t operation;
    CHECK(solaris_engine_start(test.engine, &operation, NULL) == SOLARIS_OK);
    CHECK(solaris_engine_flush(test.engine, 5000u, NULL) == SOLARIS_OK);
    CHECK(solaris_executor_post(test.first, first_task, &test) == SOLARIS_OK);
    solaris_test_event_wait(&test.entered);
    CHECK(solaris_executor_post(test.second, second_task, &test) == SOLARIS_OK);
    solaris_test_event_wait(&test.pinged); /* second worker runs while first is blocked */
    CHECK(!uv_thread_equal(&test.first_thread, &test.second_thread));
    CHECK(test.generation == 1u);
    CHECK(solaris_executor_post(test.first, cancelled_task, &test) == SOLARIS_OK);
    CHECK(solaris_executor_post(test.first, cancelled_task, &test) == SOLARIS_OK);
    CHECK(solaris_executor_post(test.first, cancelled_task, &test) == SOLARIS_EAGAIN);
    CHECK(solaris_engine_stop(test.engine, &operation, NULL) == SOLARIS_OK);
    wait_for_closed_admission(test.first);
    wait_for_closed_admission(test.second);
    CHECK(solaris_engine_flush(test.engine, 0u, NULL) == SOLARIS_ETIMEDOUT);
    solaris_test_event_signal(&test.release);
    solaris_test_event_wait(&test.cancelled);
    CHECK(solaris_engine_flush(test.engine, 1u, NULL) == SOLARIS_ETIMEDOUT);
    CHECK(solaris_executor_post(test.first, cancelled_task, &test) == SOLARIS_ECLOSED);
    test.late_completion.run = release_native_lease;
    test.late_completion.context = &test;
    CHECK(solaris_executor_defer(test.first, &test.late_completion) == SOLARIS_OK);
    CHECK(solaris_engine_flush(test.engine, 5000u, NULL) == SOLARIS_OK);
    CHECK(test.queued_callbacks == 2u && test.cancellations == 1u && test.completions == 1u);
    CHECK(solaris_engine_start(test.engine, &operation, NULL) == SOLARIS_OK);
    CHECK(solaris_engine_flush(test.engine, 5000u, NULL) == SOLARIS_OK);
    CHECK(solaris_executor_generation(test.first) == 2u);
    CHECK(solaris_runtime_executor(test.engine, 42u) == test.first);
    solaris_engine_snapshot_t snapshot;
    CHECK(solaris_engine_get_snapshot(test.engine, &snapshot, NULL) == SOLARIS_OK);
    CHECK(snapshot.io_workers == 2u && snapshot.generation == 2u && snapshot.io_buffer_bytes == 0u);
    CHECK(solaris_engine_destroy(test.engine, NULL) == SOLARIS_OK);
    solaris_test_event_destroy(&test.entered); solaris_test_event_destroy(&test.release);
    solaris_test_event_destroy(&test.pinged); solaris_test_event_destroy(&test.cancelled);
}

typedef struct clock_case {
    uv_mutex_t mutex;
    uint64_t now;
    solaris_executor_t *executor;
    solaris_deadline_t *first, *second;
    solaris_test_event_t ready, fired, cancelled, fenced;
    unsigned int successes, cancellations;
} clock_case_t;

static uint64_t clock_now(void *context)
{
    clock_case_t *test = context;
    uv_mutex_lock(&test->mutex);
    uint64_t now = test->now;
    uv_mutex_unlock(&test->mutex);
    return now;
}
static void deadline_first(void *context, solaris_status_t status)
{
    clock_case_t *test = context;
    CHECK(solaris_executor_is_owner(test->executor) && status == SOLARIS_OK);
    test->first = NULL; test->successes++;
    solaris_test_event_signal(&test->fired);
}
static void deadline_second(void *context, solaris_status_t status)
{
    clock_case_t *test = context;
    CHECK(solaris_executor_is_owner(test->executor) && status == SOLARIS_ECANCELLED);
    test->second = NULL; test->cancellations++;
    solaris_test_event_signal(&test->cancelled);
}
static void create_deadlines(void *context, solaris_status_t status)
{
    clock_case_t *test = context;
    CHECK(status == SOLARIS_OK);
    CHECK(solaris_deadline_start(test->executor, 100u, deadline_first, test, &test->first) == SOLARIS_OK);
    CHECK(solaris_deadline_start(test->executor, 200u, deadline_second, test, &test->second) == SOLARIS_OK);
    solaris_deadline_t *rejected = NULL;
    CHECK(solaris_deadline_start(test->executor, 300u, deadline_first, test, &rejected) == SOLARIS_EAGAIN);
    CHECK(rejected == NULL);
    solaris_test_event_signal(&test->ready);
}
static void fence(void *context, solaris_status_t status)
{
    clock_case_t *test = context; CHECK(status == SOLARIS_OK); solaris_test_event_signal(&test->fenced);
}
static void cancel_second(void *context, solaris_status_t status)
{
    clock_case_t *test = context; CHECK(status == SOLARIS_OK);
    solaris_deadline_cancel(test->second);
}
static void advance_clock(clock_case_t *test, uint64_t value)
{
    uv_mutex_lock(&test->mutex); test->now = value; uv_mutex_unlock(&test->mutex);
    solaris_executor_wake(test->executor);
}

static void test_logical_deadlines(void)
{
    clock_case_t test; memset(&test, 0, sizeof(test));
    CHECK(uv_mutex_init(&test.mutex) == 0);
    CHECK(solaris_test_event_init(&test.ready, 0) == 0 && solaris_test_event_init(&test.fired, 0) == 0);
    CHECK(solaris_test_event_init(&test.cancelled, 0) == 0 && solaris_test_event_init(&test.fenced, 0) == 0);
    solaris_runtime_services_t services; solaris_runtime_services_init(&services);
    services.context = &test; services.now_ns = clock_now;
    solaris_budget_t *budget = NULL;
    CHECK(solaris_budget_create(1024u * 1024u, &services, &budget) == SOLARIS_OK);
    solaris_executor_options_t options = {
        .id = 7u, .queue_capacity = 8u, .resource_limit = 2u, .budget = budget, .services = &services
    };
    CHECK(solaris_executor_create(&options, &test.executor) == SOLARIS_OK);
    CHECK(solaris_executor_activate(test.executor, 1u) == SOLARIS_OK);
    CHECK(solaris_executor_post(test.executor, create_deadlines, &test) == SOLARIS_OK);
    solaris_test_event_wait(&test.ready);
    advance_clock(&test, UINT64_C(50000000));
    CHECK(solaris_executor_post(test.executor, fence, &test) == SOLARIS_OK);
    solaris_test_event_wait(&test.fenced);
    CHECK(test.successes == 0u);
    advance_clock(&test, UINT64_C(150000000));
    solaris_test_event_wait(&test.fired);
    CHECK(solaris_executor_post(test.executor, cancel_second, &test) == SOLARIS_OK);
    solaris_test_event_wait(&test.cancelled);
    CHECK(solaris_executor_quiesce(test.executor) == SOLARIS_OK);
    CHECK(test.successes == 1u && test.cancellations == 1u && solaris_budget_used(budget) == 0u);
    CHECK(solaris_executor_destroy(test.executor) == SOLARIS_OK);
    solaris_budget_release(budget);
    solaris_test_event_destroy(&test.ready); solaris_test_event_destroy(&test.fired);
    solaris_test_event_destroy(&test.cancelled); solaris_test_event_destroy(&test.fenced); uv_mutex_destroy(&test.mutex);
}

typedef struct buffer_case { solaris_budget_t *budget; const solaris_buffer_t *shared; } buffer_case_t;
static void use_shared_buffer(void *context)
{
    buffer_case_t *test = context;
    for (unsigned int i = 0; i < 500u; i++) {
        solaris_buffer_retain(test->shared);
        CHECK(solaris_buffer_length(test->shared) == 128u && solaris_buffer_data(test->shared)[127] == 0x5a);
        solaris_buffer_t *buffer = NULL;
        CHECK(solaris_buffer_copy(test->budget, "sample", 6u, &buffer) == SOLARIS_OK);
        solaris_buffer_release(buffer);
        solaris_buffer_release(test->shared);
    }
}
static void test_owned_buffers(void)
{
    solaris_budget_t *budget = NULL;
    CHECK(solaris_budget_create(2048u, NULL, &budget) == SOLARIS_OK);
    solaris_buffer_t *buffer = NULL;
    CHECK(solaris_buffer_allocate(budget, 128u, &buffer) == SOLARIS_OK);
    CHECK(solaris_buffer_mutable_data(buffer) != NULL);
    memset(solaris_buffer_mutable_data(buffer), 0x5a, 128u);
    CHECK(solaris_buffer_set_length(buffer, 128u) == SOLARIS_OK);
    solaris_buffer_retain(buffer);
    CHECK(solaris_buffer_mutable_data(buffer) == NULL && solaris_buffer_set_length(buffer, 1u) == SOLARIS_EBUSY);
    solaris_buffer_release(buffer);
    CHECK(solaris_buffer_mutable_data(buffer) == NULL); /* publishing is permanent */
    solaris_buffer_t *too_big = NULL;
    CHECK(solaris_buffer_allocate(budget, 4096u, &too_big) == SOLARIS_ENOMEM && too_big == NULL);
    buffer_case_t test = {budget, buffer}; uv_thread_t threads[4];
    for (size_t i = 0; i < 4u; i++) CHECK(uv_thread_create(&threads[i], use_shared_buffer, &test) == 0);
    for (size_t i = 0; i < 4u; i++) CHECK(uv_thread_join(&threads[i]) == 0);
    CHECK(solaris_budget_used(budget) <= 2048u && solaris_budget_peak(budget) <= 2048u);
    solaris_buffer_t *empty = NULL;
    CHECK(solaris_buffer_copy(budget, NULL, 0u, &empty) == SOLARIS_OK && solaris_buffer_length(empty) == 0u);
    solaris_buffer_release(empty); solaris_buffer_release(buffer);
    CHECK(solaris_budget_used(budget) == 0u);
    CHECK(solaris_buffer_copy(budget, "last", 4u, &buffer) == SOLARIS_OK);
    solaris_budget_release(budget); /* the outstanding allocation keeps its budget alive */
    solaris_buffer_release(buffer);
}

typedef struct failure_case {
    uv_mutex_t mutex;
    size_t live;
    solaris_runtime_point_t point;
    unsigned int visits;
} failure_case_t;
static void *tracked_allocate(void *context, size_t size)
{
    failure_case_t *test = context; void *p = malloc(size);
    uv_mutex_lock(&test->mutex); if (p != NULL) test->live++; uv_mutex_unlock(&test->mutex);
    return p;
}
static void tracked_free(void *context, void *pointer)
{
    if (pointer == NULL) return;
    failure_case_t *test = context;
    uv_mutex_lock(&test->mutex); CHECK(test->live > 0u); test->live--; uv_mutex_unlock(&test->mutex);
    free(pointer);
}
static int fail_second_worker(void *context, solaris_runtime_point_t point)
{
    failure_case_t *test = context;
    uv_mutex_lock(&test->mutex);
    int fail = point == test->point && ++test->visits == 2u;
    uv_mutex_unlock(&test->mutex);
    return fail ? UV_EIO : 0;
}
static void test_partial_pool_failure(void)
{
    const solaris_runtime_point_t points[] = {
        SOLARIS_POINT_EXECUTOR_CREATE, SOLARIS_POINT_EXECUTOR_LOOP_INIT,
        SOLARIS_POINT_EXECUTOR_ASYNC_INIT, SOLARIS_POINT_EXECUTOR_TIMER_INIT
    };
    for (size_t i = 0; i < sizeof(points) / sizeof(points[0]); i++) {
        failure_case_t test; memset(&test, 0, sizeof(test)); test.point = points[i];
        CHECK(uv_mutex_init(&test.mutex) == 0);
        solaris_runtime_services_t services; solaris_runtime_services_init(&services);
        services.context = &test; services.allocate = tracked_allocate;
        services.deallocate = tracked_free; services.checkpoint = fail_second_worker;
        solaris_engine_options_t options; solaris_engine_options_init(&options); options.io_workers = 3u;
        solaris_engine_t *engine = NULL;
        CHECK(solaris_runtime_create(&options, NULL, &services, &engine, NULL) == SOLARIS_EIO);
        CHECK(engine == NULL && test.live == 0u && test.visits == 2u);
        uv_mutex_destroy(&test.mutex);
    }
}

typedef struct many_scopes_case many_scopes_case_t;
typedef struct scope_item { solaris_scope_t scope; many_scopes_case_t *test; } scope_item_t;
struct many_scopes_case {
    solaris_executor_t *executor;
    solaris_test_event_t ready;
    scope_item_t items[192];
    unsigned int cancelled, completed;
};
static void many_cancelled(void *context) { ((scope_item_t *)context)->test->cancelled++; }
static void many_completed(void *context) { ((scope_item_t *)context)->test->completed++; }
static void create_many_scopes(void *context, solaris_status_t status)
{
    many_scopes_case_t *test = context;
    CHECK(status == SOLARIS_OK);
    for (size_t i = 0; i < 192u; i++) {
        test->items[i].test = test;
        CHECK(solaris_scope_init(&test->items[i].scope, test->executor,
                                 many_cancelled, many_completed, &test->items[i]) == SOLARIS_OK);
    }
    solaris_test_event_signal(&test->ready);
}
static void test_bounded_scope_drain(void)
{
    many_scopes_case_t test; memset(&test, 0, sizeof(test));
    CHECK(solaris_test_event_init(&test.ready, 0u) == 0);
    solaris_engine_options_t options; solaris_engine_options_init(&options);
    options.io_workers = 2u; options.io_queue_capacity = 1u; options.io_resource_limit = 256u;
    solaris_engine_t *engine = NULL;
    CHECK(solaris_engine_create(&options, NULL, &engine, NULL) == SOLARIS_OK);
    uint64_t operation;
    CHECK(solaris_engine_start(engine, &operation, NULL) == SOLARIS_OK);
    CHECK(solaris_engine_flush(engine, 5000u, NULL) == SOLARIS_OK);
    test.executor = solaris_runtime_executor(engine, 1u);
    CHECK(solaris_executor_post(test.executor, create_many_scopes, &test) == SOLARIS_OK);
    solaris_test_event_wait(&test.ready);
    CHECK(solaris_engine_stop(engine, &operation, NULL) == SOLARIS_OK);
    CHECK(solaris_engine_flush(engine, 5000u, NULL) == SOLARIS_OK);
    CHECK(test.cancelled == 192u && test.completed == 192u);
    CHECK(solaris_engine_destroy(engine, NULL) == SOLARIS_OK);
    solaris_test_event_destroy(&test.ready);
}

int main(void)
{
    test_workers_and_shutdown_scope();
    test_logical_deadlines();
    test_owned_buffers();
    test_partial_pool_failure();
    test_bounded_scope_drain();
    puts("5 executor/buffer contract groups passed");
    return 0;
}
