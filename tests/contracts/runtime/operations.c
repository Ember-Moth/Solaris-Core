#include "runtime/engine/internal.h"
#include "runtime/operation/request.h"
#include "support/runtime/event.h"
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>
#define CHECK(x)                                                                                                       \
    do {                                                                                                               \
        if (!(x)) {                                                                                                    \
            fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x);                                                    \
            abort();                                                                                                   \
        }                                                                                                              \
    } while (0)

typedef struct fixture fixture_t;
typedef struct resource {
    solaris_scope_t scope;
    solaris_deferred_t release;
    solaris_executor_t *owner;
    solaris_test_event_t ready, cancelled, done;
} resource_t;
typedef struct job {
    fixture_t *fixture;
    solaris_runtime_operation_t *operation;
    solaris_status_t start_status, result_status;
    uint64_t result_revision, publish_on_cancel;
    int automatic, acknowledge_cancel, block_typed, block_host;
    resource_t *release_resource;
    atomic_uint starts, cancels, typed, generic, disposals;
    solaris_test_event_t started, cancelled, typed_entered, typed_release, host_entered, host_release, disposed;
} job_t;
struct fixture {
    solaris_engine_t *engine;
    uv_mutex_t mutex;
    uv_thread_t owner;
    int owner_set, block_start;
    job_t *typed_job;
    solaris_event_t events[256];
    size_t event_count;
    atomic_int fail_allocate, fail_wake, destroyed;
    solaris_test_event_t start_entered, start_release, shutdown_entered, destroy_done;
};
static void owner(fixture_t *f)
{
    uv_thread_t current = uv_thread_self();
    uv_mutex_lock(&f->mutex);
    if (!f->owner_set) {
        f->owner = current;
        f->owner_set = 1;
    }
    CHECK(uv_thread_equal(&current, &f->owner));
    uv_mutex_unlock(&f->mutex);
}
static void *allocate(void *context, size_t n)
{
    fixture_t *f = context;
    return atomic_load(&f->fail_allocate) ? NULL : malloc(n);
}
static int checkpoint(void *context, solaris_runtime_point_t point)
{
    fixture_t *f = context;
    if (point == SOLARIS_POINT_SHUTDOWN)
        solaris_test_event_signal(&f->shutdown_entered);
    return point == SOLARIS_POINT_ASYNC_SEND && atomic_exchange(&f->fail_wake, 0) ? UV_EIO : 0;
}
static void event(void *context, const solaris_event_t *result)
{
    fixture_t *f = context;
    owner(f);
    job_t *j = f->typed_job;
    if (result->operation > SOLARIS_OPERATION_STOP) {
        CHECK(j && atomic_load(&j->typed) == 1 && atomic_load(&j->disposals) == 0);
        CHECK(j->result_status == result->status && j->result_revision == result->config_revision);
        atomic_fetch_add(&j->generic, 1);
        f->typed_job = NULL;
        if (j->block_host) {
            solaris_test_event_signal(&j->host_entered);
            solaris_test_event_wait(&j->host_release);
        }
    }
    uv_mutex_lock(&f->mutex);
    CHECK(f->event_count < sizeof(f->events) / sizeof(*f->events));
    f->events[f->event_count++] = *result;
    uv_mutex_unlock(&f->mutex);
    if (result->operation == SOLARIS_OPERATION_START && f->block_start) {
        solaris_test_event_signal(&f->start_entered);
        solaris_test_event_wait(&f->start_release);
    }
}
static solaris_status_t start(void *context, solaris_engine_t *engine, solaris_runtime_operation_t *operation)
{
    job_t *j = context;
    owner(j->fixture);
    CHECK(engine == j->fixture->engine);
    CHECK(solaris_engine_flush(engine, 0, NULL) == SOLARIS_EDEADLOCK);
    CHECK(solaris_engine_destroy(engine, NULL) == SOLARIS_EDEADLOCK);
    CHECK(atomic_fetch_add(&j->starts, 1) == 0);
    j->operation = operation;
    solaris_test_event_signal(&j->started);
    if (j->start_status != SOLARIS_OK)
        return j->start_status;
    if (j->automatic) {
        solaris_runtime_operation_complete(operation, SOLARIS_OK, 0);
        CHECK(!atomic_load(&j->typed)); /* even synchronous acknowledgement is deferred */
    }
    return SOLARIS_OK;
}
static void cancel(void *context)
{
    job_t *j = context;
    owner(j->fixture);
    CHECK(atomic_fetch_add(&j->cancels, 1) == 0);
    solaris_test_event_signal(&j->cancelled);
    if (j->acknowledge_cancel)
        solaris_runtime_operation_complete(j->operation, j->publish_on_cancel ? SOLARIS_ECANCELLED : SOLARIS_OK,
                                           j->publish_on_cancel);
}
static void complete(void *context, solaris_status_t status, uint64_t revision)
{
    job_t *j = context;
    fixture_t *f = j->fixture;
    owner(f);
    CHECK(atomic_fetch_add(&j->typed, 1) == 0 && !atomic_load(&j->generic) && !atomic_load(&j->disposals));
    CHECK(solaris_engine_flush(f->engine, 0, NULL) == SOLARIS_EDEADLOCK);
    CHECK(solaris_engine_destroy(f->engine, NULL) == SOLARIS_EDEADLOCK);
    CHECK(!f->typed_job);
    f->typed_job = j;
    j->result_status = status;
    j->result_revision = revision;
    if (j->release_resource)
        CHECK(solaris_executor_defer(j->release_resource->owner, &j->release_resource->release) == SOLARIS_OK);
    if (j->block_typed) {
        solaris_test_event_signal(&j->typed_entered);
        solaris_test_event_wait(&j->typed_release);
    }
}
static void dispose(void *context)
{
    job_t *j = context;
    owner(j->fixture);
    CHECK(atomic_load(&j->typed) == 1 && atomic_load(&j->generic) == 1);
    CHECK(atomic_fetch_add(&j->disposals, 1) == 0);
    solaris_test_event_signal(&j->disposed);
}
static void job_init(job_t *j, fixture_t *f)
{
    memset(j, 0, sizeof(*j));
    j->fixture = f;
    atomic_init(&j->starts, 0);
    atomic_init(&j->cancels, 0);
    atomic_init(&j->typed, 0);
    atomic_init(&j->generic, 0);
    atomic_init(&j->disposals, 0);
    CHECK(!solaris_test_event_init(&j->started, 0));
    CHECK(!solaris_test_event_init(&j->cancelled, 0));
    CHECK(!solaris_test_event_init(&j->typed_entered, 0));
    CHECK(!solaris_test_event_init(&j->typed_release, 0));
    CHECK(!solaris_test_event_init(&j->host_entered, 0));
    CHECK(!solaris_test_event_init(&j->host_release, 0));
    CHECK(!solaris_test_event_init(&j->disposed, 0));
}
static void job_destroy(job_t *j)
{
    solaris_test_event_destroy(&j->started);
    solaris_test_event_destroy(&j->cancelled);
    solaris_test_event_destroy(&j->typed_entered);
    solaris_test_event_destroy(&j->typed_release);
    solaris_test_event_destroy(&j->host_entered);
    solaris_test_event_destroy(&j->host_release);
    solaris_test_event_destroy(&j->disposed);
}
static solaris_status_t submit(job_t *j, int requires_running, uint64_t *id)
{
    solaris_runtime_request_t request = {.operation = SOLARIS_OPERATION_CONFIG_PREPARE,
                                         .requires_running = requires_running,
                                         .context = j,
                                         .start = start,
                                         .cancel = cancel,
                                         .complete = complete,
                                         .dispose = dispose};
    return solaris_runtime_request_submit(j->fixture->engine, &request, id, NULL);
}
static void fixture_init(fixture_t *f, unsigned capacity)
{
    memset(f, 0, sizeof(*f));
    CHECK(!uv_mutex_init(&f->mutex));
    atomic_init(&f->fail_allocate, 0);
    atomic_init(&f->fail_wake, 0);
    atomic_init(&f->destroyed, 0);
    CHECK(!solaris_test_event_init(&f->start_entered, 0));
    CHECK(!solaris_test_event_init(&f->start_release, 0));
    CHECK(!solaris_test_event_init(&f->shutdown_entered, 0));
    CHECK(!solaris_test_event_init(&f->destroy_done, 0));
    solaris_engine_options_t options;
    solaris_engine_options_init(&options);
    options.command_capacity = capacity;
    options.io_workers = 2;
    solaris_host_t host = {.context = f, .on_event = event};
    solaris_runtime_services_t services;
    solaris_runtime_services_init(&services);
    services.context = f;
    services.allocate = allocate;
    services.checkpoint = checkpoint;
    CHECK(solaris_runtime_create(&options, &host, &services, &f->engine, NULL) == SOLARIS_OK);
}
static void fixture_destroy(fixture_t *f)
{
    if (f->engine)
        CHECK(solaris_engine_destroy(f->engine, NULL) == SOLARIS_OK);
    solaris_test_event_destroy(&f->start_entered);
    solaris_test_event_destroy(&f->start_release);
    solaris_test_event_destroy(&f->shutdown_entered);
    solaris_test_event_destroy(&f->destroy_done);
    uv_mutex_destroy(&f->mutex);
}
static void running(fixture_t *f)
{
    uint64_t id;
    CHECK(solaris_engine_start(f->engine, &id, NULL) == SOLARIS_OK);
    CHECK(solaris_engine_flush(f->engine, 5000, NULL) == SOLARIS_OK);
}
static solaris_engine_snapshot_t snapshot(fixture_t *f)
{
    solaris_engine_snapshot_t s;
    CHECK(solaris_engine_get_snapshot(f->engine, &s, NULL) == SOLARIS_OK);
    return s;
}
static void wait_completed(fixture_t *f, uint64_t count)
{
    uint64_t deadline = uv_hrtime() + UINT64_C(5000000000);
    while (snapshot(f).completed_operations != count) {
        CHECK(uv_hrtime() < deadline);
        uv_sleep(1);
    }
}
static void out_of_order(void)
{
    fixture_t f;
    fixture_init(&f, 8);
    running(&f);
    job_t slow, fast;
    job_init(&slow, &f);
    job_init(&fast, &f);
    fast.block_typed = fast.block_host = 1;
    uint64_t a, b;
    CHECK(submit(&slow, 1, &a) == SOLARIS_OK);
    solaris_test_event_wait(&slow.started);
    CHECK(submit(&fast, 1, &b) == SOLARIS_OK);
    solaris_test_event_wait(&fast.started);
    CHECK(a == 2 && b == 3);
    solaris_runtime_operation_complete(fast.operation, SOLARIS_OK, 0);
    solaris_test_event_wait(&fast.typed_entered);
    CHECK(snapshot(&f).completed_operations == 1 && snapshot(&f).pending_operations == 2);
    CHECK(solaris_engine_flush(f.engine, 0, NULL) == SOLARIS_ETIMEDOUT);
    solaris_test_event_signal(&fast.typed_release);
    solaris_test_event_wait(&fast.host_entered);
    CHECK(snapshot(&f).completed_operations == 1 && !atomic_load(&fast.disposals));
    solaris_test_event_signal(&fast.host_release);
    solaris_test_event_wait(&fast.disposed);
    wait_completed(&f, 2);
    CHECK(snapshot(&f).last_operation_id == b && snapshot(&f).pending_operations == 1);
    CHECK(solaris_engine_flush(f.engine, 1, NULL) == SOLARIS_ETIMEDOUT);
    solaris_runtime_operation_complete(slow.operation, SOLARIS_OK, 0);
    CHECK(solaris_engine_flush(f.engine, 5000, NULL) == SOLARIS_OK);
    CHECK(snapshot(&f).completed_operations == 3 && !snapshot(&f).pending_operations);
    CHECK(f.events[1].operation_id == b && f.events[2].operation_id == a);
    CHECK(solaris_engine_cancel(f.engine, a, NULL) == SOLARIS_ECLOSED);
    fixture_destroy(&f);
    job_destroy(&slow);
    job_destroy(&fast);
}
static void cancellation_and_rejections(void)
{
    fixture_t f;
    fixture_init(&f, 2);
    f.block_start = 1;
    job_t skipped, automatic, rejected;
    job_init(&skipped, &f);
    job_init(&automatic, &f);
    job_init(&rejected, &f);
    automatic.automatic = 1;
    uint64_t id = 99;
    CHECK(submit(&rejected, 1, &id) == SOLARIS_ECLOSED && !id);
    CHECK(!atomic_load(&rejected.disposals));
    CHECK(solaris_engine_start(f.engine, &id, NULL) == SOLARIS_OK);
    solaris_test_event_wait(&f.start_entered);
    CHECK(solaris_engine_cancel(f.engine, 1, NULL) == SOLARIS_ENOTSUP);
    CHECK(submit(&skipped, 1, &id) == SOLARIS_OK && id == 2);
    CHECK(solaris_engine_cancel(f.engine, id, NULL) == SOLARIS_OK);
    CHECK(solaris_engine_cancel(f.engine, id, NULL) == SOLARIS_OK);
    CHECK(submit(&automatic, 1, &id) == SOLARIS_OK && id == 3);
    CHECK(submit(&rejected, 1, &id) == SOLARIS_EBUSY && !id);
    CHECK(!atomic_load(&rejected.disposals) && !atomic_load(&rejected.starts));
    solaris_test_event_signal(&f.start_release);
    CHECK(solaris_engine_flush(f.engine, 5000, NULL) == SOLARIS_OK);
    CHECK(!atomic_load(&skipped.starts) && !atomic_load(&skipped.cancels));
    CHECK(skipped.result_status == SOLARIS_ECANCELLED && atomic_load(&skipped.disposals) == 1);
    CHECK(automatic.result_status == SOLARIS_OK && atomic_load(&automatic.disposals) == 1);
    CHECK(solaris_engine_cancel(f.engine, 999, NULL) == SOLARIS_ECLOSED);
    CHECK(solaris_engine_cancel(f.engine, 0, NULL) == SOLARIS_EINVAL);
    f.block_start = 0;
    fixture_destroy(&f);
    job_destroy(&skipped);
    job_destroy(&automatic);
    job_destroy(&rejected);

    fixture_init(&f, 8);
    running(&f);
    for (unsigned publish = 0; publish < 2; ++publish) {
        job_t j;
        job_init(&j, &f);
        j.acknowledge_cancel = 1;
        j.publish_on_cancel = publish ? 42 : 0;
        CHECK(submit(&j, 1, &id) == SOLARIS_OK);
        solaris_test_event_wait(&j.started);
        CHECK(solaris_engine_cancel(f.engine, id, NULL) == SOLARIS_OK);
        CHECK(solaris_engine_flush(f.engine, 5000, NULL) == SOLARIS_OK);
        CHECK(j.result_status == (publish ? SOLARIS_OK : SOLARIS_ECANCELLED));
        CHECK(j.result_revision == (publish ? 42u : 0u) && atomic_load(&j.cancels) == 1 &&
              atomic_load(&j.disposals) == 1);
        job_destroy(&j);
    }
    job_t fail;
    job_init(&fail, &f);
    fail.start_status = SOLARIS_ENOTSUP;
    CHECK(submit(&fail, 1, &id) == SOLARIS_OK);
    CHECK(solaris_engine_flush(f.engine, 5000, NULL) == SOLARIS_OK);
    CHECK(fail.result_status == SOLARIS_ENOTSUP && atomic_load(&fail.disposals) == 1);
    fixture_destroy(&f);
    job_destroy(&fail);
}
static void bounded_window_and_reserved_completion(void)
{
    fixture_t f;
    fixture_init(&f, 2);
    running(&f);
    job_t jobs[4];
    for (size_t i = 0; i < 4; ++i)
        job_init(&jobs[i], &f);
    uint64_t id = 55;
    atomic_store(&f.fail_wake, 1);
    CHECK(submit(&jobs[0], 1, &id) == SOLARIS_EIO && !id);
    CHECK(!atomic_load(&jobs[0].disposals) && snapshot(&f).accepted_operations == 1);
    for (size_t i = 0; i < 3; ++i) {
        CHECK(submit(&jobs[i], 1, &id) == SOLARIS_OK && id == i + 2);
        solaris_test_event_wait(&jobs[i].started);
    }
    atomic_store(&f.fail_allocate, 1);
    atomic_store(&f.fail_wake, 1);
    solaris_runtime_operation_complete(jobs[2].operation, SOLARIS_OK, 0);
    solaris_runtime_operation_complete(jobs[1].operation, SOLARIS_OK, 0);
    wait_completed(&f, 3);
    CHECK(snapshot(&f).pending_operations == 1 && snapshot(&f).accepted_operations == 4);
    CHECK(submit(&jobs[3], 1, &id) == SOLARIS_EBUSY && !id);
    CHECK(solaris_engine_flush(f.engine, 0, NULL) == SOLARIS_ETIMEDOUT);
    solaris_runtime_operation_complete(jobs[0].operation, SOLARIS_OK, 0);
    CHECK(solaris_engine_flush(f.engine, 5000, NULL) == SOLARIS_OK);
    CHECK(atomic_load(&f.fail_wake) == 1); /* completions never use fallible admission */
    atomic_store(&f.fail_allocate, 0);
    atomic_store(&f.fail_wake, 0);
    jobs[3].automatic = 1;
    CHECK(submit(&jobs[3], 1, &id) == SOLARIS_OK && id == 5);
    CHECK(solaris_engine_flush(f.engine, 5000, NULL) == SOLARIS_OK);
    fixture_destroy(&f);
    for (size_t i = 0; i < 4; ++i)
        job_destroy(&jobs[i]);
}
static void resource_cancelled(void *context)
{
    solaris_test_event_signal(&((resource_t *)context)->cancelled);
}
static void resource_done(void *context)
{
    solaris_test_event_signal(&((resource_t *)context)->done);
}
static void resource_release(void *context)
{
    solaris_scope_release(&((resource_t *)context)->scope);
}
static void resource_create(void *context, solaris_status_t status)
{
    resource_t *r = context;
    CHECK(status == SOLARIS_OK);
    CHECK(solaris_scope_init(&r->scope, r->owner, resource_cancelled, resource_done, r) == SOLARIS_OK);
    solaris_scope_retain(&r->scope);
    r->release = (solaris_deferred_t){.run = resource_release, .context = r};
    solaris_test_event_signal(&r->ready);
}
static void stop_waits_for_acknowledgement(void)
{
    fixture_t f;
    fixture_init(&f, 8);
    running(&f);
    job_t j, stopped;
    job_init(&j, &f);
    job_init(&stopped, &f);
    resource_t r = {.owner = solaris_runtime_executor(f.engine, 1)};
    CHECK(!solaris_test_event_init(&r.ready, 0));
    CHECK(!solaris_test_event_init(&r.cancelled, 0));
    CHECK(!solaris_test_event_init(&r.done, 0));
    CHECK(solaris_executor_post(r.owner, resource_create, &r) == SOLARIS_OK);
    solaris_test_event_wait(&r.ready);
    j.release_resource = &r;
    uint64_t id;
    CHECK(submit(&j, 1, &id) == SOLARIS_OK);
    solaris_test_event_wait(&j.started);
    uint64_t stop_id;
    CHECK(solaris_engine_stop(f.engine, &stop_id, NULL) == SOLARIS_OK);
    solaris_test_event_wait(&j.cancelled);
    solaris_test_event_wait(&r.cancelled);
    CHECK(snapshot(&f).state == SOLARIS_ENGINE_STOPPING && snapshot(&f).pending_operations == 2);
    CHECK(submit(&stopped, 1, &id) == SOLARIS_ECLOSED && !id && !atomic_load(&stopped.disposals));
    CHECK(solaris_engine_flush(f.engine, 0, NULL) == SOLARIS_ETIMEDOUT);
    solaris_runtime_operation_complete(j.operation, SOLARIS_OK, 0);
    CHECK(solaris_engine_flush(f.engine, 5000, NULL) == SOLARIS_OK);
    CHECK(j.result_status == SOLARIS_ECANCELLED && snapshot(&f).state == SOLARIS_ENGINE_STOPPED);
    CHECK(f.events[f.event_count - 1].operation_id == stop_id && atomic_load(&j.disposals) == 1);
    solaris_test_event_wait(&r.done);
    CHECK(snapshot(&f).io_buffer_bytes == 0);
    solaris_test_event_destroy(&r.ready);
    solaris_test_event_destroy(&r.cancelled);
    solaris_test_event_destroy(&r.done);
    running(&f);
    CHECK(snapshot(&f).generation == 2);
    fixture_destroy(&f);
    job_destroy(&j);
    job_destroy(&stopped);
}
static void destroy_thread(void *context)
{
    fixture_t *f = context;
    CHECK(solaris_engine_destroy(f->engine, NULL) == SOLARIS_OK);
    atomic_store(&f->destroyed, 1);
    solaris_test_event_signal(&f->destroy_done);
}
static void destroy_waits_for_late_work(void)
{
    fixture_t f;
    fixture_init(&f, 8);
    running(&f);
    job_t held, blocked, queued;
    job_init(&held, &f);
    job_init(&blocked, &f);
    job_init(&queued, &f);
    blocked.automatic = 1;
    blocked.block_host = 1;
    uint64_t id;
    CHECK(submit(&held, 1, &id) == SOLARIS_OK);
    solaris_test_event_wait(&held.started);
    CHECK(submit(&blocked, 1, &id) == SOLARIS_OK);
    solaris_test_event_wait(&blocked.host_entered);
    CHECK(submit(&queued, 0, &id) == SOLARIS_OK);
    CHECK(solaris_engine_stop(f.engine, &id, NULL) == SOLARIS_OK);
    uv_thread_t thread;
    CHECK(!uv_thread_create(&thread, destroy_thread, &f));
    solaris_test_event_wait(&f.shutdown_entered);
    CHECK(!atomic_load(&f.destroyed));
    solaris_test_event_signal(&blocked.host_release);
    solaris_test_event_wait(&held.cancelled);
    CHECK(!atomic_load(&f.destroyed));
    solaris_runtime_operation_complete(held.operation, SOLARIS_ECANCELLED, 73);
    solaris_test_event_wait(&f.destroy_done);
    CHECK(!uv_thread_join(&thread));
    f.engine = NULL;
    CHECK(held.result_status == SOLARIS_OK && held.result_revision == 73 && atomic_load(&held.disposals) == 1);
    CHECK(queued.result_status == SOLARIS_ECANCELLED && !atomic_load(&queued.starts) &&
          atomic_load(&queued.disposals) == 1);
    fixture_destroy(&f);
    job_destroy(&held);
    job_destroy(&blocked);
    job_destroy(&queued);
}
typedef struct race {
    fixture_t *fixture;
    job_t *job;
    uint64_t id, revision;
    solaris_test_event_t gate;
    atomic_int cancel_status;
} race_t;
static void race_cancel(void *context)
{
    race_t *r = context;
    solaris_test_event_wait(&r->gate);
    atomic_store(&r->cancel_status, solaris_engine_cancel(r->fixture->engine, r->id, NULL));
}
static void race_complete(void *context)
{
    race_t *r = context;
    solaris_test_event_wait(&r->gate);
    solaris_runtime_operation_complete(r->job->operation, SOLARIS_OK, r->revision);
}
static void cancellation_completion_race(void)
{
    fixture_t f;
    fixture_init(&f, 8);
    running(&f);
    for (unsigned i = 0; i < 64; ++i) {
        job_t j;
        job_init(&j, &f);
        race_t r = {.fixture = &f, .job = &j, .revision = i & 1u ? 91u : 0u};
        CHECK(!solaris_test_event_init(&r.gate, 0));
        atomic_init(&r.cancel_status, SOLARIS_EINVAL);
        CHECK(submit(&j, 1, &r.id) == SOLARIS_OK);
        solaris_test_event_wait(&j.started);
        uv_thread_t cancel_thread, complete_thread;
        CHECK(!uv_thread_create(&cancel_thread, race_cancel, &r));
        CHECK(!uv_thread_create(&complete_thread, race_complete, &r));
        solaris_test_event_signal(&r.gate);
        solaris_test_event_signal(&r.gate);
        CHECK(!uv_thread_join(&cancel_thread));
        CHECK(!uv_thread_join(&complete_thread));
        CHECK(solaris_engine_flush(f.engine, 5000, NULL) == SOLARIS_OK);
        int cancel_status = atomic_load(&r.cancel_status);
        CHECK(cancel_status == SOLARIS_OK || cancel_status == SOLARIS_ECLOSED);
        CHECK(j.result_status == (r.revision || cancel_status == SOLARIS_ECLOSED ? SOLARIS_OK : SOLARIS_ECANCELLED));
        CHECK(j.result_revision == r.revision && atomic_load(&j.cancels) <= 1 && atomic_load(&j.disposals) == 1);
        solaris_test_event_destroy(&r.gate);
        job_destroy(&j);
    }
    fixture_destroy(&f);
}
int main(void)
{
    out_of_order();
    cancellation_and_rejections();
    bounded_window_and_reserved_completion();
    stop_waits_for_acknowledgement();
    destroy_waits_for_late_work();
    cancellation_completion_race();
    puts("Operation contract: out-of-order fences, callback ownership, rollback, reserved completions, cancellation "
         "and lifecycle drain passed");
    return 0;
}
