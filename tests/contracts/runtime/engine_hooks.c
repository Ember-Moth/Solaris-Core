#include "runtime/engine/internal.h"
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
typedef struct request_case {
    solaris_engine_t *engine;
    solaris_runtime_operation_t *operation;
    uint64_t id, action_revision, delivered_revision;
    solaris_status_t action_status, finish_status, delivered_status;
    unsigned started, actions, cancels, completed, disposed;
    solaris_test_event_t began, attempted;
    solaris_control_completion_t completion;
} request_case_t;
static solaris_status_t start(void *context, solaris_engine_t *engine, solaris_runtime_operation_t *operation)
{
    request_case_t *r = context;
    CHECK(solaris_runtime_control_loop(engine));
    r->engine = engine;
    r->operation = operation;
    r->started++;
    solaris_test_event_signal(&r->began);
    return SOLARIS_OK;
}
static void cancel(void *context)
{
    request_case_t *r = context;
    r->cancels++;
}
static void complete(void *context, solaris_status_t status, uint64_t revision)
{
    request_case_t *r = context;
    CHECK(solaris_runtime_control_loop(r->engine));
    r->completed++;
    r->delivered_status = status;
    r->delivered_revision = revision;
}
static void dispose(void *context)
{
    ((request_case_t *)context)->disposed++;
}
static void initialize(request_case_t *r, solaris_engine_t *engine)
{
    memset(r, 0, sizeof(*r));
    r->engine = engine;
    CHECK(!solaris_test_event_init(&r->began, 0));
    CHECK(!solaris_test_event_init(&r->attempted, 0));
}
static void clear(request_case_t *r)
{
    solaris_test_event_destroy(&r->began);
    solaris_test_event_destroy(&r->attempted);
}
static solaris_status_t submit(request_case_t *r)
{
    solaris_runtime_request_t request = {.operation = SOLARIS_OPERATION_CONFIG_PREPARE,
                                         .requires_running = 1,
                                         .context = r,
                                         .start = start,
                                         .cancel = cancel,
                                         .complete = complete,
                                         .dispose = dispose};
    return solaris_runtime_request_submit(r->engine, &request, &r->id, NULL);
}
static solaris_status_t publish(void *context, uint64_t *revision)
{
    request_case_t *r = context;
    r->actions++;
    *revision = r->action_revision;
    return r->action_status;
}
static void try_finish(void *context)
{
    request_case_t *r = context;
    CHECK(solaris_runtime_control_loop(r->engine));
    r->finish_status = solaris_runtime_operation_finish(r->operation, publish, r);
    if (r->finish_status == SOLARIS_OK)
        CHECK(solaris_runtime_cancel(r->engine, r->id, NULL) == SOLARIS_ECLOSED);
    else if (r->finish_status == SOLARIS_ECANCELLED)
        solaris_runtime_operation_complete(r->operation, SOLARIS_ECANCELLED, 0);
    solaris_test_event_signal(&r->attempted);
}
static void rollback(void *context)
{
    request_case_t *r = context;
    CHECK(solaris_runtime_operation_cancelled(r->operation));
    solaris_runtime_operation_complete(r->operation, SOLARIS_ECANCELLED, 0);
}
static void finish_fences(solaris_engine_t *engine)
{
    for (unsigned mode = 0; mode < 4; ++mode) {
        request_case_t r;
        initialize(&r, engine);
        CHECK(submit(&r) == SOLARIS_OK);
        solaris_test_event_wait(&r.began);
        CHECK(!solaris_runtime_operation_cancelled(r.operation));
        CHECK(solaris_runtime_operation_finish(r.operation, publish, &r) == SOLARIS_ETHREAD && !r.actions);
        if (mode == 0)
            CHECK(solaris_runtime_cancel(engine, r.id, NULL) == SOLARIS_OK);
        r.action_status = mode == 1 ? SOLARIS_EAGAIN : SOLARIS_OK;
        r.action_revision = mode == 3 ? 77 : 0;
        r.completion = (solaris_control_completion_t){.run = try_finish, .context = &r};
        CHECK(solaris_runtime_control_post(engine, &r.completion) == SOLARIS_OK);
        solaris_test_event_wait(&r.attempted);
        if (mode == 1) {
            CHECK(r.finish_status == SOLARIS_EAGAIN && r.actions == 1);
            CHECK(solaris_engine_flush(engine, 0, NULL) == SOLARIS_ETIMEDOUT);
            CHECK(solaris_runtime_cancel(engine, r.id, NULL) == SOLARIS_OK);
            r.completion.run = rollback;
            CHECK(solaris_runtime_control_post(engine, &r.completion) == SOLARIS_OK);
        }
        CHECK(solaris_engine_flush(engine, 5000, NULL) == SOLARIS_OK);
        CHECK(r.started == 1 && r.completed == 1 && r.disposed == 1);
        if (mode < 2)
            CHECK(r.delivered_status == SOLARIS_ECANCELLED && r.cancels == 1 && !r.delivered_revision);
        else
            CHECK(r.delivered_status == SOLARIS_OK && !r.cancels && r.delivered_revision == (mode == 3 ? 77u : 0u));
        if (!mode)
            CHECK(!r.actions && r.finish_status == SOLARIS_ECANCELLED);
        clear(&r);
    }
}
typedef struct full_queue {
    request_case_t requests[4];
    solaris_control_completion_t completion;
} full_queue_t;
static void complete_full(void *context)
{
    full_queue_t *f = context;
    solaris_engine_snapshot_t snapshot;
    CHECK(solaris_engine_get_snapshot(f->requests[0].engine, &snapshot, NULL) == SOLARIS_OK &&
          snapshot.pending_operations == 3);
    for (unsigned i = 0; i < 3; ++i)
        solaris_runtime_operation_complete(f->requests[i].operation, SOLARIS_OK, 0);
}
static void reserved_capacity(solaris_engine_t *engine)
{
    full_queue_t f = {0};
    for (unsigned i = 0; i < 4; ++i)
        initialize(&f.requests[i], engine);
    for (unsigned i = 0; i < 3; ++i) {
        CHECK(submit(&f.requests[i]) == SOLARIS_OK);
        solaris_test_event_wait(&f.requests[i].began);
    }
    CHECK(submit(&f.requests[3]) == SOLARIS_EBUSY && !f.requests[3].id);
    f.completion = (solaris_control_completion_t){.run = complete_full, .context = &f};
    CHECK(solaris_runtime_control_post(engine, &f.completion) == SOLARIS_OK);
    CHECK(solaris_engine_flush(engine, 5000, NULL) == SOLARIS_OK);
    for (unsigned i = 0; i < 3; ++i)
        CHECK(f.requests[i].completed == 1 && f.requests[i].disposed == 1);
    CHECK(!f.requests[3].started && !f.requests[3].completed && !f.requests[3].disposed);
    for (unsigned i = 0; i < 4; ++i)
        clear(&f.requests[i]);
}
typedef struct attachment {
    solaris_engine_t *engine;
    solaris_executor_t *workers[2];
    solaris_test_event_t stopping, destroyed;
    solaris_control_completion_t chain, release, tail;
    atomic_uint stop_calls, destroy_calls, chain_calls, tail_calls;
    atomic_int drained;
    solaris_status_t destroy_result;
} attachment_t;
static void tail(void *context)
{
    attachment_t *a = context;
    CHECK(!atomic_load(&a->destroy_calls));
    atomic_fetch_add(&a->tail_calls, 1);
}
static void release_attachment(void *context)
{
    attachment_t *a = context;
    CHECK(solaris_runtime_control_loop(a->engine));
    atomic_store(&a->drained, 1);
    CHECK(solaris_runtime_control_post(a->engine, &a->tail) == SOLARIS_OK);
}
static void chain(void *context)
{
    attachment_t *a = context;
    unsigned calls = atomic_fetch_add(&a->chain_calls, 1) + 1;
    solaris_engine_snapshot_t snapshot;
    CHECK(solaris_engine_get_snapshot(a->engine, &snapshot, NULL) == SOLARIS_OK);
    if (calls % 2)
        CHECK(solaris_runtime_control_post(a->engine, &a->chain) == SOLARIS_OK);
}
static solaris_status_t attachment_stop(void *context, int destroy)
{
    attachment_t *a = context;
    CHECK(solaris_runtime_control_loop(a->engine));
    CHECK(solaris_runtime_attachment_get(a->engine) == a);
    unsigned calls = atomic_fetch_add(&a->stop_calls, 1) + 1;
    CHECK((calls == 1 && !destroy) || (calls == 2 && destroy));
    if (!destroy)
        for (unsigned i = 0; i < 2; ++i)
            CHECK(solaris_executor_accepting(a->workers[i]));
    atomic_store(&a->drained, 0);
    CHECK(solaris_runtime_control_post(a->engine, &a->chain) == SOLARIS_OK);
    solaris_test_event_signal(&a->stopping);
    return SOLARIS_OK;
}
static int attachment_drained(void *context)
{
    attachment_t *a = context;
    CHECK(solaris_runtime_control_loop(a->engine));
    solaris_engine_snapshot_t snapshot;
    CHECK(solaris_engine_get_snapshot(a->engine, &snapshot, NULL) == SOLARIS_OK);
    return atomic_load(&a->drained);
}
static void attachment_destroy(void *context)
{
    attachment_t *a = context;
    CHECK(solaris_runtime_control_loop(a->engine));
    CHECK(!solaris_runtime_attachment_get(a->engine));
    CHECK(atomic_load(&a->drained) && atomic_load(&a->tail_calls) == 2 && atomic_load(&a->chain_calls) == 4);
    for (unsigned i = 0; i < 2; ++i)
        CHECK(solaris_executor_is_quiescent(a->workers[i]));
    solaris_engine_snapshot_t snapshot;
    CHECK(solaris_engine_get_snapshot(a->engine, &snapshot, NULL) == SOLARIS_OK &&
          snapshot.state == SOLARIS_ENGINE_STOPPED);
    CHECK(solaris_runtime_worker_count(a->engine) == 2);
    atomic_fetch_add(&a->destroy_calls, 1);
    CHECK(solaris_runtime_control_post(a->engine, &a->tail) == SOLARIS_ECLOSED);
}
static void destroy_engine(void *context)
{
    attachment_t *a = context;
    a->destroy_result = solaris_engine_destroy(a->engine, NULL);
    solaris_test_event_signal(&a->destroyed);
}
static void attachments(solaris_engine_t *engine)
{
    attachment_t a = {.engine = engine};
    atomic_init(&a.stop_calls, 0);
    atomic_init(&a.destroy_calls, 0);
    atomic_init(&a.chain_calls, 0);
    atomic_init(&a.tail_calls, 0);
    atomic_init(&a.drained, 1);
    CHECK(!solaris_test_event_init(&a.stopping, 0));
    CHECK(!solaris_test_event_init(&a.destroyed, 0));
    for (unsigned i = 0; i < 2; ++i)
        a.workers[i] = solaris_runtime_executor(engine, i);
    a.chain = (solaris_control_completion_t){.run = chain, .context = &a};
    a.release = (solaris_control_completion_t){.run = release_attachment, .context = &a};
    a.tail = (solaris_control_completion_t){.run = tail, .context = &a};
    solaris_runtime_attachment_t hooks = {
        .context = &a, .stop = attachment_stop, .drained = attachment_drained, .destroy = attachment_destroy};
    void *existing = (void *)1;
    CHECK(solaris_runtime_attachment_install(engine, &hooks, &existing) == SOLARIS_OK && !existing);
    CHECK(solaris_runtime_attachment_install(engine, &hooks, &existing) == SOLARIS_EBUSY && existing == &a);
    CHECK(solaris_runtime_attachment_get(engine) == &a && !solaris_runtime_control_loop(engine));
    uint64_t stop;
    CHECK(solaris_engine_stop(engine, &stop, NULL) == SOLARIS_OK);
    solaris_test_event_wait(&a.stopping);
    CHECK(solaris_engine_flush(engine, 20, NULL) == SOLARIS_ETIMEDOUT && !atomic_load(&a.destroy_calls));
    CHECK(solaris_runtime_control_post(engine, &a.release) == SOLARIS_OK);
    CHECK(solaris_engine_flush(engine, 5000, NULL) == SOLARIS_OK);
    CHECK(atomic_load(&a.tail_calls) == 1 && atomic_load(&a.chain_calls) == 2 && !atomic_load(&a.destroy_calls));
    uv_thread_t thread;
    CHECK(!uv_thread_create(&thread, destroy_engine, &a));
    solaris_test_event_wait(&a.stopping);
    CHECK(!atomic_load(&a.destroy_calls));
    CHECK(solaris_runtime_control_post(engine, &a.release) == SOLARIS_OK);
    solaris_test_event_wait(&a.destroyed);
    CHECK(!uv_thread_join(&thread));
    CHECK(a.destroy_result == SOLARIS_OK && atomic_load(&a.destroy_calls) == 1);
    solaris_test_event_destroy(&a.stopping);
    solaris_test_event_destroy(&a.destroyed);
}
int main(void)
{
    solaris_engine_options_t options;
    solaris_engine_options_init(&options);
    options.io_workers = 2;
    options.command_capacity = 2;
    solaris_engine_t *engine;
    CHECK(solaris_engine_create(&options, NULL, &engine, NULL) == SOLARIS_OK);
    CHECK(solaris_runtime_worker_count(engine) == 2 && !solaris_runtime_control_loop(engine));
    uint64_t id;
    CHECK(solaris_engine_start(engine, &id, NULL) == SOLARIS_OK);
    CHECK(solaris_engine_flush(engine, 5000, NULL) == SOLARIS_OK);
    reserved_capacity(engine);
    finish_fences(engine);
    attachments(engine);
    puts("engine hooks: reserved capacity/requeue, atomic publish/cancel, rollback-live operation, attachment "
         "stop/drain/destroy barriers passed");
    return 0;
}
