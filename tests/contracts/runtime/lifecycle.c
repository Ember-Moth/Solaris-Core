#include <solaris/core.h>
#include "runtime/engine/internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>

#define CHECK(expr) do { if (!(expr)) { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expr); abort(); \
} } while (0)

typedef struct fixture {
    uv_mutex_t mutex;
    size_t allocations;
    size_t live;
    size_t fail_allocation;
    int fail_armed;
    solaris_runtime_point_t fail_point;
    uint64_t time_ns;
    uv_sem_t *release_at_shutdown;
} fixture_t;

typedef struct capture {
    solaris_engine_t *engine;
    solaris_event_t events[1024];
    size_t count;
    int block_first;
    int reenter;
    unsigned int reentered;
    uv_sem_t entered;
    uv_sem_t release;
} capture_t;

static void fixture_init(fixture_t *f)
{
    memset(f, 0, sizeof(*f));
    CHECK(uv_mutex_init(&f->mutex) == 0);
    f->time_ns = 100u;
}

static void fixture_destroy(fixture_t *f)
{
    CHECK(f->live == 0u);
    uv_mutex_destroy(&f->mutex);
}

static void *allocate(void *context, size_t size)
{
    fixture_t *f = context;
    uv_mutex_lock(&f->mutex);
    f->allocations++;
    const int fail = f->fail_allocation == f->allocations;
    void *p = fail ? NULL : malloc(size);
    if (p != NULL) f->live++;
    uv_mutex_unlock(&f->mutex);
    return p;
}

static void deallocate(void *context, void *pointer)
{
    fixture_t *f = context;
    if (pointer != NULL) {
        uv_mutex_lock(&f->mutex);
        CHECK(f->live > 0u);
        f->live--;
        uv_mutex_unlock(&f->mutex);
        free(pointer);
    }
}

static uint64_t fake_now(void *context)
{
    fixture_t *f = context;
    uv_mutex_lock(&f->mutex);
    const uint64_t now = f->time_ns;
    uv_mutex_unlock(&f->mutex);
    return now;
}

static int fault_checkpoint(void *context, solaris_runtime_point_t point)
{
    fixture_t *f = context;
    uv_mutex_lock(&f->mutex);
    int rc = 0;
    if (f->fail_armed && f->fail_point == point) {
        f->fail_armed = 0;
        rc = UV_EIO;
    }
    uv_sem_t *release = point == SOLARIS_POINT_SHUTDOWN ? f->release_at_shutdown : NULL;
    uv_mutex_unlock(&f->mutex);
    if (release != NULL) uv_sem_post(release);
    return rc;
}

static solaris_runtime_services_t services(fixture_t *f)
{
    const solaris_runtime_services_t result = {
        f, allocate, deallocate, fake_now, fault_checkpoint
    };
    return result;
}

static void event_cb(void *context, const solaris_event_t *event)
{
    capture_t *c = context;
    CHECK(c->count < sizeof(c->events) / sizeof(c->events[0]));
    CHECK(event->operation_id == c->count + 1u);
    c->events[c->count++] = *event;
    if (c->block_first && c->count == 1u) {
        uv_sem_post(&c->entered);
        uv_sem_wait(&c->release);
    }
    if (c->reenter && event->operation == SOLARIS_OPERATION_START && event->status == SOLARIS_OK) {
        solaris_engine_snapshot_t snapshot;
        solaris_error_t error;
        uint64_t id;
        CHECK(solaris_engine_get_snapshot(c->engine, &snapshot, &error) == SOLARIS_OK);
        CHECK(snapshot.state == SOLARIS_ENGINE_RUNNING);
        CHECK(solaris_engine_flush(c->engine, 0, &error) == SOLARIS_EDEADLOCK);
        CHECK(solaris_engine_destroy(c->engine, &error) == SOLARIS_EDEADLOCK);
        CHECK(solaris_engine_stop(c->engine, &id, &error) == SOLARIS_OK);
        c->reentered++;
    }
}

static void capture_init(capture_t *c)
{
    memset(c, 0, sizeof(*c));
    CHECK(uv_sem_init(&c->entered, 0u) == 0);
    CHECK(uv_sem_init(&c->release, 0u) == 0);
}

static void capture_destroy(capture_t *c)
{
    uv_sem_destroy(&c->entered);
    uv_sem_destroy(&c->release);
}

static solaris_engine_t *create(fixture_t *f, capture_t *c, uint32_t capacity)
{
    solaris_engine_t *engine = NULL;
    solaris_engine_options_t options;
    solaris_engine_options_init(&options);
    options.command_capacity = capacity;
    solaris_runtime_services_t runtime = services(f);
    solaris_host_t host = {c, event_cb};
    solaris_error_t error;
    CHECK(solaris_runtime_create(&options, &host, &runtime, &engine, &error) == SOLARIS_OK);
    CHECK(engine != NULL && error.code == SOLARIS_OK && error.message[0] == '\0');
    c->engine = engine;
    return engine;
}

static void test_validation(void)
{
    solaris_error_t error;
    solaris_engine_options_t options;
    solaris_engine_options_init(&options);
    solaris_engine_options_init(NULL);
    CHECK(solaris_engine_create(NULL, NULL, NULL, &error) == SOLARIS_EINVAL);
    solaris_engine_t *engine = NULL;
    options.io_workers = SOLARIS_MAX_IO_WORKERS + 1u;
    CHECK(solaris_engine_create(&options, NULL, &engine, &error) == SOLARIS_EINVAL);
    CHECK(engine == NULL);
    options.io_workers = 1u;
    options.command_capacity = SOLARIS_MAX_COMMAND_CAPACITY + 1u;
    CHECK(solaris_engine_create(&options, NULL, &engine, &error) == SOLARIS_EINVAL);
    CHECK(solaris_engine_create(NULL, NULL, &engine, &error) == SOLARIS_OK);
    uint64_t id = 999u;
    CHECK(solaris_engine_start(NULL, &id, &error) == SOLARIS_EINVAL && id == 0u);
    CHECK(solaris_engine_start(engine, NULL, &error) == SOLARIS_EINVAL);
    CHECK(solaris_engine_get_snapshot(engine, NULL, &error) == SOLARIS_EINVAL);
    CHECK(solaris_engine_flush(NULL, 0, &error) == SOLARIS_EINVAL);
    CHECK(solaris_engine_flush(engine, UINT64_MAX - 1u, &error) == SOLARIS_EINVAL);
    CHECK(solaris_engine_flush(engine, 0, &error) == SOLARIS_OK);
    CHECK(solaris_engine_destroy(engine, &error) == SOLARIS_OK);
    memset(&error, 0xa5, sizeof(error));
    CHECK(solaris_engine_destroy(NULL, &error) == SOLARIS_OK);
    CHECK(error.code == SOLARIS_OK && error.message[0] == '\0');
    CHECK(strlen(solaris_status_string(123456)) > 0u);
}

static void test_creation_failure_unwind(void)
{
    for (size_t failure = 1u; failure <= 2u; failure++) {
        fixture_t f; fixture_init(&f);
        f.fail_allocation = failure;
        solaris_runtime_services_t runtime = services(&f);
        solaris_engine_t *engine = NULL;
        solaris_error_t error;
        CHECK(solaris_runtime_create(NULL, NULL, &runtime, &engine, &error) == SOLARIS_ENOMEM);
        CHECK(engine == NULL);
        fixture_destroy(&f);
    }
    const solaris_runtime_point_t points[] = {
        SOLARIS_POINT_MUTEX_INIT, SOLARIS_POINT_CONDITION_INIT,
        SOLARIS_POINT_THREAD_CREATE, SOLARIS_POINT_LOOP_INIT, SOLARIS_POINT_ASYNC_INIT
    };
    for (size_t i = 0; i < sizeof(points) / sizeof(points[0]); i++) {
        fixture_t f; fixture_init(&f);
        f.fail_armed = 1; f.fail_point = points[i];
        solaris_runtime_services_t runtime = services(&f);
        solaris_engine_t *engine = NULL;
        solaris_error_t error;
        CHECK(solaris_runtime_create(NULL, NULL, &runtime, &engine, &error) == SOLARIS_EIO);
        CHECK(engine == NULL && error.system_code == UV_EIO && error.message[0] != '\0');
        fixture_destroy(&f);
    }
}

static void test_rejection_rollback_and_clock(void)
{
    fixture_t f; fixture_init(&f);
    capture_t c; capture_init(&c);
    solaris_engine_t *engine = create(&f, &c, 4u);
    uv_mutex_lock(&f.mutex);
    f.fail_point = SOLARIS_POINT_ASYNC_SEND; f.fail_armed = 1; f.time_ns = 900u;
    uv_mutex_unlock(&f.mutex);
    solaris_error_t error; uint64_t id = 123u;
    CHECK(solaris_engine_start(engine, &id, &error) == SOLARIS_EIO && id == 0u);
    solaris_engine_snapshot_t snapshot;
    CHECK(solaris_engine_get_snapshot(engine, &snapshot, NULL) == SOLARIS_OK);
    CHECK(snapshot.accepted_operations == 0u && snapshot.pending_operations == 0u);
    CHECK(snapshot.state == SOLARIS_ENGINE_IDLE && snapshot.uptime_ns == 800u);
    CHECK(solaris_engine_start(engine, &id, &error) == SOLARIS_OK && id == 1u);
    CHECK(solaris_engine_start(engine, &id, &error) == SOLARIS_EBUSY && id == 0u);
    CHECK(solaris_engine_flush(engine, 5000u, &error) == SOLARIS_OK);
    CHECK(c.count == 1u && c.events[0].monotonic_time_ns == 900u);
    CHECK(solaris_engine_destroy(engine, NULL) == SOLARIS_OK);
    fixture_destroy(&f); capture_destroy(&c);
}

static void test_backpressure_and_callback_barrier(void)
{
    fixture_t f; fixture_init(&f);
    capture_t c; capture_init(&c); c.block_first = 1;
    solaris_engine_t *engine = create(&f, &c, 2u);
    uint64_t id;
    CHECK(solaris_engine_start(engine, &id, NULL) == SOLARIS_OK);
    uv_sem_wait(&c.entered);
    CHECK(solaris_engine_stop(engine, &id, NULL) == SOLARIS_OK && id == 2u);
    CHECK(solaris_engine_start(engine, &id, NULL) == SOLARIS_OK && id == 3u);
    CHECK(solaris_engine_stop(engine, &id, NULL) == SOLARIS_EBUSY && id == 0u);
    CHECK(solaris_engine_flush(engine, 0u, NULL) == SOLARIS_ETIMEDOUT);
    CHECK(solaris_engine_flush(engine, 1u, NULL) == SOLARIS_ETIMEDOUT);
    solaris_engine_snapshot_t snapshot;
    CHECK(solaris_engine_get_snapshot(engine, &snapshot, NULL) == SOLARIS_OK);
    CHECK(snapshot.pending_operations == 3u && snapshot.completed_operations == 0u);
    uv_sem_post(&c.release);
    CHECK(solaris_engine_flush(engine, SOLARIS_TIMEOUT_INFINITE, NULL) == SOLARIS_OK);
    CHECK(c.count == 3u && c.events[1].state == SOLARIS_ENGINE_STOPPED &&
          c.events[2].state == SOLARIS_ENGINE_RUNNING);
    CHECK(solaris_engine_stop(engine, &id, NULL) == SOLARIS_OK && id == 4u);
    CHECK(solaris_engine_stop(engine, &id, NULL) == SOLARIS_OK && id == 5u);
    CHECK(solaris_engine_flush(engine, 5000u, NULL) == SOLARIS_OK);
    CHECK(c.count == 5u);
    CHECK(solaris_engine_destroy(engine, NULL) == SOLARIS_OK);
    fixture_destroy(&f); capture_destroy(&c);
}

static void test_reentrant_callbacks(void)
{
    fixture_t f; fixture_init(&f);
    capture_t c; capture_init(&c); c.reenter = 1;
    solaris_engine_t *engine = create(&f, &c, 4u);
    uint64_t id;
    CHECK(solaris_engine_start(engine, &id, NULL) == SOLARIS_OK);
    CHECK(solaris_engine_flush(engine, 5000u, NULL) == SOLARIS_OK);
    CHECK(solaris_engine_flush(engine, 5000u, NULL) == SOLARIS_OK);
    CHECK(c.count == 2u && c.reentered == 1u && c.events[1].state == SOLARIS_ENGINE_STOPPED);
    CHECK(solaris_engine_destroy(engine, NULL) == SOLARIS_OK);
    fixture_destroy(&f); capture_destroy(&c);
}

static void test_destroy_cancels_and_joins(void)
{
    fixture_t f; fixture_init(&f);
    capture_t c; capture_init(&c); c.block_first = 1;
    f.release_at_shutdown = &c.release;
    solaris_engine_t *engine = create(&f, &c, 2u);
    uint64_t id;
    CHECK(solaris_engine_start(engine, &id, NULL) == SOLARIS_OK);
    uv_sem_wait(&c.entered);
    CHECK(solaris_engine_stop(engine, &id, NULL) == SOLARIS_OK);
    CHECK(solaris_engine_start(engine, &id, NULL) == SOLARIS_OK);
    CHECK(solaris_engine_destroy(engine, NULL) == SOLARIS_OK);
    CHECK(c.count == 3u && c.events[0].status == SOLARIS_OK);
    CHECK(c.events[1].status == SOLARIS_ECANCELLED && c.events[2].status == SOLARIS_ECANCELLED);
    fixture_destroy(&f); capture_destroy(&c);
}

typedef struct producer {
    solaris_engine_t *engine;
    uint64_t ids[100];
} producer_t;

static void submit_many(void *context)
{
    producer_t *p = context;
    for (size_t i = 0; i < 100u; i++) {
        solaris_status_t rc;
        do {
            rc = solaris_engine_stop(p->engine, &p->ids[i], NULL);
            if (rc == SOLARIS_EBUSY) uv_sleep(1u);
        } while (rc == SOLARIS_EBUSY);
        CHECK(rc == SOLARIS_OK && p->ids[i] != 0u);
    }
}

static void test_concurrent_admission(void)
{
    fixture_t f; fixture_init(&f);
    capture_t c; capture_init(&c);
    solaris_engine_t *engine = create(&f, &c, 8u);
    producer_t producers[4]; uv_thread_t threads[4];
    for (size_t i = 0; i < 4u; i++) {
        producers[i].engine = engine;
        CHECK(uv_thread_create(&threads[i], submit_many, &producers[i]) == 0);
    }
    for (size_t i = 0; i < 4u; i++) CHECK(uv_thread_join(&threads[i]) == 0);
    CHECK(solaris_engine_flush(engine, 5000u, NULL) == SOLARIS_OK);
    int seen[401] = {0};
    for (size_t i = 0; i < 4u; i++) for (size_t j = 0; j < 100u; j++) {
        CHECK(producers[i].ids[j] <= 400u);
        CHECK(seen[producers[i].ids[j]]++ == 0);
    }
    CHECK(c.count == 400u);
    for (size_t i = 0; i < c.count; i++) CHECK(c.events[i].status == SOLARIS_OK);
    CHECK(solaris_engine_destroy(engine, NULL) == SOLARIS_OK);
    fixture_destroy(&f); capture_destroy(&c);
}

static void test_independent_instances(void)
{
    solaris_engine_t *a = NULL, *b = NULL;
    CHECK(solaris_engine_create(NULL, NULL, &a, NULL) == SOLARIS_OK);
    CHECK(solaris_engine_create(NULL, NULL, &b, NULL) == SOLARIS_OK);
    uint64_t id;
    CHECK(solaris_engine_start(a, &id, NULL) == SOLARIS_OK && id == 1u);
    CHECK(solaris_engine_flush(a, 5000u, NULL) == SOLARIS_OK);
    solaris_engine_snapshot_t snapshot;
    CHECK(solaris_engine_get_snapshot(b, &snapshot, NULL) == SOLARIS_OK);
    CHECK(snapshot.state == SOLARIS_ENGINE_IDLE && snapshot.accepted_operations == 0u);
    CHECK(solaris_engine_destroy(a, NULL) == SOLARIS_OK);
    CHECK(solaris_engine_start(b, &id, NULL) == SOLARIS_OK && id == 1u);
    CHECK(solaris_engine_flush(b, 5000u, NULL) == SOLARIS_OK);
    CHECK(solaris_engine_destroy(b, NULL) == SOLARIS_OK);
}

int main(void)
{
    test_validation();
    test_creation_failure_unwind();
    test_rejection_rollback_and_clock();
    test_backpressure_and_callback_barrier();
    test_reentrant_callbacks();
    test_destroy_cancels_and_joins();
    test_concurrent_admission();
    test_independent_instances();
    puts("8 Solaris lifecycle contract groups passed");
    return 0;
}
