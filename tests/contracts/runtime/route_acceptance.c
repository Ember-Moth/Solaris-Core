/* Public configuration/network driver plus deterministic private scheduling
 * gates. No route plan, policy selection or DNS answer is replaced. */
#include <solaris/core.h>
#include "runtime/engine/internal.h"
#include "support/runtime/event.h"
#include <stdatomic.h>
#include <uv.h>

static solaris_status_t acceptance_create(const solaris_engine_options_t *, const solaris_host_t *, solaris_engine_t **,
                                          solaris_error_t *);
static int acceptance_command(solaris_engine_t *, unsigned, const unsigned char *, size_t);
#define SOLARIS_RUNTIME_DRIVER_CREATE acceptance_create
#define SOLARIS_RUNTIME_DRIVER_COMMAND(engine, kind, payload, length) acceptance_command(engine, kind, payload, length)
#include "../../sdk/runtime_proxy.c"

typedef struct gate_fixture {
    solaris_engine_t *engine;
    solaris_host_t host;
    uv_loop_t pool;
    uv_work_t blockers[4];
    solaris_test_event_t entered, released;
    unsigned completed;
    int active, pending_stop, pending_close;
    uint64_t stop_id, expected_stops, close_id, expected_closes;
    atomic_uint_fast64_t offset_ns, frozen_ns, stops, last_stop_id, closes, close_matched;
    atomic_int frozen, fail_owner, fail_remaining, fail_seen, failed, stop_status, close_status;
} gate_fixture_t;
static gate_fixture_t gates;
static uint64_t gate_now(void *context)
{
    gate_fixture_t *f = context;
    return atomic_load(&f->frozen) ? atomic_load(&f->frozen_ns) : uv_hrtime() + atomic_load(&f->offset_ns);
}
static void *gate_allocate(void *context, size_t length)
{
    gate_fixture_t *f = context;
    int owner = atomic_load(&f->fail_owner);
    solaris_executor_t *current = solaris_executor_current();
    if (owner >= 0 && current && solaris_executor_id(current) == (uint32_t)owner) {
        atomic_fetch_add(&f->fail_seen, 1);
        if (atomic_fetch_sub(&f->fail_remaining, 1) == 0) {
            atomic_store(&f->fail_owner, -1);
            atomic_store(&f->failed, 1);
            return NULL;
        }
    }
    return malloc(length);
}
static void gate_event(void *context, const solaris_event_t *result)
{
    gate_fixture_t *f = context;
    if (result->operation == SOLARIS_OPERATION_STOP) {
        atomic_store(&f->last_stop_id, result->operation_id);
        atomic_store(&f->stop_status, result->status);
        atomic_fetch_add(&f->stops, 1);
    }
    if (f->host.on_event)
        f->host.on_event(f->host.context, result);
}
static void blocked_work(uv_work_t *work)
{
    gate_fixture_t *f = work->data;
    solaris_test_event_signal(&f->entered);
    solaris_test_event_wait(&f->released);
}
static void unblocked_work(uv_work_t *work, int status)
{
    gate_fixture_t *f = work->data;
    CHECK(!status);
    f->completed++;
}
static void release_pool(gate_fixture_t *f)
{
    if (!f->active)
        return;
    for (unsigned i = 0; i < 4; ++i)
        solaris_test_event_signal(&f->released);
    CHECK(!uv_run(&f->pool, UV_RUN_DEFAULT));
    CHECK(f->completed == 4);
    f->active = 0;
}
static solaris_status_t acceptance_create(const solaris_engine_options_t *options, const solaris_host_t *host,
                                          solaris_engine_t **out, solaris_error_t *error)
{
    gate_fixture_t *f = &gates;
    memset(f, 0, sizeof(*f));
    if (host)
        f->host = *host;
    CHECK(!uv_os_setenv("UV_THREADPOOL_SIZE", "4"));
    CHECK(!uv_loop_init(&f->pool));
    CHECK(!solaris_test_event_init(&f->entered, 0));
    CHECK(!solaris_test_event_init(&f->released, 0));
    atomic_init(&f->offset_ns, 0);
    atomic_init(&f->frozen_ns, 0);
    atomic_init(&f->frozen, 0);
    atomic_init(&f->fail_owner, -1);
    atomic_init(&f->fail_remaining, 0);
    atomic_init(&f->fail_seen, 0);
    atomic_init(&f->failed, 0);
    atomic_init(&f->stops, 0);
    atomic_init(&f->last_stop_id, 0);
    atomic_init(&f->stop_status, 0);
    atomic_init(&f->closes, 0);
    atomic_init(&f->close_matched, 0);
    atomic_init(&f->close_status, 0);
    solaris_runtime_services_t services;
    solaris_runtime_services_init(&services);
    services.context = f;
    services.now_ns = gate_now;
    services.allocate = gate_allocate;
    solaris_host_t selected = {.context = f, .on_event = gate_event};
    solaris_status_t status = solaris_runtime_create(options, &selected, &services, out, error);
    if (status == SOLARIS_OK)
        f->engine = *out;
    return status;
}
typedef struct fence {
    solaris_test_event_t done;
    solaris_status_t status;
} fence_t;
static void fenced(void *context, solaris_status_t status)
{
    fence_t *f = context;
    f->status = status;
    solaris_test_event_signal(&f->done);
}
static void timer_fenced(void *context, solaris_status_t status)
{
    fence_t *fence = context;
    if (status != SOLARIS_OK) {
        fenced(context, status);
        return;
    }
    solaris_deadline_t *deadline;
    status = solaris_deadline_start(solaris_executor_current(), 0, fenced, fence, &deadline);
    if (status != SOLARIS_OK)
        fenced(context, status);
}
static solaris_status_t owner_fence(solaris_engine_t *engine, int timers)
{
    for (unsigned i = 0; i < 2; ++i) {
        solaris_executor_t *owner = solaris_runtime_executor(engine, i);
        if (!owner)
            return SOLARIS_ECLOSED;
        fence_t fence;
        CHECK(!solaris_test_event_init(&fence.done, 0));
        solaris_status_t status = solaris_executor_post(owner, timers ? timer_fenced : fenced, &fence);
        if (status == SOLARIS_OK) {
            solaris_test_event_wait(&fence.done);
            status = fence.status;
        }
        if (status == SOLARIS_OK && timers) {
            /* The deadline signals from inside its callback. A later ordinary
             * task runs only after its reserved deferred destructor, so the
             * allocation baseline cannot include the gate's own timer. */
            status = solaris_executor_post(owner, fenced, &fence);
            if (status == SOLARIS_OK) {
                solaris_test_event_wait(&fence.done);
                status = fence.status;
            }
        }
        solaris_test_event_destroy(&fence.done);
        if (status != SOLARIS_OK)
            return status;
    }
    return SOLARIS_OK;
}
static void gate_closed(void *context, solaris_status_t status, uint64_t matched, const solaris_error_t *error)
{
    (void)error;
    gate_fixture_t *f = context;
    atomic_store(&f->close_status, status);
    atomic_store(&f->close_matched, matched);
    atomic_fetch_add(&f->closes, 1);
}
static int acceptance_command(solaris_engine_t *engine, unsigned kind, const unsigned char *payload, size_t length)
{
    gate_fixture_t *f = &gates;
    if (kind == 'U') {
        CHECK(!length && !f->active);
        f->completed = 0;
        f->active = 1;
        for (unsigned i = 0; i < 4; ++i) {
            f->blockers[i].data = f;
            CHECK(!uv_queue_work(&f->pool, &f->blockers[i], blocked_work, unblocked_work));
        }
        for (unsigned i = 0; i < 4; ++i)
            solaris_test_event_wait(&f->entered);
        printf("{\"status\":0,\"blocked_workers\":4}\n");
        return 1;
    }
    if (kind == 'W') {
        CHECK(!length);
        release_pool(f);
        printf("{\"status\":0,\"drained_workers\":%u}\n", f->completed);
        return 1;
    }
    if (kind == 'V') {
        CHECK(!length);
        printf("{\"status\":%d}\n", owner_fence(engine, 0));
        return 1;
    }
    if (kind == 'Z') {
        CHECK(length == 8 && !atomic_load(&f->frozen));
        uint64_t milliseconds = read64(payload);
        CHECK(milliseconds <= UINT64_MAX / UINT64_C(1000000));
        uint64_t duration = milliseconds * UINT64_C(1000000);
        CHECK(atomic_load(&f->offset_ns) <= UINT64_MAX - duration);
        atomic_fetch_add(&f->offset_ns, duration);
        for (unsigned i = 0; i < 2; ++i) {
            solaris_executor_t *owner = solaris_runtime_executor(engine, i);
            CHECK(owner);
            solaris_executor_wake(owner);
        }
        printf("{\"status\":0,\"advanced_ms\":%llu}\n", (unsigned long long)milliseconds);
        return 1;
    }
    if (kind == 'A') {
        CHECK(length == 8);
        uint32_t owner = read32(payload), failure = read32(payload + 4);
        if (owner == UINT32_MAX) {
            atomic_store(&f->fail_owner, -1);
            atomic_store(&f->frozen, 0);
        } else {
            CHECK(owner < 2 && failure <= 4096 && !atomic_load(&f->frozen));
            atomic_store(&f->frozen_ns, gate_now(f));
            atomic_store(&f->frozen, 1);
            CHECK(owner_fence(engine, 1) == SOLARIS_OK);
            atomic_store(&f->fail_seen, 0);
            atomic_store(&f->failed, 0);
            atomic_store(&f->fail_remaining, (int)failure);
            atomic_store(&f->fail_owner, (int)owner);
        }
        solaris_engine_snapshot_t memory;
        CHECK(solaris_engine_get_snapshot(engine, &memory, NULL) == SOLARIS_OK);
        printf("{\"status\":0,\"failed\":%d,\"owner_allocations\":%d,\"buffer_bytes\":%llu}\n", atomic_load(&f->failed),
               atomic_load(&f->fail_seen), (unsigned long long)memory.io_buffer_bytes);
        return 1;
    }
    if (kind == 'd') {
        CHECK((!length || length == 16) && !f->pending_close);
        f->expected_closes = atomic_load(&f->closes) + 1;
        solaris_status_t status;
        if (length) {
            solaris_connection_id_t key = {read64(payload), read64(payload + 8)};
            status = solaris_engine_close_connection(engine, &key, gate_closed, f, &f->close_id, NULL);
        } else
            status = solaris_engine_close_connections(engine, gate_closed, f, &f->close_id, NULL);
        f->pending_close = status == SOLARIS_OK;
        printf("{\"status\":%d,\"operation\":%llu}\n", status, (unsigned long long)f->close_id);
        return 1;
    }
    if (kind == 'e') {
        CHECK(!length && f->pending_close);
        CHECK(solaris_engine_flush(engine, 10000, NULL) == SOLARIS_OK);
        CHECK(atomic_load(&f->closes) == f->expected_closes);
        f->pending_close = 0;
        printf("{\"status\":%d,\"matched\":%llu,\"close_callbacks\":1}\n", atomic_load(&f->close_status),
               (unsigned long long)atomic_load(&f->close_matched));
        return 1;
    }
    if (kind == 'm') {
        CHECK(!length);
        solaris_engine_snapshot_t snapshot;
        solaris_status_t status = solaris_engine_get_snapshot(engine, &snapshot, NULL);
        printf("{\"status\":%d,\"state\":%u,\"generation\":%llu,\"buffer_bytes\":%llu}\n", status, snapshot.state,
               (unsigned long long)snapshot.generation, (unsigned long long)snapshot.io_buffer_bytes);
        return 1;
    }
    if (kind == 's') {
        CHECK(!length && !f->pending_stop);
        f->expected_stops = atomic_load(&f->stops) + 1;
        solaris_status_t status = solaris_engine_stop(engine, &f->stop_id, NULL);
        f->pending_stop = status == SOLARIS_OK;
        printf("{\"status\":%d,\"operation\":%llu}\n", status, (unsigned long long)f->stop_id);
        return 1;
    }
    if (kind == 'w') {
        CHECK(!length && f->pending_stop);
        CHECK(solaris_engine_flush(engine, 10000, NULL) == SOLARIS_OK);
        CHECK(atomic_load(&f->stops) == f->expected_stops && atomic_load(&f->last_stop_id) == f->stop_id);
        f->pending_stop = 0;
        printf("{\"status\":%d,\"stop_events\":1}\n", atomic_load(&f->stop_status));
        return 1;
    }
    if (kind == 'T') {
        atomic_store(&f->fail_owner, -1);
        atomic_store(&f->frozen, 0);
        release_pool(f);
        CHECK(!uv_loop_close(&f->pool));
        solaris_test_event_destroy(&f->entered);
        solaris_test_event_destroy(&f->released);
    }
    return 0;
}
