#include <solaris/core.h>
#include "runtime/engine/internal.h"
#include "support/runtime/event.h"
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)

typedef struct fixture fixture_t;
typedef struct operation {
    fixture_t *fixture;
    uint64_t id, applied;
    solaris_status_t status;
    solaris_error_t error;
    solaris_prepared_config_t *prepared;
    atomic_uint typed, generic;
    int block_typed, block_event;
    solaris_test_event_t typed_entered, typed_release, event_entered, event_release;
} operation_t;
struct fixture {
    solaris_engine_t *engine;
    uv_mutex_t mutex;
    uv_thread_t owner, host;
    int owner_set, block_start;
    operation_t *typed_operation;
    atomic_int fail_background, gate_background, destroyed;
    solaris_test_event_t start_entered, start_release;
    solaris_test_event_t work_entered, work_release, destroy_entered, destroy_done;
};
typedef struct reserved_port { uv_loop_t loop; uv_tcp_t tcp; uint16_t port; } reserved_port_t;
static void connection(uv_stream_t *stream, int status) { (void)stream; (void)status; }
static int reserve(reserved_port_t *port, uint16_t desired)
{
    memset(port, 0, sizeof(*port)); CHECK(!uv_loop_init(&port->loop)); CHECK(!uv_tcp_init(&port->loop, &port->tcp));
    struct sockaddr_in address; CHECK(!uv_ip4_addr("127.0.0.1", desired, &address));
    int status = uv_tcp_bind(&port->tcp, (const struct sockaddr *)&address, 0);
    if (!status) status = uv_listen((uv_stream_t *)&port->tcp, 8, connection);
    if (!status) {
        struct sockaddr_storage bound; int length = sizeof(bound);
        CHECK(!uv_tcp_getsockname(&port->tcp, (struct sockaddr *)&bound, &length));
        port->port = ntohs(((struct sockaddr_in *)&bound)->sin_port); return 1;
    }
    uv_close((uv_handle_t *)&port->tcp, NULL); CHECK(!uv_run(&port->loop, UV_RUN_DEFAULT)); CHECK(!uv_loop_close(&port->loop));
    return 0;
}
static void unreserve(reserved_port_t *port)
{
    uv_close((uv_handle_t *)&port->tcp, NULL); CHECK(!uv_run(&port->loop, UV_RUN_DEFAULT)); CHECK(!uv_loop_close(&port->loop));
}
static void owner(fixture_t *f)
{
    uv_thread_t current = uv_thread_self(); uv_mutex_lock(&f->mutex);
    if (!f->owner_set) { f->owner = current; f->owner_set = 1; }
    CHECK(uv_thread_equal(&current, &f->owner)); uv_mutex_unlock(&f->mutex);
}
static void *allocate(void *context, size_t size)
{
    fixture_t *f = context;
    if ((atomic_load(&f->fail_background) || atomic_load(&f->gate_background)) && !solaris_executor_current()) {
        uv_thread_t current = uv_thread_self(); uv_mutex_lock(&f->mutex);
        int foreground = uv_thread_equal(&current, &f->host) ||
            (f->owner_set && uv_thread_equal(&current, &f->owner)); uv_mutex_unlock(&f->mutex);
        if (!foreground) {
            if (atomic_exchange(&f->gate_background, 0)) {
                solaris_test_event_signal(&f->work_entered);
                solaris_test_event_wait(&f->work_release);
            }
            if (atomic_load(&f->fail_background)) return NULL;
        }
    }
    return malloc(size);
}
static int checkpoint(void *context, solaris_runtime_point_t point)
{
    fixture_t *f = context;
    if (point == SOLARIS_POINT_SHUTDOWN) solaris_test_event_signal(&f->destroy_entered);
    return 0;
}
static void event(void *context, const solaris_event_t *result)
{
    fixture_t *f = context; owner(f);
    if (result->operation == SOLARIS_OPERATION_START && f->block_start) {
        solaris_test_event_signal(&f->start_entered); solaris_test_event_wait(&f->start_release);
    }
    if (result->operation == SOLARIS_OPERATION_CONFIG_PREPARE || result->operation == SOLARIS_OPERATION_CONFIG_APPLY) {
        operation_t *operation = f->typed_operation;
        CHECK(operation && operation->typed == 1 && !operation->generic && operation->id == result->operation_id);
        CHECK(operation->status == result->status && operation->applied == result->config_revision);
        operation->generic = 1; f->typed_operation = NULL;
        solaris_test_event_signal(&operation->event_entered);
        if (operation->block_event) {
            solaris_test_event_wait(&operation->event_release);
        }
    }
}
static void operation_init(operation_t *operation, fixture_t *f)
{
    memset(operation, 0, sizeof(*operation)); operation->fixture = f;
    atomic_init(&operation->typed, 0); atomic_init(&operation->generic, 0);
    CHECK(!solaris_test_event_init(&operation->typed_entered, 0)); CHECK(!solaris_test_event_init(&operation->typed_release, 0));
    CHECK(!solaris_test_event_init(&operation->event_entered, 0)); CHECK(!solaris_test_event_init(&operation->event_release, 0));
}
static void operation_done(operation_t *operation)
{
    if (operation->prepared) solaris_prepared_config_release(operation->prepared);
    solaris_test_event_destroy(&operation->typed_entered); solaris_test_event_destroy(&operation->typed_release);
    solaris_test_event_destroy(&operation->event_entered); solaris_test_event_destroy(&operation->event_release);
}
static void typed(operation_t *operation, solaris_status_t status, uint64_t applied, const solaris_error_t *error)
{
    fixture_t *f = operation->fixture; owner(f);
    CHECK(!operation->typed && !operation->generic && !f->typed_operation);
    CHECK(solaris_engine_flush(f->engine, 0, NULL) == SOLARIS_EDEADLOCK);
    CHECK(solaris_engine_destroy(f->engine, NULL) == SOLARIS_EDEADLOCK);
    operation->status = status; operation->applied = applied;
    if (error) { operation->error = *error; CHECK(error->code == status); }
    operation->typed = 1; f->typed_operation = operation;
    if (operation->block_typed) {
        solaris_test_event_signal(&operation->typed_entered); solaris_test_event_wait(&operation->typed_release);
    }
}
static void prepared(void *context, solaris_status_t status, solaris_prepared_config_t *result, const solaris_error_t *error)
{
    operation_t *operation = context;
    CHECK((status == SOLARIS_OK) == (result != NULL)); operation->prepared = result;
    typed(operation, status, 0, error);
}
static void committed(void *context, solaris_status_t status, uint64_t applied, const solaris_error_t *error)
{
    CHECK(status == SOLARIS_OK || applied == 0); typed(context, status, applied, error);
}
static void fixture_init(fixture_t *f)
{
    memset(f, 0, sizeof(*f)); f->host = uv_thread_self();
    atomic_init(&f->fail_background, 0); atomic_init(&f->gate_background, 0); atomic_init(&f->destroyed, 0);
    CHECK(!uv_mutex_init(&f->mutex));
    CHECK(!solaris_test_event_init(&f->start_entered, 0)); CHECK(!solaris_test_event_init(&f->start_release, 0));
    CHECK(!solaris_test_event_init(&f->work_entered, 0)); CHECK(!solaris_test_event_init(&f->work_release, 0));
    CHECK(!solaris_test_event_init(&f->destroy_entered, 0)); CHECK(!solaris_test_event_init(&f->destroy_done, 0));
    solaris_engine_options_t options; solaris_engine_options_init(&options); options.io_workers = 2;
    solaris_host_t host = {.context = f, .on_event = event};
    solaris_runtime_services_t services; solaris_runtime_services_init(&services);
    services.context = f; services.allocate = allocate; services.checkpoint = checkpoint;
    CHECK(solaris_runtime_create(&options, &host, &services, &f->engine, NULL) == SOLARIS_OK);
}
static void flush(fixture_t *f) { CHECK(solaris_engine_flush(f->engine, 5000, NULL) == SOLARIS_OK); }
static void running(fixture_t *f)
{
    uint64_t id; CHECK(solaris_engine_start(f->engine, &id, NULL) == SOLARIS_OK); flush(f);
}
static void fixture_destroy(fixture_t *f)
{
    if (f->engine) CHECK(solaris_engine_destroy(f->engine, NULL) == SOLARIS_OK);
    f->engine = NULL; solaris_test_event_destroy(&f->start_entered); solaris_test_event_destroy(&f->start_release);
    solaris_test_event_destroy(&f->work_entered); solaris_test_event_destroy(&f->work_release);
    solaris_test_event_destroy(&f->destroy_entered); solaris_test_event_destroy(&f->destroy_done);
    uv_mutex_destroy(&f->mutex);
}
static solaris_config_t *compile(uint16_t port)
{
    char yaml[128]; int size = snprintf(yaml, sizeof(yaml), "mode: direct\nmixed-port: %u\nbind-address: 127.0.0.1\n", port);
    solaris_config_t *image; solaris_diagnostics_t *diagnostics = NULL; solaris_error_t error;
    CHECK(solaris_config_compile_bytes(yaml, (size_t)size, NULL, &image, &diagnostics, &error) == SOLARIS_OK);
    solaris_diagnostics_release(diagnostics); memset(yaml, 0xff, sizeof(yaml)); return image;
}
static void prepare_submit(operation_t *operation, solaris_config_t *image, int ephemeral)
{
    solaris_config_listener_info_t listener; CHECK(solaris_config_get_listener(image, 0, &listener) == SOLARIS_OK);
    solaris_config_bind_override_t binding = {.listener_id = listener.id, .address = "127.0.0.1", .port = 0};
    solaris_config_prepare_options_t options; solaris_config_prepare_options_init(&options);
    if (ephemeral) { options.bindings = &binding; options.binding_count = 1; }
    CHECK(solaris_engine_prepare_config(operation->fixture->engine, image, &options, prepared, operation,
        &operation->id, NULL) == SOLARIS_OK && operation->id);
}
static void prepare_ready(operation_t *operation, solaris_config_t *image, int ephemeral)
{
    prepare_submit(operation, image, ephemeral); flush(operation->fixture);
    CHECK(operation->typed == 1 && operation->generic == 1 && operation->status == SOLARIS_OK && operation->prepared);
    solaris_prepared_config_snapshot_t snapshot; CHECK(solaris_prepared_config_get_snapshot(operation->prepared, &snapshot) == SOLARIS_OK);
    CHECK(snapshot.state == SOLARIS_PREPARED_READY);
}
static void commit_submit(operation_t *operation, solaris_prepared_config_t *candidate)
{
    CHECK(solaris_engine_commit_config(operation->fixture->engine, candidate, committed, operation,
        &operation->id, NULL) == SOLARIS_OK && operation->id);
}
static void commit_ready(operation_t *operation, solaris_prepared_config_t *candidate)
{
    commit_submit(operation, candidate); flush(operation->fixture);
    CHECK(operation->typed == 1 && operation->generic == 1 && operation->status == SOLARIS_OK && operation->applied);
}
static solaris_active_config_snapshot_t active(fixture_t *f)
{
    solaris_active_config_snapshot_t snapshot; CHECK(solaris_engine_get_config_snapshot(f->engine, &snapshot, NULL) == SOLARIS_OK); return snapshot;
}
static void rejection_copy_and_callbacks(void)
{
    fixture_t f; fixture_init(&f); solaris_config_t *image = compile(45731);
    operation_t rejected, request, commit; operation_init(&rejected, &f); operation_init(&request, &f); operation_init(&commit, &f);
    rejected.id = 99;
    CHECK(solaris_engine_prepare_config(f.engine, image, NULL, prepared, &rejected, &rejected.id, NULL) == SOLARIS_ECLOSED);
    CHECK(!rejected.id && !rejected.typed && !rejected.generic);
    f.block_start = 1; uint64_t start_id; CHECK(solaris_engine_start(f.engine, &start_id, NULL) == SOLARIS_OK);
    solaris_test_event_wait(&f.start_entered);
    solaris_config_listener_info_t listener; CHECK(solaris_config_get_listener(image, 0, &listener) == SOLARIS_OK);
    char text[] = "127.0.0.1";
    solaris_config_bind_override_t binding = {.listener_id = listener.id, .address = text, .port = 0};
    solaris_config_prepare_options_t options = {.bindings = &binding, .binding_count = 1};
    request.block_typed = request.block_event = 1;
    CHECK(solaris_engine_prepare_config(f.engine, image, &options, prepared, &request, &request.id, NULL) == SOLARIS_OK);
    memset(text, 'x', sizeof(text) - 1); memset(&binding, 0xff, sizeof(binding)); memset(&options, 0xff, sizeof(options));
    solaris_config_release(image); image = NULL;
    solaris_test_event_signal(&f.start_release); solaris_test_event_wait(&request.typed_entered);
    CHECK(solaris_engine_flush(f.engine, 0, NULL) == SOLARIS_ETIMEDOUT && !request.generic);
    solaris_test_event_signal(&request.typed_release); solaris_test_event_wait(&request.event_entered);
    CHECK(solaris_engine_flush(f.engine, 0, NULL) == SOLARIS_ETIMEDOUT);
    solaris_test_event_signal(&request.event_release); flush(&f); f.block_start = 0;
    CHECK(request.status == SOLARIS_OK && request.typed == 1 && request.generic == 1);
    CHECK(solaris_prepared_config_get_listener(request.prepared, 0, &listener) == SOLARIS_OK);
    CHECK(!strcmp(listener.address, "127.0.0.1") && !strcmp(listener.requested_address, "127.0.0.1") && listener.port);
    CHECK(listener.configured_port == 45731 && !listener.requested_port && listener.binding_overridden);
    CHECK(!active(&f).active_revision);
    commit_ready(&commit, request.prepared);
    solaris_active_config_snapshot_t snapshot = active(&f);
    CHECK(snapshot.active_revision == commit.applied && snapshot.listener_count == 1 && snapshot.runtime_generation == 1);
    CHECK(solaris_engine_get_bound_listener(f.engine, snapshot.active_revision + 1, 0, &listener, NULL) == SOLARIS_EAGAIN);
    CHECK(solaris_engine_get_bound_listener(f.engine, snapshot.active_revision, 0, &listener, NULL) == SOLARIS_OK && listener.port);
    fixture_destroy(&f);
    solaris_prepared_config_snapshot_t held; CHECK(solaris_prepared_config_get_snapshot(request.prepared, &held) == SOLARIS_OK);
    CHECK(held.state == SOLARIS_PREPARED_COMMITTED && held.applied_revision == commit.applied);
    CHECK(solaris_prepared_config_get_listener(request.prepared, 0, &listener) == SOLARIS_OK && listener.port);
    operation_done(&rejected); operation_done(&request); operation_done(&commit);
}
static void queued_cancel_reuse_and_stale(void)
{
    fixture_t f; fixture_init(&f); running(&f); solaris_config_t *image = compile(45732);
    operation_t candidate, gate, cancelled, applied, stale, duplicate;
    operation_init(&candidate, &f); operation_init(&gate, &f); operation_init(&cancelled, &f);
    operation_init(&applied, &f); operation_init(&stale, &f); operation_init(&duplicate, &f);
    prepare_ready(&candidate, image, 1);
    gate.block_typed = 1; prepare_submit(&gate, image, 1); solaris_test_event_wait(&gate.typed_entered);
    commit_submit(&cancelled, candidate.prepared);
    CHECK(solaris_engine_cancel(f.engine, cancelled.id, NULL) == SOLARIS_OK);
    solaris_test_event_signal(&gate.typed_release); flush(&f);
    CHECK(cancelled.status == SOLARIS_ECANCELLED && !cancelled.applied && cancelled.typed == 1 && cancelled.generic == 1);
    solaris_prepared_config_snapshot_t snapshot; CHECK(solaris_prepared_config_get_snapshot(candidate.prepared, &snapshot) == SOLARIS_OK);
    CHECK(snapshot.state == SOLARIS_PREPARED_READY);
    commit_ready(&applied, candidate.prepared);
    commit_submit(&stale, gate.prepared); flush(&f);
    CHECK(stale.status == SOLARIS_EAGAIN && !stale.applied);
    CHECK(solaris_prepared_config_get_snapshot(gate.prepared, &snapshot) == SOLARIS_OK && snapshot.state == SOLARIS_PREPARED_CLOSED);
    CHECK(active(&f).active_revision == applied.applied);
    solaris_status_t rc = solaris_engine_commit_config(f.engine, candidate.prepared, committed, &duplicate, &duplicate.id, NULL);
    if (rc == SOLARIS_OK) { flush(&f); CHECK(duplicate.status != SOLARIS_OK && !duplicate.applied); }
    else CHECK(!duplicate.id && !duplicate.typed && !duplicate.generic);
    CHECK(active(&f).active_revision == applied.applied);
    solaris_config_release(image); fixture_destroy(&f);
    operation_done(&candidate); operation_done(&gate); operation_done(&cancelled);
    operation_done(&applied); operation_done(&stale); operation_done(&duplicate);
}
static void failures_preserve_active(void)
{
    fixture_t f; fixture_init(&f); running(&f); solaris_config_t *image = compile(45733);
    operation_t prepared_active, applied, conflict, gate, allocation;
    operation_init(&prepared_active, &f); operation_init(&applied, &f); operation_init(&conflict, &f);
    operation_init(&gate, &f); operation_init(&allocation, &f);
    prepare_ready(&prepared_active, image, 1); commit_ready(&applied, prepared_active.prepared);
    solaris_config_listener_info_t bound; CHECK(solaris_engine_get_bound_listener(f.engine, applied.applied, 0, &bound, NULL) == SOLARIS_OK);
    reserved_port_t occupied; CHECK(reserve(&occupied, 0)); solaris_config_t *conflicting = compile(occupied.port);
    prepare_submit(&conflict, conflicting, 0); solaris_config_release(conflicting); flush(&f);
    CHECK(conflict.status != SOLARIS_OK && !conflict.prepared && conflict.typed == 1 && conflict.generic == 1);
    CHECK(active(&f).active_revision == applied.applied);
    reserved_port_t probe; CHECK(!reserve(&probe, bound.port)); unreserve(&occupied);
    gate.block_typed = 1; prepare_submit(&gate, image, 1); solaris_test_event_wait(&gate.typed_entered);
    prepare_submit(&allocation, image, 1); atomic_store(&f.fail_background, 1);
    solaris_test_event_signal(&gate.typed_release); flush(&f); atomic_store(&f.fail_background, 0);
    CHECK(allocation.status == SOLARIS_ENOMEM && !allocation.prepared && allocation.typed == 1 && allocation.generic == 1);
    CHECK(active(&f).active_revision == applied.applied && !reserve(&probe, bound.port));
    solaris_config_release(image); fixture_destroy(&f);
    operation_done(&prepared_active); operation_done(&applied); operation_done(&conflict); operation_done(&gate); operation_done(&allocation);
}
static void abandon_ready_and_stop_handles(void)
{
    fixture_t f; fixture_init(&f); running(&f); solaris_config_t *image = compile(45734);
    operation_t abandoned, held, commit; operation_init(&abandoned, &f); operation_init(&held, &f); operation_init(&commit, &f);
    prepare_ready(&abandoned, image, 1);
    solaris_config_listener_info_t info; CHECK(solaris_prepared_config_get_listener(abandoned.prepared, 0, &info) == SOLARIS_OK);
    uint16_t port = info.port; reserved_port_t probe; CHECK(!reserve(&probe, port));
    solaris_prepared_config_release(abandoned.prepared); abandoned.prepared = NULL;
    /* Last-release has no operation ID. Observe actual port release instead of
     * assuming a sleep/flush proves the asynchronous cleanup has completed. */
    uint64_t deadline = uv_hrtime() + UINT64_C(5000000000);
    while (!reserve(&probe, port)) CHECK(uv_hrtime() < deadline);
    unreserve(&probe);
    solaris_engine_snapshot_t state; CHECK(solaris_engine_get_snapshot(f.engine, &state, NULL) == SOLARIS_OK && state.state == SOLARIS_ENGINE_RUNNING);
    prepare_ready(&held, image, 1); solaris_config_release(image);
    solaris_prepared_config_snapshot_t before; CHECK(solaris_prepared_config_get_snapshot(held.prepared, &before) == SOLARIS_OK);
    uint64_t stop; CHECK(solaris_engine_stop(f.engine, &stop, NULL) == SOLARIS_OK); flush(&f);
    CHECK(!active(&f).active_revision);
    solaris_prepared_config_snapshot_t after; CHECK(solaris_prepared_config_get_snapshot(held.prepared, &after) == SOLARIS_OK);
    CHECK(after.state == SOLARIS_PREPARED_CLOSED && after.base_revision == before.base_revision && after.runtime_generation == before.runtime_generation);
    CHECK(solaris_prepared_config_get_listener(held.prepared, 0, &info) == SOLARIS_OK);
    CHECK(solaris_engine_commit_config(f.engine, held.prepared, committed, &commit, &commit.id, NULL) != SOLARIS_OK);
    CHECK(!commit.id && !commit.typed && !commit.generic);
    fixture_destroy(&f);
    CHECK(solaris_prepared_config_get_snapshot(held.prepared, &after) == SOLARIS_OK && after.state == SOLARIS_PREPARED_CLOSED);
    CHECK(solaris_prepared_config_get_listener(held.prepared, 0, &info) == SOLARIS_OK && info.port);
    operation_done(&abandoned); operation_done(&held); operation_done(&commit);
}
static void destroy_thread(void *context)
{
    fixture_t *f = context;
    CHECK(solaris_engine_destroy(f->engine, NULL) == SOLARIS_OK);
    atomic_store(&f->destroyed, 1); solaris_test_event_signal(&f->destroy_done);
}
static void background_cancel(unsigned destroy)
{
    fixture_t f; fixture_init(&f); running(&f);
    operation_t request; operation_init(&request, &f); solaris_config_t *image = compile(45735);
    atomic_store(&f.gate_background, 1);
    prepare_submit(&request, image, 1); solaris_config_release(image);
    solaris_test_event_wait(&f.work_entered);
    CHECK(!request.typed && !request.generic);
    if (destroy) {
        uv_thread_t thread; CHECK(!uv_thread_create(&thread, destroy_thread, &f));
        solaris_test_event_wait(&f.destroy_entered);
        CHECK(!atomic_load(&f.destroyed) && !request.typed && !request.generic);
        solaris_test_event_signal(&f.work_release);
        solaris_test_event_wait(&f.destroy_done); CHECK(!uv_thread_join(&thread)); f.engine = NULL;
    } else {
        uint64_t stop; CHECK(solaris_engine_stop(f.engine, &stop, NULL) == SOLARIS_OK);
        uint64_t deadline = uv_hrtime() + UINT64_C(5000000000);
        solaris_engine_snapshot_t state;
        do {
            CHECK(solaris_engine_get_snapshot(f.engine, &state, NULL) == SOLARIS_OK);
            CHECK(state.state == SOLARIS_ENGINE_RUNNING || state.state == SOLARIS_ENGINE_STOPPING);
            CHECK(uv_hrtime() < deadline);
        } while (state.state != SOLARIS_ENGINE_STOPPING);
        CHECK(solaris_engine_flush(f.engine, 0, NULL) == SOLARIS_ETIMEDOUT);
        CHECK(!request.typed && !request.generic);
        solaris_test_event_signal(&f.work_release); flush(&f);
        CHECK(!active(&f).active_revision);
        CHECK(solaris_engine_get_snapshot(f.engine, &state, NULL) == SOLARIS_OK && state.state == SOLARIS_ENGINE_STOPPED);
    }
    CHECK(request.typed == 1 && request.generic == 1 && request.status == SOLARIS_ECANCELLED && !request.prepared);
    fixture_destroy(&f); operation_done(&request);
}
static void background_base_revision(void)
{
    fixture_t f; fixture_init(&f); running(&f); solaris_config_t *image = compile(45736);
    operation_t earlier, pending, applied, stale;
    operation_init(&earlier, &f); operation_init(&pending, &f); operation_init(&applied, &f); operation_init(&stale, &f);
    prepare_ready(&earlier, image, 1);
    uint64_t base = active(&f).publication_revision;
    atomic_store(&f.gate_background, 1); prepare_submit(&pending, image, 1);
    solaris_test_event_wait(&f.work_entered);
    commit_submit(&applied, earlier.prepared);
    solaris_test_event_wait(&applied.event_entered);
    CHECK(applied.status == SOLARIS_OK && applied.applied == base + 1 && applied.typed == 1 && applied.generic == 1);
    CHECK(active(&f).active_revision == applied.applied);
    CHECK(solaris_engine_flush(f.engine, 0, NULL) == SOLARIS_ETIMEDOUT);
    solaris_test_event_signal(&f.work_release); flush(&f);
    CHECK(pending.status == SOLARIS_OK && pending.prepared && pending.typed == 1 && pending.generic == 1);
    solaris_prepared_config_snapshot_t snapshot;
    CHECK(solaris_prepared_config_get_snapshot(pending.prepared, &snapshot) == SOLARIS_OK);
    CHECK(snapshot.base_revision == base && snapshot.state == SOLARIS_PREPARED_READY);
    commit_submit(&stale, pending.prepared); flush(&f);
    CHECK(stale.status == SOLARIS_EAGAIN && !stale.applied && active(&f).active_revision == applied.applied);
    solaris_config_release(image); fixture_destroy(&f);
    operation_done(&earlier); operation_done(&pending); operation_done(&applied); operation_done(&stale);
}
int main(void)
{
    rejection_copy_and_callbacks(); queued_cancel_reuse_and_stale(); failures_preserve_active(); abandon_ready_and_stop_handles();
    background_cancel(0); background_cancel(1); background_base_revision();
    puts("Config transactions: input ownership, queued cancellation reuse, stale/duplicate commits, rollback, abandonment, metadata lifetime, callback/flush fences and held background stop/destroy/base revision passed");
    return 0;
}
