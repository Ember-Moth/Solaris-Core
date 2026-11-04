#include "runtime/engine_internal.h"
#include "api/error_internal.h"

#include <stdlib.h>
#include <string.h>
#include <uv.h>

typedef struct solaris_command {
    uint64_t id;
    solaris_operation_t operation;
} solaris_command_t;

struct solaris_engine {
    solaris_runtime_services_t services;
    solaris_host_t host;
    uv_mutex_t mutex;
    uv_cond_t condition;
    uv_thread_t thread;
    uv_thread_t owner;
    uv_loop_t loop;
    uv_async_t wake;
    solaris_command_t *commands;
    size_t capacity;
    size_t head;
    size_t count;
    uint64_t accepted;
    uint64_t completed;
    uint64_t started_ns;
    uint64_t last_id;
    solaris_status_t last_status;
    solaris_engine_state_t state;
    solaris_engine_state_t requested_state;
    int ready;
    int ready_status;
    int closing;
    int wake_closing;
    int joined;
    int exit_status;
};

static void *default_allocate(void *context, size_t size)
{
    (void)context;
    return malloc(size);
}

static void default_deallocate(void *context, void *pointer)
{
    (void)context;
    free(pointer);
}

static uint64_t default_now_ns(void *context)
{
    (void)context;
    return uv_hrtime();
}

static int checkpoint(solaris_engine_t *engine, solaris_runtime_point_t point)
{
    return engine->services.checkpoint == NULL
               ? 0
               : engine->services.checkpoint(engine->services.context, point);
}

static uint64_t now_ns(solaris_engine_t *engine)
{
    return engine->services.now_ns(engine->services.context);
}

static int is_owner(solaris_engine_t *engine)
{
    uv_thread_t current = uv_thread_self();
    return uv_thread_equal(&engine->owner, &current);
}

static solaris_status_t runtime_error(solaris_error_t *error, int rc)
{
    return solaris_error_set(error,
                            rc == UV_ENOMEM ? SOLARIS_ENOMEM : SOLARIS_EIO,
                            rc, uv_strerror(rc));
}

static void release_storage(solaris_engine_t *engine)
{
    solaris_runtime_services_t services = engine->services;
    if (engine->commands != NULL) {
        services.deallocate(services.context, engine->commands);
    }
    services.deallocate(services.context, engine);
}

static void complete_command(solaris_engine_t *engine,
                              const solaris_command_t *command)
{
    solaris_event_t event;
    memset(&event, 0, sizeof(event));
    uv_mutex_lock(&engine->mutex);
    event.status = engine->closing ? SOLARIS_ECANCELLED : SOLARIS_OK;
    if (!engine->closing) {
        engine->state = command->operation == SOLARIS_OPERATION_START
                            ? SOLARIS_ENGINE_RUNNING
                            : SOLARIS_ENGINE_STOPPED;
    }
    event.state = engine->state;
    event.operation_id = command->id;
    event.operation = command->operation;
    event.monotonic_time_ns = now_ns(engine);
    uv_mutex_unlock(&engine->mutex);

    if (engine->host.on_event != NULL) {
        engine->host.on_event(engine->host.context, &event);
    }

    /* Publish completion only after the callback's borrowed state is released. */
    uv_mutex_lock(&engine->mutex);
    engine->last_id = command->id;
    engine->last_status = event.status;
    engine->completed = command->id;
    uv_cond_broadcast(&engine->condition);
    uv_mutex_unlock(&engine->mutex);
}

static void dispatch_commands(uv_async_t *handle)
{
    solaris_engine_t *engine = handle->data;
    for (unsigned int budget = 0; budget < 64u; budget++) {
        solaris_command_t command;
        uv_mutex_lock(&engine->mutex);
        if (engine->count == 0u) {
            if (engine->closing && !engine->wake_closing) {
                engine->wake_closing = 1;
                engine->state = SOLARIS_ENGINE_STOPPED;
                uv_close((uv_handle_t *)&engine->wake, NULL);
            }
            uv_mutex_unlock(&engine->mutex);
            return;
        }
        command = engine->commands[engine->head];
        engine->head = (engine->head + 1u) % engine->capacity;
        engine->count--;
        uv_mutex_unlock(&engine->mutex);
        complete_command(engine, &command);
    }
    uv_mutex_lock(&engine->mutex);
    if (engine->count != 0u || engine->closing) {
        (void)uv_async_send(&engine->wake);
    }
    uv_mutex_unlock(&engine->mutex);
}

static void worker_main(void *context)
{
    solaris_engine_t *engine = context;
    int loop_initialized = 0;
    int rc = checkpoint(engine, SOLARIS_POINT_LOOP_INIT);
    if (rc == 0) {
        rc = uv_loop_init(&engine->loop);
        loop_initialized = rc == 0;
    }
    if (rc == 0) {
        rc = checkpoint(engine, SOLARIS_POINT_ASYNC_INIT);
        if (rc == 0) {
            rc = uv_async_init(&engine->loop, &engine->wake, dispatch_commands);
        }
    }
    if (rc == 0) {
        engine->wake.data = engine;
    }
    uv_mutex_lock(&engine->mutex);
    engine->owner = uv_thread_self();
    engine->ready_status = rc;
    engine->ready = 1;
    uv_cond_broadcast(&engine->condition);
    uv_mutex_unlock(&engine->mutex);

    if (rc == 0) {
        (void)uv_run(&engine->loop, UV_RUN_DEFAULT);
    }
    if (loop_initialized) {
        engine->exit_status = uv_loop_close(&engine->loop);
    }
}

solaris_status_t solaris_runtime_create(
    const solaris_engine_options_t *options, const solaris_host_t *host,
    const solaris_runtime_services_t *services,
    solaris_engine_t **out_engine, solaris_error_t *error)
{
    if (out_engine == NULL) {
        return solaris_error_set(error, SOLARIS_EINVAL, 0, NULL);
    }
    *out_engine = NULL;
    const uint32_t workers = options == NULL || options->io_workers == 0u
                                 ? 1u : options->io_workers;
    const uint32_t capacity = options == NULL || options->command_capacity == 0u
                                 ? SOLARIS_DEFAULT_COMMAND_CAPACITY
                                 : options->command_capacity;
    if (workers != 1u) {
        return solaris_error_set(error, SOLARIS_ENOTSUP, 0,
                                "M0 supports one control worker; data-plane workers arrive in M1");
    }
    if (capacity > SOLARIS_MAX_COMMAND_CAPACITY ||
        (services != NULL && (services->allocate == NULL ||
         services->deallocate == NULL || services->now_ns == NULL))) {
        return solaris_error_set(error, SOLARIS_EINVAL, 0, NULL);
    }

    const solaris_runtime_services_t defaults = {
        NULL, default_allocate, default_deallocate, default_now_ns, NULL
    };
    solaris_runtime_services_t selected = services == NULL ? defaults : *services;
    solaris_engine_t *engine = selected.allocate(selected.context, sizeof(*engine));
    if (engine == NULL) {
        return solaris_error_set(error, SOLARIS_ENOMEM, 0, NULL);
    }
    memset(engine, 0, sizeof(*engine));
    engine->services = selected;
    engine->capacity = capacity;
    engine->commands = selected.allocate(selected.context,
                                         capacity * sizeof(*engine->commands));
    if (engine->commands == NULL) {
        release_storage(engine);
        return solaris_error_set(error, SOLARIS_ENOMEM, 0, NULL);
    }
    if (host != NULL) {
        engine->host = *host;
    }
    engine->started_ns = now_ns(engine);
    engine->state = SOLARIS_ENGINE_IDLE;
    engine->requested_state = SOLARIS_ENGINE_IDLE;

    int rc = checkpoint(engine, SOLARIS_POINT_MUTEX_INIT);
    if (rc == 0) rc = uv_mutex_init(&engine->mutex);
    if (rc != 0) {
        release_storage(engine);
        return runtime_error(error, rc);
    }
    rc = checkpoint(engine, SOLARIS_POINT_CONDITION_INIT);
    if (rc == 0) rc = uv_cond_init(&engine->condition);
    if (rc != 0) {
        uv_mutex_destroy(&engine->mutex);
        release_storage(engine);
        return runtime_error(error, rc);
    }
    rc = checkpoint(engine, SOLARIS_POINT_THREAD_CREATE);
    if (rc == 0) rc = uv_thread_create(&engine->thread, worker_main, engine);
    if (rc == 0) {
        uv_mutex_lock(&engine->mutex);
        while (!engine->ready) uv_cond_wait(&engine->condition, &engine->mutex);
        rc = engine->ready_status;
        uv_mutex_unlock(&engine->mutex);
        if (rc != 0) (void)uv_thread_join(&engine->thread);
    }
    if (rc != 0) {
        uv_cond_destroy(&engine->condition);
        uv_mutex_destroy(&engine->mutex);
        release_storage(engine);
        return runtime_error(error, rc);
    }
    *out_engine = engine;
    return solaris_error_set(error, SOLARIS_OK, 0, NULL);
}

solaris_status_t solaris_runtime_submit(solaris_engine_t *engine,
                                        solaris_operation_t operation,
                                        uint64_t *id, solaris_error_t *error)
{
    if (id != NULL) *id = 0u;
    if (engine == NULL || id == NULL ||
        (operation != SOLARIS_OPERATION_START && operation != SOLARIS_OPERATION_STOP)) {
        return solaris_error_set(error, SOLARIS_EINVAL, 0, NULL);
    }
    uv_mutex_lock(&engine->mutex);
    solaris_status_t status = SOLARIS_OK;
    if (engine->closing) status = SOLARIS_ECLOSED;
    else if (engine->count == engine->capacity) status = SOLARIS_EBUSY;
    else if (operation == SOLARIS_OPERATION_START &&
             engine->requested_state == SOLARIS_ENGINE_RUNNING) status = SOLARIS_EBUSY;
    else if (engine->accepted == UINT64_MAX) status = SOLARIS_EOVERFLOW;
    if (status != SOLARIS_OK) {
        uv_mutex_unlock(&engine->mutex);
        return solaris_error_set(error, status, 0, NULL);
    }

    const size_t index = (engine->head + engine->count) % engine->capacity;
    const uint64_t next_id = engine->accepted + 1u;
    engine->commands[index].id = next_id;
    engine->commands[index].operation = operation;
    engine->count++;
    int rc = checkpoint(engine, SOLARIS_POINT_ASYNC_SEND);
    if (rc == 0) rc = uv_async_send(&engine->wake);
    if (rc != 0) {
        /* The owner cannot consume this command until the lock is released. */
        engine->count--;
        uv_mutex_unlock(&engine->mutex);
        return runtime_error(error, rc);
    }
    engine->accepted = next_id;
    engine->requested_state = operation == SOLARIS_OPERATION_START
                                  ? SOLARIS_ENGINE_RUNNING : SOLARIS_ENGINE_STOPPED;
    *id = next_id;
    uv_mutex_unlock(&engine->mutex);
    return solaris_error_set(error, SOLARIS_OK, 0, NULL);
}

solaris_status_t solaris_runtime_snapshot(solaris_engine_t *engine,
                                          solaris_engine_snapshot_t *snapshot,
                                          solaris_error_t *error)
{
    if (engine == NULL || snapshot == NULL) {
        return solaris_error_set(error, SOLARIS_EINVAL, 0, NULL);
    }
    uv_mutex_lock(&engine->mutex);
    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->state = engine->state;
    snapshot->io_workers = 1u;
    snapshot->closing = (uint32_t)engine->closing;
    snapshot->command_capacity = (uint32_t)engine->capacity;
    snapshot->accepted_operations = engine->accepted;
    snapshot->completed_operations = engine->completed;
    snapshot->pending_operations = engine->accepted - engine->completed;
    snapshot->last_operation_id = engine->last_id;
    snapshot->last_status = engine->last_status;
    const uint64_t now = now_ns(engine);
    snapshot->uptime_ns = now >= engine->started_ns ? now - engine->started_ns : 0u;
    uv_mutex_unlock(&engine->mutex);
    return solaris_error_set(error, SOLARIS_OK, 0, NULL);
}

solaris_status_t solaris_runtime_flush(solaris_engine_t *engine,
                                       uint64_t timeout_ms,
                                       solaris_error_t *error)
{
    if (engine == NULL || (timeout_ms != SOLARIS_TIMEOUT_INFINITE &&
                           timeout_ms > UINT64_MAX / UINT64_C(1000000))) {
        return solaris_error_set(error, SOLARIS_EINVAL, 0, NULL);
    }
    if (is_owner(engine)) {
        return solaris_error_set(error, SOLARIS_EDEADLOCK, 0, NULL);
    }
    /* The blocking host wait uses the OS monotonic clock, not the test clock. */
    const uint64_t started = uv_hrtime();
    const uint64_t budget = timeout_ms == SOLARIS_TIMEOUT_INFINITE
                                ? 0u : timeout_ms * UINT64_C(1000000);
    uv_mutex_lock(&engine->mutex);
    const uint64_t target = engine->accepted;
    while (engine->completed < target) {
        if (timeout_ms == SOLARIS_TIMEOUT_INFINITE) {
            uv_cond_wait(&engine->condition, &engine->mutex);
            continue;
        }
        const uint64_t elapsed = uv_hrtime() - started;
        if (elapsed >= budget) {
            uv_mutex_unlock(&engine->mutex);
            return solaris_error_set(error, SOLARIS_ETIMEDOUT, 0, NULL);
        }
        const int rc = uv_cond_timedwait(&engine->condition, &engine->mutex,
                                         budget - elapsed);
        if (rc != 0 && rc != UV_ETIMEDOUT) {
            uv_mutex_unlock(&engine->mutex);
            return runtime_error(error, rc);
        }
    }
    uv_mutex_unlock(&engine->mutex);
    return solaris_error_set(error, SOLARIS_OK, 0, NULL);
}

solaris_status_t solaris_runtime_destroy(solaris_engine_t *engine,
                                         solaris_error_t *error)
{
    if (engine == NULL) return solaris_error_set(error, SOLARIS_OK, 0, NULL);
    if (is_owner(engine)) {
        return solaris_error_set(error, SOLARIS_EDEADLOCK, 0, NULL);
    }
    if (!engine->joined) {
        uv_mutex_lock(&engine->mutex);
        engine->closing = 1;
        int rc = uv_async_send(&engine->wake);
        if (rc != 0) engine->closing = 0;
        uv_mutex_unlock(&engine->mutex);
        if (rc != 0) return runtime_error(error, rc);
        (void)checkpoint(engine, SOLARIS_POINT_SHUTDOWN);
        rc = uv_thread_join(&engine->thread);
        if (rc != 0) return runtime_error(error, rc);
        engine->joined = 1;
    }
    if (engine->exit_status != 0) return runtime_error(error, engine->exit_status);
    uv_cond_destroy(&engine->condition);
    uv_mutex_destroy(&engine->mutex);
    release_storage(engine);
    return solaris_error_set(error, SOLARIS_OK, 0, NULL);
}
