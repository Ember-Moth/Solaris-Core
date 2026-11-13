#include "runtime/engine/internal.h"
#include "runtime/operation/request.h"
#include "runtime/operation/ledger.h"
#include "api/common/error.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>

typedef enum operation_state {
    OPERATION_FREE,
    OPERATION_QUEUED,
    OPERATION_RUNNING,
    OPERATION_RESULT,
    OPERATION_DELIVERING,
    OPERATION_DONE
} operation_state_t;
struct solaris_runtime_operation {
    solaris_engine_t *engine;
    uint64_t id;
    solaris_operation_t kind;
    solaris_runtime_request_t request;
    operation_state_t state;
    solaris_status_t status;
    uint64_t published_revision;
    int cancel_requested, cancel_delivered;
};
typedef struct solaris_command {
    uint64_t id;
} solaris_command_t;
struct solaris_engine {
    solaris_runtime_services_t services;
    solaris_host_t host;
    uv_mutex_t mutex;
    uv_cond_t condition;
    uv_thread_t thread, owner;
    uv_loop_t loop;
    uv_async_t wake;
    uv_timer_t drain_timer;
    solaris_command_t *commands;
    solaris_runtime_operation_t *operations, *lifecycle;
    solaris_operation_ledger_t ledger;
    solaris_budget_t *control_budget;
    solaris_control_completion_t *control_head, *control_tail;
    size_t control_running;
    solaris_runtime_attachment_t attachment;
    int attachment_stop_level;
    size_t capacity, head, count;
    uint64_t started_ns, last_id;
    solaris_status_t last_status, quiesce_status;
    solaris_engine_state_t state, requested_state;
    int ready, ready_status, closing, wake_closing, joined, exit_status;
    int quiescing, workers_quiet, destroy_draining;
    solaris_executor_t **executors;
    uint32_t executor_count;
    uint64_t generation;
    solaris_budget_t *budget;
};
static void progress(solaris_engine_t *engine);
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
    return engine->services.checkpoint == NULL ? 0 : engine->services.checkpoint(engine->services.context, point);
}
static uint64_t now_ns(solaris_engine_t *engine)
{
    return engine->services.now_ns(engine->services.context);
}
static int is_owner(solaris_engine_t *engine)
{
    solaris_executor_t *executor = solaris_executor_current();
    if (executor != NULL && solaris_executor_context(executor) == engine)
        return 1;
    uv_thread_t current = uv_thread_self();
    return uv_thread_equal(&engine->owner, &current);
}
static int is_control_owner(solaris_engine_t *engine)
{
    uv_thread_t current = uv_thread_self();
    return uv_thread_equal(&engine->owner, &current);
}
solaris_status_t solaris_runtime_control_post(solaris_engine_t *engine, solaris_control_completion_t *completion)
{
    if (!engine || !completion || !completion->run)
        return SOLARIS_EINVAL;
    uv_mutex_lock(&engine->mutex);
    solaris_status_t status = SOLARIS_OK;
    if (engine->wake_closing)
        status = SOLARIS_ECLOSED;
    else if (completion->queued)
        status = SOLARIS_EBUSY;
    else {
        solaris_control_completion_t *previous = engine->control_tail;
        completion->next = NULL;
        completion->queued = 1;
        if (previous)
            previous->next = completion;
        else
            engine->control_head = completion;
        engine->control_tail = completion;
        if (uv_async_send(&engine->wake)) {
            if (previous)
                previous->next = NULL;
            else
                engine->control_head = NULL;
            engine->control_tail = previous;
            completion->queued = 0;
            status = SOLARIS_EIO;
        }
    }
    uv_mutex_unlock(&engine->mutex);
    return status;
}
solaris_status_t solaris_runtime_attachment_install(solaris_engine_t *engine,
                                                    const solaris_runtime_attachment_t *attachment, void **existing)
{
    if (existing)
        *existing = NULL;
    if (!engine || !attachment || !attachment->context || !attachment->stop || !attachment->drained ||
        !attachment->destroy || !existing)
        return SOLARIS_EINVAL;
    uv_mutex_lock(&engine->mutex);
    solaris_status_t status = SOLARIS_OK;
    if (engine->closing || engine->wake_closing)
        status = SOLARIS_ECLOSED;
    else if (engine->attachment.context) {
        *existing = engine->attachment.context;
        status = SOLARIS_EBUSY;
    } else if (engine->state == SOLARIS_ENGINE_STARTING || engine->state == SOLARIS_ENGINE_STOPPING ||
               (engine->state == SOLARIS_ENGINE_RUNNING && engine->requested_state != SOLARIS_ENGINE_RUNNING))
        status = SOLARIS_ECLOSED;
    else {
        engine->attachment = *attachment;
        engine->attachment_stop_level = 0;
    }
    uv_mutex_unlock(&engine->mutex);
    return status;
}
void *solaris_runtime_attachment_get(solaris_engine_t *engine)
{
    if (!engine)
        return NULL;
    uv_mutex_lock(&engine->mutex);
    void *context = engine->attachment.context;
    uv_mutex_unlock(&engine->mutex);
    return context;
}
uv_loop_t *solaris_runtime_control_loop(solaris_engine_t *engine)
{
    return engine && is_control_owner(engine) ? &engine->loop : NULL;
}
uint32_t solaris_runtime_worker_count(solaris_engine_t *engine)
{
    if (!engine)
        return 0;
    uv_mutex_lock(&engine->mutex);
    uint32_t count = engine->executor_count;
    uv_mutex_unlock(&engine->mutex);
    return count;
}
static solaris_status_t runtime_error(solaris_error_t *error, int rc)
{
    return solaris_error_set(error, rc == UV_ENOMEM ? SOLARIS_ENOMEM : SOLARIS_EIO, rc, uv_strerror(rc));
}
static void release_storage(solaris_engine_t *engine)
{
    solaris_runtime_services_t services = engine->services;
    solaris_status_t rc = solaris_operation_ledger_dispose(&engine->ledger);
    assert(rc == SOLARIS_OK);
    (void)rc;
    solaris_budget_release(engine->control_budget);
    if (engine->commands)
        services.deallocate(services.context, engine->commands);
    if (engine->operations)
        services.deallocate(services.context, engine->operations);
    if (engine->executors)
        services.deallocate(services.context, engine->executors);
    solaris_budget_release(engine->budget);
    solaris_network_snapshot_release(engine->host.network);
    services.deallocate(services.context, engine);
}
static int custom(const solaris_runtime_operation_t *operation)
{
    return operation->kind != SOLARIS_OPERATION_START && operation->kind != SOLARIS_OPERATION_STOP;
}
static solaris_runtime_operation_t *lookup_locked(solaris_engine_t *engine, uint64_t id)
{
    if (!id || id <= engine->ledger.watermark || id > engine->ledger.accepted)
        return NULL;
    solaris_runtime_operation_t *operation = &engine->operations[id % engine->ledger.capacity];
    return operation->id == id ? operation : NULL;
}
static void refresh_requested_locked(solaris_engine_t *engine)
{
    solaris_engine_state_t requested = engine->state;
    if (engine->lifecycle)
        requested =
            engine->lifecycle->kind == SOLARIS_OPERATION_START ? SOLARIS_ENGINE_RUNNING : SOLARIS_ENGINE_STOPPED;
    for (size_t i = 0; i < engine->count; ++i) {
        solaris_runtime_operation_t *operation =
            lookup_locked(engine, engine->commands[(engine->head + i) % engine->capacity].id);
        if (operation && !custom(operation))
            requested = operation->kind == SOLARIS_OPERATION_START ? SOLARIS_ENGINE_RUNNING : SOLARIS_ENGINE_STOPPED;
    }
    engine->requested_state = requested;
}
static void result_locked(solaris_runtime_operation_t *operation, solaris_status_t status, uint64_t revision)
{
    if (revision && status == SOLARIS_ECANCELLED)
        status = SOLARIS_OK;
    if (!revision && operation->cancel_requested && status == SOLARIS_OK)
        status = SOLARIS_ECANCELLED;
    operation->status = status;
    operation->published_revision = revision;
    operation->state = OPERATION_RESULT;
}
void solaris_runtime_operation_complete(solaris_runtime_operation_t *operation, solaris_status_t status,
                                        uint64_t published_revision)
{
    if (operation == NULL)
        return;
    solaris_engine_t *engine = operation->engine;
    uv_mutex_lock(&engine->mutex);
    /* The caller owns this reserved completion until its one acknowledgement.
     * It remains allocated even after worker admission has been closed. */
    assert(custom(operation) && operation->state == OPERATION_RUNNING);
    if (custom(operation) && operation->state == OPERATION_RUNNING) {
        result_locked(operation, status, published_revision);
        int rc = uv_async_send(&engine->wake);
        assert(rc == 0);
        (void)rc;
    }
    uv_mutex_unlock(&engine->mutex);
}
solaris_status_t solaris_runtime_operation_finish(solaris_runtime_operation_t *operation,
                                                  solaris_operation_publish_fn action, void *context)
{
    if (!operation || !action)
        return SOLARIS_EINVAL;
    solaris_engine_t *engine = operation->engine;
    if (!engine || !is_control_owner(engine))
        return SOLARIS_ETHREAD;
    uv_mutex_lock(&engine->mutex);
    solaris_status_t status;
    if (!custom(operation) || operation->state != OPERATION_RUNNING)
        status = SOLARIS_ECLOSED;
    else if (operation->cancel_requested || engine->closing)
        status = SOLARIS_ECANCELLED;
    else {
        uint64_t revision = 0;
        status = action(context, &revision);
        if (status == SOLARIS_OK) {
            result_locked(operation, SOLARIS_OK, revision);
            int rc = uv_async_send(&engine->wake);
            assert(rc == 0);
            (void)rc;
        }
    }
    uv_mutex_unlock(&engine->mutex);
    return status;
}
int solaris_runtime_operation_cancelled(solaris_runtime_operation_t *operation)
{
    if (!operation || !operation->engine)
        return 1;
    solaris_engine_t *engine = operation->engine;
    uv_mutex_lock(&engine->mutex);
    int cancelled = operation->cancel_requested || engine->closing;
    uv_mutex_unlock(&engine->mutex);
    return cancelled;
}
static void deliver(solaris_engine_t *engine, solaris_runtime_operation_t *operation)
{
    solaris_event_t event;
    uv_mutex_lock(&engine->mutex);
    assert(operation->state == OPERATION_RESULT);
    operation->state = OPERATION_DELIVERING;
    event = (solaris_event_t){.operation_id = operation->id,
                              .monotonic_time_ns = now_ns(engine),
                              .operation = operation->kind,
                              .status = operation->status,
                              .state = engine->state,
                              .config_revision = operation->published_revision};
    uv_mutex_unlock(&engine->mutex);
    if (custom(operation) && operation->request.complete)
        operation->request.complete(operation->request.context, event.status, event.config_revision);
    if (engine->host.on_event)
        engine->host.on_event(engine->host.context, &event);
    if (custom(operation) && operation->request.dispose)
        operation->request.dispose(operation->request.context);
    /* Both callbacks and owned-context disposal belong to the completion fence. */
    uv_mutex_lock(&engine->mutex);
    operation->state = OPERATION_DONE;
    engine->last_id = operation->id;
    engine->last_status = event.status;
    solaris_status_t rc = solaris_operation_ledger_complete(&engine->ledger, operation->id);
    assert(rc == SOLARIS_OK);
    (void)rc;
    refresh_requested_locked(engine);
    uv_cond_broadcast(&engine->condition);
    uv_mutex_unlock(&engine->mutex);
}
static void drain_tick(uv_timer_t *timer)
{
    progress(timer->data);
}
static void stop_attachment(solaris_engine_t *engine)
{
    uv_mutex_lock(&engine->mutex);
    int level = engine->destroy_draining ? 2 : 1;
    solaris_runtime_attachment_t attachment = engine->attachment;
    int call = attachment.context && engine->attachment_stop_level < level;
    if (call)
        engine->attachment_stop_level = level;
    uv_mutex_unlock(&engine->mutex);
    if (call) {
        solaris_status_t status = attachment.stop(attachment.context, level == 2);
        if (engine->quiesce_status == SOLARIS_OK)
            engine->quiesce_status = status;
    }
}
static int attachment_drained(solaris_engine_t *engine)
{
    uv_mutex_lock(&engine->mutex);
    solaris_runtime_attachment_t attachment = engine->attachment;
    uv_mutex_unlock(&engine->mutex);
    return !attachment.context || attachment.drained(attachment.context);
}
static void begin_quiescence(solaris_engine_t *engine)
{
    if (engine->quiescing) {
        stop_attachment(engine);
        return;
    }
    engine->quiescing = 1;
    engine->workers_quiet = 0;
    engine->quiesce_status = SOLARIS_OK;
    stop_attachment(engine);
    for (uint32_t i = 0; i < engine->executor_count; ++i) {
        solaris_status_t rc = solaris_executor_begin_quiesce(engine->executors[i]);
        if (rc != SOLARIS_OK && engine->quiesce_status == SOLARIS_OK)
            engine->quiesce_status = rc;
    }
    int rc = uv_timer_start(&engine->drain_timer, drain_tick, 1, 1);
    assert(rc == 0);
    (void)rc;
}
static int workers_drained(solaris_engine_t *engine)
{
    if (engine->workers_quiet)
        return 1;
    for (uint32_t i = 0; i < engine->executor_count; ++i)
        if (!solaris_executor_is_quiescent(engine->executors[i]))
            return 0;
    engine->workers_quiet = 1;
    return 1;
}
static int custom_before_locked(solaris_engine_t *engine, uint64_t cutoff)
{
    for (size_t i = 0; i < engine->ledger.capacity; ++i) {
        solaris_runtime_operation_t *operation = &engine->operations[i];
        if (operation->id && operation->id < cutoff && custom(operation) && operation->state != OPERATION_FREE &&
            operation->state != OPERATION_DONE)
            return 1;
    }
    return 0;
}
static void request_cancellation_locked(solaris_engine_t *engine, uint64_t cutoff)
{
    for (size_t i = 0; i < engine->ledger.capacity; ++i) {
        solaris_runtime_operation_t *operation = &engine->operations[i];
        if (operation->id && operation->id <= cutoff && custom(operation) &&
            (operation->state == OPERATION_QUEUED || operation->state == OPERATION_RUNNING))
            operation->cancel_requested = 1;
    }
}
static int finish_lifecycle(solaris_engine_t *engine)
{
    if (!engine->lifecycle || !engine->quiescing || !workers_drained(engine) || !attachment_drained(engine))
        return 0;
    uv_mutex_lock(&engine->mutex);
    solaris_runtime_operation_t *operation = engine->lifecycle;
    if (engine->control_head || engine->control_running ||
        (operation->kind == SOLARIS_OPERATION_STOP && custom_before_locked(engine, operation->id))) {
        uv_mutex_unlock(&engine->mutex);
        return 0;
    }
    solaris_status_t status = operation->status;
    if (status == SOLARIS_OK)
        status = engine->quiesce_status;
    engine->state = SOLARIS_ENGINE_STOPPED;
    engine->lifecycle = NULL;
    if (!engine->destroy_draining) {
        engine->quiescing = 0;
        (void)uv_timer_stop(&engine->drain_timer);
    }
    result_locked(operation, status, 0);
    refresh_requested_locked(engine);
    uv_mutex_unlock(&engine->mutex);
    return 1;
}
static void start_lifecycle(solaris_engine_t *engine, solaris_runtime_operation_t *operation)
{
    uv_mutex_lock(&engine->mutex);
    engine->lifecycle = operation;
    operation->state = OPERATION_RUNNING;
    operation->status = SOLARIS_OK;
    engine->state = operation->kind == SOLARIS_OPERATION_START ? SOLARIS_ENGINE_STARTING : SOLARIS_ENGINE_STOPPING;
    uint64_t generation = engine->generation;
    if (operation->kind == SOLARIS_OPERATION_STOP)
        request_cancellation_locked(engine, operation->id);
    uv_mutex_unlock(&engine->mutex);
    if (operation->kind == SOLARIS_OPERATION_STOP) {
        begin_quiescence(engine);
        return;
    }
    solaris_status_t status = generation == UINT64_MAX ? SOLARIS_EOVERFLOW : SOLARIS_OK;
    for (uint32_t i = 0; status == SOLARIS_OK && i < engine->executor_count; ++i)
        status = solaris_executor_activate(engine->executors[i], generation + 1);
    if (status != SOLARIS_OK) {
        operation->status = status;
        begin_quiescence(engine);
        return;
    }
    uv_mutex_lock(&engine->mutex);
    engine->generation = generation + 1;
    engine->state = SOLARIS_ENGINE_RUNNING;
    engine->attachment_stop_level = 0;
    engine->lifecycle = NULL;
    result_locked(operation, SOLARIS_OK, 0);
    refresh_requested_locked(engine);
    uv_mutex_unlock(&engine->mutex);
}
static void start_request(solaris_engine_t *engine, solaris_runtime_operation_t *operation)
{
    uv_mutex_lock(&engine->mutex);
    if (operation->cancel_requested || engine->closing) {
        result_locked(operation, SOLARIS_ECANCELLED, 0);
        uv_mutex_unlock(&engine->mutex);
        return;
    }
    if (operation->request.requires_running && engine->state != SOLARIS_ENGINE_RUNNING) {
        result_locked(operation, SOLARIS_ECLOSED, 0);
        uv_mutex_unlock(&engine->mutex);
        return;
    }
    operation->state = OPERATION_RUNNING;
    uv_mutex_unlock(&engine->mutex);
    solaris_status_t rc = operation->request.start(operation->request.context, engine, operation);
    if (rc != SOLARIS_OK) {
        uv_mutex_lock(&engine->mutex);
        assert(operation->state == OPERATION_RUNNING);
        if (operation->state == OPERATION_RUNNING)
            result_locked(operation, rc, 0);
        uv_mutex_unlock(&engine->mutex);
    }
}
static void progress(solaris_engine_t *engine)
{
    for (unsigned budget = 0; budget < 64; ++budget) {
        uv_mutex_lock(&engine->mutex);
        int begin_destroy = engine->closing && !engine->destroy_draining;
        if (begin_destroy) {
            engine->destroy_draining = 1;
            request_cancellation_locked(engine, engine->ledger.accepted);
        }
        solaris_runtime_operation_t *result = NULL, *cancel = NULL;
        /* A fixed window bounds both this scan and all reserved completions. */
        for (size_t i = 0; i < engine->ledger.capacity; ++i) {
            solaris_runtime_operation_t *operation = &engine->operations[i];
            if (operation->state == OPERATION_RESULT && (!result || operation->id < result->id))
                result = operation;
            if (operation->state == OPERATION_RUNNING && custom(operation) && operation->cancel_requested &&
                !operation->cancel_delivered && (!cancel || operation->id < cancel->id))
                cancel = operation;
        }
        if (cancel && !result)
            cancel->cancel_delivered = 1;
        uv_mutex_unlock(&engine->mutex);
        if (begin_destroy)
            begin_quiescence(engine);
        if (result) {
            deliver(engine, result);
            continue;
        }
        if (cancel) {
            if (cancel->request.cancel)
                cancel->request.cancel(cancel->request.context);
            continue;
        }
        uv_mutex_lock(&engine->mutex);
        solaris_control_completion_t *completion = engine->control_head;
        if (completion) {
            engine->control_head = completion->next;
            if (!engine->control_head)
                engine->control_tail = NULL;
            completion->next = NULL;
            completion->queued = 0;
            engine->control_running++;
        }
        uv_mutex_unlock(&engine->mutex);
        if (completion) {
            /* The callback may free the containing object or requeue its node. */
            void (*run)(void *) = completion->run;
            void *context = completion->context;
            run(context);
            uv_mutex_lock(&engine->mutex);
            assert(engine->control_running);
            engine->control_running--;
            uv_mutex_unlock(&engine->mutex);
            continue;
        }
        if (finish_lifecycle(engine))
            continue;
        uv_mutex_lock(&engine->mutex);
        solaris_runtime_operation_t *next = NULL;
        if (engine->count && ((!engine->lifecycle && !engine->quiescing) || engine->closing)) {
            uint64_t id = engine->commands[engine->head].id;
            engine->head = (engine->head + 1) % engine->capacity;
            --engine->count;
            next = lookup_locked(engine, id);
            assert(next && next->state == OPERATION_QUEUED);
            if (engine->closing)
                result_locked(next, SOLARIS_ECANCELLED, 0);
        }
        int closing = engine->closing;
        int drained = closing && !engine->lifecycle && engine->count == 0 && !engine->control_head &&
                      !engine->control_running && engine->ledger.accepted == engine->ledger.watermark;
        uv_mutex_unlock(&engine->mutex);
        if (next) {
            if (!closing) {
                if (custom(next))
                    start_request(engine, next);
                else
                    start_lifecycle(engine, next);
            }
            continue;
        }
        if (drained && workers_drained(engine) && attachment_drained(engine)) {
            uv_mutex_lock(&engine->mutex);
            int teardown = !engine->wake_closing && !engine->control_head && !engine->control_running;
            solaris_runtime_attachment_t attachment = {0};
            if (teardown) {
                engine->wake_closing = 1;
                engine->state = SOLARIS_ENGINE_STOPPED;
                attachment = engine->attachment;
                memset(&engine->attachment, 0, sizeof(engine->attachment));
            }
            uv_mutex_unlock(&engine->mutex);
            if (teardown) {
                if (attachment.context)
                    attachment.destroy(attachment.context);
                (void)uv_timer_stop(&engine->drain_timer);
                uv_close((uv_handle_t *)&engine->drain_timer, NULL);
                uv_close((uv_handle_t *)&engine->wake, NULL);
            }
        }
        return;
    }
    (void)uv_async_send(&engine->wake);
}
static void dispatch_commands(uv_async_t *handle)
{
    progress(handle->data);
}
static void worker_main(void *context)
{
    solaris_engine_t *engine = context;
    int loop_initialized = 0, wake_initialized = 0;
    int rc = checkpoint(engine, SOLARIS_POINT_LOOP_INIT);
    if (rc == 0) {
        rc = uv_loop_init(&engine->loop);
        loop_initialized = rc == 0;
    }
    if (rc == 0) {
        rc = checkpoint(engine, SOLARIS_POINT_ASYNC_INIT);
        if (rc == 0)
            rc = uv_async_init(&engine->loop, &engine->wake, dispatch_commands);
        wake_initialized = rc == 0;
    }
    if (rc == 0) {
        engine->wake.data = engine;
        rc = uv_timer_init(&engine->loop, &engine->drain_timer);
        if (rc == 0) {
            engine->drain_timer.data = engine;
        }
    }
    if (rc != 0 && wake_initialized)
        uv_close((uv_handle_t *)&engine->wake, NULL);
    uv_mutex_lock(&engine->mutex);
    engine->owner = uv_thread_self();
    engine->ready_status = rc;
    engine->ready = 1;
    uv_cond_broadcast(&engine->condition);
    uv_mutex_unlock(&engine->mutex);
    if (rc == 0 || wake_initialized)
        (void)uv_run(&engine->loop, UV_RUN_DEFAULT);
    if (loop_initialized)
        engine->exit_status = uv_loop_close(&engine->loop);
    if (rc == 0) {
        for (uint32_t i = 0; i < engine->executor_count; ++i) {
            if (solaris_executor_destroy(engine->executors[i]) != SOLARIS_OK)
                engine->exit_status = UV_EBUSY;
            else
                engine->executors[i] = NULL;
        }
    }
}

solaris_status_t solaris_runtime_create(const solaris_engine_options_t *options, const solaris_host_t *host,
                                        const solaris_runtime_services_t *services, solaris_engine_t **out_engine,
                                        solaris_error_t *error)
{
    if (out_engine == NULL) {
        return solaris_error_set(error, SOLARIS_EINVAL, 0, NULL);
    }
    *out_engine = NULL;
    const uint32_t workers = options == NULL || options->io_workers == 0u ? 1u : options->io_workers;
    const uint32_t capacity = options == NULL || options->command_capacity == 0u ? SOLARIS_DEFAULT_COMMAND_CAPACITY
                                                                                 : options->command_capacity;
    const uint32_t io_capacity = options == NULL || options->io_queue_capacity == 0u ? SOLARIS_DEFAULT_IO_QUEUE_CAPACITY
                                                                                     : options->io_queue_capacity;
    const uint32_t resource_limit = options == NULL || options->io_resource_limit == 0u
                                        ? SOLARIS_DEFAULT_IO_RESOURCE_LIMIT
                                        : options->io_resource_limit;
    const uint64_t buffer_limit = options == NULL || options->buffer_limit_bytes == 0u
                                      ? SOLARIS_DEFAULT_BUFFER_LIMIT_BYTES
                                      : options->buffer_limit_bytes;
#if SIZE_MAX < UINT64_MAX
    if (buffer_limit > SIZE_MAX)
        return solaris_error_set(error, SOLARIS_EINVAL, 0, NULL);
#endif
    if (workers > SOLARIS_MAX_IO_WORKERS || io_capacity > 65536u || resource_limit > 65536u ||
        capacity > SOLARIS_MAX_COMMAND_CAPACITY ||
        (services != NULL &&
         (services->allocate == NULL || services->deallocate == NULL || services->now_ns == NULL))) {
        return solaris_error_set(error, SOLARIS_EINVAL, 0, NULL);
    }

    const solaris_runtime_services_t defaults = {NULL, default_allocate, default_deallocate, default_now_ns, NULL};
    solaris_runtime_services_t selected = services == NULL ? defaults : *services;
    solaris_engine_t *engine = selected.allocate(selected.context, sizeof(*engine));
    if (engine == NULL) {
        return solaris_error_set(error, SOLARIS_ENOMEM, 0, NULL);
    }
    memset(engine, 0, sizeof(*engine));
    engine->services = selected;
    engine->capacity = capacity;
    engine->commands = selected.allocate(selected.context, capacity * sizeof(*engine->commands));
    if (engine->commands == NULL) {
        release_storage(engine);
        return solaris_error_set(error, SOLARIS_ENOMEM, 0, NULL);
    }
    /* The extra slot preserves the existing queue capacity while a callback
     * executes. Retained out-of-order completions also occupy this window. */
    size_t window = (size_t)capacity + 1u;
    engine->operations = selected.allocate(selected.context, window * sizeof(*engine->operations));
    if (engine->operations == NULL) {
        release_storage(engine);
        return solaris_error_set(error, SOLARIS_ENOMEM, 0, NULL);
    }
    memset(engine->operations, 0, window * sizeof(*engine->operations));
    /* Fixed control storage is separate from the existing I/O-byte snapshot,
     * just like commands/executors, and bounded by command_capacity. */
    solaris_status_t ledger_status =
        solaris_budget_create(window * sizeof(solaris_operation_slot_t) + 1024u, &selected, &engine->control_budget);
    if (ledger_status == SOLARIS_OK)
        ledger_status = solaris_operation_ledger_init(&engine->ledger, engine->control_budget, window);
    if (ledger_status != SOLARIS_OK) {
        release_storage(engine);
        return solaris_error_set(error, ledger_status, 0, NULL);
    }
    if (host != NULL) {
        engine->host = *host;
        solaris_network_snapshot_retain(engine->host.network);
    }
    engine->started_ns = now_ns(engine);
    engine->state = SOLARIS_ENGINE_IDLE;
    engine->requested_state = SOLARIS_ENGINE_IDLE;

    int rc = checkpoint(engine, SOLARIS_POINT_MUTEX_INIT);
    if (rc == 0)
        rc = uv_mutex_init(&engine->mutex);
    if (rc != 0) {
        release_storage(engine);
        return runtime_error(error, rc);
    }
    rc = checkpoint(engine, SOLARIS_POINT_CONDITION_INIT);
    if (rc == 0)
        rc = uv_cond_init(&engine->condition);
    if (rc != 0) {
        uv_mutex_destroy(&engine->mutex);
        release_storage(engine);
        return runtime_error(error, rc);
    }
    rc = checkpoint(engine, SOLARIS_POINT_THREAD_CREATE);
    if (rc == 0)
        rc = uv_thread_create(&engine->thread, worker_main, engine);
    if (rc == 0) {
        uv_mutex_lock(&engine->mutex);
        while (!engine->ready)
            uv_cond_wait(&engine->condition, &engine->mutex);
        rc = engine->ready_status;
        uv_mutex_unlock(&engine->mutex);
        if (rc != 0)
            (void)uv_thread_join(&engine->thread);
    }
    if (rc != 0) {
        uv_cond_destroy(&engine->condition);
        uv_mutex_destroy(&engine->mutex);
        release_storage(engine);
        return runtime_error(error, rc);
    }
    engine->executors = selected.allocate(selected.context, workers * sizeof(*engine->executors));
    solaris_status_t status = engine->executors == NULL
                                  ? SOLARIS_ENOMEM
                                  : solaris_budget_create((size_t)buffer_limit, &selected, &engine->budget);
    if (engine->executors != NULL)
        memset(engine->executors, 0, workers * sizeof(*engine->executors));
    for (uint32_t i = 0; status == SOLARIS_OK && i < workers; i++) {
        const solaris_executor_options_t executor_options = {.id = i,
                                                             .owner_context = engine,
                                                             .queue_capacity = io_capacity,
                                                             .resource_limit = resource_limit,
                                                             .budget = engine->budget,
                                                             .services = &selected};
        status = solaris_executor_create(&executor_options, &engine->executors[i]);
        if (status == SOLARIS_OK)
            engine->executor_count++;
    }
    if (status != SOLARIS_OK) {
        (void)solaris_runtime_destroy(engine, NULL);
        return solaris_error_set(error, status, 0, NULL);
    }
    *out_engine = engine;
    return solaris_error_set(error, SOLARIS_OK, 0, NULL);
}

static solaris_status_t submit(solaris_engine_t *engine, solaris_operation_t kind,
                               const solaris_runtime_request_t *request, uint64_t *id, solaris_error_t *error)
{
    if (id)
        *id = 0;
    if (!engine || !id)
        return solaris_error_set(error, SOLARIS_EINVAL, 0, NULL);
    uv_mutex_lock(&engine->mutex);
    solaris_status_t status = SOLARIS_OK;
    if (engine->closing)
        status = SOLARIS_ECLOSED;
    else if (request && request->requires_running &&
             (engine->state != SOLARIS_ENGINE_RUNNING || engine->requested_state != SOLARIS_ENGINE_RUNNING))
        status = SOLARIS_ECLOSED;
    else if (engine->count == engine->capacity)
        status = SOLARIS_EBUSY;
    else if (kind == SOLARIS_OPERATION_START && engine->requested_state == SOLARIS_ENGINE_RUNNING)
        status = SOLARIS_EBUSY;
    uint64_t accepted = 0;
    if (status == SOLARIS_OK)
        status = solaris_operation_ledger_accept(&engine->ledger, &accepted);
    if (status != SOLARIS_OK) {
        uv_mutex_unlock(&engine->mutex);
        return solaris_error_set(error, status, 0, NULL);
    }
    solaris_runtime_operation_t *operation = &engine->operations[accepted % engine->ledger.capacity];
    memset(operation, 0, sizeof(*operation));
    operation->engine = engine;
    operation->id = accepted;
    operation->kind = kind;
    operation->state = OPERATION_QUEUED;
    if (request)
        operation->request = *request;
    engine->commands[(engine->head + engine->count) % engine->capacity].id = accepted;
    ++engine->count;
    int rc = checkpoint(engine, SOLARIS_POINT_ASYNC_SEND);
    if (rc == 0)
        rc = uv_async_send(&engine->wake);
    if (rc != 0) {
        --engine->count;
        solaris_status_t rolled_back = solaris_operation_ledger_rollback(&engine->ledger, accepted);
        assert(rolled_back == SOLARIS_OK);
        (void)rolled_back;
        memset(operation, 0, sizeof(*operation));
        uv_mutex_unlock(&engine->mutex);
        return runtime_error(error, rc);
    }
    if (!request)
        engine->requested_state = kind == SOLARIS_OPERATION_START ? SOLARIS_ENGINE_RUNNING : SOLARIS_ENGINE_STOPPED;
    *id = accepted;
    uv_mutex_unlock(&engine->mutex);
    return solaris_error_set(error, SOLARIS_OK, 0, NULL);
}
solaris_status_t solaris_runtime_submit(solaris_engine_t *engine, solaris_operation_t kind, uint64_t *id,
                                        solaris_error_t *error)
{
    if (id)
        *id = 0;
    if (kind != SOLARIS_OPERATION_START && kind != SOLARIS_OPERATION_STOP)
        return solaris_error_set(error, SOLARIS_EINVAL, 0, NULL);
    return submit(engine, kind, NULL, id, error);
}
solaris_status_t solaris_runtime_request_submit(solaris_engine_t *engine, const solaris_runtime_request_t *request,
                                                uint64_t *id, solaris_error_t *error)
{
    if (id)
        *id = 0;
    if (!request || !request->start || request->operation < SOLARIS_OPERATION_CONFIG_PREPARE ||
        request->operation > SOLARIS_OPERATION_PROBE ||
        (request->requires_running != 0 && request->requires_running != 1))
        return solaris_error_set(error, SOLARIS_EINVAL, 0, NULL);
    return submit(engine, request->operation, request, id, error);
}
solaris_status_t solaris_runtime_cancel(solaris_engine_t *engine, uint64_t id, solaris_error_t *error)
{
    if (!engine || !id)
        return solaris_error_set(error, SOLARIS_EINVAL, 0, NULL);
    uv_mutex_lock(&engine->mutex);
    solaris_runtime_operation_t *operation = lookup_locked(engine, id);
    solaris_status_t status = SOLARIS_OK;
    if (engine->closing || !operation)
        status = SOLARIS_ECLOSED;
    else if (!custom(operation))
        status = SOLARIS_ENOTSUP;
    else if (operation->state >= OPERATION_RESULT)
        status = SOLARIS_ECLOSED;
    else {
        operation->cancel_requested = 1;
        int rc = uv_async_send(&engine->wake);
        assert(rc == 0);
        (void)rc;
    }
    uv_mutex_unlock(&engine->mutex);
    return solaris_error_set(error, status, 0, NULL);
}
solaris_budget_t *solaris_runtime_budget(solaris_engine_t *engine)
{
    return engine ? engine->budget : NULL;
}
uint64_t solaris_runtime_operation_id(const solaris_runtime_operation_t *operation)
{
    return operation ? operation->id : 0;
}
solaris_status_t solaris_runtime_snapshot(solaris_engine_t *engine, solaris_engine_snapshot_t *snapshot,
                                          solaris_error_t *error)
{
    if (!engine || !snapshot)
        return solaris_error_set(error, SOLARIS_EINVAL, 0, NULL);
    uv_mutex_lock(&engine->mutex);
    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->state = engine->state;
    snapshot->io_workers = engine->executor_count;
    snapshot->closing = (uint32_t)engine->closing;
    snapshot->command_capacity = (uint32_t)engine->capacity;
    snapshot->accepted_operations = engine->ledger.accepted;
    snapshot->completed_operations = engine->ledger.completed;
    snapshot->pending_operations = engine->ledger.accepted - engine->ledger.completed;
    snapshot->last_operation_id = engine->last_id;
    snapshot->last_status = engine->last_status;
    uint64_t now = now_ns(engine);
    snapshot->uptime_ns = now >= engine->started_ns ? now - engine->started_ns : 0;
    snapshot->generation = engine->generation;
    snapshot->io_buffer_bytes = solaris_budget_used(engine->budget);
    snapshot->io_buffer_peak_bytes = solaris_budget_peak(engine->budget);
    uv_mutex_unlock(&engine->mutex);
    return solaris_error_set(error, SOLARIS_OK, 0, NULL);
}
solaris_executor_t *solaris_runtime_executor(solaris_engine_t *engine, uint64_t affinity_key)
{
    if (!engine)
        return NULL;
    uv_mutex_lock(&engine->mutex);
    solaris_executor_t *executor =
        engine->closing || !engine->executor_count ? NULL : engine->executors[affinity_key % engine->executor_count];
    uv_mutex_unlock(&engine->mutex);
    return executor;
}
solaris_status_t solaris_runtime_flush(solaris_engine_t *engine, uint64_t timeout_ms, solaris_error_t *error)
{
    if (!engine || (timeout_ms != SOLARIS_TIMEOUT_INFINITE && timeout_ms > UINT64_MAX / UINT64_C(1000000)))
        return solaris_error_set(error, SOLARIS_EINVAL, 0, NULL);
    if (is_owner(engine))
        return solaris_error_set(error, SOLARIS_EDEADLOCK, 0, NULL);
    /* The host wait uses the OS monotonic clock, independently of injected time. */
    uint64_t started = uv_hrtime(),
             budget = timeout_ms == SOLARIS_TIMEOUT_INFINITE ? 0 : timeout_ms * UINT64_C(1000000);
    uv_mutex_lock(&engine->mutex);
    uint64_t target = engine->ledger.accepted;
    while (engine->ledger.watermark < target) {
        if (timeout_ms == SOLARIS_TIMEOUT_INFINITE) {
            uv_cond_wait(&engine->condition, &engine->mutex);
            continue;
        }
        uint64_t elapsed = uv_hrtime() - started;
        if (elapsed >= budget) {
            uv_mutex_unlock(&engine->mutex);
            return solaris_error_set(error, SOLARIS_ETIMEDOUT, 0, NULL);
        }
        int rc = uv_cond_timedwait(&engine->condition, &engine->mutex, budget - elapsed);
        if (rc != 0 && rc != UV_ETIMEDOUT) {
            uv_mutex_unlock(&engine->mutex);
            return runtime_error(error, rc);
        }
    }
    uv_mutex_unlock(&engine->mutex);
    return solaris_error_set(error, SOLARIS_OK, 0, NULL);
}
solaris_status_t solaris_runtime_destroy(solaris_engine_t *engine, solaris_error_t *error)
{
    if (!engine)
        return solaris_error_set(error, SOLARIS_OK, 0, NULL);
    if (is_owner(engine))
        return solaris_error_set(error, SOLARIS_EDEADLOCK, 0, NULL);
    if (!engine->joined) {
        uv_mutex_lock(&engine->mutex);
        engine->closing = 1;
        int rc = uv_async_send(&engine->wake);
        if (rc != 0)
            engine->closing = 0;
        uv_mutex_unlock(&engine->mutex);
        if (rc != 0)
            return runtime_error(error, rc);
        (void)checkpoint(engine, SOLARIS_POINT_SHUTDOWN);
        rc = uv_thread_join(&engine->thread);
        if (rc != 0)
            return runtime_error(error, rc);
        engine->joined = 1;
    }
    if (engine->exit_status != 0)
        return runtime_error(error, engine->exit_status);
    uv_cond_destroy(&engine->condition);
    uv_mutex_destroy(&engine->mutex);
    release_storage(engine);
    return solaris_error_set(error, SOLARIS_OK, 0, NULL);
}

solaris_network_snapshot_t *solaris_runtime_network_acquire(solaris_engine_t *engine)
{
    if (!engine) return NULL;
    uv_mutex_lock(&engine->mutex);
    solaris_network_snapshot_t *network = engine->host.network;
    solaris_network_snapshot_retain(network);
    uv_mutex_unlock(&engine->mutex);
    return network;
}
