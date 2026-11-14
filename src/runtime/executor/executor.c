#include "runtime/executor/executor.h"
#include "runtime/executor/uv.h"
#include <assert.h>
#include <string.h>
#ifdef __linux__
#include <pthread.h>
#include <signal.h>
#endif

typedef struct solaris_task {
    solaris_task_fn run;
    void *context;
} solaris_task_t;

struct solaris_executor {
    solaris_runtime_services_t services;
    solaris_budget_t *budget;
    uint32_t id;
    void *owner_context;
    uv_thread_t thread;
    uv_thread_t owner;
    uv_mutex_t mutex;
    uv_cond_t condition;
    uv_loop_t loop;
    uv_async_t wake;
    uv_timer_t timer_driver;
    solaris_task_t *tasks;
    size_t capacity, head, count;
    size_t executing, resources, resource_limit;
    solaris_scope_t *scopes;
    solaris_deferred_t *deferred_head, *deferred_tail;
    solaris_deadline_t *deadlines;
    uint64_t generation;
    int ready, ready_status, accepting, draining, stopping, handles_closing;
    int joined, exit_status;
};

struct solaris_deadline {
    solaris_scope_t scope;
    solaris_deferred_t result;
    solaris_deadline_t *previous, *next;
    uint64_t due_ns;
    solaris_task_fn callback;
    void *context;
    solaris_status_t status;
    int linked, settled;
};

#if defined(_MSC_VER)
static __declspec(thread) solaris_executor_t *current_executor;
#else
static _Thread_local solaris_executor_t *current_executor;
#endif

static void executor_progress(solaris_executor_t *executor);
static void timer_driver_cb(uv_timer_t *handle);

static int fault(solaris_executor_t *executor, solaris_runtime_point_t point)
{
    return executor->services.checkpoint == NULL ? 0 :
        executor->services.checkpoint(executor->services.context, point);
}

int solaris_executor_is_owner(const solaris_executor_t *executor)
{
    return current_executor == executor;
}

solaris_executor_t *solaris_executor_current(void) { return current_executor; }
void *solaris_executor_context(const solaris_executor_t *executor) { return executor->owner_context; }

int solaris_executor_accepting(solaris_executor_t *executor)
{
    uv_mutex_lock(&executor->mutex);
    const int result = executor->accepting;
    uv_mutex_unlock(&executor->mutex);
    return result;
}

uint32_t solaris_executor_id(const solaris_executor_t *executor) { return executor->id; }
uint64_t solaris_executor_now_ns(solaris_executor_t *executor)
{
    return executor->services.now_ns(executor->services.context);
}
uint64_t solaris_executor_generation(solaris_executor_t *executor)
{
    uv_mutex_lock(&executor->mutex);
    const uint64_t generation = executor->generation;
    uv_mutex_unlock(&executor->mutex);
    return generation;
}
uv_loop_t *solaris_executor_loop(solaris_executor_t *executor)
{
    assert(solaris_executor_is_owner(executor));
    return &executor->loop;
}
solaris_budget_t *solaris_executor_budget(solaris_executor_t *executor) { return executor->budget; }

static void rearm_deadlines(solaris_executor_t *executor)
{
    if (executor->deadlines == NULL) {
        uv_timer_stop(&executor->timer_driver);
        return;
    }
    const uint64_t now = solaris_executor_now_ns(executor);
    const uint64_t due = executor->deadlines->due_ns;
    const uint64_t delta = due > now ? due - now : 0u;
    const uint64_t delay = delta / UINT64_C(1000000) + (delta % UINT64_C(1000000) != 0u);
    (void)uv_timer_start(&executor->timer_driver, timer_driver_cb, delay, 0u);
}

static void unlink_deadline(solaris_deadline_t *deadline)
{
    if (!deadline->linked) return;
    solaris_executor_t *executor = deadline->scope.owner;
    if (deadline->previous != NULL) deadline->previous->next = deadline->next;
    else executor->deadlines = deadline->next;
    if (deadline->next != NULL) deadline->next->previous = deadline->previous;
    deadline->previous = deadline->next = NULL;
    deadline->linked = 0;
}

static void deliver_deadline(void *context)
{
    solaris_deadline_t *deadline = context;
    deadline->callback(deadline->context, deadline->status);
    solaris_scope_release(&deadline->scope);
}

static void settle_deadline(solaris_deadline_t *deadline, solaris_status_t status)
{
    if (deadline->settled) return;
    deadline->settled = 1;
    deadline->status = status;
    unlink_deadline(deadline);
    solaris_scope_retain(&deadline->scope);
    const solaris_status_t rc = solaris_executor_defer(deadline->scope.owner, &deadline->result);
    assert(rc == SOLARIS_OK);
    (void)rc;
}

static void cancel_deadline(void *context)
{
    solaris_deadline_t *deadline = context;
    settle_deadline(deadline, SOLARIS_ECANCELLED);
    rearm_deadlines(deadline->scope.owner);
}

static void free_deadline(void *context) { solaris_memory_free(context); }

static void poll_deadlines(solaris_executor_t *executor)
{
    const uint64_t now = solaris_executor_now_ns(executor);
    for (unsigned int budget = 0; budget < 64u && executor->deadlines != NULL &&
         executor->deadlines->due_ns <= now; budget++) {
        solaris_deadline_t *deadline = executor->deadlines;
        settle_deadline(deadline, solaris_executor_accepting(executor) ?
                        SOLARIS_OK : SOLARIS_ECANCELLED);
        solaris_scope_cancel(&deadline->scope);
    }
    rearm_deadlines(executor);
}

static void timer_driver_cb(uv_timer_t *handle)
{
    solaris_executor_t *executor = handle->data;
    poll_deadlines(executor);
    executor_progress(executor);
}

static void unlink_scope_locked(solaris_scope_t *scope)
{
    if (!scope->listed) return;
    solaris_executor_t *executor = scope->owner;
    if (scope->previous != NULL) scope->previous->next = scope->next;
    else executor->scopes = scope->next;
    if (scope->next != NULL) scope->next->previous = scope->previous;
    scope->previous = scope->next = NULL;
    scope->listed = 0;
}

static void scope_finished(void *context)
{
    solaris_scope_t *scope = context;
    solaris_executor_t *executor = scope->owner;
    void (*done)(void *) = scope->done;
    void *user = scope->context;
    uv_mutex_lock(&executor->mutex);
    unlink_scope_locked(scope);
    assert(executor->resources > 0u);
    executor->resources--;
    uv_mutex_unlock(&executor->mutex);
    /* dispatch counts this callback as executing until done returns. */
    if (done != NULL) done(user);
}

solaris_status_t solaris_scope_init(solaris_scope_t *scope, solaris_executor_t *executor,
                                    void (*cancel)(void *), void (*done)(void *), void *context)
{
    if (scope == NULL || executor == NULL) return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(executor)) return SOLARIS_ETHREAD;
    uv_mutex_lock(&executor->mutex);
    solaris_status_t rc = SOLARIS_OK;
    if (!executor->accepting) rc = SOLARIS_ECLOSED;
    else if (executor->resources == executor->resource_limit) rc = SOLARIS_EAGAIN;
    if (rc == SOLARIS_OK) {
        memset(scope, 0, sizeof(*scope));
        scope->owner = executor;
        scope->generation = executor->generation;
        scope->references = 1u;
        scope->listed = 1;
        scope->cancel = cancel;
        scope->done = done;
        scope->context = context;
        scope->completion.run = scope_finished;
        scope->completion.context = scope;
        scope->next = executor->scopes;
        if (scope->next != NULL) scope->next->previous = scope;
        executor->scopes = scope;
        executor->resources++;
    }
    uv_mutex_unlock(&executor->mutex);
    return rc;
}

void solaris_scope_retain(solaris_scope_t *scope)
{
    assert(solaris_executor_is_owner(scope->owner));
    assert(scope->references > 0u && !scope->finishing);
    scope->references++;
}

void solaris_scope_release(solaris_scope_t *scope)
{
    assert(solaris_executor_is_owner(scope->owner));
    assert(scope->references > 0u);
    if (--scope->references == 0u) {
        scope->finishing = 1;
        uv_mutex_lock(&scope->owner->mutex);
        unlink_scope_locked(scope);
        uv_mutex_unlock(&scope->owner->mutex);
        const solaris_status_t rc = solaris_executor_defer(scope->owner, &scope->completion);
        assert(rc == SOLARIS_OK);
        (void)rc;
    }
}

void solaris_scope_cancel(solaris_scope_t *scope)
{
    assert(solaris_executor_is_owner(scope->owner));
    if (scope->cancelled || scope->finishing) return;
    scope->cancelled = 1;
    uv_mutex_lock(&scope->owner->mutex);
    unlink_scope_locked(scope);
    uv_mutex_unlock(&scope->owner->mutex);
    if (scope->cancel != NULL) scope->cancel(scope->context);
    solaris_scope_release(scope);
}

solaris_status_t solaris_executor_defer(solaris_executor_t *executor, solaris_deferred_t *completion)
{
    if (executor == NULL || completion == NULL || completion->run == NULL) return SOLARIS_EINVAL;
    uv_mutex_lock(&executor->mutex);
    solaris_status_t rc = SOLARIS_OK;
    if (executor->handles_closing) rc = SOLARIS_ECLOSED;
    else if (completion->queued) rc = SOLARIS_EBUSY;
    else {
        completion->queued = 1;
        completion->next = NULL;
        if (executor->deferred_tail != NULL) executor->deferred_tail->next = completion;
        else executor->deferred_head = completion;
        executor->deferred_tail = completion;
        (void)uv_async_send(&executor->wake);
    }
    uv_mutex_unlock(&executor->mutex);
    return rc;
}

static void executor_progress(solaris_executor_t *executor)
{
    uv_mutex_lock(&executor->mutex);
    const int drain = executor->draining;
    uv_mutex_unlock(&executor->mutex);
    if (drain) {
        /* The list contains only uncancelled scopes. Removing on cancellation
         * makes bounded shutdown progress without rescanning pending OS work. */
        for (unsigned int budget = 0; budget < 64u && executor->scopes != NULL; budget++) {
            solaris_scope_cancel(executor->scopes);
        }
    }
    poll_deadlines(executor);
    uv_mutex_lock(&executor->mutex);
    const int empty = executor->count == 0u && executor->deferred_head == NULL &&
                      executor->executing == 0u && executor->resources == 0u;
    if (executor->draining && empty) {
        executor->draining = 0;
        uv_cond_broadcast(&executor->condition);
    }
    if (executor->stopping && empty && !executor->handles_closing) {
        executor->handles_closing = 1;
        uv_timer_stop(&executor->timer_driver);
        uv_close((uv_handle_t *)&executor->timer_driver, NULL);
        uv_close((uv_handle_t *)&executor->wake, NULL);
    } else if (executor->count != 0u || executor->deferred_head != NULL ||
               (executor->draining && executor->scopes != NULL)) {
        (void)uv_async_send(&executor->wake);
    }
    uv_mutex_unlock(&executor->mutex);
}

static void dispatch(uv_async_t *handle)
{
    solaris_executor_t *executor = handle->data;
    for (unsigned int budget = 0; budget < 64u; budget++) {
        solaris_deferred_t *completion = NULL;
        solaris_task_t task = {NULL, NULL};
        uv_mutex_lock(&executor->mutex);
        if (executor->draining && executor->scopes != NULL) {
            /* Publish cancellation before queued pumps can enter lower
             * transports whose admission is already closed. Scope cancellation
             * removes the scope immediately; OS callbacks still drain normally.
             * Keep the existing bounded batches and yield between them. */
            uv_mutex_unlock(&executor->mutex);
            executor_progress(executor);
            return;
        }
        const solaris_status_t status = executor->accepting ? SOLARIS_OK : SOLARIS_ECANCELLED;
        if (executor->deferred_head != NULL) {
            completion = executor->deferred_head;
            executor->deferred_head = completion->next;
            if (executor->deferred_head == NULL) executor->deferred_tail = NULL;
            completion->queued = 0;
            completion->next = NULL;
        } else if (executor->count != 0u) {
            task = executor->tasks[executor->head];
            executor->head = (executor->head + 1u) % executor->capacity;
            executor->count--;
        } else {
            uv_mutex_unlock(&executor->mutex);
            break;
        }
        executor->executing++;
        uv_mutex_unlock(&executor->mutex);
        if (completion != NULL) completion->run(completion->context);
        else task.run(task.context, status);
        uv_mutex_lock(&executor->mutex);
        executor->executing--;
        uv_mutex_unlock(&executor->mutex);
    }
    executor_progress(executor);
}

static void worker(void *context)
{
    solaris_executor_t *executor = context;
    current_executor = executor;
    int loop_ok = 0, wake_ok = 0, timer_ok = 0;
    int rc = fault(executor, SOLARIS_POINT_EXECUTOR_LOOP_INIT);
#ifdef __linux__
    /* libuv's stream write/writev can raise SIGPIPE on a closed peer. Limit
     * the signal mask to our I/O thread so the host keeps its own disposition. */
    if (rc == 0) {
        sigset_t blocked;
        sigemptyset(&blocked);
        sigaddset(&blocked, SIGPIPE);
        int error = pthread_sigmask(SIG_BLOCK, &blocked, NULL);
        if (error) rc = uv_translate_sys_error(error);
    }
#endif
    if (rc == 0) { rc = uv_loop_init(&executor->loop); loop_ok = rc == 0; }
    if (rc == 0) {
        rc = fault(executor, SOLARIS_POINT_EXECUTOR_ASYNC_INIT);
        if (rc == 0) { rc = uv_async_init(&executor->loop, &executor->wake, dispatch); wake_ok = rc == 0; }
    }
    if (rc == 0) {
        rc = fault(executor, SOLARIS_POINT_EXECUTOR_TIMER_INIT);
        if (rc == 0) { rc = uv_timer_init(&executor->loop, &executor->timer_driver); timer_ok = rc == 0; }
    }
    executor->wake.data = executor;
    executor->timer_driver.data = executor;
    uv_mutex_lock(&executor->mutex);
    executor->owner = uv_thread_self();
    executor->ready = 1;
    executor->ready_status = rc;
    uv_cond_broadcast(&executor->condition);
    uv_mutex_unlock(&executor->mutex);
    if (rc == 0) {
        (void)uv_run(&executor->loop, UV_RUN_DEFAULT);
    } else if (loop_ok) {
        if (timer_ok) uv_close((uv_handle_t *)&executor->timer_driver, NULL);
        if (wake_ok) uv_close((uv_handle_t *)&executor->wake, NULL);
        (void)uv_run(&executor->loop, UV_RUN_DEFAULT);
    }
    if (loop_ok) executor->exit_status = uv_loop_close(&executor->loop);
    current_executor = NULL;
}

solaris_status_t solaris_executor_create(const solaris_executor_options_t *options,
                                         solaris_executor_t **out)
{
    if (out == NULL) return SOLARIS_EINVAL;
    *out = NULL;
    if (options == NULL || options->budget == NULL || options->queue_capacity == 0u ||
        options->queue_capacity > 65536u || options->resource_limit == 0u) return SOLARIS_EINVAL;
    solaris_runtime_services_t services;
    if (options->services != NULL) services = *options->services;
    else solaris_runtime_services_init(&services);
    if (services.allocate == NULL || services.deallocate == NULL || services.now_ns == NULL) return SOLARIS_EINVAL;
    if (services.checkpoint != NULL &&
        services.checkpoint(services.context, SOLARIS_POINT_EXECUTOR_CREATE) != 0) return SOLARIS_EIO;
    solaris_executor_t *executor = services.allocate(services.context, sizeof(*executor));
    if (executor == NULL) return SOLARIS_ENOMEM;
    memset(executor, 0, sizeof(*executor));
    executor->services = services;
    executor->budget = options->budget;
    executor->id = options->id;
    executor->owner_context = options->owner_context;
    executor->capacity = options->queue_capacity;
    executor->resource_limit = options->resource_limit;
    executor->tasks = services.allocate(services.context, executor->capacity * sizeof(*executor->tasks));
    if (executor->tasks == NULL) { services.deallocate(services.context, executor); return SOLARIS_ENOMEM; }
    int rc = uv_mutex_init(&executor->mutex);
    if (rc != 0) goto fail_storage;
    rc = uv_cond_init(&executor->condition);
    if (rc != 0) goto fail_mutex;
    rc = uv_thread_create(&executor->thread, worker, executor);
    if (rc == 0) {
        uv_mutex_lock(&executor->mutex);
        while (!executor->ready) uv_cond_wait(&executor->condition, &executor->mutex);
        rc = executor->ready_status;
        uv_mutex_unlock(&executor->mutex);
        if (rc != 0) (void)uv_thread_join(&executor->thread);
    }
    if (rc != 0) goto fail_condition;
    solaris_budget_retain(executor->budget);
    *out = executor;
    return SOLARIS_OK;
fail_condition:
    uv_cond_destroy(&executor->condition);
fail_mutex:
    uv_mutex_destroy(&executor->mutex);
fail_storage:
    services.deallocate(services.context, executor->tasks);
    services.deallocate(services.context, executor);
    return rc == UV_ENOMEM ? SOLARIS_ENOMEM : SOLARIS_EIO;
}

solaris_status_t solaris_executor_activate(solaris_executor_t *executor, uint64_t generation)
{
    if (executor == NULL || generation == 0u) return SOLARIS_EINVAL;
    uv_mutex_lock(&executor->mutex);
    solaris_status_t rc = SOLARIS_OK;
    if (executor->stopping) rc = SOLARIS_ECLOSED;
    else if (executor->accepting || executor->draining || executor->resources != 0u ||
             executor->count != 0u || executor->executing != 0u || executor->deferred_head != NULL) rc = SOLARIS_EBUSY;
    else { executor->generation = generation; executor->accepting = 1; }
    uv_mutex_unlock(&executor->mutex);
    return rc;
}

solaris_status_t solaris_executor_post(solaris_executor_t *executor, solaris_task_fn task, void *context)
{
    if (executor == NULL || task == NULL) return SOLARIS_EINVAL;
    uv_mutex_lock(&executor->mutex);
    solaris_status_t rc = SOLARIS_OK;
    if (!executor->accepting || executor->stopping) rc = SOLARIS_ECLOSED;
    else if (executor->count == executor->capacity) rc = SOLARIS_EAGAIN;
    else {
        const size_t index = (executor->head + executor->count) % executor->capacity;
        executor->tasks[index].run = task;
        executor->tasks[index].context = context;
        executor->count++;
        if (uv_async_send(&executor->wake) != 0) { executor->count--; rc = SOLARIS_EIO; }
    }
    uv_mutex_unlock(&executor->mutex);
    return rc;
}

void solaris_executor_wake(solaris_executor_t *executor)
{
    uv_mutex_lock(&executor->mutex);
    if (!executor->handles_closing) (void)uv_async_send(&executor->wake);
    uv_mutex_unlock(&executor->mutex);
}

solaris_status_t solaris_executor_begin_quiesce(solaris_executor_t *executor)
{
    if (executor == NULL) return SOLARIS_EINVAL;
    if (solaris_executor_is_owner(executor)) return SOLARIS_EDEADLOCK;
    uv_mutex_lock(&executor->mutex);
    if (executor->stopping) { uv_mutex_unlock(&executor->mutex); return SOLARIS_ECLOSED; }
    executor->accepting = 0;
    executor->draining = 1;
    (void)uv_async_send(&executor->wake);
    uv_mutex_unlock(&executor->mutex);
    return SOLARIS_OK;
}

int solaris_executor_is_quiescent(solaris_executor_t *executor)
{
    if (executor == NULL) return 0;
    uv_mutex_lock(&executor->mutex);
    const int quiet = !executor->accepting && !executor->draining && executor->resources == 0u &&
        executor->count == 0u && executor->executing == 0u && executor->deferred_head == NULL;
    uv_mutex_unlock(&executor->mutex);
    return quiet;
}

solaris_status_t solaris_executor_wait_quiescent(solaris_executor_t *executor)
{
    if (executor == NULL) return SOLARIS_EINVAL;
    if (solaris_executor_is_owner(executor)) return SOLARIS_EDEADLOCK;
    uv_mutex_lock(&executor->mutex);
    while (executor->draining) uv_cond_wait(&executor->condition, &executor->mutex);
    uv_mutex_unlock(&executor->mutex);
    return SOLARIS_OK;
}

solaris_status_t solaris_executor_quiesce(solaris_executor_t *executor)
{
    const solaris_status_t rc = solaris_executor_begin_quiesce(executor);
    return rc == SOLARIS_OK ? solaris_executor_wait_quiescent(executor) : rc;
}

solaris_status_t solaris_executor_destroy(solaris_executor_t *executor)
{
    if (executor == NULL) return SOLARIS_OK;
    if (solaris_executor_is_owner(executor)) return SOLARIS_EDEADLOCK;
    if (!executor->joined) {
        if (!executor->stopping) {
            const solaris_status_t rc = solaris_executor_quiesce(executor);
            if (rc != SOLARIS_OK) return rc;
            uv_mutex_lock(&executor->mutex);
            executor->stopping = 1;
            (void)uv_async_send(&executor->wake);
            uv_mutex_unlock(&executor->mutex);
        }
        if (uv_thread_join(&executor->thread) != 0) return SOLARIS_EIO;
        executor->joined = 1;
    }
    if (executor->exit_status != 0) return SOLARIS_EIO;
    solaris_runtime_services_t services = executor->services;
    solaris_budget_release(executor->budget);
    uv_cond_destroy(&executor->condition);
    uv_mutex_destroy(&executor->mutex);
    services.deallocate(services.context, executor->tasks);
    services.deallocate(services.context, executor);
    return SOLARIS_OK;
}

solaris_status_t solaris_deadline_start(solaris_executor_t *executor, uint64_t delay_ms,
                                        solaris_task_fn callback, void *context,
                                        solaris_deadline_t **out)
{
    if (out == NULL) return SOLARIS_EINVAL;
    *out = NULL;
    if (executor == NULL || callback == NULL || delay_ms > UINT64_MAX / UINT64_C(1000000)) return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(executor)) return SOLARIS_ETHREAD;
    const uint64_t now = solaris_executor_now_ns(executor);
    const uint64_t duration = delay_ms * UINT64_C(1000000);
    if (duration > UINT64_MAX - now) return SOLARIS_EOVERFLOW;
    solaris_deadline_t *deadline = solaris_memory_allocate(executor->budget, sizeof(*deadline));
    if (deadline == NULL) return SOLARIS_ENOMEM;
    memset(deadline, 0, sizeof(*deadline));
    solaris_status_t rc = solaris_scope_init(&deadline->scope, executor,
                                            cancel_deadline, free_deadline, deadline);
    if (rc != SOLARIS_OK) { solaris_memory_free(deadline); return rc; }
    deadline->due_ns = now + duration;
    deadline->callback = callback;
    deadline->context = context;
    deadline->result.run = deliver_deadline;
    deadline->result.context = deadline;
    solaris_deadline_t *previous = NULL, *cursor = executor->deadlines;
    while (cursor != NULL && cursor->due_ns <= deadline->due_ns) { previous = cursor; cursor = cursor->next; }
    deadline->previous = previous; deadline->next = cursor;
    if (previous != NULL) previous->next = deadline;
    else executor->deadlines = deadline;
    if (cursor != NULL) cursor->previous = deadline;
    deadline->linked = 1;
    rearm_deadlines(executor);
    *out = deadline;
    return SOLARIS_OK;
}

void solaris_deadline_cancel(solaris_deadline_t *deadline)
{
    if (deadline != NULL) solaris_scope_cancel(&deadline->scope);
}
