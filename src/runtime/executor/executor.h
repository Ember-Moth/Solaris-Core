#ifndef SOLARIS_EXECUTOR_H
#define SOLARIS_EXECUTOR_H

#include "contracts/io/buffer.h"
#include "runtime/services/services.h"

typedef struct solaris_executor solaris_executor_t;
typedef struct solaris_deadline solaris_deadline_t;
typedef void (*solaris_task_fn)(void *context, solaris_status_t status);

/* A reserved completion node is embedded in an accepted request. It may be
 * posted while data admission is closed. One node may be queued only once. */
typedef struct solaris_deferred {
    struct solaris_deferred *next;
    void (*run)(void *context);
    void *context;
    int queued;
} solaris_deferred_t;

typedef struct solaris_scope {
    solaris_executor_t *owner;
    struct solaris_scope *previous;
    struct solaris_scope *next;
    uint64_t generation;
    size_t references;
    int cancelled;
    int finishing;
    int listed;
    void (*cancel)(void *context);
    void (*done)(void *context);
    void *context;
    solaris_deferred_t completion;
} solaris_scope_t;

typedef struct solaris_executor_options {
    uint32_t id;
    void *owner_context;
    size_t queue_capacity;
    size_t resource_limit;
    solaris_budget_t *budget;
    const solaris_runtime_services_t *services;
} solaris_executor_options_t;

/* Executors start parked. activate/quiesce/destroy are serialized lifecycle
 * operations; quiesce is a callback/resource barrier, not just a queue drain. */
solaris_status_t solaris_executor_create(const solaris_executor_options_t *options,
                                         solaris_executor_t **out);
solaris_status_t solaris_executor_activate(solaris_executor_t *executor, uint64_t generation);
solaris_status_t solaris_executor_begin_quiesce(solaris_executor_t *executor);
solaris_status_t solaris_executor_wait_quiescent(solaris_executor_t *executor);
solaris_status_t solaris_executor_quiesce(solaris_executor_t *executor);
solaris_status_t solaris_executor_destroy(solaris_executor_t *executor);
solaris_status_t solaris_executor_post(solaris_executor_t *executor, solaris_task_fn task, void *context);
solaris_status_t solaris_executor_defer(solaris_executor_t *executor, solaris_deferred_t *completion);
void solaris_executor_wake(solaris_executor_t *executor);
int solaris_executor_is_owner(const solaris_executor_t *executor);
solaris_executor_t *solaris_executor_current(void);
void *solaris_executor_context(const solaris_executor_t *executor);
int solaris_executor_accepting(solaris_executor_t *executor);
uint32_t solaris_executor_id(const solaris_executor_t *executor);
uint64_t solaris_executor_generation(solaris_executor_t *executor);
uint64_t solaris_executor_now_ns(solaris_executor_t *executor);
solaris_budget_t *solaris_executor_budget(solaris_executor_t *executor);

/* Scope operations are owner-only. Initial reference is released by cancel;
 * native handles/requests hold extra references until their callbacks finish.
 * done is deferred and may free the enclosing object. */
solaris_status_t solaris_scope_init(solaris_scope_t *scope, solaris_executor_t *executor,
                                    void (*cancel)(void *), void (*done)(void *), void *context);
void solaris_scope_retain(solaris_scope_t *scope);
void solaris_scope_release(solaris_scope_t *scope);
void solaris_scope_cancel(solaris_scope_t *scope);

/* One-shot, owner-only logical deadline; callback exactly once, including
 * cancellation. A deadline handle expires when its callback returns. */
solaris_status_t solaris_deadline_start(solaris_executor_t *executor, uint64_t delay_ms,
                                        solaris_task_fn callback, void *context,
                                        solaris_deadline_t **out);
void solaris_deadline_cancel(solaris_deadline_t *deadline);

#endif
