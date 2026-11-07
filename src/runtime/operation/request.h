#ifndef SOLARIS_RUNTIME_OPERATION_REQUEST_H
#define SOLARIS_RUNTIME_OPERATION_REQUEST_H
#include <solaris/engine.h>
#include "contracts/io/buffer.h"

typedef struct solaris_runtime_operation solaris_runtime_operation_t;
typedef struct solaris_runtime_request {
    solaris_operation_t operation;
    int requires_running;
    void *context;
    /* Called on the control owner, never inline on the submitting stack.
     * start must not block. OK promises a future operation_complete; a reject
     * is completed by the engine. After cancellation, accepted work still
     * acknowledges completion once all its owned async work is drained. */
    solaris_status_t (*start)(void *context, solaris_engine_t *engine, solaris_runtime_operation_t *operation);
    /* Serialized on the control owner, but may race a background completion
     * decision. The request synchronizes its own background state; context
     * stays alive until dispose even after operation_complete is called. */
    void (*cancel)(void *context);
    /* Runs on control owner before the generic host event. Context/result data
     * is valid until dispose; callbacks may submit operations but not block.
     * config_revision is nonzero when an application was actually published,
     * including if a cancellation request arrived after publication. */
    void (*complete)(void *context, solaris_status_t status, uint64_t config_revision);
    void (*dispose)(void *context);
} solaris_runtime_request_t;
/* Embedded reserved control completion. Its owner retains the node/context
 * until run returns; queued must start at zero. No allocation and no ordinary
 * command-capacity admission. Posts remain valid through stop/drain. */
typedef struct solaris_control_completion {
    struct solaris_control_completion *next;
    void (*run)(void *context);
    void *context;
    int queued;
} solaris_control_completion_t;
solaris_status_t solaris_runtime_control_post(solaris_engine_t *engine, solaris_control_completion_t *completion);
/* Control-owner transaction fence. A successful action must transfer owned
 * resources to the engine and return the published revision (zero for prepare).
 * It runs under the cancellation lock: no blocking, allocation or engine API
 * reentry. Success records the final result atomically; failure leaves the
 * operation live so rollback can drain before operation_complete. */
typedef solaris_status_t (*solaris_operation_publish_fn)(void *context, uint64_t *published_revision);
solaris_status_t solaris_runtime_operation_finish(solaris_runtime_operation_t *operation,
    solaris_operation_publish_fn action, void *context);
int solaris_runtime_operation_cancelled(solaris_runtime_operation_t *operation);
/* Valid while the request owns its live operation handle, including start.
 * Read before completing it; no access is allowed after final completion. */
uint64_t solaris_runtime_operation_id(const solaris_runtime_operation_t *operation);

/* Thread-safe. On success engine owns context; rejection owns nothing and has
 * no callback. Commands and retained out-of-order results are bounded. START
 * and STOP use the lifecycle facade, not this extension entry point. */
solaris_status_t solaris_runtime_request_submit(solaris_engine_t *engine, const solaris_runtime_request_t *request,
    uint64_t *id, solaris_error_t *error);
/* Thread-safe reserved completion; no allocation or fallible mailbox post.
 * Exactly once per successful start. The handle must not be used afterwards.
 * Nonzero published_revision cannot be reported as cancelled/unapplied. */
void solaris_runtime_operation_complete(solaris_runtime_operation_t *operation,
    solaris_status_t status, uint64_t published_revision);
solaris_status_t solaris_runtime_cancel(solaris_engine_t *engine, uint64_t id, solaris_error_t *error);
/* Borrowed for engine lifetime. Public callers still obey exclusive destroy. */
solaris_budget_t *solaris_runtime_budget(solaris_engine_t *engine);
#endif
