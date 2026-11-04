#ifndef SOLARIS_ENGINE_H
#define SOLARIS_ENGINE_H

#include <stdint.h>
#include <solaris/error.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct solaris_engine solaris_engine_t;
typedef uint32_t solaris_engine_state_t;
enum {
    SOLARIS_ENGINE_IDLE = 0,
    SOLARIS_ENGINE_RUNNING = 1,
    SOLARIS_ENGINE_STOPPED = 2
};

typedef uint32_t solaris_operation_t;
enum {
    SOLARIS_OPERATION_START = 1,
    SOLARIS_OPERATION_STOP = 2
};

#define SOLARIS_TIMEOUT_INFINITE UINT64_MAX
#define SOLARIS_DEFAULT_COMMAND_CAPACITY 32u
#define SOLARIS_MAX_COMMAND_CAPACITY 1024u

typedef struct solaris_engine_options {
    /* Zero uses the default (one). M0 rejects values above one explicitly. */
    uint32_t io_workers;
    /* Pending commands, excluding a callback currently executing. */
    uint32_t command_capacity;
} solaris_engine_options_t;

typedef struct solaris_event {
    uint64_t operation_id;
    uint64_t monotonic_time_ns;
    solaris_operation_t operation;
    solaris_status_t status;
    solaris_engine_state_t state;
} solaris_event_t;

/*
 * Invoked on the engine owner thread, never inline on the submitting stack.
 * It may run before start()/stop() returns on another thread. The event is
 * borrowed until return; copying the struct makes it independent of the engine.
 * Callbacks may submit operations or get a snapshot, but must return promptly.
 * flush()/destroy() from this callback return SOLARIS_EDEADLOCK.
 */
typedef void (*solaris_event_callback_t)(void *context,
                                         const solaris_event_t *event);

typedef struct solaris_host {
    void *context;
    /* Optional. Keep context alive until destroy() has returned successfully. */
    solaris_event_callback_t on_event;
} solaris_host_t;

typedef struct solaris_engine_snapshot {
    solaris_engine_state_t state;
    uint32_t io_workers;
    uint32_t closing;
    uint32_t command_capacity;
    uint64_t accepted_operations;
    uint64_t completed_operations;
    uint64_t pending_operations;
    uint64_t last_operation_id;
    solaris_status_t last_status;
    uint64_t uptime_ns;
} solaris_engine_snapshot_t;

SOLARIS_API void solaris_engine_options_init(solaris_engine_options_t *options);

/*
 * Synchronous initialization; no network, TUN, YAML, or protocol activation.
 * options/host may be NULL for defaults and are copied before return.
 * On failure *out_engine is NULL. error is optional and caller-owned.
 */
SOLARIS_API solaris_status_t solaris_engine_create(
    const solaris_engine_options_t *options,
    const solaris_host_t *host,
    solaris_engine_t **out_engine,
    solaris_error_t *error);

/*
 * Thread-safe asynchronous lifecycle commands, FIFO by accepted operation ID.
 * Success assigns a nonzero engine-local ID and promises exactly one result
 * (and callback if installed). Failure sets *operation_id to zero and has no
 * callback. A full queue returns EBUSY without changing the requested state.
 * start rejects an already running/requested-running engine. stop is idempotent.
 * RUNNING in M0 denotes the control runtime only, not an active proxy/VPN.
 */
SOLARIS_API solaris_status_t solaris_engine_start(
    solaris_engine_t *engine, uint64_t *operation_id, solaris_error_t *error);
SOLARIS_API solaris_status_t solaris_engine_stop(
    solaris_engine_t *engine, uint64_t *operation_id, solaris_error_t *error);

/* Copies a pointer-free snapshot under the engine lock. */
SOLARIS_API solaris_status_t solaris_engine_get_snapshot(
    solaris_engine_t *engine, solaris_engine_snapshot_t *snapshot,
    solaris_error_t *error);

/*
 * Waits for all commands accepted at entry AND their callbacks to return.
 * Later submissions need another flush. Zero timeout polls; INFINITE waits.
 * Timeout does not cancel commands. Success is a barrier, not their status;
 * operation results are delivered through events and the snapshot.
 */
SOLARIS_API solaris_status_t solaris_engine_flush(
    solaris_engine_t *engine, uint64_t timeout_ms, solaris_error_t *error);

/*
 * Exclusive lifetime operation: the host must stop concurrent API calls first.
 * Prevents new admission, completes queued commands as cancelled, and joins
 * the owner after all callbacks return. An executing callback may finish.
 * Successful return invalidates engine and is the host-context release barrier.
 * NULL is accepted. On error ownership remains with the caller; never invoke
 * destroy from an event callback (EDEADLOCK, without changing the engine).
 */
SOLARIS_API solaris_status_t solaris_engine_destroy(
    solaris_engine_t *engine, solaris_error_t *error);

#ifdef __cplusplus
}
#endif

#endif
