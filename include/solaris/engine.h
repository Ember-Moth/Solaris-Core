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
    SOLARIS_ENGINE_STOPPED = 2,
    SOLARIS_ENGINE_STARTING = 3,
    SOLARIS_ENGINE_STOPPING = 4
};

typedef uint32_t solaris_operation_t;
enum {
    SOLARIS_OPERATION_START = 1,
    SOLARIS_OPERATION_STOP = 2,
    SOLARIS_OPERATION_CONFIG_PREPARE = 3,
    SOLARIS_OPERATION_CONFIG_APPLY = 4,
    SOLARIS_OPERATION_SET_MODE = 5,
    SOLARIS_OPERATION_SELECT = 6,
    SOLARIS_OPERATION_CLOSE_CONNECTIONS = 7,
    SOLARIS_OPERATION_PROBE = 8
};

#define SOLARIS_TIMEOUT_INFINITE UINT64_MAX
#define SOLARIS_DEFAULT_COMMAND_CAPACITY 32u
#define SOLARIS_MAX_COMMAND_CAPACITY 1024u
#define SOLARIS_MAX_IO_WORKERS 32u
#define SOLARIS_DEFAULT_IO_QUEUE_CAPACITY 128u
#define SOLARIS_DEFAULT_IO_RESOURCE_LIMIT 1024u
#define SOLARIS_DEFAULT_BUFFER_LIMIT_BYTES UINT64_C(16777216)

typedef struct solaris_engine_options {
    /* Zero uses one worker. Valid explicit range: 1..SOLARIS_MAX_IO_WORKERS. */
    uint32_t io_workers;
    /* Pending commands, excluding a callback currently executing. A separate
     * fixed window of capacity+1 also bounds unfinished operations and retained
     * out-of-order results; that window can be full while this queue is empty. */
    uint32_t command_capacity;
    /* Zero uses defaults; queue/resource limits are per worker. */
    uint32_t io_queue_capacity;
    uint32_t io_resource_limit;
    /* Shared engine quota for I/O buffers and request allocations. */
    uint64_t buffer_limit_bytes;
} solaris_engine_options_t;

typedef struct solaris_event {
    uint64_t operation_id;
    uint64_t monotonic_time_ns;
    solaris_operation_t operation;
    solaris_status_t status;
    solaris_engine_state_t state;
    /* Applied configuration revision for config/mode/selection publication;
     * zero for operations that did not publish a configuration/control view. */
    uint64_t config_revision;
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
    uint64_t generation;
    uint64_t io_buffer_bytes;
    uint64_t io_buffer_peak_bytes;
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
 * start activates I/O workers; stop cancels their work and waits for resources
 * and callbacks to drain. These calls do not create listeners or a system VPN.
 */
SOLARIS_API solaris_status_t solaris_engine_start(
    solaris_engine_t *engine, uint64_t *operation_id, solaris_error_t *error);
SOLARIS_API solaris_status_t solaris_engine_stop(
    solaris_engine_t *engine, uint64_t *operation_id, solaris_error_t *error);

/* Thread-safe request to cancel a still-live non-lifecycle operation. Success
 * requests cancellation, not rollback; its original operation still completes
 * once, with the applied revision if publication already happened. */
SOLARIS_API solaris_status_t solaris_engine_cancel(solaris_engine_t *engine,
    uint64_t operation_id, solaris_error_t *error);

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
 * destroy from a control or I/O callback (EDEADLOCK, without changing the engine).
 */
SOLARIS_API solaris_status_t solaris_engine_destroy(
    solaris_engine_t *engine, solaris_error_t *error);

#ifdef __cplusplus
}
#endif

#endif
