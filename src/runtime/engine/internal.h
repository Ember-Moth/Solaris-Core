#ifndef SOLARIS_ENGINE_INTERNAL_H
#define SOLARIS_ENGINE_INTERNAL_H

#include <stddef.h>
#include <uv.h>
#include <solaris/engine.h>
#include "runtime/services/services.h"
#include "runtime/executor/executor.h"
#include "runtime/operation/request.h"

/* Borrowed during engine lifetime; returns NULL during destruction. The key
 * selects a stable worker, not a destination-dependent per-packet route. */
solaris_executor_t *solaris_runtime_executor(solaris_engine_t *engine, uint64_t affinity_key);

typedef struct solaris_runtime_attachment {
    void *context;
    /* Control-owner, before workers quiesce. Idempotent; closes admission and
     * invalidates candidates without blocking. destroy distinguishes teardown. */
    solaris_status_t (*stop)(void *context, int destroy);
    int (*drained)(void *context);
    /* Control-owner after all operations, reserved completions and I/O drain. */
    void (*destroy)(void *context);
} solaris_runtime_attachment_t;
/* Thread-safe lazy attachment. OK transfers context; EBUSY returns the existing
 * borrowed context and transfers nothing. Exclusive engine destroy applies. */
solaris_status_t solaris_runtime_attachment_install(solaris_engine_t *engine,
    const solaris_runtime_attachment_t *attachment, void **existing);
void *solaris_runtime_attachment_get(solaris_engine_t *engine);
/* Control-owner only. Used for bounded asynchronous library work requests. */
uv_loop_t *solaris_runtime_control_loop(solaris_engine_t *engine);
uint32_t solaris_runtime_worker_count(solaris_engine_t *engine);

solaris_status_t solaris_runtime_create(
    const solaris_engine_options_t *options, const solaris_host_t *host,
    const solaris_runtime_services_t *services,
    solaris_engine_t **out_engine, solaris_error_t *error);
solaris_status_t solaris_runtime_submit(solaris_engine_t *engine,
                                        solaris_operation_t operation,
                                        uint64_t *id, solaris_error_t *error);
solaris_status_t solaris_runtime_snapshot(solaris_engine_t *engine,
                                          solaris_engine_snapshot_t *snapshot,
                                          solaris_error_t *error);
solaris_status_t solaris_runtime_flush(solaris_engine_t *engine,
                                       uint64_t timeout_ms,
                                       solaris_error_t *error);
solaris_status_t solaris_runtime_destroy(solaris_engine_t *engine,
                                         solaris_error_t *error);

#endif
