#ifndef SOLARIS_ENGINE_INTERNAL_H
#define SOLARIS_ENGINE_INTERNAL_H

#include <stddef.h>
#include <solaris/engine.h>
#include "runtime/services/services.h"
#include "runtime/executor/executor.h"

/* Borrowed during engine lifetime; returns NULL during destruction. The key
 * selects a stable worker, not a destination-dependent per-packet route. */
solaris_executor_t *solaris_runtime_executor(solaris_engine_t *engine, uint64_t affinity_key);

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
