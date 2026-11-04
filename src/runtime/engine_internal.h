#ifndef SOLARIS_ENGINE_INTERNAL_H
#define SOLARIS_ENGINE_INTERNAL_H

#include <stddef.h>
#include <solaris/engine.h>

typedef enum solaris_runtime_point {
    SOLARIS_POINT_MUTEX_INIT,
    SOLARIS_POINT_CONDITION_INIT,
    SOLARIS_POINT_THREAD_CREATE,
    SOLARIS_POINT_LOOP_INIT,
    SOLARIS_POINT_ASYNC_INIT,
    SOLARIS_POINT_ASYNC_SEND,
    SOLARIS_POINT_SHUTDOWN
} solaris_runtime_point_t;

/* Private, per-instance services; no production-global test switches. */
typedef struct solaris_runtime_services {
    void *context;
    void *(*allocate)(void *context, size_t size);
    void (*deallocate)(void *context, void *pointer);
    uint64_t (*now_ns)(void *context);
    int (*checkpoint)(void *context, solaris_runtime_point_t point);
} solaris_runtime_services_t;

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
