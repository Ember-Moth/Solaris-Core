#include <solaris/engine.h>
#include "api/error_internal.h"
#include "runtime/engine_internal.h"

#include <string.h>

void solaris_engine_options_init(solaris_engine_options_t *options)
{
    if (options != NULL) {
        memset(options, 0, sizeof(*options));
        options->io_workers = 1u;
        options->command_capacity = SOLARIS_DEFAULT_COMMAND_CAPACITY;
    }
}

solaris_status_t solaris_engine_create(const solaris_engine_options_t *options,
                                       const solaris_host_t *host,
                                       solaris_engine_t **out_engine,
                                       solaris_error_t *error)
{
    return solaris_runtime_create(options, host, NULL, out_engine, error);
}

solaris_status_t solaris_engine_start(solaris_engine_t *engine,
                                      uint64_t *operation_id,
                                      solaris_error_t *error)
{
    return solaris_runtime_submit(engine, SOLARIS_OPERATION_START,
                                  operation_id, error);
}

solaris_status_t solaris_engine_stop(solaris_engine_t *engine,
                                     uint64_t *operation_id,
                                     solaris_error_t *error)
{
    return solaris_runtime_submit(engine, SOLARIS_OPERATION_STOP,
                                  operation_id, error);
}

solaris_status_t solaris_engine_get_snapshot(solaris_engine_t *engine,
                                             solaris_engine_snapshot_t *snapshot,
                                             solaris_error_t *error)
{
    return solaris_runtime_snapshot(engine, snapshot, error);
}

solaris_status_t solaris_engine_flush(solaris_engine_t *engine,
                                      uint64_t timeout_ms,
                                      solaris_error_t *error)
{
    return solaris_runtime_flush(engine, timeout_ms, error);
}

solaris_status_t solaris_engine_destroy(solaris_engine_t *engine,
                                        solaris_error_t *error)
{
    return solaris_runtime_destroy(engine, error);
}
