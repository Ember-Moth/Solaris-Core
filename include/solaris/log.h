#ifndef SOLARIS_LOG_H
#define SOLARIS_LOG_H
#include <solaris/engine.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C"
{
#endif
    typedef struct solaris_log_snapshot solaris_log_snapshot_t;
    enum
    {
        SOLARIS_LOG_INFO = 1,
        SOLARIS_LOG_WARNING = 2,
        SOLARIS_LOG_ERROR = 3
    };
    enum
    {
        SOLARIS_LOG_DIAGNOSTIC = 1,
        SOLARIS_LOG_PREPARE = 2,
        SOLARIS_LOG_COMMIT = 3,
        SOLARIS_LOG_CONTROL = 4,
        SOLARIS_LOG_PROBE = 5
    };
    typedef struct solaris_log_record
    {
        uint64_t sequence, monotonic_time_ns, runtime_generation, config_revision, operation_id, node_id;
        uint32_t level, event;
        solaris_status_t status;
        /* Safe component identifier only; no credentials, URLs or peer text. */
        char component[32];
    } solaris_log_record_t;
    typedef struct solaris_log_info
    {
        size_t count;
        uint64_t cursor, oldest_sequence, latest_sequence, overwritten, dropped, missed;
    } solaris_log_info_t;
    /* Thread-safe owned copies, ascending sequence, independent of engine lifetime.
     * after_sequence is exclusive. max_records=0 selects ring capacity; larger
     * limits are clamped. cursor is the last copied sequence (or the input cursor
     * if empty). overwritten/dropped are cumulative; missed reports records lost
     * before this cursor due to ring eviction. Poll again with the returned cursor.
     * Live logging is bounded and never invokes a host callback on I/O workers. */
    SOLARIS_API solaris_status_t solaris_engine_get_logs(solaris_engine_t *engine, uint64_t after_sequence,
                                                         size_t max_records, solaris_log_snapshot_t **out,
                                                         solaris_error_t *error);
    SOLARIS_API void solaris_log_snapshot_retain(solaris_log_snapshot_t *snapshot);
    SOLARIS_API void solaris_log_snapshot_release(solaris_log_snapshot_t *snapshot);
    SOLARIS_API solaris_status_t solaris_log_snapshot_get_info(const solaris_log_snapshot_t *snapshot,
                                                               solaris_log_info_t *out);
    SOLARIS_API solaris_status_t solaris_log_snapshot_get_record(const solaris_log_snapshot_t *snapshot,
                                                                 size_t index, solaris_log_record_t *out);
#ifdef __cplusplus
}
#endif
#endif
