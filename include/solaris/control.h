#ifndef SOLARIS_CONTROL_H
#define SOLARIS_CONTROL_H
#include <solaris/config.h>
#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct solaris_control_snapshot solaris_control_snapshot_t;
    typedef struct solaris_control_info
    {
        uint64_t config_revision, selection_revision, runtime_generation;
        solaris_mode_t mode;
        size_t node_count, group_count;
    } solaris_control_info_t;
    enum
    {
        SOLARIS_SELECTION_INITIAL = 1,
        SOLARIS_SELECTION_USER = 2,
        SOLARIS_SELECTION_RELOAD_PRESERVED = 3,
        SOLARIS_SELECTION_MEMBER_REMOVED = 4,
        SOLARIS_SELECTION_GROUP_ADDED = 5
    };
    typedef struct solaris_group_info
    {
        uint64_t id, selected_id, previous_selected_id, reason_revision;
        char name[128];
        size_t member_count;
        uint32_t selection_reason;
    } solaris_group_info_t;
    typedef struct solaris_control_result
    {
        uint64_t config_revision, selection_revision;
        solaris_mode_t mode;
        uint64_t group_id, selected_id;
    } solaris_control_result_t;
    /* Borrowed result/error, on the control owner before the generic event.
     * Failure has zero revisions. Success identifies the applied control view. */
    typedef void (*solaris_control_callback_t)(void *context, solaris_status_t status,
                                               const solaris_control_result_t *result,
                                               const solaris_error_t *error);

    /* Thread-safe, revision-qualified operations. expected_config_revision must
     * be nonzero and match the active configuration at execution, otherwise
     * EINVAL / EAGAIN. An unchanged value preserves selection_revision. New TCP
     * admissions / UDP associations use the new view; existing flows keep theirs.
     * Cancellation before publication prevents it; after publication it cannot
     * roll back the result. callback may be NULL. Rejection sets operation_id=0. */
    SOLARIS_API solaris_status_t solaris_engine_set_mode(solaris_engine_t *engine,
                                                         uint64_t expected_config_revision,
                                                         solaris_mode_t mode,
                                                         solaris_control_callback_t callback, void *context,
                                                         uint64_t *operation_id, solaris_error_t *error);
    SOLARIS_API solaris_status_t solaris_engine_select(solaris_engine_t *engine,
                                                       uint64_t expected_config_revision, uint64_t group_id,
                                                       uint64_t node_id, solaris_control_callback_t callback,
                                                       void *context, uint64_t *operation_id,
                                                       solaris_error_t *error);

    /* One coherent, owned copy of configuration and control metadata. No live
     * worker pointers or credentials. Remains usable after engine destruction. */
    SOLARIS_API solaris_status_t solaris_engine_get_control_snapshot(solaris_engine_t *engine,
                                                                     solaris_control_snapshot_t **out,
                                                                     solaris_error_t *error);
    SOLARIS_API void solaris_control_snapshot_retain(solaris_control_snapshot_t *snapshot);
    SOLARIS_API void solaris_control_snapshot_release(solaris_control_snapshot_t *snapshot);
    SOLARIS_API solaris_status_t solaris_control_snapshot_get_info(const solaris_control_snapshot_t *snapshot,
                                                                   solaris_control_info_t *out);
    SOLARIS_API solaris_status_t solaris_control_snapshot_get_node(const solaris_control_snapshot_t *snapshot,
                                                                   size_t index,
                                                                   solaris_config_node_info_t *out);
    SOLARIS_API solaris_status_t solaris_control_snapshot_get_group(
        const solaris_control_snapshot_t *snapshot, size_t index, solaris_group_info_t *out);
    SOLARIS_API solaris_status_t
    solaris_control_snapshot_get_group_member(const solaris_control_snapshot_t *snapshot, size_t group_index,
                                              size_t member_index, uint64_t *node_id);
#ifdef __cplusplus
}
#endif
#endif
