#ifndef SOLARIS_SELECT_H
#define SOLARIS_SELECT_H

#include "contracts/module/module.h"

typedef struct solaris_select_control solaris_select_control_t;
typedef struct solaris_select_group solaris_select_group_t;
enum { SOLARIS_HEALTH_UNKNOWN, SOLARIS_HEALTH_PASS, SOLARIS_HEALTH_FAIL };
typedef struct solaris_select_member { uint64_t id; const char *name; } solaris_select_member_t;
typedef struct solaris_select_snapshot { uint64_t selected_id, revision; size_t member_count; } solaris_select_snapshot_t;
typedef struct solaris_select_member_snapshot {
    uint64_t id;
    char name[128];
    uint32_t health, checking;
    solaris_status_t last_probe_status;
    uint64_t probe_token, completed_ns, latency_ns;
} solaris_select_member_snapshot_t;

/* One control is shared by every worker. Members are immutable and copied;
 * selection and health operations below are thread-safe and perform no I/O.
 * Health never changes the selected member. A cancelled check preserves the
 * previous health; a stale check token cannot replace a newer result. */
solaris_status_t solaris_select_control_create(solaris_budget_t *budget,
    const solaris_select_member_t *members, size_t count, uint64_t selected_id, solaris_select_control_t **out);
void solaris_select_control_retain(solaris_select_control_t *control);
void solaris_select_control_release(solaris_select_control_t *control);
solaris_status_t solaris_select_set(solaris_select_control_t *control, uint64_t id);
solaris_status_t solaris_select_snapshot(solaris_select_control_t *control, solaris_select_snapshot_t *out);
solaris_status_t solaris_select_member_snapshot(solaris_select_control_t *control, size_t index, solaris_select_member_snapshot_t *out);
solaris_status_t solaris_select_probe_begin(solaris_select_control_t *control, uint64_t id, uint64_t *token);
solaris_status_t solaris_select_probe_finish(solaris_select_control_t *control, uint64_t id, uint64_t token,
    solaris_status_t status, uint64_t completed_ns, uint64_t latency_ns);

/* Flat M1 group: members are module instances in control-member order, all on
 * owner. Creation retains them and control; retirement stops new group opens
 * without retiring shared members or existing channels. A caller preparing a
 * UDP association must acquire one plan here, then use its fixed leaf for all
 * lanes. The outbound interface selects once for each direct open. */
solaris_status_t solaris_select_group_create(solaris_executor_t *owner, solaris_select_control_t *control,
    solaris_module_instance_t *const *members, size_t count, void (*on_close)(void *), void *context,
    solaris_select_group_t **out);
solaris_outbound_t *solaris_select_outbound(solaris_select_group_t *group);
solaris_status_t solaris_select_plan_acquire(solaris_select_group_t *group, solaris_dial_plan_t *out);
solaris_status_t solaris_select_group_retire(solaris_select_group_t *group);

#endif
