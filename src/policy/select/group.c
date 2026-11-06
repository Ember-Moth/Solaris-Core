#include "policy/select/select.h"
#include <assert.h>
#include <string.h>

struct solaris_select_group {
    solaris_outbound_t outbound;
    solaris_scope_t scope;
    solaris_select_control_t *control;
    void (*on_close)(void *);
    void *context;
    size_t count;
    int accepted, retired;
    struct { uint64_t id; solaris_module_instance_t *instance; } members[];
};
solaris_status_t solaris_select_plan_acquire(solaris_select_group_t *group, solaris_dial_plan_t *out)
{
    if (out == NULL) return SOLARIS_EINVAL;
    memset(out, 0, sizeof(*out));
    if (group == NULL) return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(group->outbound.owner)) return SOLARIS_ETHREAD;
    if (group->retired || !solaris_executor_accepting(group->outbound.owner)) return SOLARIS_ECLOSED;
    solaris_select_snapshot_t snapshot;
    solaris_status_t rc = solaris_select_snapshot(group->control, &snapshot);
    if (rc != SOLARIS_OK) return rc;
    for (size_t i = 0u; i < group->count; ++i) if (group->members[i].id == snapshot.selected_id) {
        rc = solaris_module_plan_acquire(group->members[i].instance, snapshot.selected_id, out);
        if (rc == SOLARIS_OK) out->selection_revision = snapshot.revision;
        return rc;
    }
    return SOLARIS_EINVAL;
}
static uint32_t capabilities(void *state)
{
    solaris_dial_plan_t plan; uint32_t caps = 0u;
    if (solaris_select_plan_acquire(state, &plan) == SOLARIS_OK) {
        (void)solaris_outbound_capabilities(plan.outbound, &caps); (void)solaris_dial_plan_release(&plan);
    }
    return caps;
}
static solaris_status_t open_stream(void *state, const solaris_address_t *target,
    const solaris_stream_callbacks_t *callbacks, void *context, solaris_stream_t **out)
{
    solaris_dial_plan_t plan; solaris_status_t rc = solaris_select_plan_acquire(state, &plan);
    if (rc != SOLARIS_OK) return rc;
    rc = solaris_outbound_open_stream(plan.outbound, target, callbacks, context, out);
    (void)solaris_dial_plan_release(&plan); return rc;
}
static solaris_status_t open_datagram(void *state, uint32_t family,
    const solaris_datagram_callbacks_t *callbacks, void *context, solaris_datagram_t **out)
{
    solaris_dial_plan_t plan; solaris_status_t rc = solaris_select_plan_acquire(state, &plan);
    if (rc != SOLARIS_OK) return rc;
    rc = solaris_outbound_open_datagram(plan.outbound, family, callbacks, context, out);
    (void)solaris_dial_plan_release(&plan); return rc;
}
static void retired(void *context) { ((solaris_select_group_t *)context)->retired = 1; }
static void retire_outbound(void *state) { solaris_scope_cancel(&((solaris_select_group_t *)state)->scope); }
static const solaris_outbound_ops_t operations = {capabilities, open_stream, open_datagram, retire_outbound};
static void destroyed(void *context)
{
    solaris_select_group_t *group = context;
    for (size_t i = 0u; i < group->count; ++i) {
        solaris_status_t rc = solaris_module_release(group->members[i].instance); assert(rc == SOLARIS_OK); (void)rc;
    }
    solaris_select_control_release(group->control);
    if (group->accepted && group->on_close != NULL) group->on_close(group->context);
    solaris_memory_free(group);
}
solaris_status_t solaris_select_group_create(solaris_executor_t *owner, solaris_select_control_t *control,
    solaris_module_instance_t *const *members, size_t count, void (*on_close)(void *), void *context,
    solaris_select_group_t **out)
{
    if (out == NULL) return SOLARIS_EINVAL;
    *out = NULL;
    if (owner == NULL || control == NULL || members == NULL || count == 0u || count > 1024u) return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(owner)) return SOLARIS_ETHREAD;
    solaris_select_snapshot_t snapshot; solaris_status_t rc = solaris_select_snapshot(control, &snapshot);
    if (rc != SOLARIS_OK || count != snapshot.member_count) return SOLARIS_EINVAL;
    for (size_t i = 0u; i < count; ++i) {
        solaris_outbound_t *outbound = solaris_module_outbound(members[i]);
        if (outbound == NULL || outbound->owner != owner) return SOLARIS_EINVAL;
    }
    solaris_select_group_t *group = solaris_memory_allocate(solaris_executor_budget(owner), sizeof(*group) + count * sizeof(*group->members));
    if (group == NULL) return SOLARIS_ENOMEM;
    memset(group, 0, sizeof(*group) + count * sizeof(*group->members));
    group->control = control; solaris_select_control_retain(control); group->on_close = on_close; group->context = context;
    group->outbound = (solaris_outbound_t){&operations, group, owner};
    for (size_t i = 0u; i < count; ++i) {
        rc = solaris_module_retain(members[i]);
        if (rc != SOLARIS_OK) { destroyed(group); return rc; }
        solaris_select_member_snapshot_t member; (void)solaris_select_member_snapshot(control, i, &member);
        group->members[i].id = member.id; group->members[i].instance = members[i]; group->count++;
    }
    rc = solaris_scope_init(&group->scope, owner, retired, destroyed, group);
    if (rc != SOLARIS_OK) { destroyed(group); return rc; }
    group->accepted = 1; *out = group; return SOLARIS_OK;
}
solaris_outbound_t *solaris_select_outbound(solaris_select_group_t *group)
{ return group != NULL && solaris_executor_is_owner(group->outbound.owner) && !group->retired ? &group->outbound : NULL; }
solaris_status_t solaris_select_group_retire(solaris_select_group_t *group)
{
    if (group == NULL) return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(group->outbound.owner)) return SOLARIS_ETHREAD;
    solaris_scope_cancel(&group->scope); return SOLARIS_OK;
}
