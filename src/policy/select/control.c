#include "policy/select/select.h"
#include <stdatomic.h>
#include <string.h>
#include <uv.h>

struct solaris_select_control {
    atomic_uint references;
    uv_mutex_t mutex;
    size_t count, selected;
    uint64_t revision;
    solaris_select_member_snapshot_t members[];
};
static size_t index_of(solaris_select_control_t *control, uint64_t id)
{ for (size_t i = 0u; i < control->count; ++i) if (control->members[i].id == id) return i; return control->count; }
solaris_status_t solaris_select_control_create(solaris_budget_t *budget,
    const solaris_select_member_t *members, size_t count, uint64_t selected_id, solaris_select_control_t **out)
{
    if (out == NULL) return SOLARIS_EINVAL;
    *out = NULL;
    if (budget == NULL || members == NULL || count == 0u || count > 1024u || selected_id == 0u) return SOLARIS_EINVAL;
    size_t selected = count;
    for (size_t i = 0u; i < count; ++i) {
        if (members[i].id == 0u || members[i].name == NULL || members[i].name[0] == '\0' || strlen(members[i].name) >= 128u) return SOLARIS_EINVAL;
        for (size_t n = 0u; n < i; ++n)
            if (members[i].id == members[n].id || strcmp(members[i].name, members[n].name) == 0) return SOLARIS_EINVAL;
        if (members[i].id == selected_id) selected = i;
    }
    if (selected == count) return SOLARIS_EINVAL;
    solaris_select_control_t *control = solaris_memory_allocate(budget, sizeof(*control) + count * sizeof(*control->members));
    if (control == NULL) return SOLARIS_ENOMEM;
    memset(control, 0, sizeof(*control) + count * sizeof(*control->members)); atomic_init(&control->references, 1u);
    if (uv_mutex_init(&control->mutex) != 0) { solaris_memory_free(control); return SOLARIS_EIO; }
    control->count = count; control->selected = selected; control->revision = 1u;
    for (size_t i = 0u; i < count; ++i) {
        control->members[i].id = members[i].id; memcpy(control->members[i].name, members[i].name, strlen(members[i].name) + 1u);
    }
    *out = control; return SOLARIS_OK;
}
void solaris_select_control_retain(solaris_select_control_t *control)
{ if (control != NULL) (void)atomic_fetch_add_explicit(&control->references, 1u, memory_order_relaxed); }
void solaris_select_control_release(solaris_select_control_t *control)
{
    if (control != NULL && atomic_fetch_sub_explicit(&control->references, 1u, memory_order_acq_rel) == 1u) {
        uv_mutex_destroy(&control->mutex); solaris_memory_free(control);
    }
}
solaris_status_t solaris_select_set(solaris_select_control_t *control, uint64_t id)
{
    if (control == NULL) return SOLARIS_EINVAL;
    uv_mutex_lock(&control->mutex); size_t index = index_of(control, id); solaris_status_t rc = SOLARIS_OK;
    if (index == control->count) rc = SOLARIS_EINVAL;
    else if (index != control->selected) {
        if (control->revision == UINT64_MAX) rc = SOLARIS_EOVERFLOW;
        else { control->selected = index; control->revision++; }
    }
    uv_mutex_unlock(&control->mutex); return rc;
}
solaris_status_t solaris_select_snapshot(solaris_select_control_t *control, solaris_select_snapshot_t *out)
{
    if (control == NULL || out == NULL) return SOLARIS_EINVAL;
    uv_mutex_lock(&control->mutex);
    *out = (solaris_select_snapshot_t){control->members[control->selected].id, control->revision, control->count};
    uv_mutex_unlock(&control->mutex); return SOLARIS_OK;
}
solaris_status_t solaris_select_member_snapshot(solaris_select_control_t *control, size_t index, solaris_select_member_snapshot_t *out)
{
    if (control == NULL || out == NULL || index >= control->count) return SOLARIS_EINVAL;
    uv_mutex_lock(&control->mutex); *out = control->members[index]; uv_mutex_unlock(&control->mutex); return SOLARIS_OK;
}
solaris_status_t solaris_select_probe_begin(solaris_select_control_t *control, uint64_t id, uint64_t *token)
{
    if (token == NULL) return SOLARIS_EINVAL;
    *token = 0u; if (control == NULL) return SOLARIS_EINVAL;
    uv_mutex_lock(&control->mutex); size_t index = index_of(control, id); solaris_status_t rc = SOLARIS_OK;
    if (index == control->count) rc = SOLARIS_EINVAL;
    else if (control->members[index].probe_token == UINT64_MAX) rc = SOLARIS_EOVERFLOW;
    else { *token = ++control->members[index].probe_token; control->members[index].checking = 1u; }
    uv_mutex_unlock(&control->mutex); return rc;
}
solaris_status_t solaris_select_probe_finish(solaris_select_control_t *control, uint64_t id, uint64_t token,
    solaris_status_t status, uint64_t completed_ns, uint64_t latency_ns)
{
    if (control == NULL || token == 0u) return SOLARIS_EINVAL;
    uv_mutex_lock(&control->mutex); size_t index = index_of(control, id); solaris_status_t rc = SOLARIS_OK;
    if (index == control->count) rc = SOLARIS_EINVAL;
    else {
        solaris_select_member_snapshot_t *member = &control->members[index];
        if (member->probe_token != token || !member->checking) rc = SOLARIS_ECANCELLED;
        else {
            member->checking = 0u; member->last_probe_status = status;
            member->completed_ns = completed_ns; member->latency_ns = latency_ns;
            if (status != SOLARIS_ECANCELLED) member->health = status == SOLARIS_OK ? SOLARIS_HEALTH_PASS : SOLARIS_HEALTH_FAIL;
        }
    }
    uv_mutex_unlock(&control->mutex); return rc;
}
