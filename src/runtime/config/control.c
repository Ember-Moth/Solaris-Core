#include "runtime/config/control.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
static solaris_status_t allocate_view(solaris_budget_t *budget, size_t count, solaris_control_view_t **out)
{
    *out = NULL;
    if (count > (SIZE_MAX - sizeof(solaris_control_view_t)) / sizeof(solaris_control_selection_t))
        return SOLARIS_EOVERFLOW;
    solaris_control_view_t *view = solaris_memory_allocate(budget, sizeof(*view) + count * sizeof(*view->groups));
    if (!view)
        return SOLARIS_ENOMEM;
    memset(view, 0, sizeof(*view) + count * sizeof(*view->groups));
    atomic_init(&view->references, 1);
    view->count = count;
    *out = view;
    return SOLARIS_OK;
}
solaris_status_t solaris_control_view_create(solaris_budget_t *budget, solaris_config_t *image,
                                             solaris_control_view_t **out)
{
    if (!out)
        return SOLARIS_EINVAL;
    *out = NULL;
    if (!budget || !image)
        return SOLARIS_EINVAL;
    size_t count;
    const solaris_config_group_t *groups = solaris_config_groups(image, &count);
    solaris_config_snapshot_t info;
    solaris_status_t rc = solaris_config_get_snapshot(image, &info);
    if (rc != SOLARIS_OK)
        return rc;
    rc = allocate_view(budget, count, out);
    if (rc != SOLARIS_OK)
        return rc;
    (*out)->mode = info.mode;
    for (size_t i = 0; i < count; ++i)
        (*out)->groups[i] =
            (solaris_control_selection_t){.selected = groups[i].selected_id, .reason = SOLARIS_SELECTION_INITIAL};
    return SOLARIS_OK;
}
solaris_status_t solaris_control_view_clone(solaris_budget_t *budget, const solaris_control_view_t *source,
                                            solaris_control_view_t **out)
{
    if (!out)
        return SOLARIS_EINVAL;
    *out = NULL;
    if (!budget || !source)
        return SOLARIS_EINVAL;
    solaris_status_t rc = allocate_view(budget, source->count, out);
    if (rc != SOLARIS_OK)
        return rc;
    (*out)->revision = source->revision;
    (*out)->mode = source->mode;
    if (source->count)
        memcpy((*out)->groups, source->groups, source->count * sizeof(*source->groups));
    return SOLARIS_OK;
}
void solaris_control_view_retain(solaris_control_view_t *view)
{
    if (view)
        (void)atomic_fetch_add_explicit(&view->references, 1, memory_order_relaxed);
}
void solaris_control_view_release(solaris_control_view_t *view)
{
    if (view && atomic_fetch_sub_explicit(&view->references, 1, memory_order_acq_rel) == 1)
        solaris_memory_free(view);
}
void solaris_control_view_migrate(solaris_control_view_t *view, solaris_config_t *image,
                                  const solaris_control_view_t *old, solaris_config_t *old_image, uint64_t revision)
{
    size_t count, old_count = 0;
    const solaris_config_group_t *groups = solaris_config_groups(image, &count);
    const solaris_config_group_t *previous = old_image ? solaris_config_groups(old_image, &old_count) : NULL;
    assert(count == view->count && (!old || old->count == old_count));
    view->revision = revision;
    if (old)
        view->mode = old->mode;
    for (size_t i = 0; i < count; ++i) {
        solaris_control_selection_t *selection = &view->groups[i];
        *selection =
            (solaris_control_selection_t){.selected = groups[i].selected_id,
                                          .reason_revision = revision,
                                          .reason = old ? SOLARIS_SELECTION_GROUP_ADDED : SOLARIS_SELECTION_INITIAL};
        if (!old)
            continue;
        for (size_t j = 0; j < old_count; ++j)
            if (groups[i].id == previous[j].id) {
                selection->previous = old->groups[j].selected;
                selection->reason = SOLARIS_SELECTION_MEMBER_REMOVED;
                for (size_t k = 0; k < groups[i].member_count; ++k)
                    if (groups[i].members[k] == old->groups[j].selected) {
                        selection->selected = old->groups[j].selected;
                        selection->reason = SOLARIS_SELECTION_RELOAD_PRESERVED;
                        break;
                    }
                break;
            }
    }
}
struct solaris_control_snapshot {
    atomic_size_t references;
    solaris_control_info_t info;
    solaris_config_node_info_t *nodes;
    solaris_group_info_t *groups;
    uint64_t *offsets;
    uint64_t *members;
};
static int add_size(size_t *size, size_t count, size_t unit)
{
    if (count > (SIZE_MAX - *size) / unit)
        return 0;
    *size += count * unit;
    return 1;
}
solaris_status_t solaris_control_snapshot_copy(solaris_config_t *image, const solaris_control_view_t *view,
                                               uint64_t config_revision, uint64_t runtime_generation,
                                               solaris_control_snapshot_t **out)
{
    if (!out)
        return SOLARIS_EINVAL;
    *out = NULL;
    if (!image || !view)
        return SOLARIS_EINVAL;
    solaris_config_snapshot_t info;
    solaris_status_t rc = solaris_config_get_snapshot(image, &info);
    if (rc != SOLARIS_OK)
        return rc;
    size_t count;
    const solaris_config_group_t *groups = solaris_config_groups(image, &count);
    assert(count == view->count);
    size_t members = 0;
    for (size_t i = 0; i < count; ++i) {
        if (groups[i].member_count > SIZE_MAX - members)
            return SOLARIS_EOVERFLOW;
        members += groups[i].member_count;
    }
    size_t bytes = sizeof(solaris_control_snapshot_t);
    if (!add_size(&bytes, info.node_count, sizeof(solaris_config_node_info_t)) ||
        !add_size(&bytes, count, sizeof(solaris_group_info_t)) || !add_size(&bytes, count, sizeof(uint64_t)) ||
        !add_size(&bytes, members, sizeof(uint64_t)))
        return SOLARIS_EOVERFLOW;
    /* Owned public metadata outlives engine/host allocator destruction. */
    solaris_control_snapshot_t *snapshot = calloc(1, bytes);
    if (!snapshot)
        return SOLARIS_ENOMEM;
    atomic_init(&snapshot->references, 1);
    snapshot->info = (solaris_control_info_t){.config_revision = config_revision,
                                              .selection_revision = view->revision,
                                              .runtime_generation = runtime_generation,
                                              .mode = view->mode,
                                              .node_count = info.node_count,
                                              .group_count = count};
    snapshot->nodes = (void *)(snapshot + 1);
    snapshot->groups = (void *)(snapshot->nodes + info.node_count);
    snapshot->offsets = (void *)(snapshot->groups + count);
    snapshot->members = (void *)(snapshot->offsets + count);
    for (size_t i = 0; i < info.node_count; ++i)
        (void)solaris_config_get_node(image, i, &snapshot->nodes[i]);
    size_t offset = 0;
    for (size_t i = 0; i < count; ++i) {
        const solaris_control_selection_t *selected = &view->groups[i];
        snapshot->groups[i] = (solaris_group_info_t){.id = groups[i].id,
                                                     .selected_id = selected->selected,
                                                     .previous_selected_id = selected->previous,
                                                     .reason_revision = selected->reason_revision,
                                                     .member_count = groups[i].member_count,
                                                     .selection_reason = selected->reason};
        (void)snprintf(snapshot->groups[i].name, sizeof(snapshot->groups[i].name), "%s", groups[i].name);
        snapshot->offsets[i] = offset;
        if (groups[i].member_count)
            memcpy(snapshot->members + offset, groups[i].members, groups[i].member_count * sizeof(uint64_t));
        offset += groups[i].member_count;
    }
    *out = snapshot;
    return SOLARIS_OK;
}
void solaris_control_snapshot_retain(solaris_control_snapshot_t *snapshot)
{
    if (snapshot)
        (void)atomic_fetch_add_explicit(&snapshot->references, 1, memory_order_relaxed);
}
void solaris_control_snapshot_release(solaris_control_snapshot_t *snapshot)
{
    if (snapshot && atomic_fetch_sub_explicit(&snapshot->references, 1, memory_order_acq_rel) == 1)
        free(snapshot);
}
solaris_status_t solaris_control_snapshot_get_info(const solaris_control_snapshot_t *snapshot,
                                                   solaris_control_info_t *out)
{
    if (!snapshot || !out)
        return SOLARIS_EINVAL;
    *out = snapshot->info;
    return SOLARIS_OK;
}
solaris_status_t solaris_control_snapshot_get_node(const solaris_control_snapshot_t *snapshot, size_t index,
                                                   solaris_config_node_info_t *out)
{
    if (!snapshot || !out || index >= snapshot->info.node_count)
        return SOLARIS_EINVAL;
    *out = snapshot->nodes[index];
    return SOLARIS_OK;
}
solaris_status_t solaris_control_snapshot_get_group(const solaris_control_snapshot_t *snapshot, size_t index,
                                                    solaris_group_info_t *out)
{
    if (!snapshot || !out || index >= snapshot->info.group_count)
        return SOLARIS_EINVAL;
    *out = snapshot->groups[index];
    return SOLARIS_OK;
}
solaris_status_t solaris_control_snapshot_get_group_member(const solaris_control_snapshot_t *snapshot, size_t group,
                                                           size_t member, uint64_t *out)
{
    if (!snapshot || !out || group >= snapshot->info.group_count || member >= snapshot->groups[group].member_count)
        return SOLARIS_EINVAL;
    *out = snapshot->members[snapshot->offsets[group] + member];
    return SOLARIS_OK;
}
