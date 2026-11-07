#include "config/image/internal.h"
#include "api/common/error.h"
#include <string.h>
#include <stdio.h>
void *cfg_alloc(cfg_arena_t *arena, size_t size)
{
    if (size > SIZE_MAX - sizeof(cfg_allocation_t))
        return NULL;
    cfg_allocation_t *p = solaris_memory_allocate(arena->budget, sizeof(*p) + size);
    if (!p)
        return NULL;
    p->h.next = arena->head;
    p->h.size = size;
    arena->head = p;
    memset(p + 1, 0, size);
    return p + 1;
}
char *cfg_string(cfg_arena_t *arena, const char *text, size_t size)
{
    if (size == SIZE_MAX)
        return NULL;
    char *p = cfg_alloc(arena, size + 1);
    if (p && size)
        memcpy(p, text, size);
    return p;
}
void cfg_arena_clear(cfg_arena_t *arena)
{
    while (arena->head) {
        cfg_allocation_t *p = arena->head;
        arena->head = p->h.next;
        for (size_t i = 0; i < p->h.size; ++i)
            ((volatile unsigned char *)(p + 1))[i] = 0;
        solaris_memory_free(p);
    }
}
void cfg_diagnostic(cfg_context_t *c, const cfg_node_t *node, const char *path, uint32_t severity, uint32_t stage,
                    solaris_status_t status, const char *message)
{
    if (severity == SOLARIS_DIAGNOSTIC_ERROR) {
        if (!c->errors++)
            c->status = status;
    }
    solaris_diagnostics_t *d = c->diagnostics;
    if (!d || !d->capacity)
        return;
    size_t index = d->count;
    if (index == d->capacity) {
        if (severity != SOLARIS_DIAGNOSTIC_ERROR)
            return;
        index--;
    } else
        d->count++;
    solaris_config_diagnostic_t *entry = &d->entries[index];
    memset(entry, 0, sizeof(*entry));
    entry->severity = severity;
    entry->stage = stage;
    entry->status = status;
    if (node) {
        entry->line = node->line;
        entry->column = node->column;
        entry->related_line = node->related_line;
        entry->related_column = node->related_column;
    }
    (void)snprintf(entry->source, sizeof(entry->source), "%s",
                   c->options.source_name ? c->options.source_name : "<bytes>");
    (void)snprintf(entry->path, sizeof(entry->path), "%s", path ? path : "$");
    (void)snprintf(entry->message, sizeof(entry->message), "%s", message);
}
void cfg_fail(cfg_context_t *c, const cfg_node_t *node, const char *path, solaris_status_t status, const char *message)
{
    cfg_diagnostic(c, node, path, SOLARIS_DIAGNOSTIC_ERROR, SOLARIS_CONFIG_NORMALIZE, status, message);
}
void solaris_config_retain(solaris_config_t *c)
{
    if (c)
        (void)atomic_fetch_add_explicit(&c->references, 1, memory_order_relaxed);
}
void solaris_config_release(solaris_config_t *c)
{
    if (c && atomic_fetch_sub_explicit(&c->references, 1, memory_order_acq_rel) == 1) {
        cfg_arena_clear(&c->arena);
        solaris_memory_free(c);
    }
}
solaris_status_t solaris_config_get_snapshot(const solaris_config_t *c, solaris_config_snapshot_t *out)
{
    if (!c || !out)
        return SOLARIS_EINVAL;
    *out = c->snapshot;
    return SOLARIS_OK;
}
solaris_status_t solaris_config_get_node(const solaris_config_t *c, size_t i, solaris_config_node_info_t *out)
{
    if (!c || !out || i >= c->snapshot.node_count)
        return SOLARIS_EINVAL;
    memset(out, 0, sizeof(*out));
    const solaris_config_node_t *n = &c->nodes[i];
    out->id = n->id;
    out->udp_enabled = n->udp_enabled;
    (void)snprintf(out->name, sizeof(out->name), "%s", n->name);
    (void)snprintf(out->type, sizeof(out->type), "%s", n->type);
    return SOLARIS_OK;
}
void solaris_diagnostics_retain(solaris_diagnostics_t *d)
{
    if (d)
        (void)atomic_fetch_add_explicit(&d->references, 1, memory_order_relaxed);
}
void solaris_diagnostics_release(solaris_diagnostics_t *d)
{
    if (d && atomic_fetch_sub_explicit(&d->references, 1, memory_order_acq_rel) == 1)
        solaris_memory_free(d);
}
size_t solaris_diagnostics_count(const solaris_diagnostics_t *d)
{
    return d ? d->count : 0;
}
solaris_status_t solaris_diagnostics_get(const solaris_diagnostics_t *d, size_t i, solaris_config_diagnostic_t *out)
{
    if (!d || !out || i >= d->count)
        return SOLARIS_EINVAL;
    *out = d->entries[i];
    return SOLARIS_OK;
}
const solaris_config_node_t *solaris_config_nodes(const solaris_config_t *c, size_t *count)
{
    if (count)
        *count = c ? c->snapshot.node_count : 0;
    return c ? c->nodes : NULL;
}
const solaris_config_group_t *solaris_config_groups(const solaris_config_t *c, size_t *count)
{
    if (count)
        *count = c ? c->snapshot.group_count : 0;
    return c ? c->groups : NULL;
}
const solaris_route_rule_t *solaris_config_rules(const solaris_config_t *c, size_t *count)
{
    if (count)
        *count = c ? c->snapshot.rule_count : 0;
    return c ? c->rules : NULL;
}
const solaris_config_listener_t *solaris_config_listeners(const solaris_config_t *c, size_t *count)
{
    if (count)
        *count = c ? c->snapshot.listener_count : 0;
    return c ? c->listeners : NULL;
}
uint64_t solaris_config_direct_target(const solaris_config_t *c)
{
    return c ? c->direct_target : 0;
}
uint64_t solaris_config_global_target(const solaris_config_t *c)
{
    return c ? c->global_target : 0;
}
const char *solaris_config_base_directory(const solaris_config_t *c)
{
    return c ? c->base_directory : NULL;
}

const char *solaris_config_source_name(const solaris_config_t *c)
{
    return c ? c->source_name : NULL;
}
