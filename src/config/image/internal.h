#ifndef SOLARIS_CONFIG_INTERNAL_H
#define SOLARIS_CONFIG_INTERNAL_H
#include "contracts/config/image.h"
#include "contracts/io/buffer.h"
#include "runtime/memory/alignment.h"
#include <stdatomic.h>
#include <stdio.h>

typedef union cfg_allocation cfg_allocation_t;
union cfg_allocation {
    solaris_max_align_t align;
    struct {
        cfg_allocation_t *next;
        size_t size;
    } h;
};
typedef struct cfg_arena {
    solaris_budget_t *budget;
    cfg_allocation_t *head;
} cfg_arena_t;
typedef struct cfg_node cfg_node_t;
enum { CFG_SCALAR, CFG_MAP, CFG_SEQUENCE, CFG_ALIAS };
struct cfg_node {
    unsigned kind, plain;
    uint32_t line, column, related_line, related_column;
    const char *scalar, *tag, *anchor;
    size_t length, count;
    cfg_node_t *children, *tail, *next, *target;
    int building;
};
struct solaris_config {
    atomic_size_t references;
    cfg_arena_t arena;
    solaris_config_snapshot_t snapshot;
    solaris_config_node_t *nodes;
    solaris_config_group_t *groups;
    solaris_route_rule_t *rules;
    solaris_config_listener_t *listeners;
    uint64_t direct_target, global_target;
    const char *base_directory, *source_name;
};
struct solaris_diagnostics {
    atomic_size_t references;
    size_t count, capacity;
    solaris_config_diagnostic_t entries[];
};
typedef struct cfg_context {
    solaris_config_options_t options;
    solaris_budget_t *budget;
    cfg_arena_t ast;
    solaris_config_t *image;
    solaris_diagnostics_t *diagnostics;
    solaris_status_t status;
    uint32_t nodes, aliases, expanded;
    unsigned errors;
} cfg_context_t;
void *cfg_alloc(cfg_arena_t *arena, size_t size);
char *cfg_string(cfg_arena_t *arena, const char *text, size_t size);
void cfg_arena_clear(cfg_arena_t *arena);
void cfg_diagnostic(cfg_context_t *c, const cfg_node_t *node, const char *path, uint32_t severity, uint32_t stage,
                    solaris_status_t status, const char *message);
void cfg_fail(cfg_context_t *c, const cfg_node_t *node, const char *path, solaris_status_t status, const char *message);
solaris_budget_t *solaris_yaml_enter_budget(solaris_budget_t *budget);
cfg_node_t *cfg_yaml_parse(cfg_context_t *c, const void *bytes, size_t length);
cfg_node_t *cfg_yaml_expand(cfg_context_t *c, cfg_node_t *root);
void cfg_image_compile(cfg_context_t *c, cfg_node_t *root);
int cfg_scalar_numeric_kind(const cfg_node_t *node);
solaris_status_t solaris_config_compile_bytes_services(const void *bytes, size_t length,
                                                       const solaris_config_options_t *options,
                                                       const solaris_runtime_services_t *services,
                                                       solaris_config_t **out_config,
                                                       solaris_diagnostics_t **out_diagnostics, solaris_error_t *error);
#endif
