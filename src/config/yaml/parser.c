#include "config/image/internal.h"
#include "solaris_yaml_symbols.h"
#include <yaml.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>

typedef struct anchor {
    const char *name;
    cfg_node_t *node;
    struct anchor *next;
} anchor_t;
typedef struct parser {
    cfg_context_t *c;
    yaml_parser_t yaml;
    anchor_t *anchors;
} parser_t;
static int event_next(parser_t *p, yaml_event_t *event)
{
    if (yaml_parser_parse(&p->yaml, event))
        return 1;
    cfg_node_t location = {.line = (uint32_t)p->yaml.problem_mark.line + 1,
                           .column = (uint32_t)p->yaml.problem_mark.column + 1};
    cfg_diagnostic(p->c, &location, "$", SOLARIS_DIAGNOSTIC_ERROR, SOLARIS_CONFIG_PARSE,
                   p->yaml.error == YAML_MEMORY_ERROR ? SOLARIS_ENOMEM : SOLARIS_EINVAL,
                   p->yaml.error == YAML_MEMORY_ERROR ? "YAML parser memory budget exhausted" : "invalid YAML syntax");
    return 0;
}
static cfg_node_t *node_new(cfg_context_t *c, int expanded)
{
    uint32_t *count = expanded ? &c->expanded : &c->nodes;
    if (*count >= c->options.node_limit) {
        cfg_fail(c, NULL, "$", SOLARIS_EOVERFLOW, "YAML node limit exceeded");
        return NULL;
    }
    (*count)++;
    cfg_node_t *n = cfg_alloc(&c->ast, sizeof(*n));
    if (!n)
        cfg_fail(c, NULL, "$", SOLARIS_ENOMEM, "configuration memory budget exhausted");
    return n;
}
static void append(cfg_node_t *parent, cfg_node_t *child)
{
    if (parent->tail)
        parent->tail->next = child;
    else
        parent->children = child;
    parent->tail = child;
    parent->count++;
}
static const char *copy(parser_t *p, const yaml_char_t *text)
{
    if (!text)
        return NULL;
    size_t size = strlen((const char *)text);
    if (size > p->c->options.string_limit_bytes) {
        cfg_fail(p->c, NULL, "$", SOLARIS_EOVERFLOW, "YAML string limit exceeded");
        return NULL;
    }
    char *result = cfg_string(&p->c->ast, (const char *)text, size);
    if (!result)
        cfg_fail(p->c, NULL, "$", SOLARIS_ENOMEM, "configuration memory budget exhausted");
    return result;
}
static int tagged_scalar_valid(const cfg_node_t *n)
{
    if (!strcmp(n->tag, YAML_STR_TAG))
        return 1;
    if (!strcmp(n->tag, "tag:yaml.org,2002:merge"))
        return !strcmp(n->scalar, "<<");
    if (!strcmp(n->tag, YAML_NULL_TAG))
        return !*n->scalar || !strcmp(n->scalar, "~") || !strcmp(n->scalar, "null") || !strcmp(n->scalar, "Null") ||
               !strcmp(n->scalar, "NULL");
    if (!strcmp(n->tag, YAML_BOOL_TAG))
        return !strcmp(n->scalar, "true") || !strcmp(n->scalar, "True") || !strcmp(n->scalar, "TRUE") ||
               !strcmp(n->scalar, "false") || !strcmp(n->scalar, "False") || !strcmp(n->scalar, "FALSE");
    if (strcmp(n->tag, YAML_INT_TAG) && strcmp(n->tag, YAML_FLOAT_TAG))
        return 0;
    if (!n->length || n->length >= 128)
        return 0;
    cfg_node_t implicit = *n;
    implicit.tag = NULL;
    implicit.plain = 1;
    int kind = cfg_scalar_numeric_kind(&implicit);
    return !strcmp(n->tag, YAML_INT_TAG) ? kind == 1 : kind == 1 || kind == 2;
}
static void child_path(char out[256], const char *path, const cfg_node_t *parent)
{
    if (parent->kind == CFG_SEQUENCE)
        (void)snprintf(out, 256, "%s[%zu]", path, parent->count);
    else if (parent->kind == CFG_MAP && parent->count % 2 && parent->tail && parent->tail->scalar)
        (void)snprintf(out, 256, "%s.%s", path, parent->tail->scalar);
    else
        (void)snprintf(out, 256, "%s", path);
}
static cfg_node_t *parse_node(parser_t *p, yaml_event_t *event, unsigned depth, const char *path)
{
    cfg_context_t *c = p->c;
    if (depth > c->options.depth_limit) {
        cfg_fail(c, NULL, path, SOLARIS_EOVERFLOW, "YAML depth limit exceeded");
        yaml_event_delete(event);
        return NULL;
    }
    cfg_node_t *n = node_new(c, 0);
    if (!n) {
        yaml_event_delete(event);
        return NULL;
    }
    n->line = (uint32_t)event->start_mark.line + 1;
    n->column = (uint32_t)event->start_mark.column + 1;
    if (event->type == YAML_ALIAS_EVENT) {
        n->kind = CFG_ALIAS;
        for (anchor_t *a = p->anchors; a; a = a->next)
            if (!strcmp(a->name, (const char *)event->data.alias.anchor)) {
                n->target = a->node;
                break;
            }
        if (!n->target || n->target->building)
            cfg_fail(c, n, path, SOLARIS_EINVAL, "undefined or cyclic YAML alias");
        yaml_event_delete(event);
        return c->errors ? NULL : n;
    }
    const yaml_char_t *anchor = NULL, *tag = NULL;
    yaml_event_type_t end = YAML_NO_EVENT;
    if (event->type == YAML_SCALAR_EVENT) {
        n->kind = CFG_SCALAR;
        n->plain = event->data.scalar.style == YAML_PLAIN_SCALAR_STYLE;
        n->length = event->data.scalar.length;
        if (n->length > c->options.string_limit_bytes || memchr(event->data.scalar.value, 0, n->length))
            cfg_fail(c, n, path, SOLARIS_EINVAL, "invalid or oversized YAML scalar");
        else
            n->scalar = copy(p, event->data.scalar.value);
        anchor = event->data.scalar.anchor;
        tag = event->data.scalar.tag;
    } else if (event->type == YAML_MAPPING_START_EVENT) {
        n->kind = CFG_MAP;
        anchor = event->data.mapping_start.anchor;
        tag = event->data.mapping_start.tag;
        end = YAML_MAPPING_END_EVENT;
    } else if (event->type == YAML_SEQUENCE_START_EVENT) {
        n->kind = CFG_SEQUENCE;
        anchor = event->data.sequence_start.anchor;
        tag = event->data.sequence_start.tag;
        end = YAML_SEQUENCE_END_EVENT;
    } else
        cfg_fail(c, n, path, SOLARIS_EINVAL, "expected a YAML scalar, sequence or map");
    n->tag = copy(p, tag);
    n->anchor = copy(p, anchor);
    if (n->tag) {
        const char *tags[] = {YAML_STR_TAG,   YAML_NULL_TAG, YAML_BOOL_TAG, YAML_INT_TAG,
                              YAML_FLOAT_TAG, YAML_SEQ_TAG,  YAML_MAP_TAG,  "tag:yaml.org,2002:merge"};
        size_t i = 0;
        while (i < sizeof(tags) / sizeof(*tags) && strcmp(n->tag, tags[i]))
            i++;
        if (i == sizeof(tags) / sizeof(*tags))
            cfg_fail(c, n, path, SOLARIS_ENOTSUP, "unsupported YAML tag");
    }
    if (n->tag && !c->errors) {
        int compatible = n->kind == CFG_MAP        ? !strcmp(n->tag, YAML_MAP_TAG)
                         : n->kind == CFG_SEQUENCE ? !strcmp(n->tag, YAML_SEQ_TAG)
                                                   : tagged_scalar_valid(n);
        if (!compatible)
            cfg_fail(c, n, path, SOLARIS_EINVAL, "explicit YAML tag does not match the value or node kind");
    }
    n->building = end != YAML_NO_EVENT;
    if (n->anchor) {
        for (anchor_t *a = p->anchors; a; a = a->next)
            if (!strcmp(a->name, n->anchor)) {
                n->related_line = a->node->line;
                n->related_column = a->node->column;
                cfg_fail(c, n, path, SOLARIS_EINVAL, "duplicate YAML anchor");
                break;
            }
        anchor_t *a = cfg_alloc(&c->ast, sizeof(*a));
        if (!a)
            cfg_fail(c, n, path, SOLARIS_ENOMEM, "configuration memory budget exhausted");
        else {
            a->name = n->anchor;
            a->node = n;
            a->next = p->anchors;
            p->anchors = a;
        }
    }
    yaml_event_delete(event);
    if (c->errors)
        return NULL;
    if (end != YAML_NO_EVENT)
        for (;;) {
            yaml_event_t next;
            if (!event_next(p, &next))
                return NULL;
            if (next.type == end) {
                yaml_event_delete(&next);
                break;
            }
            char field_path[256];
            child_path(field_path, path, n);
            cfg_node_t *child = parse_node(p, &next, depth + 1, field_path);
            if (!child)
                return NULL;
            append(n, child);
        }
    n->building = 0;
    return n;
}
cfg_node_t *cfg_yaml_parse(cfg_context_t *c, const void *bytes, size_t length)
{
    parser_t p = {.c = c};
    cfg_node_t *root = NULL;
    solaris_budget_t *previous = solaris_yaml_enter_budget(c->budget);
    if (!yaml_parser_initialize(&p.yaml)) {
        cfg_fail(c, NULL, "$", SOLARIS_ENOMEM, "YAML parser memory budget exhausted");
        goto done;
    }
    yaml_parser_set_input_string(&p.yaml, bytes, length);
    yaml_event_t event;
    if (!event_next(&p, &event))
        goto cleanup;
    int stream = event.type == YAML_STREAM_START_EVENT;
    yaml_event_delete(&event);
    if (!stream || !event_next(&p, &event))
        goto cleanup;
    int document = event.type == YAML_DOCUMENT_START_EVENT;
    yaml_event_delete(&event);
    if (!document) {
        cfg_fail(c, NULL, "$", SOLARIS_EINVAL, "expected one YAML document");
        goto cleanup;
    }
    if (!event_next(&p, &event))
        goto cleanup;
    root = parse_node(&p, &event, 1, "$");
    if (!root)
        goto cleanup;
    if (!event_next(&p, &event)) {
        root = NULL;
        goto cleanup;
    }
    document = event.type == YAML_DOCUMENT_END_EVENT;
    yaml_event_delete(&event);
    if (!document || !event_next(&p, &event)) {
        root = NULL;
        goto cleanup;
    }
    stream = event.type == YAML_STREAM_END_EVENT;
    yaml_event_delete(&event);
    if (!stream) {
        cfg_fail(c, root, "$", SOLARIS_ENOTSUP, "multiple YAML documents are not supported");
        root = NULL;
    }
cleanup:
    yaml_parser_delete(&p.yaml);
done:
    (void)solaris_yaml_enter_budget(previous);
    return root;
}
static int same_key(const cfg_node_t *a, const cfg_node_t *b)
{
    return a && b && a->kind == CFG_SCALAR && b->kind == CFG_SCALAR && a->scalar && b->scalar &&
           !strcmp(a->scalar, b->scalar);
}
static cfg_node_t *find_key(cfg_node_t *map, const cfg_node_t *key)
{
    for (cfg_node_t *k = map->children; k && k->next; k = k->next->next)
        if (same_key(k, key))
            return k;
    return NULL;
}
static int scalar_key(const cfg_node_t *n)
{
    if (n->kind != CFG_SCALAR || !n->scalar)
        return 0;
    if (n->tag)
        return !strcmp(n->tag, YAML_STR_TAG) || !strcmp(n->tag, "tag:yaml.org,2002:merge");
    if (!n->plain)
        return 1;
    const char *s = n->scalar;
    if (!*s || !strcmp(s, "~") || !strcmp(s, "null") || !strcmp(s, "Null") || !strcmp(s, "NULL") ||
        !strcmp(s, "true") || !strcmp(s, "True") || !strcmp(s, "TRUE") || !strcmp(s, "false") || !strcmp(s, "False") ||
        !strcmp(s, "FALSE"))
        return 0;
    return cfg_scalar_numeric_kind(n) == 0;
}
static cfg_node_t *expand(cfg_context_t *c, cfg_node_t *raw, unsigned depth, const cfg_node_t *use, const char *path)
{
    if (depth > c->options.depth_limit) {
        cfg_fail(c, raw, path, SOLARIS_EOVERFLOW, "expanded YAML depth limit exceeded");
        return NULL;
    }
    if (raw->kind == CFG_ALIAS) {
        if (!raw->target)
            return NULL;
        return expand(c, raw->target, depth, use ? use : raw, path);
    }
    if (use && ++c->aliases > c->options.alias_limit) {
        cfg_fail(c, use, path, SOLARIS_EOVERFLOW, "YAML alias expansion limit exceeded");
        return NULL;
    }
    cfg_node_t *n = node_new(c, 1);
    if (!n)
        return NULL;
    *n = *raw;
    n->next = n->children = n->tail = NULL;
    n->count = 0;
    if (use) {
        n->line = use->line;
        n->column = use->column;
        n->related_line = raw->line;
        n->related_column = raw->column;
    }
    for (cfg_node_t *child = raw->children; child; child = child->next) {
        char field_path[256];
        child_path(field_path, path, n);
        cfg_node_t *copy = expand(c, child, depth + 1, use, field_path);
        if (!copy)
            return NULL;
        append(n, copy);
    }
    if (n->kind != CFG_MAP)
        return n;
    cfg_node_t *merge = NULL;
    for (cfg_node_t *key = n->children; key; key = key->next->next) {
        if (!scalar_key(key) || !key->next) {
            cfg_fail(c, key, path, SOLARIS_EINVAL, "mapping keys must be scalar strings");
            return NULL;
        }
        for (cfg_node_t *before = n->children; before != key; before = before->next->next)
            if (same_key(key, before)) {
                key->related_line = before->line;
                key->related_column = before->column;
                char field_path[256];
                (void)snprintf(field_path, sizeof(field_path), "%s.%s", path, key->scalar);
                cfg_fail(c, key, field_path, SOLARIS_EINVAL, "duplicate mapping key");
                return NULL;
            }
        if (!strcmp(key->scalar, "<<") &&
            ((key->plain && !key->tag) || (key->tag && !strcmp(key->tag, "tag:yaml.org,2002:merge"))))
            merge = key->next;
    }
    if (!merge)
        return n;
    cfg_node_t *result = node_new(c, 1);
    if (!result)
        return NULL;
    *result = *n;
    result->children = result->tail = NULL;
    result->count = 0;
    for (cfg_node_t *key = n->children; key;) {
        cfg_node_t *value = key->next, *next = value->next;
        if (value != merge) {
            key->next = NULL;
            value->next = NULL;
            append(result, key);
            append(result, value);
        }
        key = next;
    }
    cfg_node_t *maps = merge->kind == CFG_SEQUENCE ? merge->children : merge;
    for (cfg_node_t *map = maps; map; map = merge->kind == CFG_SEQUENCE ? map->next : NULL) {
        if (map->kind != CFG_MAP) {
            cfg_fail(c, merge, path, SOLARIS_EINVAL, "YAML merge requires a map or sequence of maps");
            return NULL;
        }
        for (cfg_node_t *key = map->children; key; key = key->next->next) {
            if (find_key(result, key))
                continue;
            cfg_node_t *k = node_new(c, 1), *v = node_new(c, 1);
            if (!k || !v)
                return NULL;
            *k = *key;
            *v = *key->next;
            k->next = v->next = NULL;
            append(result, k);
            append(result, v);
        }
    }
    return result;
}
cfg_node_t *cfg_yaml_expand(cfg_context_t *c, cfg_node_t *root)
{
    return expand(c, root, 1, NULL, "$");
}
