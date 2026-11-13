#include "config/image/internal.h"
#include "contracts/io/address.h"
#include "solaris_builtin_modules.h"
#if SOLARIS_HAS_SHADOWSOCKS
#include "adapters/outbound/shadowsocks/internal.h"
#endif
#if SOLARIS_HAS_VLESS
#include "adapters/outbound/vless/encryption/config.h"
#endif
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

static cfg_node_t *get(cfg_node_t *map, const char *name) {
    if (!map || map->kind != CFG_MAP)
        return NULL;
    for (cfg_node_t *key = map->children; key && key->next; key = key->next->next)
        if (!strcmp(key->scalar, name))
            return key->next;
    return NULL;
}
static int null_value(const cfg_node_t *n) { return n == NULL; }
static void path_field(char out[256], const char *base, const char *field) {
    (void)snprintf(out, 256, "%s%s%s", base, *base ? "." : "", field);
}
static int boolean_value(const cfg_node_t *n, int *out) {
    if (!n || n->kind != CFG_SCALAR || !n->scalar)
        return 0;
    if (!strcmp(n->scalar, "true")) {
        *out = 1;
        return 1;
    }
    if (!strcmp(n->scalar, "false")) {
        *out = 0;
        return 1;
    }
    return 0;
}
static int integer_value(const cfg_node_t *n, int64_t *out) {
    if (!n || n->kind != CFG_SCALAR || !n->scalar || !n->length)
        return 0;
    uint64_t value = 0;
    for (size_t i = 0; i < n->length; ++i) {
        unsigned ch = (unsigned char)n->scalar[i];
        if (ch < '0' || ch > '9' || value > (INT64_MAX - (ch - '0')) / 10u)
            return 0;
        value = value * 10u + ch - '0';
    }
    *out = (int64_t)value;
    return 1;
}
static const char *string_value(cfg_context_t *c, cfg_node_t *n, const char *path, size_t limit, int allow_empty) {
    if (!n || n->kind != CFG_SCALAR || !n->scalar || n->length > limit || (!allow_empty && !n->length)) {
        cfg_fail(c, n, path, SOLARIS_EINVAL, "expected a bounded string");
        return NULL;
    }
    char *copy = cfg_string(&c->image->arena, n->scalar, n->length);
    if (!copy)
        cfg_fail(c, n, path, SOLARIS_ENOMEM, "configuration memory budget exhausted");
    return copy;
}
static const char *text_field(cfg_context_t *c, cfg_node_t *map, const char *key, const char *path, int required,
                              size_t limit, int empty) {
    cfg_node_t *n = get(map, key);
    if (!n || null_value(n)) {
        if (required) {
            char full[256];
            path_field(full, path, key);
            cfg_fail(c, n ? n : map, full, SOLARIS_EINVAL, "required field is missing");
        }
        return NULL;
    }
    char full[256];
    path_field(full, path, key);
    return string_value(c, n, full, limit, empty);
}
static int bool_field(cfg_context_t *c, cfg_node_t *map, const char *key, const char *path, int fallback) {
    cfg_node_t *n = get(map, key);
    if (!n || null_value(n))
        return fallback;
    int result;
    if (boolean_value(n, &result))
        return result;
    char full[256];
    path_field(full, path, key);
    cfg_fail(c, n, full, SOLARIS_EINVAL, "expected a boolean");
    return fallback;
}
static uint64_t uint_field(cfg_context_t *c, cfg_node_t *map, const char *key, const char *path, uint64_t fallback,
                           uint64_t low, uint64_t high, int required) {
    cfg_node_t *n = get(map, key);
    char full[256];
    path_field(full, path, key);
    if (!n || null_value(n)) {
        if (required)
            cfg_fail(c, n ? n : map, full, SOLARIS_EINVAL, "required integer is missing");
        return fallback;
    }
    int64_t value;
    if (!integer_value(n, &value) || (uint64_t)value < low || (uint64_t)value > high) {
        cfg_fail(c, n, full, SOLARIS_EINVAL, "integer is outside the supported range");
        return fallback;
    }
    return (uint64_t)value;
}
static int name_in(const char *name, const char *const *names, size_t count) {
    for (size_t i = 0; i < count; ++i)
        if (!strcmp(name, names[i]))
            return 1;
    return 0;
}
static void fields_check(cfg_context_t *c, cfg_node_t *map, const char *path, const char *const *names, size_t count) {
    if (!map || map->kind != CFG_MAP) {
        cfg_fail(c, map, path, SOLARIS_EINVAL, "expected a map");
        return;
    }
    for (cfg_node_t *key = map->children; key && key->next; key = key->next->next)
        if (!name_in(key->scalar, names, count)) {
            char full[256];
            path_field(full, path, "unknown-field");
            cfg_fail(c, key, full, SOLARIS_ENOTSUP, "unknown or unsupported field");
        }
}
static uint64_t identity(const char *text) {
    uint64_t value = UINT64_C(14695981039346656037);
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p) {
        value ^= *p;
        value *= UINT64_C(1099511628211);
    }
    return value ? value : 1;
}
static int reserved(const char *name) {
    const char *names[] = {"DIRECT", "REJECT", "GLOBAL"};
    return name_in(name, names, sizeof(names) / sizeof(*names));
}
static int register_name(cfg_context_t *c, cfg_node_t *n, const char *path, const char *name, uint64_t id) {
    solaris_config_t *image = c->image;
    for (size_t i = 0; i < image->snapshot.node_count; ++i)
        if (image->nodes[i].id == id) {
            cfg_fail(c, n, path, SOLARIS_EINVAL, "duplicate name or stable identity collision");
            return 0;
        }
    for (size_t i = 0; i < image->snapshot.group_count; ++i)
        if (image->groups[i].id == id) {
            cfg_fail(c, n, path, SOLARIS_EINVAL, "duplicate name or stable identity collision");
            return 0;
        }
    if (reserved(name)) {
        cfg_fail(c, n, path, SOLARIS_EINVAL, "reserved node or group name");
        return 0;
    }
    return 1;
}
static uint64_t target(cfg_context_t *c, const char *name, int groups) {
    for (size_t i = 0; i < c->image->snapshot.node_count; ++i)
        if (!strcmp(c->image->nodes[i].name, name))
            return c->image->nodes[i].id;
    if (groups)
        for (size_t i = 0; i < c->image->snapshot.group_count; ++i)
            if (!strcmp(c->image->groups[i].name, name))
                return c->image->groups[i].id;
    return 0;
}
static int available(const char *type) {
    if (!strcmp(type, "direct"))
        return SOLARIS_HAS_DIRECT;
    if (!strcmp(type, "block"))
        return SOLARIS_HAS_BLOCK;
    if (!strcmp(type, "socks5"))
        return SOLARIS_HAS_SOCKS5;
    if (!strcmp(type, "shadowsocks"))
        return SOLARIS_HAS_SHADOWSOCKS;
    if (!strcmp(type, "vless"))
        return SOLARIS_HAS_VLESS;
    if (!strcmp(type, "anytls"))
        return SOLARIS_HAS_ANYTLS;
    return 0;
}
static solaris_config_view_t *module_view(cfg_context_t *c, cfg_node_t *map, solaris_config_field_t **fields) {
    solaris_config_view_t *view = cfg_alloc(&c->image->arena, sizeof(*view));
    *fields = cfg_alloc(&c->image->arena, 24 * sizeof(**fields));
    if (!view || !*fields) {
        cfg_fail(c, map, "$", SOLARIS_ENOMEM, "configuration memory budget exhausted");
        return NULL;
    }
    view->kind = SOLARIS_CONFIG_MAP;
    view->line = map ? map->line : 0;
    view->column = map ? map->column : 0;
    view->value.map.fields = *fields;
    return view;
}
static void add_string(solaris_config_view_t *view, solaris_config_field_t *fields, const char *key, const char *value,
                       cfg_node_t *source) {
    if (!value)
        return;
    solaris_config_field_t *f = &fields[view->value.map.count++];
    f->name = key;
    f->value = (solaris_config_view_t){.kind = SOLARIS_CONFIG_STRING,
                                       .line = source ? source->line : 0,
                                       .column = source ? source->column : 0,
                                       .value.string = {value, strlen(value)}};
}
static void add_integer(solaris_config_view_t *view, solaris_config_field_t *fields, const char *key, uint64_t value,
                        cfg_node_t *source, int boolean) {
    solaris_config_field_t *f = &fields[view->value.map.count++];
    f->name = key;
    f->value = (solaris_config_view_t){.kind = boolean ? SOLARIS_CONFIG_BOOL : SOLARIS_CONFIG_INTEGER,
                                       .line = source ? source->line : 0,
                                       .column = source ? source->column : 0};
    if (boolean)
        f->value.value.boolean = value != 0;
    else
        f->value.value.integer = (int64_t)value;
}
static void node_compile(cfg_context_t *c, cfg_node_t *map, size_t index) {
    char path[256];
    (void)snprintf(path, sizeof(path), "Proxy[%zu]", index);
    const char *name = text_field(c, map, "name", path, 1, 127, 0);
    const char *type = text_field(c, map, "type", path, 1, 31, 0);
    if (!name || !type)
        return;
    const char *public_types[] = {"direct", "reject", "socks5", "ss", "vless", "anytls"};
    if (!name_in(type, public_types, sizeof(public_types) / sizeof(*public_types))) {
        cfg_fail(c, get(map, "type"), path, SOLARIS_ENOTSUP, "unsupported public protocol type");
        return;
    }
    if (!strcmp(type, "ss"))
        type = "shadowsocks";
    else if (!strcmp(type, "reject"))
        type = "block";
    if (!available(type)) {
        cfg_fail(c, get(map, "type"), path, SOLARIS_ENOTSUP, "protocol is unsupported or disabled in this build");
        return;
    }
    uint64_t id = identity(name);
    if (!register_name(c, get(map, "name"), path, name, id))
        return;
    const char *common[] = {"name", "type", "udp-relay", "server", "port", "network"};
    const char *specific_ss[] = {"encrypt-method", "password", "udp-over-tcp", "udp-over-tcp-version"};
    const char *specific_vless[] = {"uuid", "flow", "encryption", "tls", "tls-server-name", "packet-encoding"};
    const char *specific_anytls[] = {"password", "tls-server-name", "idle-session-timeout-ms",
                                     "idle-session-check-interval-ms", "min-idle-session"};
    const char *specific_socks[] = {"username", "password"};
    const char *const *specific = NULL;
    size_t specific_count = 0;
    if (!strcmp(type, "shadowsocks")) {
        specific = specific_ss;
        specific_count = sizeof(specific_ss) / sizeof(*specific_ss);
    } else if (!strcmp(type, "vless")) {
        specific = specific_vless;
        specific_count = sizeof(specific_vless) / sizeof(*specific_vless);
    } else if (!strcmp(type, "anytls")) {
        specific = specific_anytls;
        specific_count = sizeof(specific_anytls) / sizeof(*specific_anytls);
    } else if (!strcmp(type, "socks5")) {
        specific = specific_socks;
        specific_count = sizeof(specific_socks) / sizeof(*specific_socks);
    }
    if (!map || map->kind != CFG_MAP) {
        cfg_fail(c, map, path, SOLARIS_EINVAL, "expected a proxy map");
        return;
    }
    for (cfg_node_t *key = map->children; key; key = key->next->next)
        if (!name_in(key->scalar, common, sizeof(common) / sizeof(*common)) &&
            !name_in(key->scalar, specific, specific_count)) {
            char full[256];
            path_field(full, path, "unknown-field");
            cfg_fail(c, key, full, SOLARIS_ENOTSUP, "unknown or unsupported protocol field");
        }
    const char *network = text_field(c, map, "network", path, 0, 16, 1);
    if (network && *network && strcmp(network, "tcp"))
        cfg_fail(c, get(map, "network"), path, SOLARIS_ENOTSUP, "only TCP carrier is implemented");
    solaris_config_node_t *out = &c->image->nodes[c->image->snapshot.node_count++];
    *out = (solaris_config_node_t){
        .id = id,
        .name = name,
        .type = type,
        .udp_enabled = bool_field(c, map, "udp-relay", path, !strcmp(type, "direct") || !strcmp(type, "block")),
        .line = map->line,
        .column = map->column};
    solaris_config_field_t *fields;
    solaris_config_view_t *view = module_view(c, map, &fields);
    out->fields = view;
    if (!view)
        return;
    if (!strcmp(type, "direct") || !strcmp(type, "block")) {
        for (cfg_node_t *key = map->children; key; key = key->next->next)
            if (strcmp(key->scalar, "name") && strcmp(key->scalar, "type") && strcmp(key->scalar, "udp-relay"))
                cfg_fail(c, key, path, SOLARIS_ENOTSUP, "field is unsupported for this protocol");
        return;
    }
    const char *server = text_field(c, map, "server", path, 1, 255, 0);
    uint64_t port = uint_field(c, map, "port", path, 0, 1, 65535, 1);
    solaris_address_t address;
    if (server && solaris_address_parse(server, (uint16_t)port, &address) != SOLARIS_OK)
        cfg_fail(c, get(map, "server"), path, SOLARIS_EINVAL, "invalid server address");
    add_string(view, fields, "server", server, get(map, "server"));
    add_integer(view, fields, "port", port, get(map, "port"), 0);
    if (!strcmp(type, "socks5")) {
        const char *user = text_field(c, map, "username", path, 0, 255, 0),
                   *password = text_field(c, map, "password", path, 0, 255, 0);
        if (!!user != !!password)
            cfg_fail(c, map, path, SOLARIS_EINVAL, "username and password must both be provided");
        add_string(view, fields, "username", user, get(map, "username"));
        add_string(view, fields, "password", password, get(map, "password"));
    } else if (!strcmp(type, "shadowsocks")) {
        const char *cipher = text_field(c, map, "encrypt-method", path, 1, 63, 0),
                   *password = text_field(c, map, "password", path, 1, 1024, 0);
        int uot = bool_field(c, map, "udp-over-tcp", path, 0);
        uint64_t version = uint_field(c, map, "udp-over-tcp-version", path, 0, 0, 2, 0);
        if (uot && version != 2)
            cfg_fail(c, map, path, SOLARIS_ENOTSUP,
                     "UoT requires explicit udp-over-tcp-version=2; legacy is unsupported");
#if SOLARIS_HAS_SHADOWSOCKS
        solaris_ss_key_t key;
        if (cipher && password && solaris_ss_key_parse(cipher, password, &key) != SOLARIS_OK)
            cfg_fail(c, map, path, SOLARIS_EINVAL, "invalid Shadowsocks cipher or key material");
        memset(&key, 0, sizeof(key));
#endif
        add_string(view, fields, "cipher", cipher, get(map, "encrypt-method"));
        add_string(view, fields, "password", password, get(map, "password"));
        add_integer(view, fields, "udp-over-tcp", uot, get(map, "udp-over-tcp"), 1);
    } else if (!strcmp(type, "vless")) {
        const char *uuid = text_field(c, map, "uuid", path, 1, 36, 0),
                   *flow = text_field(c, map, "flow", path, 0, 31, 1);
        const char *encryption = text_field(c, map, "encryption", path, 0, 16383, 0),
                   *sni = text_field(c, map, "tls-server-name", path, 0, 253, 0);
        const char *packet = text_field(c, map, "packet-encoding", path, 0, 32, 0);
        if (packet && strcmp(packet, "xudp"))
            cfg_fail(c, get(map, "packet-encoding"), path, SOLARIS_ENOTSUP, "only XUDP packet encoding is implemented");
        if (uuid) {
            size_t len = strlen(uuid), digits = 0;
            int valid = len == 32 || len == 36;
            for (size_t i = 0; i < len; ++i) {
                if (len == 36 && (i == 8 || i == 13 || i == 18 || i == 23))
                    valid &= uuid[i] == '-';
                else {
                    valid &= isxdigit((unsigned char)uuid[i]) != 0;
                    digits++;
                }
            }
            if (!valid || digits != 32)
                cfg_fail(c, get(map, "uuid"), path, SOLARIS_EINVAL, "invalid UUID");
        }
        int tls = bool_field(c, map, "tls", path, 0), encrypted = 0;
        if (encryption && !strcmp(encryption, "none"))
            encryption = NULL;
#if SOLARIS_HAS_VLESS
        if (encryption) {
            solaris_vless_encryption_config_t parsed;
            if (solaris_vless_encryption_config_parse(encryption, &parsed) != SOLARIS_OK)
                cfg_fail(c, get(map, "encryption"), path, SOLARIS_EINVAL, "invalid VLESS encryption configuration");
            else
                encrypted = parsed.key_count != 0;
            memset(&parsed, 0, sizeof(parsed));
        }
#endif
        if (flow && *flow) {
            if (strcmp(flow, "xtls-rprx-vision") && strcmp(flow, "xtls-rprx-vision-udp443"))
                cfg_fail(c, get(map, "flow"), path, SOLARIS_ENOTSUP, "unsupported VLESS flow");
            if (!tls && !encrypted)
                cfg_fail(c, get(map, "flow"), path, SOLARIS_EINVAL, "Vision requires TLS or VLESS encryption");
        }
        if (sni && !tls)
            cfg_fail(c, get(map, "tls-server-name"), path, SOLARIS_EINVAL, "servername requires TLS");
        add_string(view, fields, "uuid", uuid, get(map, "uuid"));
        if (flow && *flow)
            add_string(view, fields, "flow", flow, get(map, "flow"));
        add_string(view, fields, "encryption", encryption, get(map, "encryption"));
        add_string(view, fields, "servername", sni, get(map, "tls-server-name"));
        add_integer(view, fields, "tls", tls, get(map, "tls"), 1);
    } else if (!strcmp(type, "anytls")) {
        const char *password = text_field(c, map, "password", path, 1, 1024, 0),
                   *sni = text_field(c, map, "tls-server-name", path, 0, 253, 0);
        uint64_t timeout = uint_field(c, map, "idle-session-timeout-ms", path, 30000, 1, 3600000, 0),
                 interval = uint_field(c, map, "idle-session-check-interval-ms", path, 30000, 1, 3600000, 0);
        uint64_t minimum = uint_field(c, map, "min-idle-session", path, 0, 0, 64, 0);
        add_string(view, fields, "password", password, get(map, "password"));
        add_string(view, fields, "servername", sni, get(map, "tls-server-name"));
        add_integer(view, fields, "tls", 1, NULL, 1);
        add_integer(view, fields, "idle-session-timeout-ms", timeout, get(map, "idle-session-timeout-ms"), 0);
        add_integer(view, fields, "idle-session-check-interval-ms", interval,
                    get(map, "idle-session-check-interval-ms"), 0);
        add_integer(view, fields, "min-idle-session", minimum, get(map, "min-idle-session"), 0);
    }
}
static void groups_compile(cfg_context_t *c, cfg_node_t *groups) {
    if (groups && !null_value(groups) && groups->kind != CFG_SEQUENCE) {
        cfg_fail(c, groups, "Proxy Group", SOLARIS_EINVAL, "expected a sequence");
        return;
    }
    size_t count = groups && groups->kind == CFG_SEQUENCE ? groups->count : 0;
    c->image->groups = cfg_alloc(&c->image->arena, (count + 1) * sizeof(*c->image->groups));
    if (!c->image->groups) {
        cfg_fail(c, groups, "Proxy Group", SOLARIS_ENOMEM, "configuration memory budget exhausted");
        return;
    }
    size_t index = 0;
    for (cfg_node_t *map = groups && groups->kind == CFG_SEQUENCE ? groups->children : NULL; map;
         map = map->next, ++index) {
        char path[256];
        (void)snprintf(path, sizeof(path), "Proxy Group[%zu]", index);
        const char *allowed[] = {"name", "type", "members"};
        fields_check(c, map, path, allowed, 3);
        const char *name = text_field(c, map, "name", path, 1, 127, 0),
                   *type = text_field(c, map, "type", path, 1, 31, 0);
        if (!name || !type)
            continue;
        if (strcmp(type, "select")) {
            cfg_fail(c, get(map, "type"), path, SOLARIS_ENOTSUP, "only flat select groups are implemented");
            continue;
        }
        uint64_t id = identity(name);
        if (!register_name(c, get(map, "name"), path, name, id))
            continue;
        cfg_node_t *members = get(map, "members");
        if (!members || members->kind != CFG_SEQUENCE || !members->count) {
            cfg_fail(c, members ? members : map, path, SOLARIS_EINVAL, "select requires a nonempty node sequence");
            continue;
        }
        uint64_t *ids = cfg_alloc(&c->image->arena, members->count * sizeof(*ids));
        if (!ids) {
            cfg_fail(c, members, path, SOLARIS_ENOMEM, "configuration memory budget exhausted");
            return;
        }
        size_t mi = 0;
        for (cfg_node_t *member = members->children; member; member = member->next, ++mi) {
            char full[256];
            (void)snprintf(full, sizeof(full), "Proxy Group[%zu].members[%zu]", index, mi);
            const char *ref = string_value(c, member, full, 127, 0);
            ids[mi] = ref ? target(c, ref, 0) : 0;
            if (ref && !ids[mi])
                cfg_fail(c, member, full, SOLARIS_EINVAL, "unknown node or unsupported nested group reference");
            for (size_t j = 0; j < mi; ++j)
                if (ids[mi] && ids[j] == ids[mi])
                    cfg_fail(c, member, full, SOLARIS_EINVAL, "duplicate group member");
        }
        solaris_config_group_t *g = &c->image->groups[c->image->snapshot.group_count++];
        *g = (solaris_config_group_t){
            .id = id, .name = name, .members = ids, .member_count = members->count, .selected_id = ids[0]};
    }
    uint64_t *all = cfg_alloc(&c->image->arena, c->image->snapshot.node_count * sizeof(*all));
    if (!all) {
        cfg_fail(c, NULL, "GLOBAL", SOLARIS_ENOMEM, "configuration memory budget exhausted");
        return;
    }
    for (size_t i = 0; i < c->image->snapshot.node_count; ++i)
        all[i] = c->image->nodes[i].id;
    uint64_t id = identity("GLOBAL");
    for (size_t i = 0; i < c->image->snapshot.node_count; ++i)
        if (c->image->nodes[i].id == id)
            cfg_fail(c, NULL, "GLOBAL", SOLARIS_EINVAL, "stable identity collision");
    for (size_t i = 0; i < c->image->snapshot.group_count; ++i)
        if (c->image->groups[i].id == id)
            cfg_fail(c, NULL, "GLOBAL", SOLARIS_EINVAL, "stable identity collision");
    c->image->groups[c->image->snapshot.group_count++] =
        (solaris_config_group_t){.id = id,
                                 .name = "GLOBAL",
                                 .members = all,
                                 .member_count = c->image->snapshot.node_count,
                                 .selected_id = all[0]};
    c->image->global_target = id;
}
static void rules_compile(cfg_context_t *c, cfg_node_t *rules, cfg_node_t *general) {
    if (!rules || !rules->count) {
        if (c->image->snapshot.mode == SOLARIS_MODE_RULE)
            cfg_fail(c, rules ? rules : general, "Rule.FINAL", SOLARIS_EINVAL, "rule mode requires a final FINAL rule");
        return;
    }
    c->image->rules = cfg_alloc(&c->image->arena, rules->count * sizeof(*c->image->rules));
    if (!c->image->rules) {
        cfg_fail(c, rules, "Rule", SOLARIS_ENOMEM, "configuration memory budget exhausted");
        return;
    }
    size_t index = 0;
    int final = 0;
    for (cfg_node_t *item = rules->children; item; item = item->next, ++index) {
        char path[256];
        (void)snprintf(path, sizeof(path), "Rule[%zu]", index);
        const char *parts[4] = {0};
        size_t n = 0;
        for (cfg_node_t *part = item->children; part; part = part->next) {
            if (n < 4)
                parts[n] = part->scalar;
            ++n;
        }
        int match = n && !strcmp(parts[0], "FINAL"), no_resolve = 0;
        size_t expected = match ? 2 : 3;
        if (!match && n == expected + 1 && !strcmp(parts[n - 1], "no-resolve"))
            no_resolve = 1;
        else if (n != expected) {
            cfg_fail(c, item, path, SOLARIS_EINVAL, "invalid rule field count or modifier");
            continue;
        }
        if (match) {
            if (final || item->next)
                cfg_fail(c, item, path, SOLARIS_EINVAL, "FINAL must occur once at the end");
            final = 1;
        } else if (!strcmp(parts[0], "MATCH")) {
            cfg_fail(c, item, path, SOLARIS_ENOTSUP, "use FINAL for the final action");
            continue;
        }
        uint64_t id = target(c, parts[match ? 1 : 2], 1);
        if (!id) {
            cfg_fail(c, item, path, SOLARIS_EINVAL, "unknown rule target");
            continue;
        }
        solaris_route_rule_t compiled;
        solaris_status_t rc = solaris_route_rule_compile(match ? "FINAL" : parts[0], match ? "" : parts[1], no_resolve,
                                                         id, &compiled, NULL);
        if (rc != SOLARIS_OK) {
            cfg_fail(c, item, path, rc, "invalid or unsupported routing rule");
            continue;
        }
        compiled.line = item->line;
        compiled.column = item->column;
        c->image->rules[c->image->snapshot.rule_count++] = compiled;
    }
    if (!final)
        cfg_fail(c, rules, "Rule.FINAL", SOLARIS_EINVAL, "rules require a final FINAL rule");
}
typedef struct auth_profile {
    const char *name;
    const solaris_config_auth_t *users;
    size_t count;
} auth_profile_t;
static auth_profile_t *auth_compile(cfg_context_t *c, cfg_node_t *map, size_t *count) {
    *count = map ? map->count / 2 : 0;
    if (!*count)
        return NULL;
    auth_profile_t *profiles = cfg_alloc(&c->image->arena, *count * sizeof(*profiles));
    if (!profiles) {
        cfg_fail(c, map, "Authentication", SOLARIS_ENOMEM, "configuration memory budget exhausted");
        return NULL;
    }
    size_t index = 0;
    for (cfg_node_t *key = map->children; key; key = key->next->next, ++index) {
        auth_profile_t *profile = &profiles[index];
        profile->name = string_value(c, key, "Authentication.name", 127, 0);
        cfg_node_t *users = key->next;
        solaris_config_auth_t *items = cfg_alloc(&c->image->arena, users->count / 2 * sizeof(*items));
        if (!items) {
            cfg_fail(c, key, "Authentication", SOLARIS_ENOMEM, "configuration memory budget exhausted");
            return profiles;
        }
        profile->users = items;
        for (cfg_node_t *user = users->children; user; user = user->next->next) {
            const char *name = string_value(c, user, "Authentication.username", 255, 0);
            const char *password = string_value(c, user->next, "Authentication.password", 255, 0);
            items[profile->count++] = (solaris_config_auth_t){name, password};
        }
    }
    return profiles;
}
static const auth_profile_t *auth_select(cfg_context_t *c, cfg_node_t *ref, const auth_profile_t *profiles,
                                         size_t count, const auth_profile_t *fallback) {
    if (!ref)
        return fallback;
    const char *name = string_value(c, ref, "authentication", 127, 1);
    if (!name || !*name)
        return NULL;
    for (size_t i = 0; profiles && i < count; ++i)
        if (profiles[i].name && !strcmp(profiles[i].name, name))
            return &profiles[i];
    cfg_fail(c, ref, "authentication", SOLARIS_EINVAL, "unknown authentication profile");
    return NULL;
}
static void add_listener(cfg_context_t *c, cfg_node_t *location, const char *path, const char *name, uint32_t protocol,
                         const char *host, uint64_t port, int udp, const solaris_config_auth_t *auth,
                         size_t auth_count) {
    if (!port)
        return;
#if !SOLARIS_HAS_PROXY_INBOUND
    (void)name;
    (void)protocol;
    (void)host;
    (void)udp;
    (void)auth;
    (void)auth_count;
    cfg_fail(c, location, path, SOLARIS_ENOTSUP, "proxy inbound support is disabled in this build");
    return;
#else
    solaris_address_t address;
    if (solaris_address_parse(host, (uint16_t)port, &address) != SOLARIS_OK ||
        address.family == SOLARIS_ADDRESS_DOMAIN) {
        cfg_fail(c, location, path, SOLARIS_EINVAL, "listener address must be numeric");
        return;
    }
    uint64_t id = identity(name);
    for (size_t i = 0; i < c->image->snapshot.listener_count; ++i) {
        const solaris_config_listener_t *old = &c->image->listeners[i];
        if (old->id == id) {
            cfg_fail(c, location, path, SOLARIS_EINVAL, "duplicate listener name or identity collision");
            return;
        }
        if (solaris_address_equal(&old->listen, &address)) {
            cfg_fail(c, location, path, SOLARIS_EINVAL, "duplicate enabled listener endpoint");
            return;
        }
    }
    solaris_config_listener_t *out = &c->image->listeners[c->image->snapshot.listener_count++];
    *out = (solaris_config_listener_t){.id = id,
                                       .name = name,
                                       .protocol = protocol,
                                       .udp = (uint32_t)udp,
                                       .listen = address,
                                       .auth = auth,
                                       .auth_count = auth_count};
#endif
}
static int endpoint(const char *text, char host[256], uint16_t *port) {
    const char *start = text, *end = NULL, *number = NULL;
    if (*text == '[') {
        start = text + 1;
        end = strchr(start, ']');
        if (!end || end[1] != ':')
            return 0;
        number = end + 2;
    } else {
        end = strrchr(text, ':');
        if (!end || strchr(text, ':') != end)
            return 0;
        number = end + 1;
    }
    if (!*number || end == start || (size_t)(end - start) > 255)
        return 0;
    cfg_node_t value = {.kind = CFG_SCALAR, .scalar = number, .length = strlen(number)};
    int64_t parsed;
    if (!integer_value(&value, &parsed) || parsed < 1 || parsed > 65535)
        return 0;
    memcpy(host, start, (size_t)(end - start));
    host[end - start] = 0;
    *port = (uint16_t)parsed;
    return 1;
}
static void listeners_compile(cfg_context_t *c, cfg_node_t *root, cfg_node_t *general) {
    cfg_node_t *listeners = get(root, "Listener");
    size_t extra = listeners ? listeners->count : 0;
    c->image->listeners = cfg_alloc(&c->image->arena, (extra + 3) * sizeof(*c->image->listeners));
    if (!c->image->listeners) {
        cfg_fail(c, root, "Listener", SOLARIS_ENOMEM, "configuration memory budget exhausted");
        return;
    }
    size_t auth_count;
    auth_profile_t *profiles = auth_compile(c, get(root, "Authentication"), &auth_count);
    const auth_profile_t *default_auth = auth_select(c, get(general, "authentication"), profiles, auth_count, NULL);
    const char *keys[] = {"http-listen", "socks-listen", "mixed-listen"};
    const char *names[] = {"http", "socks", "mixed"};
    for (size_t i = 0; i < 3; ++i) {
        const char *value = text_field(c, general, keys[i], "General", 0, 300, 0);
        if (!value || !strcmp(value, "off"))
            continue;
        char host[256];
        uint16_t port;
        if (!endpoint(value, host, &port)) {
            cfg_fail(c, get(general, keys[i]), "General.listen", SOLARIS_EINVAL,
                     "listener requires numeric address:port in 1..65535 or off");
            continue;
        }
        add_listener(c, get(general, keys[i]), "General.listen", names[i], (uint32_t)i + 1, host, port, i != 0,
                     default_auth ? default_auth->users : NULL, default_auth ? default_auth->count : 0);
    }
    size_t index = 0;
    for (cfg_node_t *map = listeners ? listeners->children : NULL; map; map = map->next, ++index) {
        char path[256];
        (void)snprintf(path, sizeof(path), "Listener[%zu]", index);
        const char *allowed[] = {"name", "type", "listen", "port", "udp-relay", "authentication"};
        fields_check(c, map, path, allowed, 6);
        const char *name = text_field(c, map, "name", path, 1, 127, 0),
                   *type = text_field(c, map, "type", path, 1, 31, 0),
                   *listen = text_field(c, map, "listen", path, 1, 255, 0);
        if (!name || !type || !listen)
            continue;
        uint32_t protocol = !strcmp(type, "http") ? 1 : !strcmp(type, "socks5") ? 2 : !strcmp(type, "mixed") ? 3 : 0;
        if (!protocol) {
            cfg_fail(c, get(map, "type"), path, SOLARIS_ENOTSUP, "unsupported listener protocol");
            continue;
        }
        uint64_t port = uint_field(c, map, "port", path, 0, 1, 65535, 1);
        int udp = bool_field(c, map, "udp-relay", path, protocol != 1);
        if (protocol == 1 && get(map, "udp-relay"))
            cfg_fail(c, get(map, "udp-relay"), path, SOLARIS_ENOTSUP, "HTTP listener has no UDP capability");
        const auth_profile_t *auth = auth_select(c, get(map, "authentication"), profiles, auth_count, default_auth);
        add_listener(c, map, path, name, protocol, listen, port, udp, auth ? auth->users : NULL,
                     auth ? auth->count : 0);
    }
}
void cfg_image_compile(cfg_context_t *c, cfg_node_t *root) {
    if (!root || root->kind != CFG_MAP) {
        cfg_fail(c, root, "$", SOLARIS_EINVAL, "configuration root must be a map");
        return;
    }
    cfg_node_t *general = get(root, "General");
    if (!general) {
        cfg_fail(c, root, "General", SOLARIS_EINVAL, "[General] with config-version = 1 is required");
        return;
    }
    const char *allowed[] = {"config-version", "mode", "http-listen", "socks-listen", "mixed-listen", "authentication"};
    fields_check(c, general, "General", allowed, sizeof(allowed) / sizeof(*allowed));
    cfg_node_t *version = get(general, "config-version");
    if (!version || strcmp(version->scalar, "1")) {
        cfg_fail(c, version ? version : general, "General.config-version", SOLARIS_EINVAL,
                 "config-version must be exactly 1");
        return;
    }
    const char *mode = text_field(c, general, "mode", "General", 0, 16, 0);
    c->image->snapshot.mode = SOLARIS_MODE_RULE;
    if (mode) {
        if (!strcmp(mode, "rule"))
            c->image->snapshot.mode = SOLARIS_MODE_RULE;
        else if (!strcmp(mode, "global"))
            c->image->snapshot.mode = SOLARIS_MODE_GLOBAL;
        else if (!strcmp(mode, "direct"))
            c->image->snapshot.mode = SOLARIS_MODE_DIRECT;
        else
            cfg_fail(c, get(general, "mode"), "General.mode", SOLARIS_EINVAL, "unsupported routing mode");
    }
    if (!SOLARIS_HAS_DIRECT || !SOLARIS_HAS_BLOCK) {
        cfg_fail(c, root, "Proxy", SOLARIS_ENOTSUP, "configuration requires built-in DIRECT and REJECT modules");
        return;
    }
    cfg_node_t *proxies = get(root, "Proxy");
    size_t count = proxies && proxies->kind == CFG_SEQUENCE ? proxies->count : 0;
    c->image->nodes = cfg_alloc(&c->image->arena, (count + 2) * sizeof(*c->image->nodes));
    if (!c->image->nodes) {
        cfg_fail(c, proxies, "Proxy", SOLARIS_ENOMEM, "configuration memory budget exhausted");
        return;
    }
    const char *builtin_names[] = {"DIRECT", "REJECT"}, *builtin_types[] = {"direct", "block"};
    for (size_t i = 0; i < 2; ++i) {
        solaris_config_field_t *fields;
        solaris_config_view_t *view = module_view(c, NULL, &fields);
        if (!view)
            return;
        c->image->nodes[c->image->snapshot.node_count++] = (solaris_config_node_t){.id = identity(builtin_names[i]),
                                                                                   .name = builtin_names[i],
                                                                                   .type = builtin_types[i],
                                                                                   .udp_enabled = 1,
                                                                                   .fields = view};
    }
    c->image->direct_target = c->image->nodes[0].id;
    if (proxies && !null_value(proxies)) {
        if (proxies->kind != CFG_SEQUENCE)
            cfg_fail(c, proxies, "Proxy", SOLARIS_EINVAL, "expected a sequence");
        else {
            size_t i = 0;
            for (cfg_node_t *item = proxies->children; item; item = item->next)
                node_compile(c, item, i++);
        }
    }
    groups_compile(c, get(root, "Proxy Group"));
    rules_compile(c, get(root, "Rule"), general);
    listeners_compile(c, root, general);
    cfg_dns_compile(c, root);
    uint64_t fingerprint = UINT64_C(14695981039346656037);
    for (size_t i = 0; i < c->image->snapshot.node_count; ++i) {
        fingerprint ^= c->image->nodes[i].id;
        fingerprint *= UINT64_C(1099511628211);
        fingerprint ^= identity(c->image->nodes[i].type);
        fingerprint ^= c->image->nodes[i].udp_enabled;
    }
    for (size_t i = 0; i < c->image->snapshot.group_count; ++i) {
        fingerprint ^= c->image->groups[i].id;
        fingerprint *= UINT64_C(1099511628211);
    }
    for (size_t i = 0; i < c->image->snapshot.rule_count; ++i) {
        const unsigned char *p = (const unsigned char *)&c->image->rules[i];
        for (size_t j = 0; j < sizeof(*c->image->rules); ++j) {
            fingerprint ^= p[j];
            fingerprint *= UINT64_C(1099511628211);
        }
    }
    for (size_t i = 0; i < c->image->snapshot.listener_count; ++i) {
        fingerprint ^= c->image->listeners[i].id;
        fingerprint *= UINT64_C(1099511628211);
        fingerprint ^= c->image->listeners[i].listen.port;
    }
    c->image->snapshot.fingerprint = fingerprint ^ c->image->snapshot.mode;
}

/* Narrow shared field conversion for additional offline image components. */
cfg_node_t *cfg_field(cfg_node_t *map, const char *name) { return get(map, name); }
int cfg_is_null(const cfg_node_t *node) { return null_value(node); }
const char *cfg_text(cfg_context_t *c, cfg_node_t *map, const char *key, const char *path, int required, size_t limit,
                     int empty) {
    return text_field(c, map, key, path, required, limit, empty);
}
const char *cfg_string_value(cfg_context_t *c, cfg_node_t *node, const char *path, size_t limit, int empty) {
    return string_value(c, node, path, limit, empty);
}
int cfg_bool(cfg_context_t *c, cfg_node_t *map, const char *key, const char *path, int fallback) {
    return bool_field(c, map, key, path, fallback);
}
uint64_t cfg_uint(cfg_context_t *c, cfg_node_t *map, const char *key, const char *path, uint64_t fallback, uint64_t low,
                  uint64_t high, int required) {
    return uint_field(c, map, key, path, fallback, low, high, required);
}
void cfg_fields(cfg_context_t *c, cfg_node_t *map, const char *path, const char *const *names, size_t count) {
    fields_check(c, map, path, names, count);
}
