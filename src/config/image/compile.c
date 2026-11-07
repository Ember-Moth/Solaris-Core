#include "config/image/internal.h"
#include "solaris_builtin_modules.h"
#include "contracts/io/address.h"
#if SOLARIS_HAS_SHADOWSOCKS
#include "adapters/outbound/shadowsocks/internal.h"
#endif
#if SOLARIS_HAS_VLESS
#include "adapters/outbound/vless/encryption/config.h"
#endif
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

static cfg_node_t *get(cfg_node_t *map, const char *name)
{
    if (!map || map->kind != CFG_MAP)
        return NULL;
    for (cfg_node_t *key = map->children; key && key->next; key = key->next->next)
        if (!strcmp(key->scalar, name))
            return key->next;
    return NULL;
}
static int null_value(const cfg_node_t *n)
{
    return n && n->kind == CFG_SCALAR &&
           ((n->tag && !strcmp(n->tag, "tag:yaml.org,2002:null")) ||
            (n->plain && !n->tag &&
             (!n->length || !strcmp(n->scalar, "~") || !strcmp(n->scalar, "null") || !strcmp(n->scalar, "Null") ||
              !strcmp(n->scalar, "NULL"))));
}
static void path_field(char out[256], const char *base, const char *field)
{
    (void)snprintf(out, 256, "%s%s%s", base, *base ? "." : "", field);
}
static int boolean_value(const cfg_node_t *n, int *out)
{
    if (!n || n->kind != CFG_SCALAR || !n->scalar || n->length > 5)
        return 0;
    const char *truths[] = {"true", "True", "TRUE", "yes", "Yes", "YES", "y", "Y", "on", "On", "ON"};
    const char *falses[] = {"false", "False", "FALSE", "no", "No", "NO", "n", "N", "off", "Off", "OFF"};
    for (size_t i = 0; i < sizeof(truths) / sizeof(*truths); ++i)
        if (!strcmp(n->scalar, truths[i])) {
            *out = 1;
            return 1;
        }
    for (size_t i = 0; i < sizeof(falses) / sizeof(*falses); ++i)
        if (!strcmp(n->scalar, falses[i])) {
            *out = 0;
            return 1;
        }
    return 0;
}
static int integer_value(const cfg_node_t *n, int64_t *out)
{
    if (!n || n->kind != CFG_SCALAR || !n->scalar || !n->length || n->length >= 96)
        return 0;
    size_t first = n->scalar[0] == '+' || n->scalar[0] == '-' ? 1 : 0;
    if (first == n->length || n->scalar[first] < '0' || n->scalar[first] > '9')
        return 0;
    char value[96];
    size_t used = 0;
    for (size_t i = 0; i < n->length; ++i)
        if (n->scalar[i] != '_')
            value[used++] = n->scalar[i];
    value[used] = 0;
    if (!used || isspace((unsigned char)value[0]))
        return 0;
    int base = 10;
    char *begin = value, *digits = begin + (*begin == '-' || *begin == '+');
    if (digits[0] == '0' && (digits[1] == 'o' || digits[1] == 'O' || digits[1] == 'b' || digits[1] == 'B')) {
        base = digits[1] == 'o' || digits[1] == 'O' ? 8 : 2;
        memmove(digits + 1, digits + 2, strlen(digits + 2) + 1);
    } else if (digits[0] == '0' && (digits[1] == 'x' || digits[1] == 'X'))
        base = 0;
    else if (digits[0] == '0' && digits[1]) {
        base = 8;
        if (n->plain && !n->tag && (strchr(digits, '8') || strchr(digits, '9')))
            base = 10;
    }
    errno = 0;
    char *end = NULL;
    long long result = strtoll(begin, &end, base);
    if (errno || !end || end == begin || *end)
        return 0;
    *out = (int64_t)result;
    return 1;
}
/* YAML v3 resolves numeric-looking scalars before weak map decoding. C's
 * strtod also accepts bare nan/Inf and hex floats, which YAML treats as strings. */
int cfg_scalar_numeric_kind(const cfg_node_t *n)
{
    if (n->tag) {
        if (!strcmp(n->tag, "tag:yaml.org,2002:int"))
            return 1;
        if (!strcmp(n->tag, "tag:yaml.org,2002:float"))
            return 2;
        return 0;
    }
    if (!n->plain || !n->length)
        return 0;
    const char *raw = n->scalar;
    if (!strcmp(raw, ".nan") || !strcmp(raw, ".NaN") || !strcmp(raw, ".NAN") || !strcmp(raw, ".inf") ||
        !strcmp(raw, ".Inf") || !strcmp(raw, ".INF") || !strcmp(raw, "+.inf") || !strcmp(raw, "+.Inf") ||
        !strcmp(raw, "+.INF") || !strcmp(raw, "-.inf") || !strcmp(raw, "-.Inf") || !strcmp(raw, "-.INF"))
        return 2;
    size_t first = raw[0] == '+' || raw[0] == '-' ? 1 : 0;
    if (first == n->length || !((raw[first] >= '0' && raw[first] <= '9') || raw[first] == '.'))
        return 0;
    if (n->length >= 128) {
        for (size_t i = 0; i < n->length; ++i)
            if (!strchr("0123456789_+-.eE", raw[i]))
                return 0;
        return 2; /* bounded conservative conversion: quote long numeric strings */
    }
    char text[128];
    size_t used = 0;
    for (size_t i = 0; i < n->length; ++i)
        if (raw[i] != '_')
            text[used++] = raw[i];
    text[used] = 0;
    char *digits = text + first, *end = NULL;
    int base = 0;
    if (digits[0] == '0' && (digits[1] == 'o' || digits[1] == 'O' || digits[1] == 'b' || digits[1] == 'B')) {
        base = digits[1] == 'o' || digits[1] == 'O' ? 8 : 2;
        memmove(digits + 1, digits + 2, strlen(digits + 2) + 1);
    }
    errno = 0;
    if (*text == '-')
        (void)strtoll(text, &end, base);
    else
        (void)strtoull(text, &end, base);
    if (!errno && end != text && !*end)
        return 1;
    /* Only decimal float grammar, never strtod's additional extensions. */
    const char *p = text + first;
    size_t decimal_digits = 0;
    while (*p >= '0' && *p <= '9') {
        p++;
        decimal_digits++;
    }
    if (*p == '.') {
        p++;
        while (*p >= '0' && *p <= '9') {
            p++;
            decimal_digits++;
        }
    }
    if (!decimal_digits)
        return 0;
    if (*p == 'e' || *p == 'E') {
        p++;
        if (*p == '+' || *p == '-')
            p++;
        const char *exp = p;
        while (*p >= '0' && *p <= '9')
            p++;
        if (p == exp)
            return 0;
    }
    if (*p)
        return 0;
    errno = 0;
    (void)strtod(text, &end);
    return !errno && end != text && !*end ? 2 : 0;
}
static const char *string_value(cfg_context_t *c, cfg_node_t *n, const char *path, size_t limit, int allow_empty)
{
    if (!n || n->kind != CFG_SCALAR || null_value(n) || !n->scalar || n->length > limit ||
        (!allow_empty && !n->length)) {
        cfg_fail(c, n, path, SOLARIS_EINVAL, "expected a bounded scalar string");
        return NULL;
    }
    for (size_t i = 0; i < n->length; ++i)
        if ((unsigned char)n->scalar[i] < 32 && n->scalar[i] != '\n' && n->scalar[i] != '\t') {
            cfg_fail(c, n, path, SOLARIS_EINVAL, "control bytes are not allowed here");
            return NULL;
        }
    const char *value = n->scalar;
    size_t length = n->length;
    char converted[96];
    int weak = !strncmp(path, "proxies[", 8) || !strncmp(path, "listeners[", 10) || !strncmp(path, "proxy-groups[", 13);
    if (weak && ((n->plain && !n->tag) || (n->tag && strcmp(n->tag, "tag:yaml.org,2002:str")))) {
        int boolean;
        int64_t integer;
        if ((n->tag && !strcmp(n->tag, "tag:yaml.org,2002:bool")) ||
            (boolean_value(n, &boolean) &&
             (n->scalar[0] == 't' || n->scalar[0] == 'T' || n->scalar[0] == 'f' || n->scalar[0] == 'F'))) {
            cfg_fail(c, n, path, SOLARIS_EINVAL, "boolean cannot be converted to a string field");
            return NULL;
        }
        int numeric = cfg_scalar_numeric_kind(n);
        if (numeric == 1 && integer_value(n, &integer)) {
            (void)snprintf(converted, sizeof(converted), "%lld", (long long)integer);
            value = converted;
            length = strlen(value);
        } else if (numeric) {
            cfg_fail(c, n, path, SOLARIS_ENOTSUP,
                     "floating or oversized numeric string conversion is unsupported; quote the string");
            return NULL;
        }
    }
    char *copy = cfg_string(&c->image->arena, value, length);
    if (!copy)
        cfg_fail(c, n, path, SOLARIS_ENOMEM, "configuration memory budget exhausted");
    return copy;
}
static const char *text_field(cfg_context_t *c, cfg_node_t *map, const char *key, const char *path, int required,
                              size_t limit, int empty)
{
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
static int bool_field(cfg_context_t *c, cfg_node_t *map, const char *key, const char *path, int fallback)
{
    cfg_node_t *n = get(map, key);
    if (!n || null_value(n))
        return fallback;
    int result;
    int typed = !*path;
    int bool_tag = n->tag && !strcmp(n->tag, "tag:yaml.org,2002:bool");
    if ((n->plain && !n->tag) || bool_tag) {
        if (boolean_value(n, &result) &&
            (typed || n->scalar[0] == 't' || n->scalar[0] == 'T' || n->scalar[0] == 'f' || n->scalar[0] == 'F'))
            return result;
    }
    if (typed && boolean_value(n, &result) && n->scalar[0] != 't' && n->scalar[0] != 'T' && n->scalar[0] != 'f' &&
        n->scalar[0] != 'F')
        return result;
    if (!typed && ((n->plain && !n->tag) || (n->tag && !strcmp(n->tag, "tag:yaml.org,2002:int")))) {
        int64_t integer;
        if (integer_value(n, &integer))
            return integer != 0;
    }
    char full[256];
    path_field(full, path, key);
    cfg_fail(c, n, full, SOLARIS_EINVAL, "expected a boolean");
    return fallback;
}
static uint64_t uint_field(cfg_context_t *c, cfg_node_t *map, const char *key, const char *path, uint64_t fallback,
                           uint64_t low, uint64_t high, int required)
{
    cfg_node_t *n = get(map, key);
    char full[256];
    path_field(full, path, key);
    if (!n || null_value(n)) {
        if (required)
            cfg_fail(c, n ? n : map, full, SOLARIS_EINVAL, "required integer is missing");
        return fallback;
    }
    int64_t value;
    if ((!*path && ((!n->plain && !(n->tag && !strcmp(n->tag, "tag:yaml.org,2002:int"))) ||
                    (n->tag && strcmp(n->tag, "tag:yaml.org,2002:int")))) ||
        !integer_value(n, &value) || value < 0 || (uint64_t)value < low || (uint64_t)value > high) {
        cfg_fail(c, n, full, SOLARIS_EINVAL, "integer is outside the supported range");
        return fallback;
    }
    return (uint64_t)value;
}
static int name_in(const char *name, const char *const *names, size_t count)
{
    for (size_t i = 0; i < count; ++i)
        if (!strcmp(name, names[i]))
            return 1;
    return 0;
}
static void fields_check(cfg_context_t *c, cfg_node_t *map, const char *path, const char *const *names, size_t count)
{
    if (!map || map->kind != CFG_MAP) {
        cfg_fail(c, map, path, SOLARIS_EINVAL, "expected a map");
        return;
    }
    for (cfg_node_t *key = map->children; key && key->next; key = key->next->next)
        if (!name_in(key->scalar, names, count)) {
            char full[256];
            path_field(full, path, key->scalar);
            cfg_fail(c, key, full, SOLARIS_ENOTSUP, "unknown or unsupported field");
        }
}
static uint64_t identity(const char *text)
{
    uint64_t value = UINT64_C(14695981039346656037);
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p) {
        value ^= *p;
        value *= UINT64_C(1099511628211);
    }
    return value ? value : 1;
}
static int reserved(const char *name)
{
    const char *names[] = {"DIRECT", "REJECT", "GLOBAL", "PASS", "COMPATIBLE", "REJECT-DROP"};
    return name_in(name, names, sizeof(names) / sizeof(*names));
}
static int register_name(cfg_context_t *c, cfg_node_t *n, const char *path, const char *name, uint64_t id)
{
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
static uint64_t target(cfg_context_t *c, const char *name, int groups)
{
    for (size_t i = 0; i < c->image->snapshot.node_count; ++i)
        if (!strcmp(c->image->nodes[i].name, name))
            return c->image->nodes[i].id;
    if (groups)
        for (size_t i = 0; i < c->image->snapshot.group_count; ++i)
            if (!strcmp(c->image->groups[i].name, name))
                return c->image->groups[i].id;
    return 0;
}
static int available(const char *type)
{
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
static solaris_config_view_t *module_view(cfg_context_t *c, cfg_node_t *map, solaris_config_field_t **fields)
{
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
                       cfg_node_t *source)
{
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
                        cfg_node_t *source, int boolean)
{
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
static void node_compile(cfg_context_t *c, cfg_node_t *map, size_t index)
{
    char path[256];
    (void)snprintf(path, sizeof(path), "proxies[%zu]", index);
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
    const char *common[] = {"name", "type", "udp", "server", "port", "network"};
    const char *specific_ss[] = {"cipher", "password", "udp-over-tcp", "udp-over-tcp-version"};
    const char *specific_vless[] = {"uuid", "flow", "encryption", "tls", "servername", "packet-encoding"};
    const char *specific_anytls[] = {"password", "sni", "idle-session-timeout", "idle-session-check-interval",
                                     "min-idle-session"};
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
            path_field(full, path, key->scalar);
            cfg_fail(c, key, full, SOLARIS_ENOTSUP, "unknown or unsupported protocol field");
        }
    const char *network = text_field(c, map, "network", path, 0, 16, 1);
    if (network && *network && strcmp(network, "tcp"))
        cfg_fail(c, get(map, "network"), path, SOLARIS_ENOTSUP, "only TCP carrier is implemented");
    solaris_config_node_t *out = &c->image->nodes[c->image->snapshot.node_count++];
    *out = (solaris_config_node_t){.id = id,
                                   .name = name,
                                   .type = type,
                                   .udp_enabled = bool_field(c, map, "udp", path,
                                                             !strcmp(type, "direct") || !strcmp(type, "block")),
                                   .line = map->line,
                                   .column = map->column};
    solaris_config_field_t *fields;
    solaris_config_view_t *view = module_view(c, map, &fields);
    out->fields = view;
    if (!view)
        return;
    if (!strcmp(type, "direct") || !strcmp(type, "block")) {
        for (cfg_node_t *key = map->children; key; key = key->next->next)
            if (strcmp(key->scalar, "name") && strcmp(key->scalar, "type") && strcmp(key->scalar, "udp"))
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
        const char *cipher = text_field(c, map, "cipher", path, 1, 63, 0),
                   *password = text_field(c, map, "password", path, 1, 1024, 0);
        int uot = bool_field(c, map, "udp-over-tcp", path, 0);
        uint64_t version = uint_field(c, map, "udp-over-tcp-version", path, 0, 0, 2, 0);
        if (uot && version != 2)
            cfg_fail(c, map, path, SOLARIS_ENOTSUP,
                     "UoT requires explicit udp-over-tcp-version: 2; legacy is unsupported");
#if SOLARIS_HAS_SHADOWSOCKS
        solaris_ss_key_t key;
        if (cipher && password && solaris_ss_key_parse(cipher, password, &key) != SOLARIS_OK)
            cfg_fail(c, map, path, SOLARIS_EINVAL, "invalid Shadowsocks cipher or key material");
        memset(&key, 0, sizeof(key));
#endif
        add_string(view, fields, "cipher", cipher, get(map, "cipher"));
        add_string(view, fields, "password", password, get(map, "password"));
        add_integer(view, fields, "udp-over-tcp", uot, get(map, "udp-over-tcp"), 1);
    } else if (!strcmp(type, "vless")) {
        const char *uuid = text_field(c, map, "uuid", path, 1, 36, 0),
                   *flow = text_field(c, map, "flow", path, 0, 31, 1);
        const char *encryption = text_field(c, map, "encryption", path, 0, 16383, 0),
                   *sni = text_field(c, map, "servername", path, 0, 253, 0);
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
            cfg_fail(c, get(map, "servername"), path, SOLARIS_EINVAL, "servername requires TLS");
        add_string(view, fields, "uuid", uuid, get(map, "uuid"));
        if (flow && *flow)
            add_string(view, fields, "flow", flow, get(map, "flow"));
        add_string(view, fields, "encryption", encryption, get(map, "encryption"));
        add_string(view, fields, "servername", sni, get(map, "servername"));
        add_integer(view, fields, "tls", tls, get(map, "tls"), 1);
    } else if (!strcmp(type, "anytls")) {
        const char *password = text_field(c, map, "password", path, 1, 1024, 0),
                   *sni = text_field(c, map, "sni", path, 0, 253, 0);
        uint64_t timeout = uint_field(c, map, "idle-session-timeout", path, 30, 0, 3600, 0),
                 interval = uint_field(c, map, "idle-session-check-interval", path, 30, 0, 3600, 0);
        uint64_t minimum = uint_field(c, map, "min-idle-session", path, 0, 0, 64, 0);
        /* Match the pinned mihomo AnyTLS session constructor: omitted values
         * and every duration up to five seconds normalize to thirty seconds. */
        if (timeout <= 5)
            timeout = 30;
        if (interval <= 5)
            interval = 30;
        add_string(view, fields, "password", password, get(map, "password"));
        add_string(view, fields, "servername", sni, get(map, "sni"));
        add_integer(view, fields, "tls", 1, NULL, 1);
        add_integer(view, fields, "idle-session-timeout-ms", timeout * 1000, get(map, "idle-session-timeout"), 0);
        add_integer(view, fields, "idle-session-check-interval-ms", interval * 1000,
                    get(map, "idle-session-check-interval"), 0);
        add_integer(view, fields, "min-idle-session", minimum, get(map, "min-idle-session"), 0);
    }
}
static void groups_compile(cfg_context_t *c, cfg_node_t *groups)
{
    if (groups && !null_value(groups) && groups->kind != CFG_SEQUENCE) {
        cfg_fail(c, groups, "proxy-groups", SOLARIS_EINVAL, "expected a sequence");
        return;
    }
    size_t count = groups && groups->kind == CFG_SEQUENCE ? groups->count : 0;
    c->image->groups = cfg_alloc(&c->image->arena, (count + 1) * sizeof(*c->image->groups));
    if (!c->image->groups) {
        cfg_fail(c, groups, "proxy-groups", SOLARIS_ENOMEM, "configuration memory budget exhausted");
        return;
    }
    size_t index = 0;
    for (cfg_node_t *map = groups && groups->kind == CFG_SEQUENCE ? groups->children : NULL; map;
         map = map->next, ++index) {
        char path[256];
        (void)snprintf(path, sizeof(path), "proxy-groups[%zu]", index);
        const char *allowed[] = {"name", "type", "proxies"};
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
        cfg_node_t *members = get(map, "proxies");
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
            (void)snprintf(full, sizeof(full), "proxy-groups[%zu].proxies[%zu]", index, mi);
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
static char *trim(char *text)
{
    while (*text == ' ' || *text == '\t')
        text++;
    size_t n = strlen(text);
    while (n && (text[n - 1] == ' ' || text[n - 1] == '\t'))
        text[--n] = 0;
    return text;
}
static void rules_compile(cfg_context_t *c, cfg_node_t *rules)
{
    if (!rules || null_value(rules))
        return;
    if (rules->kind != CFG_SEQUENCE) {
        cfg_fail(c, rules, "rules", SOLARIS_EINVAL, "expected a sequence");
        return;
    }
    c->image->rules = cfg_alloc(&c->image->arena, rules->count * sizeof(*c->image->rules));
    if (!c->image->rules) {
        cfg_fail(c, rules, "rules", SOLARIS_ENOMEM, "configuration memory budget exhausted");
        return;
    }
    size_t index = 0;
    for (cfg_node_t *item = rules->children; item; item = item->next, ++index) {
        char path[256];
        (void)snprintf(path, sizeof(path), "rules[%zu]", index);
        const char *text = string_value(c, item, path, 2048, 0);
        if (!text)
            continue;
        char buffer[2049];
        memcpy(buffer, text, strlen(text) + 1);
        char *parts[5] = {0};
        size_t n = 0;
        char *start = buffer;
        for (char *p = buffer;; ++p)
            if (*p == ',' || !*p) {
                int end = !*p;
                *p = 0;
                if (n < 5)
                    parts[n++] = trim(start);
                else
                    n++;
                start = p + 1;
                if (end)
                    break;
            }
        int match = n >= 1 && !strcmp(parts[0], "MATCH"), no_resolve = 0;
        size_t expected = match ? 2 : 3;
        if (n == expected + 1 && n <= 5 && !strcmp(parts[n - 1], "no-resolve"))
            no_resolve = 1;
        else if (n != expected) {
            cfg_fail(c, item, path, SOLARIS_EINVAL, "invalid rule field count or modifier");
            continue;
        }
        const char *policy = parts[match ? 1 : 2];
        uint64_t id = target(c, policy, 1);
        if (!id) {
            cfg_fail(c, item, path, SOLARIS_EINVAL, "unknown rule target");
            continue;
        }
        solaris_route_rule_t compiled;
        solaris_error_t error;
        solaris_status_t rc =
            solaris_route_rule_compile(parts[0], match ? "" : parts[1], no_resolve, id, &compiled, &error);
        if (rc != SOLARIS_OK) {
            cfg_fail(c, item, path, rc, "invalid or unsupported routing rule");
            continue;
        }
        compiled.line = item->line;
        compiled.column = item->column;
        c->image->rules[c->image->snapshot.rule_count++] = compiled;
    }
}
static const solaris_config_auth_t *auth_compile(cfg_context_t *c, cfg_node_t *list, const char *path, int users,
                                                 size_t *count)
{
    *count = 0;
    if (!list || null_value(list))
        return NULL;
    if (list->kind != CFG_SEQUENCE) {
        cfg_fail(c, list, path, SOLARIS_EINVAL, "expected authentication sequence");
        return NULL;
    }
    solaris_config_auth_t *auth = cfg_alloc(&c->image->arena, list->count * sizeof(*auth));
    if (!auth) {
        cfg_fail(c, list, path, SOLARIS_ENOMEM, "configuration memory budget exhausted");
        return NULL;
    }
    size_t index = 0;
    for (cfg_node_t *item = list->children; item; item = item->next, ++index) {
        char full[256];
        (void)snprintf(full, sizeof(full), "%s[%zu]", path, index);
        const char *user = NULL, *password = NULL;
        if (users) {
            const char *allowed[] = {"username", "password"};
            fields_check(c, item, full, allowed, 2);
            user = text_field(c, item, "username", full, 1, 255, 0);
            password = text_field(c, item, "password", full, 1, 255, 0);
        } else {
            const char *text = string_value(c, item, full, 511, 0);
            if (!text)
                continue;
            const char *colon = strchr(text, ':');
            if (!colon || colon == text || !colon[1] || (size_t)(colon - text) > 255 || strlen(colon + 1) > 255) {
                cfg_fail(c, item, full, SOLARIS_EINVAL,
                         "authentication requires bounded nonempty username and password");
                continue;
            }
            user = cfg_string(&c->image->arena, text, (size_t)(colon - text));
            password = colon + 1;
            if (!user) {
                cfg_fail(c, item, full, SOLARIS_ENOMEM, "configuration memory budget exhausted");
                return NULL;
            }
        }
        if (!user || !password)
            continue;
        for (size_t i = 0; i < *count; ++i)
            if (!strcmp(auth[i].username, user))
                cfg_fail(c, item, full, SOLARIS_EINVAL, "duplicate authentication user");
        auth[(*count)++] = (solaris_config_auth_t){user, password};
    }
    return auth;
}
static void add_listener(cfg_context_t *c, cfg_node_t *location, const char *path, const char *name, uint32_t protocol,
                         const char *host, uint64_t port, int udp, const solaris_config_auth_t *auth, size_t auth_count)
{
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
static void listeners_compile(cfg_context_t *c, cfg_node_t *root)
{
    cfg_node_t *listeners = get(root, "listeners");
    size_t extra = listeners && listeners->kind == CFG_SEQUENCE ? listeners->count : 0;
    c->image->listeners = cfg_alloc(&c->image->arena, (extra + 3) * sizeof(*c->image->listeners));
    if (!c->image->listeners) {
        cfg_fail(c, root, "listeners", SOLARIS_ENOMEM, "configuration memory budget exhausted");
        return;
    }
    size_t auth_count;
    const solaris_config_auth_t *auth = auth_compile(c, get(root, "authentication"), "authentication", 0, &auth_count);
    int lan = bool_field(c, root, "allow-lan", "", 0);
    const char *bind = text_field(c, root, "bind-address", "", 0, 255, 0);
    const char *host = !lan ? "127.0.0.1" : !bind || !strcmp(bind, "*") ? "::" : bind;
    const char *ports[] = {"port", "socks-port", "mixed-port"};
    const char *names[] = {"http", "socks", "mixed"};
    for (size_t i = 0; i < 3; ++i) {
        uint64_t port = uint_field(c, root, ports[i], "", 0, 0, 65535, 0);
        add_listener(c, get(root, ports[i]), ports[i], names[i], (uint32_t)i + 1, host, port, i != 0, auth, auth_count);
    }
    if (!listeners || null_value(listeners))
        return;
    if (listeners->kind != CFG_SEQUENCE) {
        cfg_fail(c, listeners, "listeners", SOLARIS_EINVAL, "expected a sequence");
        return;
    }
    size_t index = 0;
    for (cfg_node_t *map = listeners->children; map; map = map->next, ++index) {
        char path[256];
        (void)snprintf(path, sizeof(path), "listeners[%zu]", index);
        const char *allowed[] = {"name", "type", "listen", "port", "udp", "users"};
        fields_check(c, map, path, allowed, 6);
        const char *name = text_field(c, map, "name", path, 1, 127, 0),
                   *type = text_field(c, map, "type", path, 1, 31, 0),
                   *listen = text_field(c, map, "listen", path, 0, 255, 0);
        if (!name || !type)
            continue;
        uint32_t protocol = !strcmp(type, "http")                               ? 1
                            : !strcmp(type, "socks") || !strcmp(type, "socks5") ? 2
                            : !strcmp(type, "mixed")                            ? 3
                                                                                : 0;
        if (!protocol) {
            cfg_fail(c, get(map, "type"), path, SOLARIS_ENOTSUP, "unsupported listener protocol");
            continue;
        }
        cfg_node_t *port_node = get(map, "port");
        /* Listener ports are weak strings in the reference, then parsed in
         * decimal: quoted '010' is 10, while the YAML integer 010 becomes 8. */
        const char *port_text = text_field(c, map, "port", path, 0, 32, 0);
        uint64_t raw_port = 0;
        int valid_port = port_text != NULL;
        for (const char *digit = port_text; valid_port && *digit; ++digit) {
            if (*digit < '0' || *digit > '9' || raw_port > (65535u - (unsigned)(*digit - '0')) / 10u)
                valid_port = 0;
            else
                raw_port = raw_port * 10u + (unsigned)(*digit - '0');
        }
        if (!valid_port || raw_port < 1) {
            cfg_fail(
                c, port_node ? port_node : map, path, SOLARIS_ENOTSUP,
                "explicit listener requires one fixed port in 1..65535; ranges and ephemeral ports are unsupported");
            continue;
        }
        int udp = bool_field(c, map, "udp", path, protocol != 1);
        if (protocol == 1 && get(map, "udp"))
            cfg_fail(c, get(map, "udp"), path, SOLARIS_ENOTSUP, "HTTP listener has no UDP capability");
        const solaris_config_auth_t *selected = auth;
        size_t selected_count = auth_count;
        cfg_node_t *users = get(map, "users");
        if (users && !null_value(users)) {
            char full[256];
            path_field(full, path, "users");
            selected = auth_compile(c, users, full, 1, &selected_count);
        }
        add_listener(c, map, path, name, protocol, listen ? listen : "0.0.0.0", (uint64_t)raw_port, udp, selected,
                     selected_count);
    }
}
static int template_node(const cfg_node_t *n)
{
    if (n->anchor)
        return 1;
    for (const cfg_node_t *child = n->children; child; child = child->next)
        if (template_node(child))
            return 1;
    return 0;
}
void cfg_image_compile(cfg_context_t *c, cfg_node_t *root)
{
    if (!root || root->kind != CFG_MAP) {
        cfg_fail(c, root, "$", SOLARIS_EINVAL, "configuration root must be a map");
        return;
    }
    const char *supported[] = {"mode",       "proxies",   "proxy-groups", "rules",          "port",     "socks-port",
                               "mixed-port", "allow-lan", "bind-address", "authentication", "listeners"};
    const char *ignored[] = {"external-controller",
                             "external-ui",
                             "secret",
                             "external-ui-url",
                             "external-ui-name",
                             "external-controller-unix",
                             "external-controller-pipe",
                             "external-controller-tls",
                             "external-controller-cors"};
    const char *unsupported[] = {"dns",
                                 "hosts",
                                 "tun",
                                 "sniffer",
                                 "proxy-providers",
                                 "rule-providers",
                                 "profile",
                                 "tunnels",
                                 "sub-rules",
                                 "redir-port",
                                 "tproxy-port",
                                 "ss-config",
                                 "vmess-config",
                                 "ipv6",
                                 "interface-name",
                                 "routing-mark",
                                 "log-level",
                                 "unified-delay",
                                 "skip-auth-prefixes",
                                 "lan-allowed-ips",
                                 "lan-disallowed-ips",
                                 "inbound-tfo",
                                 "inbound-mptcp",
                                 "tcp-concurrent",
                                 "keep-alive-idle",
                                 "keep-alive-interval",
                                 "disable-keep-alive",
                                 "tls",
                                 "ntp",
                                 "experimental"};
    for (cfg_node_t *key = root->children; key; key = key->next->next) {
        if (name_in(key->scalar, supported, sizeof(supported) / sizeof(*supported)))
            continue;
        if (name_in(key->scalar, ignored, sizeof(ignored) / sizeof(*ignored))) {
            cfg_diagnostic(c, key, key->scalar, SOLARIS_DIAGNOSTIC_WARNING, SOLARIS_CONFIG_NORMALIZE, SOLARIS_OK,
                           "controller/UI setting is not executed in library mode");
            continue;
        }
        if (!name_in(key->scalar, unsupported, sizeof(unsupported) / sizeof(*unsupported)) &&
            (!strncmp(key->scalar, "x-", 2) || template_node(key->next))) {
            cfg_diagnostic(c, key, key->scalar, SOLARIS_DIAGNOSTIC_WARNING, SOLARIS_CONFIG_NORMALIZE, SOLARIS_OK,
                           "template extension has no runtime effect");
            continue;
        }
        cfg_fail(c, key, key->scalar, SOLARIS_ENOTSUP, "unknown or unsupported top-level setting");
    }
    const char *mode = text_field(c, root, "mode", "", 0, 16, 0);
    c->image->snapshot.mode = SOLARIS_MODE_RULE;
    if (mode) {
        if (!strcmp(mode, "rule"))
            c->image->snapshot.mode = SOLARIS_MODE_RULE;
        else if (!strcmp(mode, "global"))
            c->image->snapshot.mode = SOLARIS_MODE_GLOBAL;
        else if (!strcmp(mode, "direct"))
            c->image->snapshot.mode = SOLARIS_MODE_DIRECT;
        else
            cfg_fail(c, get(root, "mode"), "mode", SOLARIS_EINVAL, "unsupported routing mode");
    }
    if (!SOLARIS_HAS_DIRECT || !SOLARIS_HAS_BLOCK) {
        cfg_fail(c, root, "proxies", SOLARIS_ENOTSUP, "configuration requires built-in DIRECT and REJECT modules");
        return;
    }
    cfg_node_t *proxies = get(root, "proxies");
    size_t count = proxies && proxies->kind == CFG_SEQUENCE ? proxies->count : 0;
    c->image->nodes = cfg_alloc(&c->image->arena, (count + 2) * sizeof(*c->image->nodes));
    if (!c->image->nodes) {
        cfg_fail(c, proxies, "proxies", SOLARIS_ENOMEM, "configuration memory budget exhausted");
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
            cfg_fail(c, proxies, "proxies", SOLARIS_EINVAL, "expected a sequence");
        else {
            size_t i = 0;
            for (cfg_node_t *item = proxies->children; item; item = item->next)
                node_compile(c, item, i++);
        }
    }
    groups_compile(c, get(root, "proxy-groups"));
    rules_compile(c, get(root, "rules"));
    listeners_compile(c, root);
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
