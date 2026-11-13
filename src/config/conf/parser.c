#include "config/image/internal.h"
#include <string.h>

/* The AST preserves section, record and token positions. It owns all decoded
 * text; no YAML, implicit scalar typing, include, or external resource access. */
typedef struct span {
    const char *text;
    size_t size;
    uint32_t line, column;
} span_t;

static int space(char ch) { return ch == ' ' || ch == '\t'; }
static span_t trim(span_t s) {
    while (s.size && space(*s.text)) {
        ++s.text;
        --s.size;
        ++s.column;
    }
    while (s.size && space(s.text[s.size - 1]))
        --s.size;
    return s;
}
static void fail(cfg_context_t *c, span_t s, const char *path, solaris_status_t status, const char *message) {
    cfg_node_t n = {.line = s.line, .column = s.column};
    cfg_diagnostic(c, &n, path, SOLARIS_DIAGNOSTIC_ERROR, SOLARIS_CONFIG_PARSE, status, message);
}
static cfg_node_t *node(cfg_context_t *c, unsigned kind, span_t s) {
    if (c->errors)
        return NULL;
    if (c->nodes == c->options.node_limit) {
        fail(c, s, "$", SOLARIS_EOVERFLOW, "configuration node limit exceeded");
        return NULL;
    }
    cfg_node_t *n = cfg_alloc(&c->ast, sizeof(*n));
    if (!n) {
        fail(c, s, "$", SOLARIS_ENOMEM, "configuration memory budget exhausted");
        return NULL;
    }
    ++c->nodes;
    n->kind = kind;
    n->line = s.line;
    n->column = s.column;
    return n;
}
static void append(cfg_node_t *parent, cfg_node_t *child) {
    if (!parent || !child)
        return;
    if (parent->tail)
        parent->tail->next = child;
    else
        parent->children = child;
    parent->tail = child;
    ++parent->count;
}
static cfg_node_t *literal(cfg_context_t *c, const char *text, span_t location) {
    cfg_node_t *n = node(c, CFG_SCALAR, location);
    if (n) {
        n->scalar = text;
        n->length = strlen(text);
    }
    return n;
}
static void pair(cfg_context_t *c, cfg_node_t *map, cfg_node_t *key, cfg_node_t *value, const char *path) {
    if (!map || !key || !value || c->errors)
        return;
    for (cfg_node_t *old = map->children; old; old = old->next->next) {
        if (!strcmp(old->scalar, key->scalar)) {
            key->related_line = old->line;
            key->related_column = old->column;
            cfg_diagnostic(c, key, path, SOLARIS_DIAGNOSTIC_ERROR, SOLARIS_CONFIG_PARSE, SOLARIS_EINVAL,
                           "duplicate section, key, name or parameter");
            return;
        }
    }
    append(map, key);
    append(map, value);
}
/* Return the first unquoted delimiter; line scanning already validated quotes. */
static size_t delimiter(span_t s, char wanted) {
    int quoted = 0;
    for (size_t i = 0; i < s.size; ++i) {
        if (quoted && s.text[i] == '\\') {
            ++i;
            continue;
        }
        if (s.text[i] == '"')
            quoted = !quoted;
        else if (!quoted && s.text[i] == wanted)
            return i;
    }
    return s.size;
}
static span_t slice(span_t s, size_t start, size_t size) {
    s.text += start;
    s.column += (uint32_t)start;
    s.size = size;
    return s;
}
static cfg_node_t *scalar(cfg_context_t *c, span_t s, const char *path) {
    s = trim(s);
    if (!s.size) {
        fail(c, s, path, SOLARIS_EINVAL, "empty token requires explicit double quotes");
        return NULL;
    }
    int quoted = s.text[0] == '"';
    span_t value = s;
    if (quoted) {
        if (s.size < 2 || s.text[s.size - 1] != '"') {
            fail(c, s, path, SOLARIS_EINVAL, "quoted token must occupy the entire value");
            return NULL;
        }
        value = slice(s, 1, s.size - 2);
    }
    if (value.size > c->options.string_limit_bytes) {
        fail(c, s, path, SOLARIS_EOVERFLOW, "configuration token limit exceeded");
        return NULL;
    }
    cfg_node_t *n = node(c, CFG_SCALAR, s);
    if (!n)
        return NULL;
    char *text = cfg_alloc(&c->ast, value.size + 1);
    if (!text) {
        fail(c, s, path, SOLARIS_ENOMEM, "configuration memory budget exhausted");
        return NULL;
    }
    for (size_t i = 0; i < value.size; ++i) {
        char ch = value.text[i];
        if (ch == '"') {
            fail(c, s, path, SOLARIS_EINVAL, "unexpected quote inside token");
            return NULL;
        }
        if (quoted && ch == '\\') {
            if (++i == value.size || (value.text[i] != '\\' && value.text[i] != '"')) {
                fail(c, s, path, SOLARIS_EINVAL, "unsupported or incomplete escape");
                return NULL;
            }
            ch = value.text[i];
        }
        text[n->length++] = ch;
    }
    n->scalar = text;
    return n;
}
static cfg_node_t *list(cfg_context_t *c, span_t s, const char *path) {
    cfg_node_t *out = node(c, CFG_SEQUENCE, trim(s));
    while (!c->errors) {
        size_t end = delimiter(s, ',');
        append(out, scalar(c, slice(s, 0, end), path));
        if (end == s.size)
            break;
        s = slice(s, end + 1, s.size - end - 1);
    }
    return out;
}
static void parameter(cfg_context_t *c, cfg_node_t *map, span_t s, const char *path) {
    size_t eq = delimiter(s, '=');
    if (eq == s.size) {
        fail(c, s, path, SOLARIS_EINVAL, "expected parameter = value");
        return;
    }
    cfg_node_t *key = scalar(c, slice(s, 0, eq), path);
    cfg_node_t *value = scalar(c, slice(s, eq + 1, s.size - eq - 1), path);
    if (key && !key->length) {
        fail(c, s, path, SOLARIS_EINVAL, "empty parameter name");
        return;
    }
    pair(c, map, key, value, path);
}
static cfg_node_t *record(cfg_context_t *c, cfg_node_t *name, span_t s, const char *section) {
    cfg_node_t *out = node(c, CFG_MAP, s);
    pair(c, out, literal(c, "name", s), name, section);
    size_t end = delimiter(s, ',');
    cfg_node_t *type = scalar(c, slice(s, 0, end), section);
    pair(c, out, literal(c, "type", s), type, section);
    if (!type || c->errors)
        return out;
    int group = !strcmp(section, "Proxy Group");
    int local = !strcmp(section, "Proxy") && (!strcmp(type->scalar, "direct") || !strcmp(type->scalar, "reject"));
    const char *positionals[] = {!strcmp(section, "Listener") ? "listen" : "server", "port"};
    size_t pos = 0;
    cfg_node_t *members = group ? node(c, CFG_SEQUENCE, s) : NULL;
    while (end < s.size && !c->errors) {
        s = slice(s, end + 1, s.size - end - 1);
        end = delimiter(s, ',');
        span_t token = slice(s, 0, end);
        if (group)
            append(members, scalar(c, token, section));
        else if (!local && pos < 2) {
            cfg_node_t *value = scalar(c, token, section);
            pair(c, out, literal(c, positionals[pos++], token), value, section);
        } else
            parameter(c, out, token, section);
    }
    if (group)
        pair(c, out, literal(c, "members", s), members, section);
    else if (!local && pos < 2 && !c->errors)
        fail(c, s, section, SOLARIS_EINVAL, "protocol requires address and port");
    return out;
}
static int utf8(cfg_context_t *c, span_t s) {
    for (size_t i = 0; i < s.size;) {
        unsigned ch = (unsigned char)s.text[i];
        if (ch < 128) {
            if ((ch < 32 && ch != '\t') || ch == 127) {
                fail(c, slice(s, i, 1), "$", SOLARIS_EINVAL, "control byte is not allowed");
                return 0;
            }
            ++i;
            continue;
        }
        size_t count = ch >= 0xc2 && ch <= 0xdf ? 2 : ch >= 0xe0 && ch <= 0xef ? 3 : ch >= 0xf0 && ch <= 0xf4 ? 4 : 0;
        unsigned cp = count ? ch & ((1u << (7u - (unsigned)count)) - 1u) : 0;
        int valid = count && count <= s.size - i;
        for (size_t j = 1; valid && j < count; ++j) {
            unsigned b = (unsigned char)s.text[i + j];
            valid = (b & 0xc0) == 0x80;
            cp = (cp << 6) | (b & 63);
        }
        valid = valid &&
                cp >= (count == 2   ? 0x80u
                       : count == 3 ? 0x800u
                                    : 0x10000u) &&
                cp <= 0x10ffff && !(cp >= 0xd800 && cp <= 0xdfff) && cp != 0xfeff;
        if (!valid) {
            fail(c, slice(s, i, 1), "$", SOLARIS_EINVAL, "invalid UTF-8 or misplaced BOM");
            return 0;
        }
        i += count;
    }
    return 1;
}
static span_t uncomment(cfg_context_t *c, span_t s, const char *path) {
    int quoted = 0;
    for (size_t i = 0; i < s.size; ++i) {
        char ch = s.text[i];
        if (quoted && ch == '\\') {
            if (++i == s.size || (s.text[i] != '\\' && s.text[i] != '"')) {
                fail(c, slice(s, i ? i - 1 : 0, 1), path, SOLARIS_EINVAL, "unsupported or incomplete escape");
                return s;
            }
        } else if (ch == '"')
            quoted = !quoted;
        else if (!quoted && (i == 0 || space(s.text[i - 1])) &&
                 (ch == '#' || ch == ';' || (ch == '/' && i + 1 < s.size && s.text[i + 1] == '/'))) {
            s.size = i;
            return trim(s);
        }
    }
    if (quoted)
        fail(c, s, path, SOLARIS_EINVAL, "unterminated double quote");
    return trim(s);
}
cfg_node_t *cfg_conf_parse(cfg_context_t *c, const void *bytes, size_t length) {
    span_t input = {(const char *)bytes, length, 1, 1};
    if (length >= 3 && !memcmp(bytes, "\xef\xbb\xbf", 3)) {
        input.text += 3;
        input.size -= 3;
    }
    cfg_node_t *root = node(c, CFG_MAP, input), *section = NULL;
    const char *section_name = "$";
    while (input.size && !c->errors) {
        const char *lf = memchr(input.text, '\n', input.size);
        size_t raw_size = lf ? (size_t)(lf - input.text) : input.size;
        span_t line = slice(input, 0, raw_size);
        if (line.size && line.text[line.size - 1] == '\r' && lf)
            --line.size;
        if (line.size > c->options.line_limit_bytes) {
            fail(c, line, section_name, SOLARIS_EOVERFLOW, "configuration line limit exceeded");
            break;
        }
        if (!utf8(c, line))
            break;
        line = trim(line);
        if (line.size >= 2 && line.text[0] == '#' && line.text[1] == '!') {
            fail(c, line, section_name, SOLARIS_ENOTSUP, "profile directives are not supported");
            break;
        }
        line = uncomment(c, line, section_name);
        if (c->errors)
            break;
        if (line.size) {
            if (c->entries == c->options.entry_limit) {
                fail(c, line, section_name, SOLARIS_EOVERFLOW, "configuration entry limit exceeded");
                break;
            }
            ++c->entries;
            if (line.text[0] == '[') {
                if (line.size < 3 || line.text[line.size - 1] != ']') {
                    fail(c, line, "$", SOLARIS_EINVAL, "invalid section header");
                    break;
                }
                span_t title = slice(line, 1, line.size - 2);
                const char *names[] = {"General",  "Proxy",          "Proxy Group", "Rule",
                                       "Listener", "Authentication", "DNS",         "Host"};
                size_t found = 0;
                for (; found < sizeof(names) / sizeof(*names); ++found)
                    if (strlen(names[found]) == title.size && !memcmp(title.text, names[found], title.size))
                        break;
                if (found == sizeof(names) / sizeof(*names)) {
                    fail(c, title, "$", SOLARIS_ENOTSUP, "unknown or unsupported section");
                    break;
                }
                section_name = names[found];
                unsigned kind = found >= 1 && found <= 4 ? CFG_SEQUENCE : CFG_MAP;
                section = node(c, kind, line);
                pair(c, root, literal(c, section_name, title), section, section_name);
            } else if (!section)
                fail(c, line, "$", SOLARIS_EINVAL, "entry requires a section header");
            else if (!strcmp(section_name, "Rule"))
                append(section, list(c, line, section_name));
            else {
                size_t eq = delimiter(line, '=');
                if (eq == line.size) {
                    fail(c, line, section_name, SOLARIS_EINVAL, "expected name = value");
                    break;
                }
                cfg_node_t *key = scalar(c, slice(line, 0, eq), section_name);
                span_t value = slice(line, eq + 1, line.size - eq - 1);
                if (key && !key->length) {
                    fail(c, line, section_name, SOLARIS_EINVAL, "empty name or key");
                    break;
                }
                if (section->kind == CFG_SEQUENCE)
                    append(section, record(c, key, value, section_name));
                else if (!strcmp(section_name, "Authentication")) {
                    cfg_node_t *auth = node(c, CFG_MAP, value);
                    while (!c->errors) {
                        size_t end = delimiter(value, ',');
                        parameter(c, auth, slice(value, 0, end), section_name);
                        if (end == value.size)
                            break;
                        value = slice(value, end + 1, value.size - end - 1);
                    }
                    pair(c, section, key, auth, section_name);
                } else if (!strcmp(section_name, "Host") ||
                           (!strcmp(section_name, "DNS") && key &&
                            (!strcmp(key->scalar, "upstream") || !strcmp(key->scalar, "direct-upstream") ||
                             !strcmp(key->scalar, "proxy-upstream") || !strcmp(key->scalar, "bootstrap-upstream")))) {
                    cfg_node_t *values = list(c, value, section_name);
                    if (!strcmp(section_name, "Host") && values && values->count == 1)
                        values = values->children;
                    pair(c, section, key, values, section_name);
                } else {
                    if (delimiter(value, ',') != value.size) {
                        fail(c, value, section_name, SOLARIS_EINVAL, "scalar field requires one token");
                        break;
                    }
                    cfg_node_t *v = scalar(c, value, section_name);
                    pair(c, section, key, v, section_name);
                }
            }
        }
        size_t used = raw_size + (lf ? 1 : 0);
        input.text += used;
        input.size -= used;
        ++input.line;
    }
    return c->errors ? NULL : root;
}
