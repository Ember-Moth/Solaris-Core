#include "codec/http/proxy.h"
#include "solaris_llhttp_symbols.h"
#include <llhttp.h>
#include <string.h>
#include <stdio.h>

struct solaris_http_request {
    solaris_budget_t *budget;
    llhttp_t parser;
    llhttp_settings_t settings;
    size_t limit, trailer_name_length, tail_length;
    uint8_t *tail;
    char trailer_name[256];
    int headers, complete, trailer, websocket;
};
typedef struct field {
    const uint8_t *name, *value;
    size_t name_length, value_length;
} field_t;
static uint8_t lower(uint8_t c)
{
    return c >= 'A' && c <= 'Z' ? (uint8_t)(c + ('a' - 'A')) : c;
}
static int equal(const uint8_t *s, size_t n, const char *text)
{
    if (n != strlen(text))
        return 0;
    for (size_t i = 0; i < n; ++i)
        if (lower(s[i]) != (uint8_t)text[i])
            return 0;
    return 1;
}
static int forbidden_trailer(const uint8_t *name, size_t n)
{
    const char *names[] = {"host",
                           "content-length",
                           "transfer-encoding",
                           "connection",
                           "proxy-authorization",
                           "proxy-authenticate",
                           "authorization",
                           "trailer",
                           "te",
                           "upgrade",
                           "keep-alive",
                           "proxy-connection",
                           "content-encoding",
                           "content-type",
                           "content-range",
                           "expect"};
    for (size_t i = 0; i < sizeof(names) / sizeof(*names); ++i)
        if (equal(name, n, names[i]))
            return 1;
    return 0;
}
static int headers_done(llhttp_t *p)
{
    solaris_http_request_t *r = p->data;
    if (!r->headers) {
        r->headers = 1;
        return HPE_PAUSED;
    }
    return 0;
}
static int message_done(llhttp_t *p)
{
    ((solaris_http_request_t *)p->data)->complete = 1;
    return HPE_PAUSED;
}
static int field_data(llhttp_t *p, const char *data, size_t n)
{
    solaris_http_request_t *r = p->data;
    if (!(p->flags & F_TRAILING))
        return 0;
    r->trailer = 1;
    if (n > sizeof(r->trailer_name) - r->trailer_name_length)
        return HPE_USER;
    memcpy(r->trailer_name + r->trailer_name_length, data, n);
    r->trailer_name_length += n;
    return 0;
}
static int field_done(llhttp_t *p)
{
    solaris_http_request_t *r = p->data;
    if (!(p->flags & F_TRAILING))
        return 0;
    int forbidden = forbidden_trailer((const uint8_t *)r->trailer_name, r->trailer_name_length);
    r->trailer_name_length = 0;
    return forbidden ? HPE_USER : 0;
}
static int token_in(const uint8_t *value, size_t n, const uint8_t *token, size_t size)
{
    for (size_t i = 0; i < n;) {
        while (i < n && (value[i] == ' ' || value[i] == '\t' || value[i] == ','))
            ++i;
        size_t start = i;
        while (i < n && value[i] != ',')
            ++i;
        size_t end = i;
        while (end > start && (value[end - 1] == ' ' || value[end - 1] == '\t'))
            --end;
        if (end - start == size) {
            size_t j = 0;
            for (; j < size && lower(value[start + j]) == lower(token[j]); ++j) {
            }
            if (j == size)
                return 1;
        }
    }
    return 0;
}
static int next_field(const uint8_t **cursor, const uint8_t *end, field_t *f)
{
    const uint8_t *p = *cursor;
    if (p + 2 > end || (p[0] == '\r' && p[1] == '\n'))
        return 0;
    const uint8_t *colon = memchr(p, ':', (size_t)(end - p));
    const uint8_t *eol = memchr(p, '\r', (size_t)(end - p));
    if (!colon || !eol || colon >= eol || eol + 1 >= end || eol[1] != '\n')
        return -1;
    f->name = p;
    f->name_length = (size_t)(colon - p);
    p = colon + 1;
    while (p < eol && (*p == ' ' || *p == '\t'))
        ++p;
    f->value = p;
    const uint8_t *stop = eol;
    while (stop > p && (stop[-1] == ' ' || stop[-1] == '\t'))
        --stop;
    f->value_length = (size_t)(stop - p);
    *cursor = eol + 2;
    return 1;
}
static solaris_status_t authority(const uint8_t *s, size_t n, int required_port, solaris_address_t *out,
                                  char *canonical, size_t capacity)
{
    if (!n || n > 262)
        return SOLARIS_EINVAL;
    for (size_t i = 0; i < n; ++i)
        if (s[i] <= 32 || s[i] >= 127 || strchr("/@?#\\%,", s[i]))
            return SOLARIS_EINVAL;
    size_t host_length, port_start = n;
    const uint8_t *host = s;
    int ipv6 = 0;
    if (s[0] == '[') {
        const uint8_t *close = memchr(s, ']', n);
        if (!close)
            return SOLARIS_EINVAL;
        host = s + 1;
        host_length = (size_t)(close - host);
        ipv6 = 1;
        size_t index = (size_t)(close - s) + 1;
        if (index < n) {
            if (s[index] != ':')
                return SOLARIS_EINVAL;
            port_start = index + 1;
        }
    } else {
        const uint8_t *colon = memchr(s, ':', n);
        host_length = colon ? (size_t)(colon - s) : n;
        if (colon)
            port_start = host_length + 1;
        for (size_t i = 0; i < host_length; ++i)
            if (!((s[i] >= 'a' && s[i] <= 'z') || (s[i] >= 'A' && s[i] <= 'Z') || (s[i] >= '0' && s[i] <= '9') ||
                  s[i] == '.' || s[i] == '-' || s[i] == '_'))
                return SOLARIS_EINVAL;
    }
    if (!host_length || host_length > 255 || (port_start == n && s[n - 1] == ':'))
        return SOLARIS_EINVAL;
    unsigned port = 80;
    if (port_start < n) {
        port = 0;
        for (size_t i = port_start; i < n; ++i) {
            if (s[i] < '0' || s[i] > '9' || port > 6553)
                return SOLARIS_EINVAL;
            port = port * 10u + (unsigned)(s[i] - '0');
        }
        if (!port || port > 65535)
            return SOLARIS_EINVAL;
    } else if (required_port)
        return SOLARIS_EINVAL;
    char text[256];
    memcpy(text, host, host_length);
    text[host_length] = 0;
    for (size_t i = 0; i < host_length; ++i)
        text[i] = (char)lower((uint8_t)text[i]);
    solaris_status_t rc = solaris_address_parse(text, (uint16_t)port, out);
    if (rc != SOLARIS_OK || (ipv6 && out->family != SOLARIS_ADDRESS_IPV6))
        return SOLARIS_EINVAL;
    int written = snprintf(canonical, capacity, ipv6 ? "[%s]:%u" : "%s:%u", text, port);
    return written < 0 || (size_t)written >= capacity ? SOLARIS_EMSGSIZE : SOLARIS_OK;
}
static int base64_value(uint8_t c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    if (c == '+')
        return 62;
    if (c == '/')
        return 63;
    return -1;
}
static int websocket_base64(const uint8_t *value, size_t length, int key)
{
    size_t size = key ? 24 : 28, padding = key ? 2 : 1;
    if (length != size)
        return 0;
    for (size_t i = 0; i < size - padding; ++i)
        if (base64_value(value[i]) < 0)
            return 0;
    for (size_t i = size - padding; i < size; ++i)
        if (value[i] != '=')
            return 0;
    return !(base64_value(value[size - padding - 1]) & (key ? 15 : 3));
}
static solaris_status_t credentials(const uint8_t *s, size_t n, solaris_http_metadata_t *m)
{
    if (n < 6 || !equal(s, 5, "basic") || s[5] != ' ')
        return SOLARIS_EINVAL;
    s += 6;
    n -= 6;
    if (!n || n % 4 || n > 684)
        return SOLARIS_EINVAL;
    uint8_t decoded[513] = {0};
    size_t used = 0;
    solaris_status_t rc = SOLARIS_EINVAL;
    for (size_t i = 0; i < n; i += 4) {
        int a = base64_value(s[i]), b = base64_value(s[i + 1]);
        int c = s[i + 2] == '=' ? 0 : base64_value(s[i + 2]);
        int d = s[i + 3] == '=' ? 0 : base64_value(s[i + 3]);
        if (a < 0 || b < 0 || c < 0 || d < 0)
            goto done;
        int padding = (s[i + 2] == '=') + (s[i + 3] == '=');
        if ((padding && i + 4 != n) || (s[i + 2] == '=' && s[i + 3] != '=') || (padding == 2 && (b & 15)) ||
            (padding == 1 && (c & 3)))
            goto done;
        decoded[used++] = (uint8_t)((a << 2) | (b >> 4));
        if (padding < 2)
            decoded[used++] = (uint8_t)((b << 4) | (c >> 2));
        if (!padding)
            decoded[used++] = (uint8_t)((c << 6) | d);
    }
    const uint8_t *colon = memchr(decoded, ':', used);
    if (!colon)
        goto done;
    size_t user = (size_t)(colon - decoded), pass = used - user - 1;
    if (user > 255 || pass > 255)
        goto done;
    memcpy(m->username, decoded, user);
    memcpy(m->password, colon + 1, pass);
    m->username_length = user;
    m->password_length = pass;
    m->credentials = 1;
    rc = SOLARIS_OK;
done:
    for (size_t i = 0; i < sizeof(decoded); ++i)
        ((volatile uint8_t *)decoded)[i] = 0;
    return rc;
}
void solaris_http_credentials_clear(solaris_http_metadata_t *m)
{
    for (size_t i = 0; i < sizeof(m->password); ++i)
        ((volatile uint8_t *)m->password)[i] = 0;
    m->password_length = 0;
}
solaris_status_t solaris_http_request_create(solaris_budget_t *budget, const uint8_t *data, size_t length, size_t limit,
                                             solaris_http_metadata_t *m, solaris_buffer_t **header,
                                             solaris_http_request_t **out)
{
    *out = NULL;
    *header = NULL;
    memset(m, 0, sizeof(*m));
    if (length > limit || length < 4 || memcmp(data + length - 4, "\r\n\r\n", 4))
        return SOLARIS_EINVAL;
    solaris_http_request_t *r = solaris_memory_allocate(budget, sizeof(*r));
    if (!r)
        return SOLARIS_ENOMEM;
    memset(r, 0, sizeof(*r));
    r->budget = budget;
    r->limit = limit;
    llhttp_settings_init(&r->settings);
    r->settings.on_headers_complete = headers_done;
    r->settings.on_message_complete = message_done;
    r->settings.on_header_field = field_data;
    r->settings.on_header_field_complete = field_done;
    llhttp_init(&r->parser, HTTP_REQUEST, &r->settings);
    r->parser.data = r;
    solaris_status_t rc = SOLARIS_EINVAL;
    if (llhttp_execute(&r->parser, (const char *)data, length) != HPE_PAUSED || !r->headers ||
        r->parser.http_major != 1 || r->parser.http_minor > 1)
        goto failed;
    const uint8_t *line = memchr(data, '\r', length);
    const uint8_t *space = memchr(data, ' ', (size_t)(line - data));
    if (!space)
        goto failed;
    size_t method_length = (size_t)(space - data);
    const uint8_t *uri = space + 1, *uri_end = memchr(uri, ' ', (size_t)(line - uri));
    if (!uri_end)
        goto failed;
    size_t uri_length = (size_t)(uri_end - uri);
    for (size_t i = 0; i < uri_length; ++i)
        if (uri[i] <= 32 || uri[i] >= 127 || uri[i] == '#' || uri[i] == '\\')
            goto failed;
    m->connect = r->parser.method == HTTP_CONNECT;
    field_t host = {0}, auth = {0}, f;
    unsigned upgrades = 0, keys = 0, versions = 0;
    int connection_upgrade = 0, connection_close = 0, expect = 0;
    const uint8_t *cursor = line + 2, *end = data + length;
    unsigned cl = 0, te = 0, hosts = 0, auths = 0, fields = 0;
    while (next_field(&cursor, end, &f) > 0) {
        if (++fields > 256)
            goto failed;
        if (equal(f.name, f.name_length, "host")) {
            host = f;
            ++hosts;
        }
        if (equal(f.name, f.name_length, "proxy-authorization")) {
            auth = f;
            ++auths;
        }
        if (equal(f.name, f.name_length, "content-length"))
            ++cl;
        if (equal(f.name, f.name_length, "transfer-encoding")) {
            ++te;
            if (!equal(f.value, f.value_length, "chunked"))
                goto failed;
        }
        if (equal(f.name, f.name_length, "upgrade")) {
            if (++upgrades > 1 || !equal(f.value, f.value_length, "websocket"))
                goto failed;
        }
        if (equal(f.name, f.name_length, "sec-websocket-key")) {
            if (++keys > 1 || !websocket_base64(f.value, f.value_length, 1))
                goto failed;
        }
        if (equal(f.name, f.name_length, "sec-websocket-version")) {
            if (++versions > 1 || !equal(f.value, f.value_length, "13"))
                goto failed;
        }
        if (equal(f.name, f.name_length, "expect"))
            expect = 1;
        if (equal(f.name, f.name_length, "connection")) {
            connection_upgrade |= token_in(f.value, f.value_length, (const uint8_t *)"upgrade", 7);
            connection_close |= token_in(f.value, f.value_length, (const uint8_t *)"close", 5);
        }
        if (equal(f.name, f.name_length, "connection") || equal(f.name, f.name_length, "proxy-connection")) {
            const char *critical[] = {"host",
                                      "content-length",
                                      "transfer-encoding",
                                      "proxy-authorization",
                                      "trailer",
                                      "sec-websocket-key",
                                      "sec-websocket-version",
                                      "sec-websocket-protocol",
                                      "sec-websocket-extensions"};
            for (size_t i = 0; i < sizeof(critical) / sizeof(*critical); ++i)
                if (token_in(f.value, f.value_length, (const uint8_t *)critical[i], strlen(critical[i])))
                    goto failed;
        }
    }
    if (hosts > 1 || cl > 1 || te > 1 || (cl && te) || auths > 1 || (r->parser.http_minor == 1 && hosts != 1))
        goto failed;
    if (m->connect && (te || cl))
        goto failed;
    if (upgrades || connection_upgrade || keys || versions) {
        if (upgrades != 1 || !connection_upgrade || connection_close || keys != 1 || versions != 1 ||
            r->parser.method != HTTP_GET || r->parser.http_minor != 1 || te || expect ||
            (cl && r->parser.content_length != 0))
            goto failed;
        r->websocket = m->websocket = 1;
    }
    char canonical[280], provided[280];
    solaris_address_t host_address;
    if (hosts && authority(host.value, host.value_length, 0, &host_address, provided, sizeof(provided)) != SOLARIS_OK)
        goto failed;
    const uint8_t *path = uri;
    size_t path_length = uri_length;
    int query_path = 0;
    if (m->connect) {
        if (authority(uri, uri_length, 1, &m->destination, canonical, sizeof(canonical)) != SOLARIS_OK)
            goto failed;
    } else if ((uri_length >= 7 && equal(uri, 7, "http://")) ||
               (m->websocket && uri_length >= 5 && equal(uri, 5, "ws://"))) {
        size_t prefix = equal(uri, 5, "ws://") ? 5 : 7;
        size_t stop = prefix;
        while (stop < uri_length && uri[stop] != '/' && uri[stop] != '?')
            ++stop;
        if (authority(uri + prefix, stop - prefix, 0, &m->destination, canonical, sizeof(canonical)) != SOLARIS_OK)
            goto failed;
        path = uri + stop;
        path_length = uri_length - stop;
        if (!path_length) {
            path = (const uint8_t *)"/";
            path_length = 1;
        } else if (path[0] == '?')
            query_path = 1;
    } else {
        if (!hosts || !uri_length || uri[0] != '/')
            goto failed;
        m->destination = host_address;
        memcpy(canonical, provided, strlen(provided) + 1);
    }
    if (hosts && !solaris_address_equal(&host_address, &m->destination))
        goto failed;
    if (auths && credentials(auth.value, auth.value_length, m) != SOLARIS_OK)
        goto failed;
    if (!m->connect) {
        solaris_buffer_t *output;
        rc = solaris_buffer_allocate(budget, length + 512, &output);
        if (rc != SOLARIS_OK)
            goto failed;
        uint8_t *p = solaris_buffer_mutable_data(output);
        size_t n = 0;
        memcpy(p, data, method_length);
        n += method_length;
        p[n++] = ' ';
        if (query_path)
            p[n++] = '/';
        memcpy(p + n, path, path_length);
        n += path_length;
        int wrote =
            snprintf((char *)p + n, length + 512 - n, " HTTP/1.1\r\nHost: %s\r\nConnection: %s\r\n%s", canonical,
                     m->websocket ? "Upgrade" : "close", m->websocket ? "Upgrade: websocket\r\n" : "");
        if (wrote < 0) {
            solaris_buffer_release(output);
            rc = SOLARIS_EIO;
            goto failed;
        }
        n += (size_t)wrote;
        cursor = line + 2;
        while (next_field(&cursor, end, &f) > 0) {
            const char *strip[] = {
                "host", "proxy-authorization", "proxy-connection", "connection", "keep-alive", "te", "upgrade"};
            int skip = m->websocket && equal(f.name, f.name_length, "content-length");
            for (size_t i = 0; i < sizeof(strip) / sizeof(*strip); ++i)
                if (equal(f.name, f.name_length, strip[i]))
                    skip = 1;
            const uint8_t *scan = line + 2;
            field_t other;
            while (!skip && next_field(&scan, end, &other) > 0)
                if ((equal(other.name, other.name_length, "connection") ||
                     equal(other.name, other.name_length, "proxy-connection")) &&
                    token_in(other.value, other.value_length, f.name, f.name_length))
                    skip = 1;
            if (skip)
                continue;
            memcpy(p + n, f.name, f.name_length);
            n += f.name_length;
            p[n++] = ':';
            memcpy(p + n, f.value, f.value_length);
            n += f.value_length;
            p[n++] = '\r';
            p[n++] = '\n';
        }
        p[n++] = '\r';
        p[n++] = '\n';
        (void)solaris_buffer_set_length(output, n);
        *header = output;
        if (!m->websocket)
            llhttp_resume(&r->parser);
    }
    *out = r;
    return SOLARIS_OK;
failed:
    solaris_http_credentials_clear(m);
    solaris_http_request_destroy(r);
    return rc;
}
solaris_status_t solaris_http_request_body(solaris_http_request_t *r, const uint8_t *data, size_t length,
                                           size_t *consumed, solaris_buffer_t **out)
{
    *consumed = 0;
    *out = NULL;
    if (r->websocket)
        return SOLARIS_ENOTSUP;
    if (r->complete)
        return SOLARIS_OK;
    const char *input = length ? (const char *)data : "";
    llhttp_errno_t e = llhttp_execute(&r->parser, input, length);
    if (e != HPE_OK && !(e == HPE_PAUSED && r->complete))
        return SOLARIS_EINVAL;
    size_t used = e == HPE_PAUSED ? (size_t)(llhttp_get_error_pos(&r->parser) - input) : length;
    if (used > length)
        return SOLARIS_EIO;
    *consumed = used;
    int trailing = r->trailer || (r->parser.flags & F_TRAILING);
    if (trailing || r->tail) {
        if (used > r->limit + 8192 - r->tail_length)
            return SOLARIS_EMSGSIZE;
        if (!r->tail) {
            r->tail = solaris_memory_allocate(r->budget, r->limit + 8192);
            if (!r->tail)
                return SOLARIS_ENOMEM;
        }
        if (used)
            memcpy(r->tail + r->tail_length, data, used);
        r->tail_length += used;
        if (!r->complete)
            return SOLARIS_OK;
        solaris_status_t rc = solaris_buffer_copy(r->budget, r->tail, r->tail_length, out);
        solaris_memory_free(r->tail);
        r->tail = NULL;
        r->tail_length = 0;
        return rc;
    }
    return used ? solaris_buffer_copy(r->budget, data, used, out) : SOLARIS_OK;
}
int solaris_http_request_complete(const solaris_http_request_t *r)
{
    return r->complete;
}
solaris_status_t solaris_http_request_eof(solaris_http_request_t *r)
{
    if (r->complete)
        return SOLARIS_OK;
    llhttp_errno_t status = llhttp_finish(&r->parser);
    return r->complete || status == HPE_OK ? SOLARIS_OK : SOLARIS_EINVAL;
}
void solaris_http_request_destroy(solaris_http_request_t *r)
{
    if (r) {
        solaris_memory_free(r->tail);
        solaris_memory_free(r);
    }
}

struct solaris_http_upgrade_response {
    solaris_http_request_t body;
    uint8_t *header;
    size_t length, message_offset;
    unsigned informational;
    int state;
};
solaris_status_t solaris_http_upgrade_response_create(solaris_budget_t *budget, size_t limit,
                                                      solaris_http_upgrade_response_t **out)
{
    *out = NULL;
    if (limit < 4 || limit > 1048576)
        return SOLARIS_EINVAL;
    solaris_http_upgrade_response_t *r = solaris_memory_allocate(budget, sizeof(*r));
    if (!r)
        return SOLARIS_ENOMEM;
    memset(r, 0, sizeof(*r));
    r->body.budget = budget;
    r->body.limit = limit;
    r->header = solaris_memory_allocate(budget, limit);
    if (!r->header) {
        solaris_memory_free(r);
        return SOLARIS_ENOMEM;
    }
    *out = r;
    return SOLARIS_OK;
}
static solaris_status_t response_header(solaris_http_upgrade_response_t *r)
{
    solaris_http_request_t *body = &r->body;
    body->headers = 0;
    llhttp_settings_init(&body->settings);
    body->settings.on_headers_complete = headers_done;
    body->settings.on_message_complete = message_done;
    body->settings.on_header_field = field_data;
    body->settings.on_header_field_complete = field_done;
    llhttp_init(&body->parser, HTTP_RESPONSE, &body->settings);
    body->parser.data = body;
    const uint8_t *data = r->header + r->message_offset, *end = r->header + r->length;
    if (llhttp_execute(&body->parser, (const char *)data, (size_t)(end - data)) != HPE_PAUSED ||
        llhttp_get_error_pos(&body->parser) != (const char *)end || !body->headers || body->parser.http_major != 1 ||
        body->parser.http_minor > 1)
        return SOLARIS_EINVAL;
    unsigned status = body->parser.status_code;
    if (status < 100 || status > 599)
        return SOLARIS_EINVAL;
    unsigned cl = 0, te = 0, upgrade = 0, accept = 0, fields = 0;
    int connection_upgrade = 0, connection_close = 0;
    field_t f;
    const uint8_t *cursor = memchr(data, '\r', (size_t)(end - data));
    if (!cursor)
        return SOLARIS_EINVAL;
    cursor += 2;
    while (next_field(&cursor, end, &f) > 0) {
        if (++fields > 256)
            return SOLARIS_EINVAL;
        if (equal(f.name, f.name_length, "content-length"))
            ++cl;
        if (equal(f.name, f.name_length, "transfer-encoding")) {
            ++te;
            if (!equal(f.value, f.value_length, "chunked"))
                return SOLARIS_EINVAL;
        }
        if (equal(f.name, f.name_length, "upgrade")) {
            ++upgrade;
            if (status == 101 && !equal(f.value, f.value_length, "websocket"))
                return SOLARIS_EINVAL;
        }
        if (equal(f.name, f.name_length, "sec-websocket-accept")) {
            ++accept;
            if (status == 101 && !websocket_base64(f.value, f.value_length, 0))
                return SOLARIS_EINVAL;
        }
        if (equal(f.name, f.name_length, "connection")) {
            connection_upgrade |= token_in(f.value, f.value_length, (const uint8_t *)"upgrade", 7);
            connection_close |= token_in(f.value, f.value_length, (const uint8_t *)"close", 5);
        }
        if (equal(f.name, f.name_length, "connection") || equal(f.name, f.name_length, "proxy-connection")) {
            const char *critical[] = {"content-length",       "transfer-encoding",      "trailer",
                                      "sec-websocket-accept", "sec-websocket-protocol", "sec-websocket-extensions"};
            for (size_t i = 0; i < sizeof(critical) / sizeof(*critical); ++i)
                if (token_in(f.value, f.value_length, (const uint8_t *)critical[i], strlen(critical[i])))
                    return SOLARIS_EINVAL;
        }
    }
    if (cl > 1 || te > 1 || (cl && te) || (status < 200 && (cl || te)))
        return SOLARIS_EINVAL;
    if (status == 101) {
        if (body->parser.http_minor != 1 || upgrade != 1 || !connection_upgrade || connection_close || accept != 1)
            return SOLARIS_EINVAL;
        r->state = SOLARIS_HTTP_UPGRADE_ACCEPTED;
    } else if (status < 200) {
        if (++r->informational > 16 || upgrade || connection_upgrade)
            return SOLARIS_EINVAL;
        r->message_offset = r->length;
    } else {
        r->state = SOLARIS_HTTP_UPGRADE_REJECTED;
        llhttp_resume(&body->parser);
    }
    return SOLARIS_OK;
}
static size_t response_rewrite(solaris_http_upgrade_response_t *r, uint8_t *out)
{
    size_t offset = 0, written = 0;
    while (offset < r->length) {
        const uint8_t *data = r->header + offset, *end = NULL;
        for (size_t i = offset + 3; i < r->length; ++i)
            if (!memcmp(r->header + i - 3, "\r\n\r\n", 4)) {
                end = r->header + i + 1;
                break;
            }
        const uint8_t *line = memchr(data, '\r', (size_t)(end - data));
        size_t line_size = (size_t)(line + 2 - data);
        memcpy(out + written, data, line_size);
        written += line_size;
        if (end == r->header + r->length) {
            const char *connection = r->state == SOLARIS_HTTP_UPGRADE_ACCEPTED
                                         ? "Connection: Upgrade\r\nUpgrade: websocket\r\n"
                                         : "Connection: close\r\n";
            memcpy(out + written, connection, strlen(connection));
            written += strlen(connection);
        }
        const uint8_t *cursor = line + 2;
        field_t f;
        while (next_field(&cursor, end, &f) > 0) {
            const char *strip[] = {"connection",         "upgrade", "proxy-connection",
                                   "keep-alive",         "te",      "proxy-authenticate",
                                   "proxy-authorization"};
            int skip = 0;
            for (size_t i = 0; i < sizeof(strip) / sizeof(*strip); ++i)
                if (equal(f.name, f.name_length, strip[i]))
                    skip = 1;
            const uint8_t *scan = line + 2;
            field_t other;
            while (!skip && next_field(&scan, end, &other) > 0)
                if ((equal(other.name, other.name_length, "connection") ||
                     equal(other.name, other.name_length, "proxy-connection")) &&
                    token_in(other.value, other.value_length, f.name, f.name_length))
                    skip = 1;
            if (skip)
                continue;
            memcpy(out + written, f.name, f.name_length);
            written += f.name_length;
            out[written++] = ':';
            memcpy(out + written, f.value, f.value_length);
            written += f.value_length;
            out[written++] = '\r';
            out[written++] = '\n';
        }
        out[written++] = '\r';
        out[written++] = '\n';
        offset = (size_t)(end - r->header);
    }
    return written;
}
solaris_status_t solaris_http_upgrade_response_feed(solaris_http_upgrade_response_t *r, const uint8_t *data,
                                                    size_t length, solaris_buffer_t **out)
{
    *out = NULL;
    if (r->state == SOLARIS_HTTP_UPGRADE_ACCEPTED)
        return length ? solaris_buffer_copy(r->body.budget, data, length, out) : SOLARIS_OK;
    if (r->state == SOLARIS_HTTP_UPGRADE_REJECTED) {
        size_t used;
        return solaris_http_request_body(&r->body, data, length, &used, out);
    }
    size_t offset = 0;
    while (offset < length && r->state == SOLARIS_HTTP_UPGRADE_PENDING) {
        if (r->length == r->body.limit)
            return SOLARIS_EMSGSIZE;
        r->header[r->length++] = data[offset++];
        if (r->length - r->message_offset >= 4 && !memcmp(r->header + r->length - 4, "\r\n\r\n", 4)) {
            solaris_status_t rc = response_header(r);
            if (rc != SOLARIS_OK)
                return rc;
        }
    }
    if (r->state == SOLARIS_HTTP_UPGRADE_PENDING)
        return SOLARIS_OK;
    solaris_buffer_t *body = NULL;
    const uint8_t *tail = data + offset;
    size_t tail_size = length - offset;
    if (r->state == SOLARIS_HTTP_UPGRADE_REJECTED) {
        size_t used;
        solaris_status_t rc = solaris_http_request_body(&r->body, tail, tail_size, &used, &body);
        if (rc != SOLARIS_OK)
            return rc;
        tail_size = body ? solaris_buffer_length(body) : 0;
        tail = body ? solaris_buffer_data(body) : NULL;
    }
    solaris_status_t rc = solaris_buffer_allocate(r->body.budget, r->length + 128 + tail_size, out);
    if (rc == SOLARIS_OK) {
        uint8_t *p = solaris_buffer_mutable_data(*out);
        size_t n = response_rewrite(r, p);
        if (tail_size)
            memcpy(p + n, tail, tail_size);
        (void)solaris_buffer_set_length(*out, n + tail_size);
    }
    solaris_buffer_release(body);
    return rc;
}
int solaris_http_upgrade_response_state(const solaris_http_upgrade_response_t *r)
{
    return r->state;
}
int solaris_http_upgrade_response_complete(const solaris_http_upgrade_response_t *r)
{
    return r->state == SOLARIS_HTTP_UPGRADE_REJECTED && r->body.complete;
}
solaris_status_t solaris_http_upgrade_response_eof(solaris_http_upgrade_response_t *r)
{
    if (r->state == SOLARIS_HTTP_UPGRADE_PENDING)
        return SOLARIS_EINVAL;
    return r->state == SOLARIS_HTTP_UPGRADE_ACCEPTED ? SOLARIS_OK : solaris_http_request_eof(&r->body);
}
void solaris_http_upgrade_response_destroy(solaris_http_upgrade_response_t *r)
{
    if (r) {
        solaris_memory_free(r->body.tail);
        solaris_memory_free(r->header);
        solaris_memory_free(r);
    }
}
