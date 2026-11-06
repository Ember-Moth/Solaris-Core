#include "observe/probe/http_codec.h"
#include <stdio.h>
#include <string.h>

static int port_number(const char *first, const char *last, uint16_t *port)
{
    if (first == last) return 0;
    unsigned int value = 0u;
    for (const char *p = first; p < last; ++p) {
        if (*p < '0' || *p > '9') return 0;
        value = value * 10u + (unsigned int)(*p - '0'); if (value > 65535u) return 0;
    }
    if (value == 0u) return 0;
    *port = (uint16_t)value; return 1;
}
solaris_status_t solaris_http_probe_request(solaris_budget_t *budget, const char *url,
    solaris_http_probe_target_t *target, solaris_buffer_t **request)
{
    if (request == NULL || target == NULL) return SOLARIS_EINVAL;
    *request = NULL; memset(target, 0, sizeof(*target));
    if (budget == NULL || url == NULL) return SOLARIS_EINVAL;
    size_t size = strlen(url); if (size > 2048u) return SOLARIS_EINVAL;
    for (size_t i = 0u; i < size; ++i) if ((unsigned char)url[i] <= 32u || (unsigned char)url[i] == 127u) return SOLARIS_EINVAL;
    const char *authority;
    if (strncmp(url, "https://", 8u) == 0) { target->tls = 1; authority = url + 8u; }
    else if (strncmp(url, "http://", 7u) == 0) authority = url + 7u;
    else return SOLARIS_ENOTSUP;
    const char *end = authority + strcspn(authority, "/?#");
    const char *host = authority, *host_end = end; uint16_t port = target->tls ? 443u : 80u; int ipv6 = 0;
    if (authority < end && *authority == '[') {
        ipv6 = 1; host = authority + 1u; host_end = memchr(host, ']', (size_t)(end - host));
        if (host_end == NULL || (host_end + 1u != end && (host_end[1] != ':' || !port_number(host_end + 2u, end, &port)))) return SOLARIS_EINVAL;
    } else {
        const char *colon = memchr(authority, ':', (size_t)(end - authority));
        if (colon != NULL) { host_end = colon; if (!port_number(colon + 1u, end, &port)) return SOLARIS_EINVAL; }
    }
    size_t host_size = (size_t)(host_end - host); if (host_size == 0u || host_size > 253u) return SOLARIS_EINVAL;
    for (size_t i = 0u; i < host_size; ++i) {
        unsigned char c = (unsigned char)host[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_' || (ipv6 && c == ':'))) return SOLARIS_EINVAL;
    }
    memcpy(target->identity, host, host_size); target->identity[host_size] = '\0';
    solaris_status_t rc = solaris_address_parse(target->identity, port, &target->address);
    if (rc != SOLARIS_OK || target->address.scope_id != 0u || (ipv6 && target->address.family != SOLARIS_ADDRESS_IPV6)) return SOLARIS_EINVAL;
    const char *path_end = strchr(end, '#'); if (path_end == NULL) path_end = url + size;
    size_t path_size = (size_t)(path_end - end);
    char path[2050]; size_t offset = 0u;
    if (path_size == 0u || *end == '?') path[offset++] = '/';
    if (path_size != 0u) { memcpy(path + offset, end, path_size); offset += path_size; }
    path[offset] = '\0';
    char bytes[4096]; int n = snprintf(bytes, sizeof(bytes), "HEAD %s HTTP/1.1\r\nHost: %s%s%s:%u\r\nConnection: close\r\nUser-Agent: Solaris\r\n\r\n",
        path, ipv6 ? "[" : "", target->identity, ipv6 ? "]" : "", port);
    if (n <= 0 || (size_t)n >= sizeof(bytes)) return SOLARIS_EMSGSIZE;
    return solaris_buffer_copy(budget, bytes, (size_t)n, request);
}
static int token(uint8_t c)
{
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) return 1;
    return strchr("!#$%&'*+-.^_`|~", (int)c) != NULL && c != 0u;
}
solaris_status_t solaris_http_probe_response(const uint8_t *header, size_t length, uint16_t *status)
{
    if (status == NULL) return SOLARIS_EINVAL;
    *status = 0u;
    if (header == NULL || length < 16u || length > SOLARIS_HTTP_PROBE_HEADER_LIMIT ||
        memcmp(header + length - 4u, "\r\n\r\n", 4u) != 0) return SOLARIS_EIO;
    size_t line = 0u;
    while (line + 1u < length && !(header[line] == '\r' && header[line + 1u] == '\n')) line++;
    if (line < 12u || (memcmp(header, "HTTP/1.0 ", 9u) != 0 && memcmp(header, "HTTP/1.1 ", 9u) != 0) ||
        header[9] < '1' || header[9] > '5' || header[10] < '0' || header[10] > '9' || header[11] < '0' || header[11] > '9' ||
        (line > 12u && header[12] != ' ')) return SOLARIS_EIO;
    for (size_t i = 12u; i < line; ++i) if (header[i] < 32u || header[i] == 127u) return SOLARIS_EIO;
    uint16_t code = (uint16_t)((header[9] - '0') * 100u + (header[10] - '0') * 10u + header[11] - '0');
    size_t start = line + 2u;
    while (start < length - 2u) {
        line = start;
        while (line + 1u < length && !(header[line] == '\r' && header[line + 1u] == '\n')) line++;
        if (line == start || line + 1u >= length) return SOLARIS_EIO;
        size_t colon = start; while (colon < line && header[colon] != ':') { if (!token(header[colon])) return SOLARIS_EIO; colon++; }
        if (colon == start || colon == line) return SOLARIS_EIO;
        for (size_t i = colon + 1u; i < line; ++i) if ((header[i] < 32u && header[i] != '\t') || header[i] == 127u) return SOLARIS_EIO;
        start = line + 2u;
    }
    if (start != length - 2u) return SOLARIS_EIO;
    *status = code; return SOLARIS_OK;
}
