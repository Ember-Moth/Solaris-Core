#include "contracts/io/address.h"
#include <string.h>
#include <uv.h>

solaris_status_t solaris_address_parse(const char *host, uint16_t port, solaris_address_t *out)
{
    if (host == NULL || out == NULL) return SOLARIS_EINVAL;
    memset(out, 0, sizeof(*out));
    size_t length = 0u;
    while (length < sizeof(out->host) && host[length] != '\0') length++;
    if (length == 0u || length >= sizeof(out->host)) return SOLARIS_EINVAL;
    out->port = port;
    if (uv_inet_pton(AF_INET, host, out->ip) == 0) out->family = SOLARIS_ADDRESS_IPV4;
    else if (uv_inet_pton(AF_INET6, host, out->ip) == 0) out->family = SOLARIS_ADDRESS_IPV6;
    else {
        for (size_t i = 0u; i < length; i++) {
            const unsigned char ch = (unsigned char)host[i];
            if (ch <= 0x20u || ch >= 0x7fu || ch == '/' || ch == ':' || ch == '%') return SOLARIS_EINVAL;
            out->host[i] = ch >= 'A' && ch <= 'Z' ? (char)(ch + ('a' - 'A')) : (char)ch;
        }
        out->family = SOLARIS_ADDRESS_DOMAIN;
    }
    return SOLARIS_OK;
}

solaris_status_t solaris_address_to_sockaddr(const solaris_address_t *address,
                                             struct sockaddr_storage *out)
{
    if (address == NULL || out == NULL) return SOLARIS_EINVAL;
    memset(out, 0, sizeof(*out));
    if (address->family == SOLARIS_ADDRESS_IPV4) {
        struct sockaddr_in *a = (struct sockaddr_in *)out;
        a->sin_family = AF_INET; a->sin_port = htons(address->port);
        memcpy(&a->sin_addr, address->ip, 4u);
        return SOLARIS_OK;
    }
    if (address->family == SOLARIS_ADDRESS_IPV6) {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)out;
        a->sin6_family = AF_INET6; a->sin6_port = htons(address->port);
        a->sin6_scope_id = address->scope_id;
        memcpy(&a->sin6_addr, address->ip, 16u);
        return SOLARIS_OK;
    }
    return SOLARIS_ENOTSUP;
}

solaris_status_t solaris_address_from_sockaddr(const struct sockaddr *address, solaris_address_t *out)
{
    if (address == NULL || out == NULL) return SOLARIS_EINVAL;
    memset(out, 0, sizeof(*out));
    if (address->sa_family == AF_INET) {
        const struct sockaddr_in *a = (const struct sockaddr_in *)address;
        out->family = SOLARIS_ADDRESS_IPV4; out->port = ntohs(a->sin_port);
        memcpy(out->ip, &a->sin_addr, 4u);
        return SOLARIS_OK;
    }
    if (address->sa_family == AF_INET6) {
        const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)address;
        out->family = SOLARIS_ADDRESS_IPV6; out->port = ntohs(a->sin6_port);
        out->scope_id = a->sin6_scope_id;
        memcpy(out->ip, &a->sin6_addr, 16u);
        return SOLARIS_OK;
    }
    return SOLARIS_ENOTSUP;
}

int solaris_address_equal(const solaris_address_t *a, const solaris_address_t *b)
{
    if (a == NULL || b == NULL || a->family != b->family || a->port != b->port || a->scope_id != b->scope_id) return 0;
    if (a->family == SOLARIS_ADDRESS_DOMAIN) {
        const char *a_end = memchr(a->host, '\0', sizeof(a->host));
        const char *b_end = memchr(b->host, '\0', sizeof(b->host));
        if (a_end == NULL || b_end == NULL || a_end - a->host != b_end - b->host) return 0;
        return memcmp(a->host, b->host, (size_t)(a_end - a->host)) == 0;
    }
    if (a->family == SOLARIS_ADDRESS_IPV4) return memcmp(a->ip, b->ip, 4u) == 0;
    if (a->family == SOLARIS_ADDRESS_IPV6) return memcmp(a->ip, b->ip, 16u) == 0;
    return 0;
}
