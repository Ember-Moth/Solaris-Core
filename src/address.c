#include "aproxy/address.h"

#include <string.h>

#include "byteorder.h"
#include "platform.h"

void aproxy_addr_set_ipv4(aproxy_addr_t *addr,
                          const uint8_t ipv4[4],
                          uint16_t port)
{
    if (addr == NULL || ipv4 == NULL) {
        return;
    }
    memset(addr, 0, sizeof(*addr));
    addr->family = APROXY_ADDR_IPV4;
    addr->port = port;
    memcpy(addr->addr, ipv4, 4u);
}

void aproxy_addr_set_ipv6(aproxy_addr_t *addr,
                          const uint8_t ipv6[16],
                          uint16_t port)
{
    if (addr == NULL || ipv6 == NULL) {
        return;
    }
    memset(addr, 0, sizeof(*addr));
    addr->family = APROXY_ADDR_IPV6;
    addr->port = port;
    memcpy(addr->addr, ipv6, 16u);
}

int aproxy_addr_set_fqdn(aproxy_addr_t *addr,
                         const char *fqdn,
                         uint16_t port)
{
    if (addr == NULL || fqdn == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    const size_t len = strlen(fqdn);
    if (len == 0u || len > APROXY_ADDR_MAX_FQDN) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    memset(addr, 0, sizeof(*addr));
    addr->family = APROXY_ADDR_FQDN;
    addr->port = port;
    addr->fqdn_len = len;
    memcpy(addr->fqdn, fqdn, len);
    addr->fqdn[len] = '\0';
    return APROXY_OK;
}

aproxy_addr_family_t aproxy_addr_get_family(const aproxy_addr_t *addr)
{
    return addr == NULL ? (aproxy_addr_family_t)0 : addr->family;
}

uint16_t aproxy_addr_get_port(const aproxy_addr_t *addr)
{
    return addr == NULL ? 0u : addr->port;
}

int aproxy_addr_format_host(const aproxy_addr_t *addr,
                            char *out,
                            size_t out_capacity,
                            size_t *out_len)
{
    if (addr == NULL || out_len == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    char text[INET6_ADDRSTRLEN];
    const char *value = NULL;
    size_t len = 0u;
    if (addr->family == APROXY_ADDR_FQDN) {
        if (addr->fqdn_len == 0u ||
            addr->fqdn_len > APROXY_ADDR_MAX_FQDN) {
            return APROXY_ERR_INVALID_ARGUMENT;
        }
        value = addr->fqdn;
        len = addr->fqdn_len;
    } else if (addr->family == APROXY_ADDR_IPV4) {
        value = inet_ntop(AF_INET, addr->addr, text, sizeof(text));
        if (value != NULL) {
            len = strlen(value);
        }
    } else if (addr->family == APROXY_ADDR_IPV6) {
        value = inet_ntop(AF_INET6, addr->addr, text, sizeof(text));
        if (value != NULL) {
            len = strlen(value);
        }
    } else {
        return APROXY_ERR_UNSUPPORTED;
    }
    if (value == NULL) {
        return APROXY_ERR_PARSE;
    }
    *out_len = len;
    if (out == NULL || out_capacity <= len) {
        return APROXY_ERR_BUFFER_TOO_SMALL;
    }
    memcpy(out, value, len);
    out[len] = '\0';
    return APROXY_OK;
}

size_t aproxy_addr_encoded_len(const aproxy_addr_t *addr)
{
    if (addr == NULL) {
        return 0u;
    }
    switch (addr->family) {
    case APROXY_ADDR_IPV4:
        return 1u + 4u + 2u;
    case APROXY_ADDR_IPV6:
        return 1u + 16u + 2u;
    case APROXY_ADDR_FQDN:
        return 1u + 1u + addr->fqdn_len + 2u;
    default:
        return 0u;
    }
}

int aproxy_addr_encode_socksaddr(const aproxy_addr_t *addr,
                                 uint8_t *out,
                                 size_t out_capacity,
                                 size_t *out_len)
{
    if (addr == NULL || out_len == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }

    const size_t need = aproxy_addr_encoded_len(addr);
    if (need == 0u) {
        return APROXY_ERR_UNSUPPORTED;
    }
    *out_len = need;
    if (out == NULL || out_capacity < need) {
        return APROXY_ERR_BUFFER_TOO_SMALL;
    }

    size_t pos = 0u;
    out[pos++] = (uint8_t)addr->family;
    switch (addr->family) {
    case APROXY_ADDR_IPV4:
        memcpy(out + pos, addr->addr, 4u);
        pos += 4u;
        break;
    case APROXY_ADDR_IPV6:
        memcpy(out + pos, addr->addr, 16u);
        pos += 16u;
        break;
    case APROXY_ADDR_FQDN:
        if (addr->fqdn_len == 0u || addr->fqdn_len > APROXY_ADDR_MAX_FQDN) {
            return APROXY_ERR_INVALID_ARGUMENT;
        }
        out[pos++] = (uint8_t)addr->fqdn_len;
        memcpy(out + pos, addr->fqdn, addr->fqdn_len);
        pos += addr->fqdn_len;
        break;
    default:
        return APROXY_ERR_UNSUPPORTED;
    }
    anytls_put_u16_be(out + pos, addr->port);
    return APROXY_OK;
}

int aproxy_addr_decode_socksaddr(const uint8_t *data,
                                 size_t data_len,
                                 aproxy_addr_t *out,
                                 size_t *consumed)
{
    if (data == NULL || out == NULL || consumed == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    *consumed = 0u;
    if (data_len < 1u) {
        return APROXY_ERR_BUFFER_TOO_SMALL;
    }

    memset(out, 0, sizeof(*out));
    size_t pos = 0u;
    const uint8_t family = data[pos++];
    out->family = (aproxy_addr_family_t)family;

    switch (family) {
    case APROXY_ADDR_IPV4:
        if (data_len - pos < 4u + 2u) {
            return APROXY_ERR_BUFFER_TOO_SMALL;
        }
        memcpy(out->addr, data + pos, 4u);
        pos += 4u;
        break;
    case APROXY_ADDR_IPV6:
        if (data_len - pos < 16u + 2u) {
            return APROXY_ERR_BUFFER_TOO_SMALL;
        }
        memcpy(out->addr, data + pos, 16u);
        pos += 16u;
        break;
    case APROXY_ADDR_FQDN: {
        if (data_len - pos < 1u) {
            return APROXY_ERR_BUFFER_TOO_SMALL;
        }
        const size_t fqdn_len = data[pos++];
        if (fqdn_len == 0u || fqdn_len > APROXY_ADDR_MAX_FQDN ||
            data_len - pos < fqdn_len + 2u) {
            return APROXY_ERR_BUFFER_TOO_SMALL;
        }
        out->fqdn_len = fqdn_len;
        memcpy(out->fqdn, data + pos, fqdn_len);
        out->fqdn[fqdn_len] = '\0';
        pos += fqdn_len;
        break;
    }
    default:
        return APROXY_ERR_UNSUPPORTED;
    }

    out->port = anytls_get_u16_be(data + pos);
    pos += 2u;
    *consumed = pos;
    return APROXY_OK;
}
