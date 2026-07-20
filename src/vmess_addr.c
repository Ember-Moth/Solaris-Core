#include "aproxy/vmess_addr.h"

#include <string.h>

#include "byteorder.h"

#define VMESS_ADDR_IPV4 0x01u
#define VMESS_ADDR_FQDN 0x02u
#define VMESS_ADDR_IPV6 0x03u

size_t aproxy_vmess_addr_encoded_len(const aproxy_addr_t *addr)
{
    if (addr == NULL) {
        return 0u;
    }
    switch (addr->family) {
    case APROXY_ADDR_IPV4:
        return 2u + 1u + 4u;
    case APROXY_ADDR_IPV6:
        return 2u + 1u + 16u;
    case APROXY_ADDR_FQDN:
        if (addr->fqdn_len == 0u || addr->fqdn_len > APROXY_ADDR_MAX_FQDN) {
            return 0u;
        }
        return 2u + 1u + 1u + addr->fqdn_len;
    default:
        return 0u;
    }
}

int aproxy_vmess_addr_encode(const aproxy_addr_t *addr,
                             uint8_t *out,
                             size_t out_capacity,
                             size_t *out_len)
{
    if (addr == NULL || out_len == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    const size_t need = aproxy_vmess_addr_encoded_len(addr);
    if (need == 0u) {
        return APROXY_ERR_UNSUPPORTED;
    }
    *out_len = need;
    if (out == NULL || out_capacity < need) {
        return APROXY_ERR_BUFFER_TOO_SMALL;
    }

    anytls_put_u16_be(out, addr->port);
    size_t pos = 2u;
    switch (addr->family) {
    case APROXY_ADDR_IPV4:
        out[pos++] = VMESS_ADDR_IPV4;
        memcpy(out + pos, addr->addr, 4u);
        break;
    case APROXY_ADDR_IPV6:
        out[pos++] = VMESS_ADDR_IPV6;
        memcpy(out + pos, addr->addr, 16u);
        break;
    case APROXY_ADDR_FQDN:
        out[pos++] = VMESS_ADDR_FQDN;
        out[pos++] = (uint8_t)addr->fqdn_len;
        memcpy(out + pos, addr->fqdn, addr->fqdn_len);
        break;
    default:
        return APROXY_ERR_UNSUPPORTED;
    }
    return APROXY_OK;
}

int aproxy_vmess_addr_decode(const uint8_t *data,
                             size_t data_len,
                             aproxy_addr_t *out,
                             size_t *consumed)
{
    if (data == NULL || out == NULL || consumed == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    *consumed = 0u;
    if (data_len < 3u) {
        return APROXY_ERR_BUFFER_TOO_SMALL;
    }

    const uint16_t port = anytls_get_u16_be(data);
    size_t pos = 3u;
    int rc = APROXY_OK;
    switch (data[2]) {
    case VMESS_ADDR_IPV4:
        if (data_len - pos < 4u) {
            return APROXY_ERR_BUFFER_TOO_SMALL;
        }
        aproxy_addr_set_ipv4(out, data + pos, port);
        pos += 4u;
        break;
    case VMESS_ADDR_IPV6:
        if (data_len - pos < 16u) {
            return APROXY_ERR_BUFFER_TOO_SMALL;
        }
        aproxy_addr_set_ipv6(out, data + pos, port);
        pos += 16u;
        break;
    case VMESS_ADDR_FQDN: {
        if (data_len - pos < 1u) {
            return APROXY_ERR_BUFFER_TOO_SMALL;
        }
        const size_t fqdn_len = data[pos++];
        if (fqdn_len == 0u || fqdn_len > APROXY_ADDR_MAX_FQDN) {
            return APROXY_ERR_INVALID_FRAME;
        }
        if (data_len - pos < fqdn_len) {
            return APROXY_ERR_BUFFER_TOO_SMALL;
        }
        char fqdn[APROXY_ADDR_MAX_FQDN + 1u];
        memcpy(fqdn, data + pos, fqdn_len);
        fqdn[fqdn_len] = '\0';
        rc = aproxy_addr_set_fqdn(out, fqdn, port);
        pos += fqdn_len;
        break;
    }
    default:
        return APROXY_ERR_UNSUPPORTED;
    }
    if (rc != APROXY_OK) {
        return rc;
    }
    *consumed = pos;
    return APROXY_OK;
}
