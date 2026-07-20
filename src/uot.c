#include "aproxy/uot.h"

#include <string.h>

#include "byteorder.h"

#define APROXY_UOT_ADDR_IPV4 0x00u
#define APROXY_UOT_ADDR_IPV6 0x01u
#define APROXY_UOT_ADDR_FQDN 0x02u

static int aproxy_uot_is_v2(uint8_t version, int *is_v2)
{
    if (is_v2 == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    switch (version) {
    case APROXY_UOT_VERSION_DEFAULT:
    case APROXY_UOT_VERSION_2:
        *is_v2 = 1;
        return APROXY_OK;
    case APROXY_UOT_VERSION_1:
        *is_v2 = 0;
        return APROXY_OK;
    default:
        return APROXY_ERR_UNSUPPORTED;
    }
}

static size_t aproxy_uot_addr_encoded_len(const aproxy_addr_t *addr)
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
        if (addr->fqdn_len == 0u || addr->fqdn_len > APROXY_ADDR_MAX_FQDN) {
            return 0u;
        }
        return 1u + 1u + addr->fqdn_len + 2u;
    default:
        return 0u;
    }
}

static int aproxy_uot_encode_addr(const aproxy_addr_t *addr,
                                  uint8_t *out,
                                  size_t out_capacity,
                                  size_t *out_len)
{
    if (addr == NULL || out_len == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }

    const size_t need = aproxy_uot_addr_encoded_len(addr);
    if (need == 0u) {
        return APROXY_ERR_UNSUPPORTED;
    }
    *out_len = need;
    if (out == NULL || out_capacity < need) {
        return APROXY_ERR_BUFFER_TOO_SMALL;
    }

    size_t pos = 0u;
    switch (addr->family) {
    case APROXY_ADDR_IPV4:
        out[pos++] = APROXY_UOT_ADDR_IPV4;
        memcpy(out + pos, addr->addr, 4u);
        pos += 4u;
        break;
    case APROXY_ADDR_IPV6:
        out[pos++] = APROXY_UOT_ADDR_IPV6;
        memcpy(out + pos, addr->addr, 16u);
        pos += 16u;
        break;
    case APROXY_ADDR_FQDN:
        out[pos++] = APROXY_UOT_ADDR_FQDN;
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

static int aproxy_uot_decode_addr(const uint8_t *data,
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

    switch (family) {
    case APROXY_UOT_ADDR_IPV4:
        if (data_len - pos < 4u + 2u) {
            return APROXY_ERR_BUFFER_TOO_SMALL;
        }
        out->family = APROXY_ADDR_IPV4;
        memcpy(out->addr, data + pos, 4u);
        pos += 4u;
        break;
    case APROXY_UOT_ADDR_IPV6:
        if (data_len - pos < 16u + 2u) {
            return APROXY_ERR_BUFFER_TOO_SMALL;
        }
        out->family = APROXY_ADDR_IPV6;
        memcpy(out->addr, data + pos, 16u);
        pos += 16u;
        break;
    case APROXY_UOT_ADDR_FQDN: {
        if (data_len - pos < 1u) {
            return APROXY_ERR_BUFFER_TOO_SMALL;
        }
        const size_t fqdn_len = data[pos++];
        if (fqdn_len == 0u || fqdn_len > APROXY_ADDR_MAX_FQDN) {
            return APROXY_ERR_INVALID_FRAME;
        }
        if (data_len - pos < fqdn_len + 2u) {
            return APROXY_ERR_BUFFER_TOO_SMALL;
        }
        out->family = APROXY_ADDR_FQDN;
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

int aproxy_uot_request_destination(uint8_t version, aproxy_addr_t *out)
{
    if (out == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }

    int is_v2 = 0;
    const int rc = aproxy_uot_is_v2(version, &is_v2);
    if (rc != APROXY_OK) {
        return rc;
    }

    return aproxy_addr_set_fqdn(out,
                                is_v2 ? APROXY_UOT_MAGIC_ADDRESS_V2
                                      : APROXY_UOT_MAGIC_ADDRESS_V1,
                                0u);
}

int aproxy_uot_encode_request(int is_connect,
                              const aproxy_addr_t *destination,
                              uint8_t *out,
                              size_t out_capacity,
                              size_t *out_len)
{
    if (destination == NULL || out_len == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }

    size_t addr_len = 0u;
    int rc = aproxy_addr_encode_socksaddr(destination, NULL, 0u, &addr_len);
    if (rc != APROXY_ERR_BUFFER_TOO_SMALL) {
        return rc;
    }

    const size_t need = 1u + addr_len;
    *out_len = need;
    if (out == NULL || out_capacity < need) {
        return APROXY_ERR_BUFFER_TOO_SMALL;
    }

    out[0] = is_connect ? 1u : 0u;
    rc = aproxy_addr_encode_socksaddr(destination, out + 1u,
                                      out_capacity - 1u, &addr_len);
    if (rc != APROXY_OK) {
        return rc;
    }
    return APROXY_OK;
}

int aproxy_uot_decode_request(const uint8_t *data,
                              size_t data_len,
                              int *is_connect,
                              aproxy_addr_t *destination,
                              size_t *consumed)
{
    if (data == NULL || is_connect == NULL || destination == NULL ||
        consumed == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    *consumed = 0u;
    if (data_len < 1u) {
        return APROXY_ERR_BUFFER_TOO_SMALL;
    }
    if (data[0] > 1u) {
        return APROXY_ERR_INVALID_FRAME;
    }

    size_t addr_consumed = 0u;
    const int rc = aproxy_addr_decode_socksaddr(data + 1u, data_len - 1u,
                                                destination, &addr_consumed);
    if (rc != APROXY_OK) {
        return rc;
    }

    *is_connect = data[0] != 0u;
    *consumed = 1u + addr_consumed;
    return APROXY_OK;
}

int aproxy_uot_packet_header_len(uint8_t version,
                                 int is_connect,
                                 const aproxy_addr_t *destination,
                                 size_t *out_len)
{
    if (out_len == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }

    int is_v2 = 0;
    int rc = aproxy_uot_is_v2(version, &is_v2);
    if (rc != APROXY_OK) {
        return rc;
    }

    size_t need = 2u;
    if (!is_v2 || !is_connect) {
        size_t addr_len = 0u;
        rc = aproxy_uot_encode_addr(destination, NULL, 0u, &addr_len);
        if (rc != APROXY_ERR_BUFFER_TOO_SMALL) {
            return rc;
        }
        need += addr_len;
    }

    *out_len = need;
    return APROXY_OK;
}

int aproxy_uot_encode_packet_header(uint8_t version,
                                    int is_connect,
                                    const aproxy_addr_t *destination,
                                    size_t payload_len,
                                    uint8_t *out,
                                    size_t out_capacity,
                                    size_t *out_len)
{
    if (out_len == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    if (payload_len > APROXY_UOT_MAX_PACKET_PAYLOAD) {
        return APROXY_ERR_FRAME_TOO_LARGE;
    }

    size_t need = 0u;
    int rc = aproxy_uot_packet_header_len(version, is_connect, destination,
                                          &need);
    if (rc != APROXY_OK) {
        return rc;
    }
    *out_len = need;
    if (out == NULL || out_capacity < need) {
        return APROXY_ERR_BUFFER_TOO_SMALL;
    }

    int is_v2 = 0;
    rc = aproxy_uot_is_v2(version, &is_v2);
    if (rc != APROXY_OK) {
        return rc;
    }

    size_t pos = 0u;
    if (!is_v2 || !is_connect) {
        size_t addr_len = 0u;
        rc = aproxy_uot_encode_addr(destination, out, out_capacity, &addr_len);
        if (rc != APROXY_OK) {
            return rc;
        }
        pos += addr_len;
    }

    anytls_put_u16_be(out + pos, (uint16_t)payload_len);
    return APROXY_OK;
}

int aproxy_uot_decode_packet_header(uint8_t version,
                                    int is_connect,
                                    const uint8_t *data,
                                    size_t data_len,
                                    aproxy_addr_t *destination,
                                    uint16_t *payload_len,
                                    size_t *header_len)
{
    if (data == NULL || payload_len == NULL || header_len == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    *header_len = 0u;

    int is_v2 = 0;
    int rc = aproxy_uot_is_v2(version, &is_v2);
    if (rc != APROXY_OK) {
        return rc;
    }

    size_t pos = 0u;
    if (!is_v2 || !is_connect) {
        if (destination == NULL) {
            return APROXY_ERR_INVALID_ARGUMENT;
        }
        size_t addr_len = 0u;
        rc = aproxy_uot_decode_addr(data, data_len, destination, &addr_len);
        if (rc != APROXY_OK) {
            return rc;
        }
        pos += addr_len;
    }

    if (data_len - pos < 2u) {
        return APROXY_ERR_BUFFER_TOO_SMALL;
    }
    *payload_len = anytls_get_u16_be(data + pos);
    pos += 2u;
    *header_len = pos;
    return APROXY_OK;
}
