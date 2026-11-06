#include "codec/address/socks.h"
#include <string.h>
solaris_status_t solaris_socks_address_encode(const solaris_address_t *a,
    uint8_t *out, size_t capacity, size_t *written)
{
    *written = 0u;
    if (a->scope_id != 0u) return SOLARIS_EINVAL;
    size_t length; uint8_t type;
    if (a->family == SOLARIS_ADDRESS_IPV4) { type = 1u; length = 4u; }
    else if (a->family == SOLARIS_ADDRESS_IPV6) { type = 4u; length = 16u; }
    else if (a->family == SOLARIS_ADDRESS_DOMAIN && memchr(a->host, 0, sizeof(a->host)) != NULL) {
        type = 3u; length = strlen(a->host);
        if (length == 0u || length > 255u) return SOLARIS_EINVAL;
    } else return SOLARIS_EINVAL;
    size_t size = 1u + (type == 3u) + length + 2u;
    if (capacity < size) return SOLARIS_EMSGSIZE;
    size_t n = 0u; out[n++] = type;
    if (type == 3u) out[n++] = (uint8_t)length;
    memcpy(out + n, type == 3u ? (const void *)a->host : (const void *)a->ip, length); n += length;
    out[n++] = (uint8_t)(a->port >> 8); out[n++] = (uint8_t)a->port;
    *written = n; return SOLARIS_OK;
}
solaris_status_t solaris_socks_address_write(const solaris_address_t *a,
    uint8_t *out, size_t capacity, size_t *written)
{
    *written = 0u;
    if (a->port == 0u) return SOLARIS_EINVAL;
    return solaris_socks_address_encode(a, out, capacity, written);
}
solaris_status_t solaris_socks_address_decode(const uint8_t *data, size_t size,
    solaris_address_t *out, size_t *consumed)
{
    *consumed = 0u;
    if (size < 1u) return SOLARIS_EAGAIN;
    size_t n = 1u, length; solaris_address_t address = {0};
    if (data[0] == 1u) { address.family = SOLARIS_ADDRESS_IPV4; length = 4u; }
    else if (data[0] == 4u) { address.family = SOLARIS_ADDRESS_IPV6; length = 16u; }
    else if (data[0] == 3u) {
        if (size < 2u) return SOLARIS_EAGAIN;
        length = data[n++]; address.family = SOLARIS_ADDRESS_DOMAIN;
        if (length == 0u) return SOLARIS_EIO;
    } else return SOLARIS_EIO;
    if (size - n < length + 2u) return SOLARIS_EAGAIN;
    if (address.family == SOLARIS_ADDRESS_DOMAIN) {
        if (memchr(data + n, 0, length) != NULL) return SOLARIS_EIO;
        memcpy(address.host, data + n, length);
    } else memcpy(address.ip, data + n, length);
    n += length; address.port = (uint16_t)(((uint16_t)data[n] << 8) | data[n + 1u]); n += 2u;
    *out = address; *consumed = n; return SOLARIS_OK;
}
solaris_status_t solaris_socks_address_read(const uint8_t *data, size_t size,
    solaris_address_t *out, size_t *consumed)
{
    solaris_address_t address;
    solaris_status_t rc = solaris_socks_address_decode(data, size, &address, consumed);
    if (rc == SOLARIS_OK && address.port == 0u) { *consumed = 0; return SOLARIS_EIO; }
    if (rc == SOLARIS_OK) *out = address;
    return rc;
}
