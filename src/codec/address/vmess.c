#include "codec/address/vmess.h"
#include "codec/address/socks.h"
#include <string.h>

solaris_status_t solaris_vmess_address_write(const solaris_address_t *address,
    uint8_t *wire, size_t capacity, size_t *written)
{
    *written = 0u;
    uint8_t socks[260]; size_t n;
    solaris_status_t rc = solaris_socks_address_write(address, socks, sizeof(socks), &n);
    if (rc != SOLARIS_OK) return rc;
    if (capacity < n) return SOLARIS_EMSGSIZE;
    wire[0] = socks[n - 2u]; wire[1] = socks[n - 1u];
    wire[2] = socks[0] == 1u ? 1u : socks[0] == 3u ? 2u : 3u;
    memcpy(wire + 3u, socks + 1u, n - 3u); *written = n; return SOLARIS_OK;
}
solaris_status_t solaris_vmess_address_read(const uint8_t *wire, size_t size,
    solaris_address_t *address, size_t *consumed)
{
    *consumed = 0u;
    if (size < 3u) return SOLARIS_EAGAIN;
    size_t n; uint8_t type;
    if (wire[2] == 1u) { n = 7u; type = 1u; }
    else if (wire[2] == 3u) { n = 19u; type = 4u; }
    else if (wire[2] == 2u) {
        if (size < 4u) return SOLARIS_EAGAIN;
        n = 4u + wire[3]; type = 3u;
    } else return SOLARIS_EIO;
    if (size < n) return SOLARIS_EAGAIN;
    uint8_t socks[260]; socks[0] = type;
    memcpy(socks + 1u, wire + 3u, n - 3u);
    socks[n - 2u] = wire[0]; socks[n - 1u] = wire[1];
    return solaris_socks_address_read(socks, n, address, consumed);
}
