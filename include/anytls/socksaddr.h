#ifndef ANYTLS_SOCKSADDR_H
#define ANYTLS_SOCKSADDR_H

#include <stddef.h>
#include <stdint.h>

#include "aproxy/address.h"

#define ANYTLS_SOCKSADDR_MAX_FQDN APROXY_ADDR_MAX_FQDN
#define ANYTLS_SOCKSADDR_MAX_ENCODED APROXY_ADDR_MAX_ENCODED

typedef aproxy_addr_family_t anytls_socksaddr_family_t;

#define ANYTLS_SOCKSADDR_IPV4 APROXY_ADDR_IPV4
#define ANYTLS_SOCKSADDR_IPV6 APROXY_ADDR_IPV6
#define ANYTLS_SOCKSADDR_FQDN APROXY_ADDR_FQDN

typedef aproxy_addr_t anytls_socksaddr_t;

static inline void anytls_socksaddr_set_ipv4(anytls_socksaddr_t *addr,
                                             const uint8_t ipv4[4],
                                             uint16_t port)
{
    aproxy_addr_set_ipv4(addr, ipv4, port);
}

static inline void anytls_socksaddr_set_ipv6(anytls_socksaddr_t *addr,
                                             const uint8_t ipv6[16],
                                             uint16_t port)
{
    aproxy_addr_set_ipv6(addr, ipv6, port);
}

static inline int anytls_socksaddr_set_fqdn(anytls_socksaddr_t *addr,
                                            const char *fqdn,
                                            uint16_t port)
{
    return aproxy_addr_set_fqdn(addr, fqdn, port);
}

static inline size_t anytls_socksaddr_encoded_len(
    const anytls_socksaddr_t *addr)
{
    return aproxy_addr_encoded_len(addr);
}

static inline int anytls_socksaddr_encode(const anytls_socksaddr_t *addr,
                                          uint8_t *out,
                                          size_t out_capacity,
                                          size_t *out_len)
{
    return aproxy_addr_encode_socksaddr(addr, out, out_capacity, out_len);
}

static inline int anytls_socksaddr_decode(const uint8_t *data,
                                          size_t data_len,
                                          anytls_socksaddr_t *out,
                                          size_t *consumed)
{
    return aproxy_addr_decode_socksaddr(data, data_len, out, consumed);
}

#endif
