#ifndef APROXY_ADDRESS_H
#define APROXY_ADDRESS_H

#include <stddef.h>
#include <stdint.h>

#include "aproxy/error.h"

#define APROXY_ADDR_MAX_FQDN 255u
#define APROXY_ADDR_MAX_ENCODED (1u + 1u + APROXY_ADDR_MAX_FQDN + 2u)

#ifdef __cplusplus
extern "C" {
#endif

typedef enum aproxy_addr_family {
    APROXY_ADDR_IPV4 = 0x01,
    APROXY_ADDR_IPV6 = 0x04,
    APROXY_ADDR_FQDN = 0x03
} aproxy_addr_family_t;

typedef struct aproxy_addr {
    aproxy_addr_family_t family;
    uint16_t port;
    uint8_t addr[16];
    char fqdn[APROXY_ADDR_MAX_FQDN + 1u];
    size_t fqdn_len;
} aproxy_addr_t;

void aproxy_addr_set_ipv4(aproxy_addr_t *addr,
                          const uint8_t ipv4[4],
                          uint16_t port);

void aproxy_addr_set_ipv6(aproxy_addr_t *addr,
                          const uint8_t ipv6[16],
                          uint16_t port);

int aproxy_addr_set_fqdn(aproxy_addr_t *addr,
                         const char *fqdn,
                         uint16_t port);

aproxy_addr_family_t aproxy_addr_get_family(const aproxy_addr_t *addr);

uint16_t aproxy_addr_get_port(const aproxy_addr_t *addr);

/* out_len excludes the trailing NUL. */
int aproxy_addr_format_host(const aproxy_addr_t *addr,
                            char *out,
                            size_t out_capacity,
                            size_t *out_len);

size_t aproxy_addr_encoded_len(const aproxy_addr_t *addr);

int aproxy_addr_encode_socksaddr(const aproxy_addr_t *addr,
                                 uint8_t *out,
                                 size_t out_capacity,
                                 size_t *out_len);

int aproxy_addr_decode_socksaddr(const uint8_t *data,
                                 size_t data_len,
                                 aproxy_addr_t *out,
                                 size_t *consumed);

#ifdef __cplusplus
}
#endif

#endif
