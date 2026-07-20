#ifndef APROXY_VMESS_ADDR_H
#define APROXY_VMESS_ADDR_H

#include <stddef.h>
#include <stdint.h>

#include "aproxy/address.h"

size_t aproxy_vmess_addr_encoded_len(const aproxy_addr_t *addr);

int aproxy_vmess_addr_encode(const aproxy_addr_t *addr,
                             uint8_t *out,
                             size_t out_capacity,
                             size_t *out_len);

int aproxy_vmess_addr_decode(const uint8_t *data,
                             size_t data_len,
                             aproxy_addr_t *out,
                             size_t *consumed);

#endif
