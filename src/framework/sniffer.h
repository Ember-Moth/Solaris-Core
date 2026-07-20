#ifndef APROXY_SNIFFER_INTERNAL_H
#define APROXY_SNIFFER_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "aproxy/address.h"
#include "aproxy/buffer.h"
#include "aproxy/ring.h"

typedef enum aproxy_sniff_status {
    APROXY_SNIFF_NO_MATCH = 0,
    APROXY_SNIFF_NEED_MORE = 1,
    APROXY_SNIFF_MATCH = 2
} aproxy_sniff_status_t;

typedef enum aproxy_sniff_protocol {
    APROXY_SNIFF_PROTOCOL_NONE = 0,
    APROXY_SNIFF_PROTOCOL_HTTP = 1,
    APROXY_SNIFF_PROTOCOL_TLS = 2,
    APROXY_SNIFF_PROTOCOL_QUIC = 3
} aproxy_sniff_protocol_t;

typedef struct aproxy_sniff_result {
    aproxy_sniff_protocol_t protocol;
    char domain[APROXY_ADDR_MAX_FQDN + 1u];
    size_t domain_len;
} aproxy_sniff_result_t;

/* Reads at most two ring spans without joining or modifying application data. */
aproxy_sniff_status_t aproxy_sniff_tcp(
    const aproxy_const_span_t *spans,
    size_t span_count,
    size_t byte_limit,
    aproxy_sniff_result_t *result);

/*
 * Decrypts QUIC v1/draft-29 Initial packets in caller-owned scratch storage.
 * crypto_data is retained across the first few datagrams for CRYPTO frames.
 */
aproxy_sniff_status_t aproxy_sniff_quic_initial(
    const uint8_t *datagram,
    size_t datagram_len,
    uint8_t *scratch,
    size_t scratch_capacity,
    aproxy_buffer_t *crypto_data,
    size_t crypto_limit,
    aproxy_sniff_result_t *result);

#endif
