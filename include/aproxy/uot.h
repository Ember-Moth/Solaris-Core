#ifndef APROXY_UOT_H
#define APROXY_UOT_H

#include <stddef.h>
#include <stdint.h>

#include "aproxy/address.h"
#include "aproxy/error.h"

#define APROXY_UOT_VERSION_DEFAULT 0u
#define APROXY_UOT_VERSION_1 1u
#define APROXY_UOT_VERSION_2 2u
#define APROXY_UOT_MAGIC_ADDRESS_V1 "sp.udp-over-tcp.arpa"
#define APROXY_UOT_MAGIC_ADDRESS_V2 "sp.v2.udp-over-tcp.arpa"
#define APROXY_UOT_MAX_PACKET_PAYLOAD 65535u
#define APROXY_UOT_MAX_REQUEST_ENCODED (1u + APROXY_ADDR_MAX_ENCODED)
#define APROXY_UOT_MAX_PACKET_HEADER (APROXY_ADDR_MAX_ENCODED + 2u)

int aproxy_uot_request_destination(uint8_t version, aproxy_addr_t *out);

int aproxy_uot_encode_request(int is_connect,
                              const aproxy_addr_t *destination,
                              uint8_t *out,
                              size_t out_capacity,
                              size_t *out_len);

int aproxy_uot_decode_request(const uint8_t *data,
                              size_t data_len,
                              int *is_connect,
                              aproxy_addr_t *destination,
                              size_t *consumed);

int aproxy_uot_packet_header_len(uint8_t version,
                                 int is_connect,
                                 const aproxy_addr_t *destination,
                                 size_t *out_len);

int aproxy_uot_encode_packet_header(uint8_t version,
                                    int is_connect,
                                    const aproxy_addr_t *destination,
                                    size_t payload_len,
                                    uint8_t *out,
                                    size_t out_capacity,
                                    size_t *out_len);

int aproxy_uot_decode_packet_header(uint8_t version,
                                    int is_connect,
                                    const uint8_t *data,
                                    size_t data_len,
                                    aproxy_addr_t *destination,
                                    uint16_t *payload_len,
                                    size_t *header_len);

#endif
