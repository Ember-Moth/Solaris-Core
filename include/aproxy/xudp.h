#ifndef APROXY_XUDP_H
#define APROXY_XUDP_H

#include <stddef.h>
#include <stdint.h>

#include "aproxy/address.h"
#include "aproxy/buffer.h"
#include "aproxy/ring.h"

#define APROXY_XUDP_STATUS_NEW 1u
#define APROXY_XUDP_STATUS_KEEP 2u
#define APROXY_XUDP_STATUS_END 3u
#define APROXY_XUDP_STATUS_KEEPALIVE 4u

#define APROXY_XUDP_OPTION_DATA 1u
#define APROXY_XUDP_OPTION_ERROR 2u
#define APROXY_XUDP_NETWORK_UDP 2u

typedef struct aproxy_xudp_encoder {
    int request_written;
} aproxy_xudp_encoder_t;

typedef struct aproxy_xudp_decoder {
    aproxy_ring_t rx;
    aproxy_buffer_t scratch;
    aproxy_addr_t default_destination;
    aproxy_addr_t current_destination;
    int ended;
} aproxy_xudp_decoder_t;

typedef int (*aproxy_xudp_packet_cb)(const aproxy_addr_t *source,
                                     const uint8_t *payload,
                                     size_t payload_len,
                                     void *user_data);

void aproxy_xudp_encoder_init(aproxy_xudp_encoder_t *encoder);

size_t aproxy_xudp_packet_encoded_len(const aproxy_addr_t *destination,
                                      size_t payload_len);

int aproxy_xudp_encode_packet(aproxy_xudp_encoder_t *encoder,
                              const aproxy_addr_t *destination,
                              const uint8_t *payload,
                              size_t payload_len,
                              uint8_t *out,
                              size_t out_capacity,
                              size_t *out_len);

void aproxy_xudp_decoder_init(aproxy_xudp_decoder_t *decoder,
                              const aproxy_addr_t *default_destination);

void aproxy_xudp_decoder_free(aproxy_xudp_decoder_t *decoder);

int aproxy_xudp_decoder_feed(aproxy_xudp_decoder_t *decoder,
                             const uint8_t *data,
                             size_t len,
                             aproxy_xudp_packet_cb on_packet,
                             void *user_data);

#endif
