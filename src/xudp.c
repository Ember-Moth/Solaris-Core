#include "aproxy/xudp.h"

#include <limits.h>
#include <string.h>

#include "aproxy/vmess_addr.h"
#include "byteorder.h"

#define XUDP_FIXED_FRAME_LEN 4u
#define XUDP_NEW_ADDR_PREFIX_LEN 1u

void aproxy_xudp_encoder_init(aproxy_xudp_encoder_t *encoder)
{
    if (encoder != NULL) {
        memset(encoder, 0, sizeof(*encoder));
    }
}

size_t aproxy_xudp_packet_encoded_len(const aproxy_addr_t *destination,
                                      size_t payload_len)
{
    const size_t addr_len = aproxy_vmess_addr_encoded_len(destination);
    if (addr_len == 0u || payload_len > UINT16_MAX) {
        return 0u;
    }
    return 2u + XUDP_FIXED_FRAME_LEN + XUDP_NEW_ADDR_PREFIX_LEN + addr_len +
           2u + payload_len;
}

int aproxy_xudp_encode_packet(aproxy_xudp_encoder_t *encoder,
                              const aproxy_addr_t *destination,
                              const uint8_t *payload,
                              size_t payload_len,
                              uint8_t *out,
                              size_t out_capacity,
                              size_t *out_len)
{
    if (encoder == NULL || destination == NULL ||
        (payload == NULL && payload_len > 0u) || out_len == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    const size_t need =
        aproxy_xudp_packet_encoded_len(destination, payload_len);
    if (need == 0u) {
        return payload_len > UINT16_MAX ? APROXY_ERR_FRAME_TOO_LARGE
                                       : APROXY_ERR_UNSUPPORTED;
    }
    *out_len = need;
    if (out == NULL || out_capacity < need) {
        return APROXY_ERR_BUFFER_TOO_SMALL;
    }

    const size_t addr_len = aproxy_vmess_addr_encoded_len(destination);
    anytls_put_u16_be(out,
                      (uint16_t)(XUDP_FIXED_FRAME_LEN +
                                 XUDP_NEW_ADDR_PREFIX_LEN + addr_len));
    out[2] = 0u;
    out[3] = 0u;
    out[4] = encoder->request_written ? APROXY_XUDP_STATUS_KEEP
                                      : APROXY_XUDP_STATUS_NEW;
    out[5] = APROXY_XUDP_OPTION_DATA;
    out[6] = APROXY_XUDP_NETWORK_UDP;
    size_t encoded_addr_len = 0u;
    int rc = aproxy_vmess_addr_encode(destination, out + 7u,
                                      out_capacity - 7u, &encoded_addr_len);
    if (rc != APROXY_OK) {
        return rc;
    }
    const size_t payload_len_pos = 7u + encoded_addr_len;
    anytls_put_u16_be(out + payload_len_pos, (uint16_t)payload_len);
    if (payload_len > 0u) {
        memcpy(out + payload_len_pos + 2u, payload, payload_len);
    }
    encoder->request_written = 1;
    return APROXY_OK;
}

void aproxy_xudp_decoder_init(aproxy_xudp_decoder_t *decoder,
                              const aproxy_addr_t *default_destination)
{
    if (decoder == NULL) {
        return;
    }
    memset(decoder, 0, sizeof(*decoder));
    aproxy_ring_init(&decoder->rx);
    aproxy_buffer_init(&decoder->scratch);
    if (default_destination != NULL) {
        decoder->default_destination = *default_destination;
        decoder->current_destination = *default_destination;
    }
}

void aproxy_xudp_decoder_free(aproxy_xudp_decoder_t *decoder)
{
    if (decoder == NULL) {
        return;
    }
    aproxy_ring_free(&decoder->rx);
    aproxy_buffer_free(&decoder->scratch);
    memset(decoder, 0, sizeof(*decoder));
}

static int peek_bytes(const aproxy_ring_t *ring,
                      size_t offset,
                      uint8_t *out,
                      size_t len)
{
    return aproxy_ring_peek(ring, offset, out, len) == len
               ? APROXY_OK
               : APROXY_ERR_BUFFER_TOO_SMALL;
}

static int decode_frame_destination(aproxy_xudp_decoder_t *decoder,
                                    size_t offset,
                                    size_t len)
{
    if (len == 0u) {
        decoder->current_destination = decoder->default_destination;
        return APROXY_OK;
    }
    if (len < 2u || len > 1u + 2u + 1u + 1u + APROXY_ADDR_MAX_FQDN) {
        return APROXY_ERR_INVALID_FRAME;
    }
    uint8_t encoded[1u + 2u + 1u + 1u + APROXY_ADDR_MAX_FQDN];
    int rc = peek_bytes(&decoder->rx, offset, encoded, len);
    if (rc != APROXY_OK) {
        return rc;
    }
    if (encoded[0] != APROXY_XUDP_NETWORK_UDP) {
        return APROXY_ERR_INVALID_FRAME;
    }
    size_t consumed = 0u;
    rc = aproxy_vmess_addr_decode(encoded + 1u, len - 1u,
                                  &decoder->current_destination, &consumed);
    if (rc != APROXY_OK) {
        return rc;
    }
    return consumed == len - 1u ? APROXY_OK : APROXY_ERR_INVALID_FRAME;
}

static int dispatch_payload(aproxy_xudp_decoder_t *decoder,
                            size_t payload_offset,
                            size_t payload_len,
                            aproxy_xudp_packet_cb on_packet,
                            void *user_data)
{
    if (on_packet == NULL) {
        return APROXY_OK;
    }
    aproxy_const_span_t spans[2];
    const size_t count = aproxy_ring_read_spans_at(
        &decoder->rx, payload_offset, payload_len, spans);
    if (payload_len == 0u) {
        return on_packet(&decoder->current_destination, NULL, 0u, user_data);
    }
    if (count == 1u) {
        return on_packet(&decoder->current_destination, spans[0].data,
                         spans[0].len, user_data);
    }
    int rc = aproxy_buffer_reserve(&decoder->scratch,
                                   payload_len == 0u ? 1u : payload_len);
    if (rc != APROXY_OK) {
        return rc;
    }
    if (aproxy_ring_peek(&decoder->rx, payload_offset,
                         decoder->scratch.data,
                         payload_len) != payload_len) {
        return APROXY_ERR_INVALID_FRAME;
    }
    decoder->scratch.len = payload_len;
    return on_packet(&decoder->current_destination, decoder->scratch.data,
                     payload_len, user_data);
}

int aproxy_xudp_decoder_feed(aproxy_xudp_decoder_t *decoder,
                             const uint8_t *data,
                             size_t len,
                             aproxy_xudp_packet_cb on_packet,
                             void *user_data)
{
    if (decoder == NULL || (data == NULL && len > 0u) || decoder->ended) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    int rc = aproxy_ring_write(&decoder->rx, data, len);
    if (rc != APROXY_OK) {
        return rc;
    }

    for (;;) {
        if (aproxy_ring_size(&decoder->rx) < 2u) {
            return APROXY_OK;
        }
        uint8_t frame_len_bytes[2];
        rc = peek_bytes(&decoder->rx, 0u, frame_len_bytes, 2u);
        if (rc != APROXY_OK) {
            return rc;
        }
        const size_t frame_len = anytls_get_u16_be(frame_len_bytes);
        if (frame_len < XUDP_FIXED_FRAME_LEN ||
            frame_len > XUDP_FIXED_FRAME_LEN + XUDP_NEW_ADDR_PREFIX_LEN +
                            2u + 1u + 1u + APROXY_ADDR_MAX_FQDN) {
            return APROXY_ERR_INVALID_FRAME;
        }
        if (aproxy_ring_size(&decoder->rx) < 2u + frame_len) {
            return APROXY_OK;
        }
        uint8_t fixed[XUDP_FIXED_FRAME_LEN];
        rc = peek_bytes(&decoder->rx, 2u, fixed, sizeof(fixed));
        if (rc != APROXY_OK) {
            return rc;
        }
        const uint8_t status = fixed[2];
        const uint8_t option = fixed[3];
        if ((option & APROXY_XUDP_OPTION_ERROR) != 0u) {
            return APROXY_ERR_INVALID_FRAME;
        }
        if (status == APROXY_XUDP_STATUS_NEW) {
            return APROXY_ERR_INVALID_FRAME;
        }
        if (status == APROXY_XUDP_STATUS_END) {
            decoder->ended = 1;
            aproxy_ring_consume(&decoder->rx, 2u + frame_len);
            return APROXY_OK;
        }
        if (status == APROXY_XUDP_STATUS_KEEPALIVE) {
            if (frame_len != XUDP_FIXED_FRAME_LEN ||
                (option & APROXY_XUDP_OPTION_DATA) != 0u) {
                return APROXY_ERR_INVALID_FRAME;
            }
            aproxy_ring_consume(&decoder->rx, 2u + frame_len);
            continue;
        }
        if (status != APROXY_XUDP_STATUS_KEEP) {
            return APROXY_ERR_INVALID_FRAME;
        }
        rc = decode_frame_destination(decoder, 2u + XUDP_FIXED_FRAME_LEN,
                                      frame_len - XUDP_FIXED_FRAME_LEN);
        if (rc != APROXY_OK) {
            return rc;
        }
        size_t total_len = 2u + frame_len;
        if ((option & APROXY_XUDP_OPTION_DATA) == 0u) {
            aproxy_ring_consume(&decoder->rx, total_len);
            continue;
        }
        if (aproxy_ring_size(&decoder->rx) < total_len + 2u) {
            return APROXY_OK;
        }
        uint8_t payload_len_bytes[2];
        rc = peek_bytes(&decoder->rx, total_len, payload_len_bytes, 2u);
        if (rc != APROXY_OK) {
            return rc;
        }
        const size_t payload_len = anytls_get_u16_be(payload_len_bytes);
        total_len += 2u + payload_len;
        if (aproxy_ring_size(&decoder->rx) < total_len) {
            return APROXY_OK;
        }
        rc = dispatch_payload(decoder, total_len - payload_len, payload_len,
                              on_packet, user_data);
        if (rc != APROXY_OK) {
            return rc;
        }
        aproxy_ring_consume(&decoder->rx, total_len);
    }
}
