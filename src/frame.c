#include "anytls/frame.h"

#include "byteorder.h"

int anytls_frame_encode_header(uint8_t out[ANYTLS_FRAME_HEADER_SIZE],
                               uint8_t command,
                               uint32_t stream_id,
                               uint16_t length)
{
    if (out == NULL) {
        return ANYTLS_ERR_INVALID_ARGUMENT;
    }
    out[0] = command;
    anytls_put_u32_be(out + 1, stream_id);
    anytls_put_u16_be(out + 5, length);
    return ANYTLS_OK;
}

int anytls_frame_decode_header(const uint8_t in[ANYTLS_FRAME_HEADER_SIZE],
                               anytls_frame_header_t *out)
{
    if (in == NULL || out == NULL) {
        return ANYTLS_ERR_INVALID_ARGUMENT;
    }
    out->command = in[0];
    out->stream_id = anytls_get_u32_be(in + 1);
    out->length = anytls_get_u16_be(in + 5);
    return ANYTLS_OK;
}

int anytls_frame_validate(const anytls_frame_header_t *header, bool is_client)
{
    if (header == NULL) {
        return ANYTLS_ERR_INVALID_ARGUMENT;
    }

    const uint8_t command = header->command;
    const uint32_t stream_id = header->stream_id;
    const uint16_t length = header->length;

    switch (command) {
    case ANYTLS_CMD_SYN:
        if (is_client || stream_id == 0u || length != 0u) {
            return ANYTLS_ERR_INVALID_FRAME;
        }
        return ANYTLS_OK;
    case ANYTLS_CMD_PSH:
        if (stream_id == 0u || length == 0u) {
            return ANYTLS_ERR_INVALID_FRAME;
        }
        return ANYTLS_OK;
    case ANYTLS_CMD_FIN:
        if (stream_id == 0u) {
            return ANYTLS_ERR_INVALID_FRAME;
        }
        return ANYTLS_OK;
    case ANYTLS_CMD_SETTINGS:
        if (is_client || stream_id != 0u || length == 0u ||
            length > ANYTLS_MAX_CONTROL_PAYLOAD) {
            return ANYTLS_ERR_INVALID_FRAME;
        }
        return ANYTLS_OK;
    case ANYTLS_CMD_ALERT:
        if (!is_client || stream_id != 0u ||
            length > ANYTLS_MAX_CONTROL_PAYLOAD) {
            return ANYTLS_ERR_INVALID_FRAME;
        }
        return ANYTLS_OK;
    case ANYTLS_CMD_UPDATE_PADDING_SCHEME:
        if (!is_client || stream_id != 0u) {
            return ANYTLS_ERR_INVALID_FRAME;
        }
        return ANYTLS_OK;
    case ANYTLS_CMD_SYNACK:
        if (!is_client || stream_id == 0u ||
            length > ANYTLS_MAX_CONTROL_PAYLOAD) {
            return ANYTLS_ERR_INVALID_FRAME;
        }
        return ANYTLS_OK;
    case ANYTLS_CMD_HEART_REQUEST:
    case ANYTLS_CMD_HEART_RESPONSE:
        if (stream_id != 0u) {
            return ANYTLS_ERR_INVALID_FRAME;
        }
        return ANYTLS_OK;
    case ANYTLS_CMD_SERVER_SETTINGS:
        if (!is_client || stream_id != 0u ||
            length > ANYTLS_MAX_CONTROL_PAYLOAD) {
            return ANYTLS_ERR_INVALID_FRAME;
        }
        return ANYTLS_OK;
    case ANYTLS_CMD_WASTE:
        if (stream_id != 0u) {
            return ANYTLS_ERR_INVALID_FRAME;
        }
        return ANYTLS_OK;
    default:
        return ANYTLS_ERR_INVALID_FRAME;
    }
}
