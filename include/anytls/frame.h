#ifndef ANYTLS_FRAME_H
#define ANYTLS_FRAME_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "anytls/error.h"

#define ANYTLS_FRAME_HEADER_SIZE 7u
#define ANYTLS_MAX_FRAME_PAYLOAD 65535u
#define ANYTLS_MAX_CONTROL_PAYLOAD (16u * 1024u)

typedef enum anytls_command {
    ANYTLS_CMD_WASTE = 0,
    ANYTLS_CMD_SYN = 1,
    ANYTLS_CMD_PSH = 2,
    ANYTLS_CMD_FIN = 3,
    ANYTLS_CMD_SETTINGS = 4,
    ANYTLS_CMD_ALERT = 5,
    ANYTLS_CMD_UPDATE_PADDING_SCHEME = 6,
    ANYTLS_CMD_SYNACK = 7,
    ANYTLS_CMD_HEART_REQUEST = 8,
    ANYTLS_CMD_HEART_RESPONSE = 9,
    ANYTLS_CMD_SERVER_SETTINGS = 10
} anytls_command_t;

typedef struct anytls_frame_header {
    uint8_t command;
    uint32_t stream_id;
    uint16_t length;
} anytls_frame_header_t;

int anytls_frame_encode_header(uint8_t out[ANYTLS_FRAME_HEADER_SIZE],
                               uint8_t command,
                               uint32_t stream_id,
                               uint16_t length);

int anytls_frame_decode_header(const uint8_t in[ANYTLS_FRAME_HEADER_SIZE],
                               anytls_frame_header_t *out);

int anytls_frame_validate(const anytls_frame_header_t *header, bool is_client);

#endif
