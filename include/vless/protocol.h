#ifndef VLESS_PROTOCOL_H
#define VLESS_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

#include "aproxy/address.h"
#include "aproxy/error.h"

#define VLESS_VERSION 0u
#define VLESS_UUID_LEN 16u
#define VLESS_MAX_FLOW_LEN 252u

#define VLESS_COMMAND_TCP 1u
#define VLESS_COMMAND_UDP 2u
#define VLESS_COMMAND_MUX 3u

#define VLESS_FLOW_VISION "xtls-rprx-vision"

typedef struct vless_request {
    uint8_t uuid[VLESS_UUID_LEN];
    uint8_t command;
    aproxy_addr_t destination;
    char flow[VLESS_MAX_FLOW_LEN + 1u];
} vless_request_t;

int vless_uuid_parse(const char *text, uint8_t out[VLESS_UUID_LEN]);

size_t vless_request_encoded_len(const vless_request_t *request);

int vless_request_encode(const vless_request_t *request,
                         uint8_t *out,
                         size_t out_capacity,
                         size_t *out_len);

int vless_request_decode(const uint8_t *data,
                         size_t data_len,
                         vless_request_t *out,
                         size_t *consumed);

int vless_response_header_decode(const uint8_t *data,
                                 size_t data_len,
                                 size_t *consumed);

#endif
