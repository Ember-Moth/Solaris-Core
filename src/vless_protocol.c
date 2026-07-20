#include "vless/protocol.h"

#include <ctype.h>
#include <string.h>

#include <openssl/sha.h>

#include "aproxy/vmess_addr.h"

static size_t uvarint_len(size_t value)
{
    size_t len = 1u;
    while (value >= 0x80u) {
        value >>= 7u;
        len++;
    }
    return len;
}

static size_t put_uvarint(uint8_t *out, size_t value)
{
    size_t pos = 0u;
    while (value >= 0x80u) {
        out[pos++] = (uint8_t)(value | 0x80u);
        value >>= 7u;
    }
    out[pos++] = (uint8_t)value;
    return pos;
}

static int get_uvarint(const uint8_t *data,
                       size_t data_len,
                       size_t *value,
                       size_t *consumed)
{
    size_t result = 0u;
    for (size_t i = 0u; i < data_len && i < 10u; i++) {
        const uint8_t byte = data[i];
        if (i >= sizeof(size_t) && (byte & 0x7fu) != 0u) {
            return APROXY_ERR_INVALID_FRAME;
        }
        result |= (size_t)(byte & 0x7fu) << (7u * i);
        if ((byte & 0x80u) == 0u) {
            *value = result;
            *consumed = i + 1u;
            return APROXY_OK;
        }
    }
    return data_len < 10u ? APROXY_ERR_BUFFER_TOO_SMALL
                          : APROXY_ERR_INVALID_FRAME;
}

static int hex_nibble(char c, uint8_t *out)
{
    if (c >= '0' && c <= '9') {
        *out = (uint8_t)(c - '0');
        return 1;
    }
    c = (char)tolower((unsigned char)c);
    if (c >= 'a' && c <= 'f') {
        *out = (uint8_t)(c - 'a' + 10);
        return 1;
    }
    return 0;
}

static int parse_uuid_hex(const char *text, uint8_t out[VLESS_UUID_LEN])
{
    const size_t len = strlen(text);
    if (len != 32u && len != 36u) {
        return 0;
    }
    if (len == 36u &&
        (text[8] != '-' || text[13] != '-' || text[18] != '-' ||
         text[23] != '-')) {
        return 0;
    }
    size_t input = 0u;
    for (size_t output = 0u; output < VLESS_UUID_LEN; output++) {
        if (len == 36u &&
            (input == 8u || input == 13u || input == 18u || input == 23u)) {
            input++;
        }
        uint8_t high = 0u;
        uint8_t low = 0u;
        if (!hex_nibble(text[input], &high) ||
            !hex_nibble(text[input + 1u], &low)) {
            return 0;
        }
        out[output] = (uint8_t)((high << 4u) | low);
        input += 2u;
    }
    return input == len;
}

int vless_uuid_parse(const char *text, uint8_t out[VLESS_UUID_LEN])
{
    if (text == NULL || text[0] == '\0' || out == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    if (parse_uuid_hex(text, out)) {
        return APROXY_OK;
    }

    uint8_t digest[SHA_DIGEST_LENGTH];
    SHA_CTX sha;
    static const uint8_t nil_namespace[VLESS_UUID_LEN] = {0};
    if (!SHA1_Init(&sha) ||
        !SHA1_Update(&sha, nil_namespace, sizeof(nil_namespace)) ||
        !SHA1_Update(&sha, text, strlen(text)) || !SHA1_Final(digest, &sha)) {
        return APROXY_ERR_CRYPTO;
    }
    memcpy(out, digest, VLESS_UUID_LEN);
    out[6] = (uint8_t)((out[6] & 0x0fu) | 0x50u);
    out[8] = (uint8_t)((out[8] & 0x3fu) | 0x80u);
    return APROXY_OK;
}

size_t vless_request_encoded_len(const vless_request_t *request)
{
    if (request == NULL) {
        return 0u;
    }
    const size_t flow_len = strnlen(request->flow, sizeof(request->flow));
    if (flow_len > VLESS_MAX_FLOW_LEN) {
        return 0u;
    }
    const size_t addons_len = flow_len == 0u
                                  ? 0u
                                  : 1u + uvarint_len(flow_len) + flow_len;
    if (addons_len > UINT8_MAX) {
        return 0u;
    }
    size_t len = 1u + VLESS_UUID_LEN + 1u + addons_len + 1u;
    if (request->command != VLESS_COMMAND_MUX) {
        const size_t addr_len =
            aproxy_vmess_addr_encoded_len(&request->destination);
        if (addr_len == 0u) {
            return 0u;
        }
        len += addr_len;
    }
    return len;
}

int vless_request_encode(const vless_request_t *request,
                         uint8_t *out,
                         size_t out_capacity,
                         size_t *out_len)
{
    if (request == NULL || out_len == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    if (request->command != VLESS_COMMAND_TCP &&
        request->command != VLESS_COMMAND_UDP &&
        request->command != VLESS_COMMAND_MUX) {
        return APROXY_ERR_UNSUPPORTED;
    }
    const size_t need = vless_request_encoded_len(request);
    if (need == 0u) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    *out_len = need;
    if (out == NULL || out_capacity < need) {
        return APROXY_ERR_BUFFER_TOO_SMALL;
    }

    size_t pos = 0u;
    out[pos++] = VLESS_VERSION;
    memcpy(out + pos, request->uuid, VLESS_UUID_LEN);
    pos += VLESS_UUID_LEN;
    const size_t flow_len = strlen(request->flow);
    const size_t addons_len = flow_len == 0u
                                  ? 0u
                                  : 1u + uvarint_len(flow_len) + flow_len;
    out[pos++] = (uint8_t)addons_len;
    if (flow_len > 0u) {
        out[pos++] = 0x0au;
        pos += put_uvarint(out + pos, flow_len);
        memcpy(out + pos, request->flow, flow_len);
        pos += flow_len;
    }
    out[pos++] = request->command;
    if (request->command != VLESS_COMMAND_MUX) {
        size_t addr_len = 0u;
        const int rc = aproxy_vmess_addr_encode(
            &request->destination, out + pos, out_capacity - pos, &addr_len);
        if (rc != APROXY_OK) {
            return rc;
        }
        pos += addr_len;
    }
    *out_len = pos;
    return APROXY_OK;
}

static int decode_addons(const uint8_t *data,
                         size_t data_len,
                         char flow[VLESS_MAX_FLOW_LEN + 1u])
{
    size_t pos = 0u;
    flow[0] = '\0';
    while (pos < data_len) {
        const uint8_t field = data[pos++];
        if (field != 0x0au && field != 0x12u) {
            return APROXY_ERR_INVALID_FRAME;
        }
        size_t value_len = 0u;
        size_t varint_len = 0u;
        int rc = get_uvarint(data + pos, data_len - pos, &value_len,
                             &varint_len);
        if (rc != APROXY_OK) {
            return rc;
        }
        pos += varint_len;
        if (value_len > data_len - pos) {
            return APROXY_ERR_BUFFER_TOO_SMALL;
        }
        if (field == 0x0au) {
            if (value_len > VLESS_MAX_FLOW_LEN) {
                return APROXY_ERR_FRAME_TOO_LARGE;
            }
            memcpy(flow, data + pos, value_len);
            flow[value_len] = '\0';
        }
        pos += value_len;
    }
    return APROXY_OK;
}

int vless_request_decode(const uint8_t *data,
                         size_t data_len,
                         vless_request_t *out,
                         size_t *consumed)
{
    if (data == NULL || out == NULL || consumed == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    *consumed = 0u;
    if (data_len < 1u + VLESS_UUID_LEN + 1u) {
        return APROXY_ERR_BUFFER_TOO_SMALL;
    }
    if (data[0] != VLESS_VERSION) {
        return APROXY_ERR_INVALID_FRAME;
    }
    memset(out, 0, sizeof(*out));
    memcpy(out->uuid, data + 1u, VLESS_UUID_LEN);
    size_t pos = 1u + VLESS_UUID_LEN;
    const size_t addons_len = data[pos++];
    if (addons_len > data_len - pos) {
        return APROXY_ERR_BUFFER_TOO_SMALL;
    }
    int rc = decode_addons(data + pos, addons_len, out->flow);
    if (rc != APROXY_OK) {
        return rc;
    }
    pos += addons_len;
    if (pos >= data_len) {
        return APROXY_ERR_BUFFER_TOO_SMALL;
    }
    out->command = data[pos++];
    if (out->command != VLESS_COMMAND_TCP &&
        out->command != VLESS_COMMAND_UDP &&
        out->command != VLESS_COMMAND_MUX) {
        return APROXY_ERR_UNSUPPORTED;
    }
    if (out->command != VLESS_COMMAND_MUX) {
        size_t addr_len = 0u;
        rc = aproxy_vmess_addr_decode(data + pos, data_len - pos,
                                      &out->destination, &addr_len);
        if (rc != APROXY_OK) {
            return rc;
        }
        pos += addr_len;
    }
    *consumed = pos;
    return APROXY_OK;
}

int vless_response_header_decode(const uint8_t *data,
                                 size_t data_len,
                                 size_t *consumed)
{
    if (data == NULL || consumed == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    *consumed = 0u;
    if (data_len < 2u) {
        return APROXY_ERR_BUFFER_TOO_SMALL;
    }
    if (data[0] != VLESS_VERSION) {
        return APROXY_ERR_INVALID_FRAME;
    }
    const size_t need = 2u + data[1];
    if (data_len < need) {
        return APROXY_ERR_BUFFER_TOO_SMALL;
    }
    *consumed = need;
    return APROXY_OK;
}
