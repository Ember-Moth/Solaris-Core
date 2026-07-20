#include "aproxy/reality.h"

#include <stddef.h>
#include <string.h>

static int base64url_value(unsigned char ch)
{
    if (ch >= 'A' && ch <= 'Z') {
        return (int)(ch - 'A');
    }
    if (ch >= 'a' && ch <= 'z') {
        return (int)(ch - 'a') + 26;
    }
    if (ch >= '0' && ch <= '9') {
        return (int)(ch - '0') + 52;
    }
    if (ch == '-') {
        return 62;
    }
    if (ch == '_') {
        return 63;
    }
    return -1;
}

static int decode_public_key(const char *input, uint8_t output[32])
{
    if (input == NULL || strlen(input) != 43u) {
        return APROXY_ERR_PARSE;
    }
    uint32_t accumulator = 0u;
    unsigned int bits = 0u;
    size_t written = 0u;
    for (size_t i = 0u; i < 43u; i++) {
        const int value = base64url_value((unsigned char)input[i]);
        if (value < 0) {
            return APROXY_ERR_PARSE;
        }
        accumulator = (accumulator << 6u) | (uint32_t)value;
        bits += 6u;
        if (bits >= 8u) {
            bits -= 8u;
            if (written >= 32u) {
                return APROXY_ERR_PARSE;
            }
            output[written++] = (uint8_t)(accumulator >> bits);
        }
    }
    if (written != 32u || bits != 2u ||
        (accumulator & ((UINT32_C(1) << bits) - 1u)) != 0u) {
        return APROXY_ERR_PARSE;
    }
    return APROXY_OK;
}

static int hex_value(unsigned char ch)
{
    if (ch >= '0' && ch <= '9') {
        return (int)(ch - '0');
    }
    if (ch >= 'a' && ch <= 'f') {
        return (int)(ch - 'a') + 10;
    }
    if (ch >= 'A' && ch <= 'F') {
        return (int)(ch - 'A') + 10;
    }
    return -1;
}

static int decode_short_id(const char *input, uint8_t output[8])
{
    if (input == NULL) {
        return APROXY_OK;
    }
    const size_t length = strlen(input);
    if (length > 16u || (length & 1u) != 0u) {
        return APROXY_ERR_PARSE;
    }
    for (size_t i = 0u; i < length; i += 2u) {
        const int high = hex_value((unsigned char)input[i]);
        const int low = hex_value((unsigned char)input[i + 1u]);
        if (high < 0 || low < 0) {
            return APROXY_ERR_PARSE;
        }
        output[i / 2u] = (uint8_t)((high << 4u) | low);
    }
    return APROXY_OK;
}

int aproxy_reality_config_parse(const char *public_key,
                                const char *short_id,
                                aproxy_reality_config_t *out)
{
    if (public_key == NULL || out == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    memset(out, 0, sizeof(*out));
    int rc = decode_public_key(public_key, out->public_key);
    if (rc == APROXY_OK) {
        rc = decode_short_id(short_id, out->short_id);
    }
    if (rc != APROXY_OK) {
        memset(out, 0, sizeof(*out));
        return rc;
    }
    out->enabled = 1;
    return APROXY_OK;
}
