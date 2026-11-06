#include "adapters/outbound/vless/encryption/config.h"
#include <openssl/aead.h>
#include <openssl/base64.h>
#include <openssl/bytestring.h>
#include <openssl/crypto.h>
#include <openssl/curve25519.h>
#include <openssl/mlkem.h>
#include <string.h>

static int equal(const char *part, size_t size, const char *word)
{ return size == strlen(word) && memcmp(part, word, size) == 0; }
static int number(const char **cursor, const char *end, uint32_t *out)
{
    const char *p = *cursor; uint32_t value = 0u;
    if (p == end || *p < '0' || *p > '9') return 0;
    do {
        uint32_t digit = (uint32_t)(*p - '0');
        if (value > (UINT32_MAX - digit) / 10u) return 0;
        value = value * 10u + digit; p++;
    } while (p < end && *p >= '0' && *p <= '9');
    *cursor = p; *out = value; return 1;
}
static int range(const char *part, size_t size, solaris_vless_encryption_range_t *out)
{
    const char *p = part, *end = part + size;
    return number(&p, end, &out->probability) && p < end && *p++ == '-' &&
        number(&p, end, &out->minimum) && p < end && *p++ == '-' &&
        number(&p, end, &out->maximum) && p == end && out->probability <= 100u &&
        out->minimum <= out->maximum;
}
static int key(const char *part, size_t size, solaris_vless_encryption_key_t *out)
{
    if (size != 43u && size != 1579u) return 0;
    uint8_t base64[1585], encoded[1585], decoded[1185];
    for (size_t i = 0u; i < size; ++i) {
        unsigned char c = (unsigned char)part[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) base64[i] = c;
        else if (c == '-') base64[i] = '+';
        else if (c == '_') base64[i] = '/';
        else return 0;
    }
    base64[size] = '=';
    if (!EVP_DecodeBase64(decoded, &out->length, sizeof(decoded), base64, size + 1u) ||
        (out->length != 32u && out->length != 1184u)) return 0;
    memcpy(out->bytes, decoded, out->length);
    int encoded_size = EVP_EncodeBlock(encoded, out->bytes, out->length);
    if (encoded_size != (int)(size + 1u) || memcmp(base64, encoded, size + 1u) != 0) return 0;
    if (out->length == 32u) {
        uint8_t private_key[32] = {9u}, shared[32];
        int valid = out->bytes[31] < 128u && X25519(shared, private_key, out->bytes);
        OPENSSL_cleanse(shared, sizeof(shared)); return valid;
    }
    struct MLKEM768_public_key public_key; CBS input;
    CBS_init(&input, out->bytes, out->length);
    return MLKEM768_parse_public_key(&public_key, &input);
}
solaris_status_t solaris_vless_encryption_config_parse(const char *text, solaris_vless_encryption_config_t *out)
{
    if (text == NULL || out == NULL) return SOLARIS_EINVAL;
    memset(out, 0, sizeof(*out)); out->chacha = !EVP_has_aes_hardware();
    size_t length = strlen(text);
    if (length >= SOLARIS_VLESS_ENCRYPTION_TEXT || length == 0u) return SOLARIS_EINVAL;
    if (strcmp(text, "none") == 0) return SOLARIS_OK;
    size_t index = 0u; const char *p = text; uint32_t total_padding = 0u, total_delay = 0u;
    while (*p != '\0') {
        const char *end = strchr(p, '.'); if (end == NULL) end = p + strlen(p);
        size_t size = (size_t)(end - p);
        if (size == 0u) return SOLARIS_EINVAL;
        if (index == 0u) { if (!equal(p, size, "mlkem768x25519plus")) return SOLARIS_ENOTSUP; }
        else if (index == 1u) {
            if (equal(p, size, "native")) out->mode = 0u;
            else if (equal(p, size, "xorpub")) out->mode = 1u;
            else if (equal(p, size, "random")) out->mode = 2u;
            else return SOLARIS_EINVAL;
        } else if (index == 2u) {
            if (equal(p, size, "0rtt")) out->resume = 1;
            else if (!equal(p, size, "1rtt")) return SOLARIS_EINVAL;
        } else if (size < 20u && out->key_count == 0u) {
            if (out->padding_count >= SOLARIS_VLESS_ENCRYPTION_PADDING) return SOLARIS_EINVAL;
            solaris_vless_encryption_range_t *r = &out->padding[out->padding_count];
            if (!range(p, size, r)) return SOLARIS_EINVAL;
            if (out->padding_count == 0u && (r->probability != 100u || r->minimum < 35u)) return SOLARIS_EINVAL;
            if ((out->padding_count & 1u) == 0u) {
                if (r->maximum > 65553u - total_padding) return SOLARIS_EINVAL;
                total_padding += r->maximum;
            } else {
                if (r->maximum > 60000u - total_delay) return SOLARIS_EINVAL;
                total_delay += r->maximum;
            }
            out->padding_count++;
        } else {
            if (out->key_count >= SOLARIS_VLESS_ENCRYPTION_KEYS || !key(p, size, &out->keys[out->key_count])) return SOLARIS_EINVAL;
            out->key_count++;
        }
        index++;
        if (*end == '\0') break;
        p = end + 1;
        if (*p == '\0') return SOLARIS_EINVAL;
    }
    if (index < 4u || out->key_count == 0u || (out->padding_count != 0u && (out->padding_count & 1u) == 0u)) return SOLARIS_EINVAL;
    if (out->padding_count == 0u) {
        out->padding[0] = (solaris_vless_encryption_range_t){100u, 111u, 1111u};
        out->padding[1] = (solaris_vless_encryption_range_t){75u, 0u, 111u};
        out->padding[2] = (solaris_vless_encryption_range_t){50u, 0u, 3333u}; out->padding_count = 3u;
    }
    return SOLARIS_OK;
}
