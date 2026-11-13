#include "codec/dns/internal.h"
#include <string.h>

int dns_name_valid(const solaris_dns_name_t *name)
{
    if (!name || !name->length || name->length > SOLARIS_DNS_MAX_NAME) return 0;
    size_t offset = 0;
    while (offset < name->length) {
        unsigned length = name->bytes[offset++];
        if (!length) return offset == name->length;
        if (length > 63 || length >= name->length - offset) return 0;
        offset += length;
    }
    return 0;
}
solaris_status_t solaris_dns_name_from_text(const char *text, solaris_dns_name_t *out)
{
    if (!out) return SOLARIS_EINVAL;
    memset(out, 0, sizeof(*out));
    if (!text || !text[0]) return SOLARIS_EINVAL;
    size_t length = 0;
    while (length <= 254 && text[length]) ++length;
    if (length > 254) return SOLARIS_EMSGSIZE;
    if (length == 1 && text[0] == '.') { out->length = 1; return SOLARIS_OK; }
    if (text[length - 1] == '.') --length;
    solaris_dns_name_t result = {0}; size_t offset = 0, start = 0;
    for (size_t i = 0; i <= length; ++i) {
        if (i != length && text[i] != '.') {
            unsigned char c = (unsigned char)text[i];
            if (c == '\\') return SOLARIS_ENOTSUP;
            if (c < 0x21 || c > 0x7e) return SOLARIS_EINVAL;
            continue;
        }
        size_t label = i - start;
        if (!label) return SOLARIS_EINVAL;
        if (label > 63 || offset + 1 + label + 1 > sizeof(result.bytes)) return SOLARIS_EMSGSIZE;
        result.bytes[offset++] = (uint8_t)label;
        memcpy(result.bytes + offset, text + start, label); offset += label; start = i + 1;
    }
    result.bytes[offset++] = 0; result.length = (uint16_t)offset;
    *out = result; return SOLARIS_OK;
}
int solaris_dns_name_equal(const solaris_dns_name_t *a, const solaris_dns_name_t *b)
{
    if (!dns_name_valid(a) || !dns_name_valid(b) || a->length != b->length) return 0;
    for (size_t i = 0; i < a->length; ++i) {
        unsigned char x = a->bytes[i], y = b->bytes[i];
        if (x >= 'A' && x <= 'Z') x = (unsigned char)(x + ('a' - 'A'));
        if (y >= 'A' && y <= 'Z') y = (unsigned char)(y + ('a' - 'A'));
        if (x != y) return 0;
    }
    return 1;
}
