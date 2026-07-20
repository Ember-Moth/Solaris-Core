#include "sniffer.h"

#include <ctype.h>
#include <limits.h>
#include <string.h>

#include <openssl/aead.h>
#include <openssl/aes.h>
#include <openssl/digest.h>
#include <openssl/hkdf.h>

typedef struct sniff_reader {
    const aproxy_const_span_t *spans;
    size_t count;
    size_t len;
} sniff_reader_t;

static int reader_byte(const sniff_reader_t *reader,
                       size_t offset,
                       uint8_t *out)
{
    if (reader == NULL || out == NULL || offset >= reader->len) {
        return 0;
    }
    for (size_t i = 0u; i < reader->count; i++) {
        if (offset < reader->spans[i].len) {
            *out = reader->spans[i].data[offset];
            return 1;
        }
        offset -= reader->spans[i].len;
    }
    return 0;
}

static int reader_u16(const sniff_reader_t *reader,
                      size_t offset,
                      size_t *out)
{
    uint8_t high = 0u;
    uint8_t low = 0u;
    if (out == NULL || !reader_byte(reader, offset, &high) ||
        !reader_byte(reader, offset + 1u, &low)) {
        return 0;
    }
    *out = ((size_t)high << 8u) | (size_t)low;
    return 1;
}

static int reader_u24(const sniff_reader_t *reader,
                      size_t offset,
                      size_t *out)
{
    uint8_t a = 0u;
    uint8_t b = 0u;
    uint8_t c = 0u;
    if (out == NULL || !reader_byte(reader, offset, &a) ||
        !reader_byte(reader, offset + 1u, &b) ||
        !reader_byte(reader, offset + 2u, &c)) {
        return 0;
    }
    *out = ((size_t)a << 16u) | ((size_t)b << 8u) | (size_t)c;
    return 1;
}

static int ascii_equal_ci(uint8_t value, char expected)
{
    return (uint8_t)tolower((unsigned char)value) ==
           (uint8_t)tolower((unsigned char)expected);
}

static int range_equal_ci(const sniff_reader_t *reader,
                          size_t offset,
                          size_t length,
                          const char *expected)
{
    if (reader == NULL || expected == NULL || strlen(expected) != length) {
        return 0;
    }
    for (size_t i = 0u; i < length; i++) {
        uint8_t value = 0u;
        if (!reader_byte(reader, offset + i, &value) ||
            !ascii_equal_ci(value, expected[i])) {
            return 0;
        }
    }
    return 1;
}

static int normalize_domain(const sniff_reader_t *reader,
                            size_t offset,
                            size_t length,
                            int strip_port,
                            aproxy_sniff_result_t *result)
{
    if (reader == NULL || result == NULL) {
        return 0;
    }
    while (length > 0u) {
        uint8_t value = 0u;
        (void)reader_byte(reader, offset, &value);
        if (value != ' ' && value != '\t') {
            break;
        }
        offset++;
        length--;
    }
    while (length > 0u) {
        uint8_t value = 0u;
        (void)reader_byte(reader, offset + length - 1u, &value);
        if (value != ' ' && value != '\t' && value != '\r') {
            break;
        }
        length--;
    }
    if (strip_port && length > 0u) {
        size_t colon = SIZE_MAX;
        size_t colon_count = 0u;
        for (size_t i = 0u; i < length; i++) {
            uint8_t value = 0u;
            (void)reader_byte(reader, offset + i, &value);
            if (value == ':') {
                colon = i;
                colon_count++;
            }
        }
        if (colon_count == 1u && colon + 1u < length) {
            int port = 1;
            for (size_t i = colon + 1u; i < length; i++) {
                uint8_t value = 0u;
                (void)reader_byte(reader, offset + i, &value);
                if (value < '0' || value > '9') {
                    port = 0;
                    break;
                }
            }
            if (port) {
                length = colon;
            }
        }
    }
    if (length == 0u || length > APROXY_ADDR_MAX_FQDN) {
        return 0;
    }

    size_t label_len = 0u;
    int has_alpha = 0;
    for (size_t i = 0u; i < length; i++) {
        uint8_t value = 0u;
        (void)reader_byte(reader, offset + i, &value);
        value = (uint8_t)tolower((unsigned char)value);
        if (value == '.') {
            if (label_len == 0u || label_len > 63u ||
                result->domain[i - 1u] == '-') {
                return 0;
            }
            label_len = 0u;
        } else {
            if (!((value >= 'a' && value <= 'z') ||
                  (value >= '0' && value <= '9') || value == '-')) {
                return 0;
            }
            if (label_len == 0u && value == '-') {
                return 0;
            }
            label_len++;
            has_alpha |= value >= 'a' && value <= 'z';
        }
        result->domain[i] = (char)value;
    }
    if (label_len == 0u || label_len > 63u ||
        result->domain[length - 1u] == '-' || !has_alpha) {
        return 0;
    }
    result->domain[length] = '\0';
    result->domain_len = length;
    return 1;
}

static aproxy_sniff_status_t sniff_http(const sniff_reader_t *reader,
                                        size_t byte_limit,
                                        aproxy_sniff_result_t *result)
{
    static const char *const methods[] = {
        "GET ", "POST ", "HEAD ", "PUT ", "DELETE ",
        "OPTIONS ", "CONNECT ", "PATCH ", "TRACE "
    };
    int method_match = 0;
    int method_possible = 0;
    for (size_t m = 0u; m < sizeof(methods) / sizeof(methods[0]); m++) {
        const size_t method_len = strlen(methods[m]);
        const size_t compare_len = reader->len < method_len
                                       ? reader->len
                                       : method_len;
        int prefix = 1;
        for (size_t i = 0u; i < compare_len; i++) {
            uint8_t value = 0u;
            (void)reader_byte(reader, i, &value);
            if (!ascii_equal_ci(value, methods[m][i])) {
                prefix = 0;
                break;
            }
        }
        if (prefix && reader->len < method_len) {
            method_possible = 1;
        } else if (prefix) {
            method_match = 1;
            break;
        }
    }
    if (!method_match) {
        return method_possible ? APROXY_SNIFF_NEED_MORE
                               : APROXY_SNIFF_NO_MATCH;
    }

    size_t line_start = 0u;
    int first_line = 1;
    for (size_t i = 0u; i + 1u < reader->len; i++) {
        uint8_t a = 0u;
        uint8_t b = 0u;
        (void)reader_byte(reader, i, &a);
        (void)reader_byte(reader, i + 1u, &b);
        if (a != '\r' || b != '\n') {
            continue;
        }
        const size_t line_len = i - line_start;
        if (first_line) {
            first_line = 0;
        } else if (line_len == 0u) {
            return APROXY_SNIFF_NO_MATCH;
        } else {
            size_t colon = SIZE_MAX;
            for (size_t j = 0u; j < line_len; j++) {
                uint8_t value = 0u;
                (void)reader_byte(reader, line_start + j, &value);
                if (value == ':') {
                    colon = j;
                    break;
                }
            }
            if (colon != SIZE_MAX &&
                range_equal_ci(reader, line_start, colon, "host") &&
                normalize_domain(reader, line_start + colon + 1u,
                                 line_len - colon - 1u, 1, result)) {
                result->protocol = APROXY_SNIFF_PROTOCOL_HTTP;
                return APROXY_SNIFF_MATCH;
            }
        }
        line_start = i + 2u;
        i++;
    }
    return reader->len < byte_limit ? APROXY_SNIFF_NEED_MORE
                                    : APROXY_SNIFF_NO_MATCH;
}

static aproxy_sniff_status_t sniff_client_hello(
    const sniff_reader_t *reader,
    size_t base,
    size_t available,
    aproxy_sniff_protocol_t protocol,
    aproxy_sniff_result_t *result)
{
    uint8_t handshake_type = 0u;
    size_t hello_len = 0u;
    if (available < 4u) {
        return APROXY_SNIFF_NEED_MORE;
    }
    (void)reader_byte(reader, base, &handshake_type);
    if (handshake_type != 1u ||
        !reader_u24(reader, base + 1u, &hello_len)) {
        return APROXY_SNIFF_NO_MATCH;
    }
    if (hello_len > available - 4u) {
        return APROXY_SNIFF_NEED_MORE;
    }
    const size_t end = base + 4u + hello_len;
    size_t cursor = base + 4u;
    if (hello_len < 2u + 32u + 1u || cursor + 35u > end) {
        return APROXY_SNIFF_NO_MATCH;
    }
    cursor += 34u;
    uint8_t session_id_len = 0u;
    (void)reader_byte(reader, cursor++, &session_id_len);
    if (session_id_len > 32u || cursor + session_id_len + 2u > end) {
        return APROXY_SNIFF_NO_MATCH;
    }
    cursor += session_id_len;
    size_t cipher_len = 0u;
    (void)reader_u16(reader, cursor, &cipher_len);
    cursor += 2u;
    if ((cipher_len & 1u) != 0u || cursor + cipher_len + 1u > end) {
        return APROXY_SNIFF_NO_MATCH;
    }
    cursor += cipher_len;
    uint8_t compression_len = 0u;
    (void)reader_byte(reader, cursor++, &compression_len);
    if (cursor + compression_len > end) {
        return APROXY_SNIFF_NO_MATCH;
    }
    cursor += compression_len;
    if (cursor == end) {
        return APROXY_SNIFF_NO_MATCH;
    }
    size_t extensions_len = 0u;
    if (cursor + 2u > end ||
        !reader_u16(reader, cursor, &extensions_len)) {
        return APROXY_SNIFF_NO_MATCH;
    }
    cursor += 2u;
    if (extensions_len != end - cursor) {
        return APROXY_SNIFF_NO_MATCH;
    }
    while (cursor + 4u <= end) {
        size_t extension_type = 0u;
        size_t extension_len = 0u;
        (void)reader_u16(reader, cursor, &extension_type);
        (void)reader_u16(reader, cursor + 2u, &extension_len);
        cursor += 4u;
        if (extension_len > end - cursor) {
            return APROXY_SNIFF_NO_MATCH;
        }
        if (extension_type == 0u) {
            size_t names_len = 0u;
            if (extension_len < 2u ||
                !reader_u16(reader, cursor, &names_len) ||
                names_len != extension_len - 2u) {
                return APROXY_SNIFF_NO_MATCH;
            }
            size_t name = cursor + 2u;
            const size_t names_end = name + names_len;
            while (name + 3u <= names_end) {
                uint8_t name_type = 0u;
                size_t name_len = 0u;
                (void)reader_byte(reader, name, &name_type);
                (void)reader_u16(reader, name + 1u, &name_len);
                name += 3u;
                if (name_len > names_end - name) {
                    return APROXY_SNIFF_NO_MATCH;
                }
                if (name_type == 0u &&
                    normalize_domain(reader, name, name_len, 0, result)) {
                    result->protocol = protocol;
                    return APROXY_SNIFF_MATCH;
                }
                name += name_len;
            }
            return APROXY_SNIFF_NO_MATCH;
        }
        cursor += extension_len;
    }
    return APROXY_SNIFF_NO_MATCH;
}

static aproxy_sniff_status_t sniff_tls_record(
    const sniff_reader_t *reader,
    aproxy_sniff_result_t *result)
{
    uint8_t content_type = 0u;
    uint8_t major = 0u;
    if (reader->len == 0u) {
        return APROXY_SNIFF_NEED_MORE;
    }
    (void)reader_byte(reader, 0u, &content_type);
    if (content_type != 0x16u) {
        return APROXY_SNIFF_NO_MATCH;
    }
    if (reader->len < 3u) {
        return APROXY_SNIFF_NEED_MORE;
    }
    (void)reader_byte(reader, 1u, &major);
    if (major != 3u) {
        return APROXY_SNIFF_NO_MATCH;
    }
    if (reader->len < 5u) {
        return APROXY_SNIFF_NEED_MORE;
    }
    size_t record_len = 0u;
    (void)reader_u16(reader, 3u, &record_len);
    if (record_len > reader->len - 5u) {
        return APROXY_SNIFF_NEED_MORE;
    }
    return sniff_client_hello(reader, 5u, record_len,
                              APROXY_SNIFF_PROTOCOL_TLS, result);
}

aproxy_sniff_status_t aproxy_sniff_tcp(
    const aproxy_const_span_t *spans,
    size_t span_count,
    size_t byte_limit,
    aproxy_sniff_result_t *result)
{
    if (spans == NULL || result == NULL || span_count == 0u ||
        span_count > 2u || byte_limit == 0u) {
        return APROXY_SNIFF_NO_MATCH;
    }
    memset(result, 0, sizeof(*result));
    sniff_reader_t reader = {.spans = spans, .count = span_count, .len = 0u};
    for (size_t i = 0u; i < span_count; i++) {
        const size_t remaining = byte_limit - reader.len;
        reader.len += spans[i].len < remaining ? spans[i].len : remaining;
        if (reader.len == byte_limit) {
            break;
        }
    }
    const aproxy_sniff_status_t http = sniff_http(&reader, byte_limit, result);
    if (http == APROXY_SNIFF_MATCH) {
        return http;
    }
    const aproxy_sniff_status_t tls = sniff_tls_record(&reader, result);
    if (tls == APROXY_SNIFF_MATCH) {
        return tls;
    }
    return http == APROXY_SNIFF_NEED_MORE ||
                   tls == APROXY_SNIFF_NEED_MORE
               ? APROXY_SNIFF_NEED_MORE
               : APROXY_SNIFF_NO_MATCH;
}

static int quic_varint(const uint8_t *data,
                       size_t length,
                       size_t *cursor,
                       uint64_t *out)
{
    if (data == NULL || cursor == NULL || out == NULL || *cursor >= length) {
        return 0;
    }
    const uint8_t first = data[*cursor];
    const size_t bytes = (size_t)1u << (first >> 6u);
    if (bytes > length - *cursor) {
        return 0;
    }
    uint64_t value = first & 0x3fu;
    for (size_t i = 1u; i < bytes; i++) {
        value = (value << 8u) | data[*cursor + i];
    }
    *cursor += bytes;
    *out = value;
    return 1;
}

static int hkdf_label(uint8_t *out,
                      size_t out_len,
                      const uint8_t *secret,
                      size_t secret_len,
                      const char *label)
{
    uint8_t info[64];
    const size_t label_len = strlen(label);
    const char prefix[] = "tls13 ";
    const size_t full_len = sizeof(prefix) - 1u + label_len;
    if (out == NULL || secret == NULL || out_len > UINT16_MAX ||
        full_len > UINT8_MAX || 4u + full_len > sizeof(info)) {
        return 0;
    }
    info[0] = (uint8_t)(out_len >> 8u);
    info[1] = (uint8_t)out_len;
    info[2] = (uint8_t)full_len;
    memcpy(info + 3u, prefix, sizeof(prefix) - 1u);
    memcpy(info + 3u + sizeof(prefix) - 1u, label, label_len);
    info[3u + full_len] = 0u;
    return HKDF_expand(out, out_len, EVP_sha256(), secret, secret_len,
                       info, 4u + full_len) == 1;
}

static aproxy_sniff_status_t sniff_quic_crypto(
    const uint8_t *plaintext,
    size_t plaintext_len,
    aproxy_buffer_t *crypto_data,
    size_t crypto_limit,
    aproxy_sniff_result_t *result)
{
    size_t cursor = 0u;
    while (cursor < plaintext_len) {
        uint64_t frame_type = 0u;
        if (!quic_varint(plaintext, plaintext_len, &cursor, &frame_type)) {
            return APROXY_SNIFF_NO_MATCH;
        }
        if (frame_type == 0u || frame_type == 1u) {
            continue;
        }
        if (frame_type == 2u || frame_type == 3u) {
            uint64_t ranges = 0u;
            uint64_t ignored = 0u;
            if (!quic_varint(plaintext, plaintext_len, &cursor, &ignored) ||
                !quic_varint(plaintext, plaintext_len, &cursor, &ignored) ||
                !quic_varint(plaintext, plaintext_len, &cursor, &ranges) ||
                !quic_varint(plaintext, plaintext_len, &cursor, &ignored) ||
                ranges > 65535u) {
                return APROXY_SNIFF_NO_MATCH;
            }
            for (uint64_t i = 0u; i < ranges; i++) {
                if (!quic_varint(plaintext, plaintext_len, &cursor,
                                 &ignored) ||
                    !quic_varint(plaintext, plaintext_len, &cursor,
                                 &ignored)) {
                    return APROXY_SNIFF_NO_MATCH;
                }
            }
            if (frame_type == 3u &&
                (!quic_varint(plaintext, plaintext_len, &cursor, &ignored) ||
                 !quic_varint(plaintext, plaintext_len, &cursor, &ignored) ||
                 !quic_varint(plaintext, plaintext_len, &cursor, &ignored))) {
                return APROXY_SNIFF_NO_MATCH;
            }
            continue;
        }
        if (frame_type == 6u) {
            uint64_t offset = 0u;
            uint64_t length = 0u;
            if (!quic_varint(plaintext, plaintext_len, &cursor, &offset) ||
                !quic_varint(plaintext, plaintext_len, &cursor, &length) ||
                length > plaintext_len - cursor || offset > crypto_limit ||
                length > crypto_limit - (size_t)offset) {
                return APROXY_SNIFF_NO_MATCH;
            }
            const size_t fragment_offset = (size_t)offset;
            const size_t fragment_len = (size_t)length;
            const size_t end = fragment_offset + fragment_len;
            if (end > crypto_data->len &&
                aproxy_buffer_append_zero(
                    crypto_data, end - crypto_data->len) != APROXY_OK) {
                return APROXY_SNIFF_NO_MATCH;
            }
            memcpy(crypto_data->data + fragment_offset,
                   plaintext + cursor, fragment_len);
            const aproxy_const_span_t span = {
                .data = crypto_data->data,
                .len = crypto_data->len,
            };
            const sniff_reader_t reader = {
                .spans = &span,
                .count = 1u,
                .len = span.len,
            };
            const aproxy_sniff_status_t status = sniff_client_hello(
                &reader, 0u, reader.len, APROXY_SNIFF_PROTOCOL_QUIC,
                result);
            if (status == APROXY_SNIFF_MATCH) {
                return status;
            }
            cursor += fragment_len;
            continue;
        }
        if (frame_type == 0x1cu) {
            uint64_t reason_len = 0u;
            uint64_t ignored = 0u;
            if (!quic_varint(plaintext, plaintext_len, &cursor, &ignored) ||
                !quic_varint(plaintext, plaintext_len, &cursor, &ignored) ||
                !quic_varint(plaintext, plaintext_len, &cursor,
                             &reason_len) ||
                reason_len > plaintext_len - cursor) {
                return APROXY_SNIFF_NO_MATCH;
            }
            cursor += (size_t)reason_len;
            continue;
        }
        return APROXY_SNIFF_NO_MATCH;
    }
    return APROXY_SNIFF_NEED_MORE;
}

aproxy_sniff_status_t aproxy_sniff_quic_initial(
    const uint8_t *datagram,
    size_t datagram_len,
    uint8_t *scratch,
    size_t scratch_capacity,
    aproxy_buffer_t *crypto_data,
    size_t crypto_limit,
    aproxy_sniff_result_t *result)
{
    static const uint8_t salt_v1[20] = {
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
        0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
    };
    static const uint8_t salt_draft29[20] = {
        0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97,
        0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99,
    };
    if (datagram == NULL || scratch == NULL || crypto_data == NULL ||
        result == NULL || datagram_len < 7u ||
        scratch_capacity < datagram_len || crypto_limit == 0u) {
        return APROXY_SNIFF_NO_MATCH;
    }
    memset(result, 0, sizeof(*result));
    memcpy(scratch, datagram, datagram_len);
    size_t packet = 0u;
    int saw_initial = 0;
    while (packet < datagram_len) {
        size_t cursor = packet;
        const uint8_t protected_first = scratch[cursor++];
        if ((protected_first & 0xc0u) != 0xc0u ||
            datagram_len - cursor < 5u) {
            return APROXY_SNIFF_NO_MATCH;
        }
        const uint32_t version =
            ((uint32_t)scratch[cursor] << 24u) |
            ((uint32_t)scratch[cursor + 1u] << 16u) |
            ((uint32_t)scratch[cursor + 2u] << 8u) |
            (uint32_t)scratch[cursor + 3u];
        cursor += 4u;
        const uint8_t *salt = NULL;
        if (version == 1u) {
            salt = salt_v1;
        } else if (version == UINT32_C(0xff00001d)) {
            salt = salt_draft29;
        } else {
            return APROXY_SNIFF_NO_MATCH;
        }
        const uint8_t dcid_len = scratch[cursor++];
        if (dcid_len == 0u || dcid_len > 20u ||
            dcid_len > datagram_len - cursor) {
            return APROXY_SNIFF_NO_MATCH;
        }
        const uint8_t *dcid = scratch + cursor;
        cursor += dcid_len;
        if (cursor >= datagram_len) {
            return APROXY_SNIFF_NO_MATCH;
        }
        const uint8_t scid_len = scratch[cursor++];
        if (scid_len > 20u || scid_len > datagram_len - cursor) {
            return APROXY_SNIFF_NO_MATCH;
        }
        cursor += scid_len;
        if ((protected_first & 0x30u) != 0u) {
            return saw_initial ? APROXY_SNIFF_NEED_MORE
                               : APROXY_SNIFF_NO_MATCH;
        }
        uint64_t token_len = 0u;
        if (!quic_varint(scratch, datagram_len, &cursor, &token_len) ||
            token_len > datagram_len - cursor) {
            return APROXY_SNIFF_NO_MATCH;
        }
        cursor += (size_t)token_len;
        uint64_t packet_len_value = 0u;
        if (!quic_varint(scratch, datagram_len, &cursor,
                         &packet_len_value) ||
            packet_len_value < 4u ||
            packet_len_value > datagram_len - cursor) {
            return APROXY_SNIFF_NO_MATCH;
        }
        const size_t pn_offset = cursor;
        const size_t packet_end = cursor + (size_t)packet_len_value;
        if (pn_offset + 4u > packet_end ||
            packet_end - (pn_offset + 4u) < AES_BLOCK_SIZE) {
            return APROXY_SNIFF_NO_MATCH;
        }

        uint8_t initial_secret[EVP_MAX_MD_SIZE];
        size_t initial_secret_len = 0u;
        uint8_t client_secret[32];
        uint8_t hp_key[16];
        uint8_t key[16];
        uint8_t iv[12];
        if (HKDF_extract(initial_secret, &initial_secret_len, EVP_sha256(),
                         dcid, dcid_len, salt, 20u) != 1 ||
            !hkdf_label(client_secret, sizeof(client_secret), initial_secret,
                        initial_secret_len, "client in") ||
            !hkdf_label(hp_key, sizeof(hp_key), client_secret,
                        sizeof(client_secret), "quic hp") ||
            !hkdf_label(key, sizeof(key), client_secret,
                        sizeof(client_secret), "quic key") ||
            !hkdf_label(iv, sizeof(iv), client_secret,
                        sizeof(client_secret), "quic iv")) {
            return APROXY_SNIFF_NO_MATCH;
        }
        AES_KEY aes;
        uint8_t mask[AES_BLOCK_SIZE];
        if (AES_set_encrypt_key(hp_key, 128u, &aes) != 0) {
            return APROXY_SNIFF_NO_MATCH;
        }
        AES_encrypt(scratch + pn_offset + 4u, mask, &aes);
        scratch[packet] ^= mask[0] & 0x0fu;
        const size_t pn_len = (scratch[packet] & 0x03u) + 1u;
        if (pn_len > packet_end - pn_offset) {
            return APROXY_SNIFF_NO_MATCH;
        }
        uint64_t packet_number = 0u;
        for (size_t i = 0u; i < pn_len; i++) {
            scratch[pn_offset + i] ^= mask[i + 1u];
            packet_number = (packet_number << 8u) |
                            scratch[pn_offset + i];
        }
        uint8_t nonce[sizeof(iv)];
        memcpy(nonce, iv, sizeof(nonce));
        for (size_t i = 0u; i < sizeof(packet_number); i++) {
            nonce[sizeof(nonce) - 1u - i] ^=
                (uint8_t)(packet_number >> (i * 8u));
        }
        const size_t header_len = pn_offset + pn_len - packet;
        const size_t ciphertext_len = packet_end - (pn_offset + pn_len);
        EVP_AEAD_CTX context;
        memset(&context, 0, sizeof(context));
        if (EVP_AEAD_CTX_init(&context, EVP_aead_aes_128_gcm(), key,
                              sizeof(key), EVP_AEAD_DEFAULT_TAG_LENGTH,
                              NULL) != 1) {
            return APROXY_SNIFF_NO_MATCH;
        }
        size_t plaintext_len = 0u;
        const int opened = EVP_AEAD_CTX_open(
            &context, scratch + pn_offset + pn_len, &plaintext_len,
            ciphertext_len, nonce, sizeof(nonce),
            scratch + pn_offset + pn_len, ciphertext_len,
            scratch + packet, header_len);
        EVP_AEAD_CTX_cleanup(&context);
        if (opened != 1) {
            return APROXY_SNIFF_NO_MATCH;
        }
        saw_initial = 1;
        const aproxy_sniff_status_t status = sniff_quic_crypto(
            scratch + pn_offset + pn_len, plaintext_len, crypto_data,
            crypto_limit, result);
        if (status != APROXY_SNIFF_NEED_MORE) {
            return status;
        }
        packet = packet_end;
    }
    return saw_initial ? APROXY_SNIFF_NEED_MORE
                       : APROXY_SNIFF_NO_MATCH;
}
