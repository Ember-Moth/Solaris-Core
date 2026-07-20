/*
 * Wire-compatible XHTTP request behavior based on Xray-core b17a88f9b46d.
 * This file is licensed under MPL-2.0.
 */

#include "xhttp_request.h"
#include "platform.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <strings.h>
#endif

#include <openssl/rand.h>

#include "aproxy/buffer.h"
#include "xhttp_internal.h"

static const char base62[] =
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

#define XHTTP_HEADER_ARENA_CHUNK 4096u

struct xhttp_header_arena_chunk {
    xhttp_header_arena_chunk_t *next;
    size_t used;
    size_t capacity;
    uint8_t data[];
};

void xhttp_request_headers_init(xhttp_request_headers_t *headers)
{
    if (headers != NULL) {
        memset(headers, 0, sizeof(*headers));
        headers->fields = headers->inline_fields;
        headers->capacity = XHTTP_REQUEST_INLINE_HEADERS;
    }
}

void xhttp_request_headers_free(xhttp_request_headers_t *headers)
{
    if (headers == NULL) {
        return;
    }
    if (headers->fields != headers->inline_fields) {
        free(headers->fields);
    }
    while (headers->arena != NULL) {
        xhttp_header_arena_chunk_t *next = headers->arena->next;
        free(headers->arena);
        headers->arena = next;
    }
    memset(headers, 0, sizeof(*headers));
}

static int header_fields_reserve(xhttp_request_headers_t *headers)
{
    if (headers->count < headers->capacity) {
        return APROXY_OK;
    }
    if (headers->capacity > SIZE_MAX / 2u) {
        return APROXY_ERR_NO_MEMORY;
    }
    const size_t capacity = headers->capacity * 2u;
    if (capacity > SIZE_MAX / sizeof(*headers->fields)) {
        return APROXY_ERR_NO_MEMORY;
    }
    nghttp2_nv *fields = (nghttp2_nv *)malloc(
        capacity * sizeof(*headers->fields));
    if (fields == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    memcpy(fields, headers->fields,
           headers->count * sizeof(*headers->fields));
    if (headers->fields != headers->inline_fields) {
        free(headers->fields);
    }
    headers->fields = fields;
    headers->capacity = capacity;
    return APROXY_OK;
}

static uint8_t *header_arena_alloc(xhttp_request_headers_t *headers,
                                   size_t size)
{
    xhttp_header_arena_chunk_t *chunk = headers->arena;
    if (chunk == NULL || size > chunk->capacity - chunk->used) {
        const size_t capacity = size > XHTTP_HEADER_ARENA_CHUNK
                                    ? size
                                    : XHTTP_HEADER_ARENA_CHUNK;
        if (capacity > SIZE_MAX - sizeof(*chunk)) {
            return NULL;
        }
        chunk = (xhttp_header_arena_chunk_t *)malloc(
            sizeof(*chunk) + capacity);
        if (chunk == NULL) {
            return NULL;
        }
        chunk->next = headers->arena;
        chunk->used = 0u;
        chunk->capacity = capacity;
        headers->arena = chunk;
    }
    uint8_t *result = chunk->data + chunk->used;
    chunk->used += size;
    return result;
}

static int add_header_bytes(xhttp_request_headers_t *headers,
                            const char *name,
                            const char *value,
                            size_t value_len)
{
    if (headers == NULL || name == NULL || value == NULL ||
        name[0] == '\0') {
        return APROXY_ERR_PARSE;
    }
    const size_t name_len = strlen(name);
    if (memchr(name, '\r', name_len) != NULL ||
        memchr(name, '\n', name_len) != NULL ||
        memchr(value, '\r', value_len) != NULL ||
        memchr(value, '\n', value_len) != NULL ||
        name_len > SIZE_MAX - value_len - 2u) {
        return APROXY_ERR_PARSE;
    }
    int rc = header_fields_reserve(headers);
    if (rc != APROXY_OK) {
        return rc;
    }
    uint8_t *storage =
        header_arena_alloc(headers, name_len + value_len + 2u);
    if (storage == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    uint8_t *name_copy = storage;
    uint8_t *value_copy = storage + name_len + 1u;
    for (size_t i = 0u; i < name_len; i++) {
        const unsigned char c = (unsigned char)name[i];
        name_copy[i] = (uint8_t)(c >= 'A' && c <= 'Z'
                                     ? c + ('a' - 'A')
                                     : c);
    }
    name_copy[name_len] = 0u;
    memcpy(value_copy, value, value_len);
    value_copy[value_len] = 0u;
    nghttp2_nv *field = &headers->fields[headers->count++];
    field->name = name_copy;
    field->namelen = name_len;
    field->value = value_copy;
    field->valuelen = value_len;
    field->flags = NGHTTP2_NV_FLAG_NONE;
    return APROXY_OK;
}

static int add_header(xhttp_request_headers_t *headers,
                      const char *name,
                      const char *value)
{
    return value == NULL
               ? APROXY_ERR_PARSE
               : add_header_bytes(headers, name, value, strlen(value));
}

const char *xhttp_request_header_find(
    const xhttp_request_headers_t *headers,
    const char *name)
{
    if (headers == NULL || name == NULL) {
        return NULL;
    }
    const size_t len = strlen(name);
    for (size_t i = 0u; i < headers->count; i++) {
        if (headers->fields[i].namelen == len &&
            strncasecmp((const char *)headers->fields[i].name,
                        name, len) == 0) {
            return (const char *)headers->fields[i].value;
        }
    }
    return NULL;
}

static int append_text(aproxy_buffer_t *output, const char *text)
{
    return aproxy_buffer_append(output, (const uint8_t *)text, strlen(text));
}

static int append_url_encoded(aproxy_buffer_t *output, const char *value)
{
    static const char hex[] = "0123456789ABCDEF";
    for (const unsigned char *p = (const unsigned char *)value;
         *p != '\0'; p++) {
        if (isalnum(*p) || *p == '-' || *p == '_' || *p == '.' ||
            *p == '~') {
            const int rc = aproxy_buffer_append(output, p, 1u);
            if (rc != APROXY_OK) {
                return rc;
            }
        } else {
            const uint8_t encoded[3] = {
                '%', (uint8_t)hex[*p >> 4u], (uint8_t)hex[*p & 0x0fu],
            };
            const int rc = aproxy_buffer_append(output, encoded,
                                                sizeof(encoded));
            if (rc != APROXY_OK) {
                return rc;
            }
        }
    }
    return APROXY_OK;
}

static int add_query(aproxy_buffer_t *path,
                     int *has_query,
                     const char *key,
                     const char *value)
{
    const uint8_t separator = *has_query ? '&' : '?';
    int rc = aproxy_buffer_append(path, &separator, 1u);
    if (rc == APROXY_OK) {
        rc = append_url_encoded(path, key);
    }
    if (rc == APROXY_OK) {
        const uint8_t equals = '=';
        rc = aproxy_buffer_append(path, &equals, 1u);
    }
    if (rc == APROXY_OK) {
        rc = append_url_encoded(path, value);
    }
    if (rc == APROXY_OK) {
        *has_query = 1;
    }
    return rc;
}

static int append_path_value(aproxy_buffer_t *path, const char *value)
{
    if (path->len == 0u || path->data[path->len - 1u] != '/') {
        const uint8_t slash = '/';
        int rc = aproxy_buffer_append(path, &slash, 1u);
        if (rc != APROXY_OK) {
            return rc;
        }
    }
    return append_url_encoded(path, value);
}

static int append_cookie(aproxy_buffer_t *cookie,
                         const char *key,
                         const char *value)
{
    int rc = APROXY_OK;
    if (cookie->len > 0u) {
        rc = append_text(cookie, "; ");
    }
    if (rc == APROXY_OK) {
        rc = append_text(cookie, key);
    }
    if (rc == APROXY_OK) {
        rc = append_text(cookie, "=");
    }
    if (rc == APROXY_OK) {
        rc = append_text(cookie, value);
    }
    return rc;
}

static int random_string(char *output, size_t len)
{
    size_t position = 0u;
    uint8_t random[256];
    const uint8_t limit = (uint8_t)(UINT8_MAX -
                                    (UINT8_MAX + 1u) %
                                        (sizeof(base62) - 1u) + 1u);
    while (position < len) {
        if (RAND_bytes(random, sizeof(random)) != 1) {
            return APROXY_ERR_CRYPTO;
        }
        for (size_t i = 0u; i < sizeof(random) && position < len; i++) {
            if (random[i] >= limit) {
                continue;
            }
            output[position++] = base62[random[i] % (sizeof(base62) - 1u)];
        }
    }
    output[len] = '\0';
    return APROXY_OK;
}

static uint8_t hpack_code_bits(uint8_t value)
{
    static const uint8_t digit_bits[10] = {5, 5, 5, 6, 6,
                                            6, 6, 6, 6, 6};
    static const uint8_t upper_bits[26] = {
        6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8};
    static const uint8_t lower_bits[26] = {
        5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6,
        6, 5, 6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7};
    if (value >= '0' && value <= '9') {
        return digit_bits[value - '0'];
    }
    if (value >= 'A' && value <= 'Z') {
        return upper_bits[value - 'A'];
    }
    return lower_bits[value - 'a'];
}

static size_t hpack_huffman_encoded_len(const char *value, size_t len)
{
    uint64_t bits = 0u;
    for (size_t i = 0u; i < len; i++) {
        bits += hpack_code_bits((uint8_t)value[i]);
    }
    return (size_t)((bits + 7u) / 8u);
}

static int make_padding(const aproxy_xhttp_config_t *config, char **out)
{
    int32_t target = 0;
    int rc = aproxy_xhttp_range_random(config->x_padding_bytes, &target);
    if (rc != APROXY_OK || target <= 0) {
        return rc != APROXY_OK ? rc : APROXY_ERR_PARSE;
    }
    size_t len = (size_t)target;
    if (config->x_padding_method == APROXY_XHTTP_PADDING_TOKENISH) {
        len = (len * 5u + 3u) / 4u;
        if (len == 0u) {
            len = 1u;
        }
    }
    const size_t capacity =
        config->x_padding_method == APROXY_XHTTP_PADDING_TOKENISH
            ? len + 150u
            : len;
    if (capacity < len) {
        return APROXY_ERR_NO_MEMORY;
    }
    char *padding = (char *)malloc(capacity + 1u);
    if (padding == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    if (config->x_padding_method == APROXY_XHTTP_PADDING_TOKENISH) {
        rc = random_string(padding, len);
        char adjust = 'X';
        for (unsigned int attempt = 0u; rc == APROXY_OK && attempt < 150u;
             attempt++) {
            const size_t encoded = hpack_huffman_encoded_len(padding, len);
            const int64_t difference =
                (int64_t)encoded - (int64_t)target;
            if (difference >= -2 && difference <= 2) {
                break;
            }
            if (difference < 0 && len < capacity) {
                padding[len++] = adjust;
                padding[len] = '\0';
                adjust = adjust == 'X' ? 'Z' : 'X';
            } else if (difference > 0 && len > 1u) {
                padding[--len] = '\0';
            }
        }
    } else {
        memset(padding, 'X', len);
        padding[len] = '\0';
    }
    if (rc != APROXY_OK) {
        free(padding);
        return rc;
    }
    *out = padding;
    return APROXY_OK;
}

static char *base64url_encode(const uint8_t *input, size_t len)
{
    static const char table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const size_t output_len = (len * 8u + 5u) / 6u;
    char *output = (char *)malloc(output_len + 1u);
    if (output == NULL) {
        return NULL;
    }
    uint32_t bits = 0u;
    unsigned int bit_count = 0u;
    size_t position = 0u;
    for (size_t i = 0u; i < len; i++) {
        bits = (bits << 8u) | input[i];
        bit_count += 8u;
        while (bit_count >= 6u) {
            bit_count -= 6u;
            output[position++] = table[(bits >> bit_count) & 0x3fu];
            bits &= bit_count == 0u ? 0u : (1u << bit_count) - 1u;
        }
    }
    if (bit_count > 0u) {
        output[position++] = table[(bits << (6u - bit_count)) & 0x3fu];
    }
    output[position] = '\0';
    return output;
}

static int add_payload_fields(const aproxy_xhttp_config_t *config,
                              const uint8_t *payload,
                              size_t payload_len,
                              xhttp_request_headers_t *headers,
                              aproxy_buffer_t *cookie)
{
    if (config->uplink_data_placement == APROXY_XHTTP_PLACEMENT_BODY) {
        return APROXY_OK;
    }
    char *encoded = base64url_encode(payload, payload_len);
    if (encoded == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    int32_t chunk_size = 0;
    int rc = aproxy_xhttp_range_random(config->uplink_chunk_size,
                                       &chunk_size);
    if (rc != APROXY_OK || chunk_size <= 0) {
        free(encoded);
        return rc != APROXY_OK ? rc : APROXY_ERR_PARSE;
    }
    const size_t len = strlen(encoded);
    for (size_t offset = 0u, index = 0u; offset < len; index++) {
        size_t part_len = (size_t)chunk_size;
        if (part_len > len - offset) {
            part_len = len - offset;
        }
        char key[128];
        const int written = snprintf(
            key, sizeof(key),
            config->uplink_data_placement == APROXY_XHTTP_PLACEMENT_COOKIE
                ? "%s_%zu"
                : "%s-%zu",
            config->uplink_data_key, index);
        if (written < 0 || (size_t)written >= sizeof(key)) {
            rc = APROXY_ERR_FRAME_TOO_LARGE;
            break;
        }
        if (config->uplink_data_placement ==
            APROXY_XHTTP_PLACEMENT_COOKIE) {
            char saved = encoded[offset + part_len];
            encoded[offset + part_len] = '\0';
            rc = append_cookie(cookie, key, encoded + offset);
            encoded[offset + part_len] = saved;
        } else {
            rc = add_header_bytes(headers, key, encoded + offset, part_len);
        }
        if (rc != APROXY_OK) {
            break;
        }
        offset += part_len;
    }
    free(encoded);
    return rc;
}

static int apply_meta(aproxy_buffer_t *path,
                      int *has_query,
                      aproxy_buffer_t *cookie,
                      xhttp_request_headers_t *headers,
                      aproxy_xhttp_placement_t placement,
                      const char *key,
                      const char *value)
{
    if (value == NULL || value[0] == '\0') {
        return APROXY_OK;
    }
    switch (placement) {
    case APROXY_XHTTP_PLACEMENT_PATH:
        return append_path_value(path, value);
    case APROXY_XHTTP_PLACEMENT_QUERY:
        return add_query(path, has_query, key, value);
    case APROXY_XHTTP_PLACEMENT_HEADER:
        return add_header(headers, key, value);
    case APROXY_XHTTP_PLACEMENT_COOKIE:
        return append_cookie(cookie, key, value);
    default:
        return APROXY_ERR_PARSE;
    }
}

static int add_default_header(xhttp_request_headers_t *headers,
                              const char *name,
                              const char *value)
{
    return xhttp_request_header_find(headers, name) == NULL
               ? add_header(headers, name, value)
               : APROXY_OK;
}

static int add_common_headers(const aproxy_xhttp_config_t *config,
                              xhttp_request_headers_t *headers)
{
    for (size_t i = 0u; i < config->header_count; i++) {
        if (strcasecmp(config->headers[i].name, "host") == 0) {
            return APROXY_ERR_PARSE;
        }
        if (strcasecmp(config->headers[i].name, "user-agent") == 0 &&
            strcmp(config->headers[i].value, "golang") == 0) {
            continue;
        }
        int rc = add_header(headers, config->headers[i].name,
                            config->headers[i].value);
        if (rc != APROXY_OK) {
            return rc;
        }
    }
    int omit_user_agent = 0;
    for (size_t i = 0u; i < config->header_count; i++) {
        omit_user_agent =
            omit_user_agent ||
            (strcasecmp(config->headers[i].name, "user-agent") == 0 &&
             strcmp(config->headers[i].value, "golang") == 0);
    }
    int rc = APROXY_OK;
    if (!omit_user_agent) {
        rc = add_default_header(
            headers, "user-agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 "
            "Safari/537.36");
    }
    const struct {
        const char *name;
        const char *value;
    } defaults[] = {
        {"accept-language", "en-US,en;q=0.9"},
        {"dnt", "1"},
        {"sec-fetch-mode", "cors"},
        {"sec-fetch-dest", "empty"},
        {"sec-fetch-site", "same-origin"},
        {"priority", "u=1, i"},
        {"cache-control", "no-cache"},
        {"pragma", "no-cache"},
        {"accept", "*/*"},
    };
    for (size_t i = 0u; rc == APROXY_OK &&
                        i < sizeof(defaults) / sizeof(defaults[0]); i++) {
        rc = add_default_header(headers, defaults[i].name,
                                defaults[i].value);
    }
    return rc;
}

static int build_base_path(const aproxy_xhttp_config_t *config,
                           aproxy_buffer_t *path,
                           const char **query)
{
    const char *question = strchr(config->path, '?');
    const size_t path_len = question == NULL
                                ? strlen(config->path)
                                : (size_t)(question - config->path);
    int rc;
    if (path_len == 0u || config->path[0] != '/') {
        const uint8_t slash = '/';
        rc = aproxy_buffer_append(path, &slash, 1u);
        if (rc != APROXY_OK) {
            return rc;
        }
    }
    rc = aproxy_buffer_append(path, (const uint8_t *)config->path,
                              path_len);
    if (rc != APROXY_OK) {
        return rc;
    }
    *query = question != NULL && question[1] != '\0' ? question + 1 : NULL;
    return rc;
}

static void move_last_header(xhttp_request_headers_t *headers, size_t index)
{
    if (headers == NULL || headers->count == 0u ||
        index >= headers->count - 1u) {
        return;
    }
    const nghttp2_nv field = headers->fields[headers->count - 1u];
    memmove(headers->fields + index + 1u, headers->fields + index,
            (headers->count - index - 1u) * sizeof(*headers->fields));
    headers->fields[index] = field;
}

int xhttp_request_headers_build(const aproxy_xhttp_config_t *config,
                                xhttp_request_kind_t kind,
                                const char *session_id,
                                const char *sequence,
                                const uint8_t *payload,
                                size_t payload_len,
                                xhttp_request_headers_t *headers)
{
    if (config == NULL || headers == NULL ||
        (payload == NULL && payload_len > 0u)) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    aproxy_buffer_t path;
    aproxy_buffer_t cookie;
    aproxy_buffer_t referer;
    aproxy_buffer_init(&path);
    aproxy_buffer_init(&cookie);
    aproxy_buffer_init(&referer);
    char *padding = NULL;
    int has_query = 0;
    const char *configured_query = NULL;
    int rc = build_base_path(config, &path, &configured_query);
    if (rc == APROXY_OK &&
        (config->session_id_placement == APROXY_XHTTP_PLACEMENT_PATH ||
         config->seq_placement == APROXY_XHTTP_PLACEMENT_PATH) &&
        (path.len == 0u || path.data[path.len - 1u] != '/')) {
        const uint8_t slash = '/';
        rc = aproxy_buffer_append(&path, &slash, 1u);
    }
    const size_t base_path_len = path.len;
    const char *authority = config->host != NULL && config->host[0] != '\0'
                                ? config->host
                                : (config->sni != NULL &&
                                           config->sni[0] != '\0'
                                       ? config->sni
                                       : config->server_host);
    const char *method = kind == XHTTP_REQUEST_DOWNLOAD
                             ? "GET"
                             : config->uplink_http_method;
    if (rc == APROXY_OK) {
        rc = add_header(headers, ":method", method);
    }
    if (rc == APROXY_OK) {
        rc = add_header(headers, ":scheme",
                        config->tls_enabled ? "https" : "http");
    }
    if (rc == APROXY_OK) {
        rc = add_header(headers, ":authority", authority);
    }
    if (rc == APROXY_OK) {
        rc = add_common_headers(config, headers);
    }
    if (rc == APROXY_OK &&
        config->session_id_placement == APROXY_XHTTP_PLACEMENT_PATH) {
        rc = apply_meta(&path, &has_query, &cookie, headers,
                        config->session_id_placement,
                        config->session_id_key, session_id);
    }
    if (rc == APROXY_OK &&
        config->seq_placement == APROXY_XHTTP_PLACEMENT_PATH) {
        rc = apply_meta(&path, &has_query, &cookie, headers,
                        config->seq_placement, config->seq_key, sequence);
    }
    if (rc == APROXY_OK && configured_query != NULL) {
        const uint8_t question = '?';
        rc = aproxy_buffer_append(&path, &question, 1u);
        if (rc == APROXY_OK) {
            rc = append_text(&path, configured_query);
        }
        if (rc == APROXY_OK) {
            has_query = 1;
        }
    }
    if (rc == APROXY_OK) {
        rc = make_padding(config, &padding);
    }
    if (rc == APROXY_OK) {
        aproxy_xhttp_placement_t placement =
            config->x_padding_obfs_mode
                ? config->x_padding_placement
                : APROXY_XHTTP_PLACEMENT_QUERY_IN_HEADER;
        const char *key = config->x_padding_obfs_mode
                              ? config->x_padding_key
                              : "x_padding";
        const char *header = config->x_padding_obfs_mode
                                 ? config->x_padding_header
                                 : "referer";
        if (placement == APROXY_XHTTP_PLACEMENT_HEADER) {
            rc = add_header(headers, header, padding);
        } else if (placement == APROXY_XHTTP_PLACEMENT_COOKIE) {
            rc = append_cookie(&cookie, key, padding);
        } else if (placement == APROXY_XHTTP_PLACEMENT_QUERY) {
            rc = add_query(&path, &has_query, key, padding);
        } else {
            rc = append_text(&referer,
                             config->tls_enabled ? "https://" : "http://");
            if (rc == APROXY_OK) {
                rc = append_text(&referer, authority);
            }
            if (rc == APROXY_OK) {
                rc = aproxy_buffer_append(&referer, path.data,
                                          base_path_len);
            }
            int referer_query = 0;
            if (rc == APROXY_OK && configured_query != NULL) {
                const uint8_t question = '?';
                rc = aproxy_buffer_append(&referer, &question, 1u);
                if (rc == APROXY_OK) {
                    rc = append_text(&referer, configured_query);
                }
                if (rc == APROXY_OK) {
                    referer_query = 1;
                }
            }
            if (rc == APROXY_OK) {
                rc = add_query(&referer, &referer_query, key, padding);
            }
            if (rc == APROXY_OK) {
                rc = aproxy_buffer_append_zero(&referer, 1u);
            }
            if (rc == APROXY_OK) {
                rc = add_header(headers, header,
                                (const char *)referer.data);
            }
        }
    }
    if (rc == APROXY_OK &&
        config->session_id_placement != APROXY_XHTTP_PLACEMENT_PATH) {
        rc = apply_meta(&path, &has_query, &cookie, headers,
                        config->session_id_placement,
                        config->session_id_key, session_id);
    }
    if (rc == APROXY_OK &&
        config->seq_placement != APROXY_XHTTP_PLACEMENT_PATH) {
        rc = apply_meta(&path, &has_query, &cookie, headers,
                        config->seq_placement, config->seq_key, sequence);
    }
    if (rc == APROXY_OK && kind == XHTTP_REQUEST_PACKET_UPLOAD) {
        rc = add_payload_fields(config, payload, payload_len, headers,
                                &cookie);
    }
    if (rc == APROXY_OK && cookie.len > 0u) {
        rc = aproxy_buffer_append_zero(&cookie, 1u);
        if (rc == APROXY_OK) {
            rc = add_header(headers, "cookie", (const char *)cookie.data);
        }
    }
    if (rc == APROXY_OK &&
        (kind == XHTTP_REQUEST_STREAM_UPLOAD ||
         kind == XHTTP_REQUEST_STREAM_ONE) &&
        !config->no_grpc_header) {
        rc = add_default_header(headers, "content-type",
                                "application/grpc");
    }
    if (rc == APROXY_OK) {
        rc = aproxy_buffer_append_zero(&path, 1u);
    }
    if (rc == APROXY_OK) {
        rc = add_header(headers, ":path", (const char *)path.data);
        if (rc == APROXY_OK) {
            move_last_header(headers, 3u);
        }
    }
    free(padding);
    aproxy_buffer_free(&path);
    aproxy_buffer_free(&cookie);
    aproxy_buffer_free(&referer);
    if (rc != APROXY_OK) {
        xhttp_request_headers_free(headers);
    }
    return rc;
}
