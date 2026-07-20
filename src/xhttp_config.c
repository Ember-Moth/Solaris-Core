/*
 * Wire-compatible XHTTP/XMUX behavior based on Xray-core b17a88f9b46d.
 * This file is licensed under MPL-2.0.
 */

#include "aproxy/xhttp.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/rand.h>

#include "xhttp_internal.h"

static int has_newline(const char *value)
{
    return value != NULL && strpbrk(value, "\r\n") != NULL;
}

static void order_range(aproxy_xhttp_range_t *value)
{
    if (value->from > value->to) {
        const int32_t swap = value->from;
        value->from = value->to;
        value->to = swap;
    }
}

typedef struct predefined_table {
    const char *name;
    const char *value;
} predefined_table_t;

static const predefined_table_t predefined_tables[] = {
    {"ALPHABET", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"},
    {"Alphabet", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"},
    {"BASE36", "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"},
    {"Base62", "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"},
    {"HEX", "0123456789ABCDEF"},
    {"alphabet", "abcdefghijklmnopqrstuvwxyz"},
    {"base36", "0123456789abcdefghijklmnopqrstuvwxyz"},
    {"hex", "0123456789abcdef"},
    {"number", "0123456789"},
};

static const char *resolve_session_table(const char *table)
{
    if (table == NULL) {
        return NULL;
    }
    for (size_t i = 0u;
         i < sizeof(predefined_tables) / sizeof(predefined_tables[0]); i++) {
        if (strcmp(table, predefined_tables[i].name) == 0) {
            return predefined_tables[i].value;
        }
    }
    return table;
}

int aproxy_xhttp_range_is_zero(aproxy_xhttp_range_t value)
{
    return value.from == 0 && value.to == 0;
}

int aproxy_xhttp_range_parse(const char *text, aproxy_xhttp_range_t *out)
{
    if (text == NULL || out == NULL || text[0] == '\0') {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    errno = 0;
    char *end = NULL;
    const long first = strtol(text, &end, 10);
    if (errno != 0 || end == text || first < INT32_MIN ||
        first > INT32_MAX) {
        return APROXY_ERR_PARSE;
    }
    long second = first;
    if (*end == '-') {
        const char *right = end + 1;
        errno = 0;
        second = strtol(right, &end, 10);
        if (errno != 0 || end == right || second < INT32_MIN ||
            second > INT32_MAX) {
            return APROXY_ERR_PARSE;
        }
    }
    if (*end != '\0') {
        return APROXY_ERR_PARSE;
    }
    out->from = (int32_t)first;
    out->to = (int32_t)second;
    order_range(out);
    return APROXY_OK;
}

int aproxy_xhttp_range_random(aproxy_xhttp_range_t value, int32_t *out)
{
    if (out == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    order_range(&value);
    if (value.from == value.to) {
        *out = value.from;
        return APROXY_OK;
    }
    const uint64_t span =
        (uint64_t)((int64_t)value.to - (int64_t)value.from) + 1u;
    const uint64_t limit = UINT64_MAX - UINT64_MAX % span;
    uint64_t random = 0u;
    do {
        if (RAND_bytes((uint8_t *)&random, sizeof(random)) != 1) {
            return APROXY_ERR_CRYPTO;
        }
    } while (random >= limit);
    *out = (int32_t)((int64_t)value.from + (int64_t)(random % span));
    return APROXY_OK;
}

static int valid_session_id_space(const aproxy_xhttp_config_t *config)
{
    if (config->session_id_table == NULL ||
        config->session_id_table[0] == '\0') {
        return 1;
    }
    const size_t base = strlen(config->session_id_table);
    if (base == 0u || config->session_id_length.from <= 0 ||
        config->session_id_length.to < config->session_id_length.from ||
        config->session_id_length.to > 65535) {
        return 0;
    }
    for (size_t i = 0u; i < base; i++) {
        if ((unsigned char)config->session_id_table[i] >= 0x80u) {
            return 0;
        }
    }
    const uint64_t required = UINT64_C(1) << 31;
    uint64_t combinations = 0u;
    uint64_t power = 1u;
    for (int32_t length = 1; length <= config->session_id_length.to;
         length++) {
        if (power >= required || power > required / base) {
            power = required;
        } else {
            power *= base;
        }
        if (length >= config->session_id_length.from) {
            if (combinations >= required - power) {
                return 1;
            }
            combinations += power;
        }
    }
    return combinations >= required;
}

static int normalize_xmux(aproxy_xmux_config_t *config)
{
    order_range(&config->max_concurrency);
    order_range(&config->max_connections);
    order_range(&config->c_max_reuse_times);
    order_range(&config->h_max_request_times);
    order_range(&config->h_max_reusable_secs);
    if (config->max_connections.to > 0 &&
        config->max_concurrency.to > 0) {
        return APROXY_ERR_PARSE;
    }
    if (aproxy_xhttp_range_is_zero(config->max_concurrency) &&
        aproxy_xhttp_range_is_zero(config->max_connections) &&
        aproxy_xhttp_range_is_zero(config->c_max_reuse_times) &&
        aproxy_xhttp_range_is_zero(config->h_max_request_times) &&
        aproxy_xhttp_range_is_zero(config->h_max_reusable_secs) &&
        config->h_keep_alive_period == 0) {
        config->max_connections = (aproxy_xhttp_range_t){6, 6};
        config->h_max_request_times =
            (aproxy_xhttp_range_t){600, 900};
        config->h_max_reusable_secs =
            (aproxy_xhttp_range_t){1800, 3000};
    }
    return APROXY_OK;
}

int aproxy_xhttp_config_normalize(aproxy_xhttp_config_t *config)
{
    if (config == NULL || config->loop == NULL ||
        config->server_host == NULL || config->server_port == NULL ||
        has_newline(config->host) || has_newline(config->path) ||
        has_newline(config->sni)) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    if (config->mode < APROXY_XHTTP_MODE_AUTO ||
        config->mode > APROXY_XHTTP_MODE_STREAM_ONE ||
        config->http_version < APROXY_XHTTP_HTTP_AUTO ||
        config->http_version > APROXY_XHTTP_HTTP_3) {
        return APROXY_ERR_PARSE;
    }
    if (config->http_version == APROXY_XHTTP_HTTP_3) {
        return APROXY_ERR_UNSUPPORTED;
    }
    if (config->reality.enabled) {
        config->tls_enabled = 1;
    }
    if ((config->ech.config_list == NULL) !=
            (config->ech.config_list_len == 0u) ||
        (config->reality.enabled &&
         (config->ech.config_list_len > 0u || config->ech.grease ||
          config->ech.required)) ||
        (!config->tls_enabled &&
         (config->ech.config_list_len > 0u || config->ech.grease ||
          config->ech.required))) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    if (!config->tls_enabled &&
        config->http_version == APROXY_XHTTP_HTTP_2) {
        return APROXY_ERR_UNSUPPORTED;
    }
    if (config->path == NULL || config->path[0] == '\0') {
        config->path = "/";
    }
    if (aproxy_xhttp_range_is_zero(config->x_padding_bytes)) {
        config->x_padding_bytes = (aproxy_xhttp_range_t){100, 1000};
    }
    order_range(&config->x_padding_bytes);
    if (config->x_padding_bytes.from <= 0) {
        return APROXY_ERR_PARSE;
    }
    if (config->x_padding_key == NULL) {
        config->x_padding_key = "x_padding";
    }
    if (config->x_padding_header == NULL) {
        config->x_padding_header = "X-Padding";
    }
    if (config->x_padding_placement == APROXY_XHTTP_PLACEMENT_AUTO) {
        config->x_padding_placement =
            APROXY_XHTTP_PLACEMENT_QUERY_IN_HEADER;
    }
    if (config->x_padding_placement < APROXY_XHTTP_PLACEMENT_QUERY ||
        config->x_padding_placement >
            APROXY_XHTTP_PLACEMENT_QUERY_IN_HEADER ||
        config->x_padding_placement == APROXY_XHTTP_PLACEMENT_PATH ||
        config->x_padding_placement == APROXY_XHTTP_PLACEMENT_BODY) {
        return APROXY_ERR_PARSE;
    }
    if (config->uplink_http_method == NULL) {
        config->uplink_http_method = "POST";
    }
    if (strcmp(config->uplink_http_method, "POST") != 0 &&
        strcmp(config->uplink_http_method, "GET") != 0) {
        return APROXY_ERR_PARSE;
    }
    if (strcmp(config->uplink_http_method, "GET") == 0 &&
        config->mode != APROXY_XHTTP_MODE_PACKET_UP) {
        return APROXY_ERR_PARSE;
    }
    if (config->session_id_placement == APROXY_XHTTP_PLACEMENT_AUTO) {
        config->session_id_placement = APROXY_XHTTP_PLACEMENT_PATH;
    }
    if (config->seq_placement == APROXY_XHTTP_PLACEMENT_AUTO) {
        config->seq_placement = APROXY_XHTTP_PLACEMENT_PATH;
    }
    if (config->session_id_placement < APROXY_XHTTP_PLACEMENT_PATH ||
        config->session_id_placement > APROXY_XHTTP_PLACEMENT_COOKIE ||
        config->seq_placement < APROXY_XHTTP_PLACEMENT_PATH ||
        config->seq_placement > APROXY_XHTTP_PLACEMENT_COOKIE) {
        return APROXY_ERR_PARSE;
    }
    if (config->session_id_key == NULL &&
        config->session_id_placement != APROXY_XHTTP_PLACEMENT_PATH) {
        config->session_id_key =
            config->session_id_placement == APROXY_XHTTP_PLACEMENT_HEADER
                ? "X-Session"
                : "x_session";
    }
    if (config->seq_key == NULL &&
        config->seq_placement != APROXY_XHTTP_PLACEMENT_PATH) {
        config->seq_key =
            config->seq_placement == APROXY_XHTTP_PLACEMENT_HEADER
                ? "X-Seq"
                : "x_seq";
    }
    if (config->uplink_data_placement == APROXY_XHTTP_PLACEMENT_AUTO) {
        config->uplink_data_placement = APROXY_XHTTP_PLACEMENT_BODY;
    }
    if (config->uplink_data_placement != APROXY_XHTTP_PLACEMENT_BODY &&
        config->uplink_data_placement != APROXY_XHTTP_PLACEMENT_HEADER &&
        config->uplink_data_placement != APROXY_XHTTP_PLACEMENT_COOKIE) {
        return APROXY_ERR_PARSE;
    }
    if (config->mode != APROXY_XHTTP_MODE_PACKET_UP &&
        config->uplink_data_placement != APROXY_XHTTP_PLACEMENT_BODY) {
        return APROXY_ERR_PARSE;
    }
    if (config->uplink_data_key == NULL &&
        config->uplink_data_placement != APROXY_XHTTP_PLACEMENT_BODY) {
        config->uplink_data_key =
            config->uplink_data_placement == APROXY_XHTTP_PLACEMENT_COOKIE
                ? "x_data"
                : "X-Data";
    }
    order_range(&config->session_id_length);
    config->session_id_table =
        resolve_session_table(config->session_id_table);
    if (!valid_session_id_space(config)) {
        return APROXY_ERR_PARSE;
    }
    if (aproxy_xhttp_range_is_zero(config->max_each_post_bytes)) {
        config->max_each_post_bytes =
            (aproxy_xhttp_range_t){1000000, 1000000};
    }
    order_range(&config->max_each_post_bytes);
    if (config->max_each_post_bytes.from <= 0) {
        return APROXY_ERR_PARSE;
    }
    if (aproxy_xhttp_range_is_zero(config->min_posts_interval_ms)) {
        config->min_posts_interval_ms = (aproxy_xhttp_range_t){30, 30};
    }
    order_range(&config->min_posts_interval_ms);
    if (config->min_posts_interval_ms.from < 0) {
        return APROXY_ERR_PARSE;
    }
    if (config->max_buffered_posts == 0) {
        config->max_buffered_posts = 30;
    }
    if (config->max_buffered_bytes == 0) {
        config->max_buffered_bytes = 4 * 1024 * 1024;
    }
    if (config->max_buffered_posts < 0 || config->max_buffered_bytes < 0) {
        return APROXY_ERR_PARSE;
    }
    if (aproxy_xhttp_range_is_zero(config->uplink_chunk_size)) {
        config->uplink_chunk_size = config->max_each_post_bytes;
    }
    order_range(&config->uplink_chunk_size);
    if (config->uplink_chunk_size.from < 64) {
        config->uplink_chunk_size.from = 64;
        if (config->uplink_chunk_size.to < 64) {
            config->uplink_chunk_size.to = 64;
        }
    }
    return normalize_xmux(&config->xmux);
}
