#include "shadowsocks/outbound.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/aead.h>
#include <openssl/rand.h>

#include "aproxy/buffer.h"
#include "aproxy/bufpool.h"
#include "aproxy/direct_outbound.h"
#include "aproxy/limits.h"
#include "aproxy/ring.h"
#include "aproxy/uot.h"
#include "framework/packet_flow_internal.h"
#include "framework/stream_internal.h"
#include "platform.h"
#include "shadowsocks/aead.h"
#include "shadowsocks_aead_internal.h"

#define SS_AEAD_MAX_FRAME_SIZE ((16u * 1024u) - 1u)
#define SS_2022_MAX_FRAME_SIZE 65535u
#define SS_2022_MAX_PADDING_LEN 900u
#define SS_2022_REQUEST_FIXED_LEN (1u + 8u + 2u)
#define SS_2022_RESPONSE_FIXED_BASE_LEN (1u + 8u + 2u)
#define SS_2022_HEADER_TYPE_CLIENT 0u
#define SS_2022_HEADER_TYPE_SERVER 1u
#define SS_2022_TIMESTAMP_WINDOW 30
#define SS_AEAD_LEN_SIZE 2u
#define SS_UDP_SEND_BATCH_SIZE 16u
#define SS_PACKET_POOL_MAX_FREE 16u

typedef struct ss_outbound_impl ss_outbound_impl_t;
typedef struct ss_stream_impl ss_stream_impl_t;
typedef struct ss_packet_impl ss_packet_impl_t;

static void ss_stream_free(void *impl);
static void ss_packet_free(void *impl);

struct ss_outbound_impl {
    uv_loop_t *loop;
    char *tag;
    aproxy_addr_t server;
    aproxy_outbound_t *transport;
    shadowsocks_aead_method_t method;
    uint8_t key[SHADOWSOCKS_AEAD_MAX_KEY_LEN];
    size_t key_len;
    shadowsocks_2022_psk_list_t psks;
    int is_2022;
    size_t max_pending_bytes;
    int closing;
    int free_pending;
    uint32_t next_stream_id;
    uint32_t next_packet_id;
    ss_stream_impl_t *streams;
    ss_packet_impl_t *packets;
    aproxy_bufpool_t packet_pool;
};

static void ss_outbound_maybe_destroy(ss_outbound_impl_t *outbound);

struct ss_stream_impl {
    ss_outbound_impl_t *outbound;
    aproxy_stream_t *owner;
    aproxy_stream_t *raw_stream;
    aproxy_addr_t destination;
    aproxy_stream_data_cb on_data;
    aproxy_stream_event_cb on_open;
    aproxy_stream_event_cb on_close;
    void *user_data;
    aproxy_ring_t pending_plain;
    aproxy_ring_t rx_cipher;
    aproxy_buffer_t plain_scratch;
    aproxy_buffer_t crypto_scratch;
    aproxy_buffer_t rx_plain;
    aproxy_buffer_t rx_cipher_scratch;
    EVP_AEAD_CTX writer_ctx;
    EVP_AEAD_CTX reader_ctx;
    const EVP_AEAD *writer_aead;
    const EVP_AEAD *reader_aead;
    uint8_t writer_nonce[EVP_AEAD_MAX_NONCE_LENGTH];
    uint8_t reader_nonce[EVP_AEAD_MAX_NONCE_LENGTH];
    uint8_t request_salt[SHADOWSOCKS_AEAD_MAX_SALT_LEN];
    size_t writer_nonce_len;
    size_t reader_nonce_len;
    uint32_t id;
    int raw_open;
    int writer_initialized;
    int reader_initialized;
    int request_salt_valid;
    int response_fixed_done;
    int response_header_done;
    uint16_t response_payload_len;
    int closing;
    int close_reported;
    unsigned int callback_depth;
    int free_pending;
    ss_stream_impl_t *prev;
    ss_stream_impl_t *next;
};

struct ss_packet_impl {
    ss_outbound_impl_t *outbound;
    aproxy_packet_flow_t *owner;
    aproxy_packet_flow_t *raw_flow;
    aproxy_packet_flow_data_cb on_data;
    aproxy_packet_flow_event_cb on_open;
    aproxy_packet_flow_event_cb on_close;
    void *user_data;
    uint64_t session_id;
    uint64_t next_packet_id;
    uint64_t remote_session_id;
    uint64_t last_remote_session_id;
    int64_t last_remote_seen;
    uint8_t session_key[SHADOWSOCKS_AEAD_MAX_KEY_LEN];
    uint8_t remote_session_key[SHADOWSOCKS_AEAD_MAX_KEY_LEN];
    uint8_t last_remote_session_key[SHADOWSOCKS_AEAD_MAX_KEY_LEN];
    shadowsocks_2022_replay_window_t remote_window;
    shadowsocks_2022_replay_window_t last_remote_window;
    uint32_t id;
    int udp_session_initialized;
    int remote_session_valid;
    int last_remote_session_valid;
    int raw_open;
    int closing;
    int close_reported;
    unsigned int callback_depth;
    int free_pending;
    ss_packet_impl_t *prev;
    ss_packet_impl_t *next;
};

static char *copy_string(const char *s)
{
    if (s == NULL) {
        return NULL;
    }
    const size_t len = strlen(s);
    char *copy = (char *)malloc(len + 1u);
    if (copy == NULL) {
        return NULL;
    }
    memcpy(copy, s, len + 1u);
    return copy;
}

static void put_u16(uint8_t *out, uint16_t v)
{
    out[0] = (uint8_t)(v >> 8u);
    out[1] = (uint8_t)v;
}

static uint16_t get_u16(const uint8_t *in)
{
    return (uint16_t)(((uint16_t)in[0] << 8u) | in[1]);
}

static void put_u64(uint8_t *out, uint64_t v)
{
    out[0] = (uint8_t)(v >> 56u);
    out[1] = (uint8_t)(v >> 48u);
    out[2] = (uint8_t)(v >> 40u);
    out[3] = (uint8_t)(v >> 32u);
    out[4] = (uint8_t)(v >> 24u);
    out[5] = (uint8_t)(v >> 16u);
    out[6] = (uint8_t)(v >> 8u);
    out[7] = (uint8_t)v;
}

static uint64_t get_u64(const uint8_t *in)
{
    return ((uint64_t)in[0] << 56u) |
           ((uint64_t)in[1] << 48u) |
           ((uint64_t)in[2] << 40u) |
           ((uint64_t)in[3] << 32u) |
           ((uint64_t)in[4] << 24u) |
           ((uint64_t)in[5] << 16u) |
           ((uint64_t)in[6] << 8u) |
           (uint64_t)in[7];
}

static void increase_nonce(uint8_t *nonce, size_t len)
{
    for (size_t i = 0u; i < len; i++) {
        nonce[i]++;
        if (nonce[i] != 0u) {
            break;
        }
    }
}

static size_t ss_stream_max_frame_size(const ss_stream_impl_t *stream)
{
    return stream != NULL && stream->outbound != NULL &&
                   stream->outbound->is_2022
               ? SS_2022_MAX_FRAME_SIZE
               : SS_AEAD_MAX_FRAME_SIZE;
}

static int timestamp_is_fresh(uint64_t epoch)
{
    const time_t now = time(NULL);
    if (now == (time_t)-1) {
        return 0;
    }
    const int64_t diff = (int64_t)now - (int64_t)epoch;
    return diff >= -SS_2022_TIMESTAMP_WINDOW &&
           diff <= SS_2022_TIMESTAMP_WINDOW;
}

static int random_tcp_padding(uint16_t *out_padding_len)
{
    if (out_padding_len == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    uint8_t rnd[2];
    if (RAND_bytes(rnd, sizeof(rnd)) != 1) {
        return APROXY_ERR_CRYPTO;
    }
    *out_padding_len = (uint16_t)((get_u16(rnd) % SS_2022_MAX_PADDING_LEN) +
                                  1u);
    return APROXY_OK;
}

static int parse_port(const char *text, uint16_t *out)
{
    if (text == NULL || out == NULL || text[0] == '\0') {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    errno = 0;
    char *end = NULL;
    const unsigned long value = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value == 0ul ||
        value > 65535ul) {
        return APROXY_ERR_PARSE;
    }
    *out = (uint16_t)value;
    return APROXY_OK;
}

static int parse_server_addr(const char *host,
                             const char *port_text,
                             aproxy_addr_t *out)
{
    if (host == NULL || out == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    uint16_t port = 0u;
    int rc = parse_port(port_text, &port);
    if (rc != APROXY_OK) {
        return rc;
    }

    uint8_t ip[16];
    if (inet_pton(AF_INET, host, ip) == 1) {
        aproxy_addr_set_ipv4(out, ip, port);
        return APROXY_OK;
    }
    if (inet_pton(AF_INET6, host, ip) == 1) {
        aproxy_addr_set_ipv6(out, ip, port);
        return APROXY_OK;
    }
    return aproxy_addr_set_fqdn(out, host, port);
}

static void stream_list_add(ss_outbound_impl_t *outbound,
                            ss_stream_impl_t *stream)
{
    stream->prev = NULL;
    stream->next = outbound->streams;
    if (outbound->streams != NULL) {
        outbound->streams->prev = stream;
    }
    outbound->streams = stream;
}

static void stream_list_remove(ss_stream_impl_t *stream)
{
    if (stream == NULL || stream->outbound == NULL) {
        return;
    }
    if (stream->prev != NULL) {
        stream->prev->next = stream->next;
    } else if (stream->outbound->streams == stream) {
        stream->outbound->streams = stream->next;
    }
    if (stream->next != NULL) {
        stream->next->prev = stream->prev;
    }
    stream->prev = NULL;
    stream->next = NULL;
}

static void packet_list_add(ss_outbound_impl_t *outbound,
                            ss_packet_impl_t *packet)
{
    packet->prev = NULL;
    packet->next = outbound->packets;
    if (outbound->packets != NULL) {
        outbound->packets->prev = packet;
    }
    outbound->packets = packet;
}

static void packet_list_remove(ss_packet_impl_t *packet)
{
    if (packet == NULL || packet->outbound == NULL) {
        return;
    }
    if (packet->prev != NULL) {
        packet->prev->next = packet->next;
    } else if (packet->outbound->packets == packet) {
        packet->outbound->packets = packet->next;
    }
    if (packet->next != NULL) {
        packet->next->prev = packet->prev;
    }
    packet->prev = NULL;
    packet->next = NULL;
}

static void ss_stream_report_close(ss_stream_impl_t *stream, int status)
{
    if (stream == NULL || stream->close_reported) {
        return;
    }
    stream->close_reported = 1;
    if (stream->on_close != NULL && stream->owner != NULL) {
        stream->callback_depth++;
        stream->on_close(stream->owner, status, stream->user_data);
        stream->callback_depth--;
    }
}

static void ss_packet_report_close(ss_packet_impl_t *packet, int status)
{
    if (packet == NULL || packet->close_reported) {
        return;
    }
    packet->close_reported = 1;
    if (packet->on_close != NULL && packet->owner != NULL) {
        packet->callback_depth++;
        packet->on_close(packet->owner, status, packet->user_data);
        packet->callback_depth--;
    }
}

static int ss_stream_init_writer(ss_stream_impl_t *stream)
{
    if (stream == NULL || stream->raw_stream == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    if (stream->writer_initialized) {
        return APROXY_OK;
    }

    uint8_t salt[SHADOWSOCKS_AEAD_MAX_SALT_LEN];
    if (RAND_bytes(salt, stream->outbound->key_len) != 1) {
        return APROXY_ERR_CRYPTO;
    }
    uint8_t subkey[SHADOWSOCKS_AEAD_MAX_KEY_LEN];
    int rc = stream->outbound->is_2022
                 ? shadowsocks_2022_session_key(
                       stream->outbound->method, stream->outbound->key,
                       stream->outbound->key_len, salt,
                       stream->outbound->key_len, subkey)
                 : shadowsocks_aead_derive_subkey(
                       stream->outbound->method, stream->outbound->key,
                       stream->outbound->key_len, salt, subkey);
    if (rc != APROXY_OK) {
        return rc;
    }
    rc = shadowsocks_aead_init_ctx(stream->outbound->method, subkey,
                                   &stream->writer_ctx,
                                   &stream->writer_aead);
    if (rc != APROXY_OK) {
        return rc;
    }
    stream->writer_nonce_len = EVP_AEAD_nonce_length(stream->writer_aead);
    memset(stream->writer_nonce, 0, sizeof(stream->writer_nonce));

    size_t eih_len = 0u;
    if (stream->outbound->is_2022 && stream->outbound->psks.count > 1u) {
        eih_len = (stream->outbound->psks.count - 1u) * 16u;
    }
    const size_t prefix_len = stream->outbound->key_len + eih_len;
    aproxy_buffer_clear(&stream->plain_scratch);
    rc = aproxy_buffer_reserve(&stream->plain_scratch, prefix_len);
    if (rc != APROXY_OK) {
        EVP_AEAD_CTX_cleanup(&stream->writer_ctx);
        stream->writer_aead = NULL;
        stream->writer_nonce_len = 0u;
        return rc;
    }
    uint8_t *prefix = stream->plain_scratch.data;
    memcpy(prefix, salt, stream->outbound->key_len);
    if (eih_len > 0u) {
        size_t written = 0u;
        rc = shadowsocks_2022_tcp_eih_write(
            stream->outbound->method, &stream->outbound->psks, salt,
            stream->outbound->key_len, prefix + stream->outbound->key_len,
            eih_len, &written);
        if (rc != APROXY_OK || written != eih_len) {
            EVP_AEAD_CTX_cleanup(&stream->writer_ctx);
            stream->writer_aead = NULL;
            stream->writer_nonce_len = 0u;
            return rc == APROXY_OK ? APROXY_ERR_INVALID_FRAME : rc;
        }
    }
    rc = aproxy_stream_write(stream->raw_stream, prefix, prefix_len);
    if (rc != APROXY_OK) {
        EVP_AEAD_CTX_cleanup(&stream->writer_ctx);
        stream->writer_aead = NULL;
        stream->writer_nonce_len = 0u;
        return rc;
    }
    if (stream->outbound->is_2022) {
        memcpy(stream->request_salt, salt, stream->outbound->key_len);
        stream->request_salt_valid = 1;
    }
    stream->writer_initialized = 1;
    return APROXY_OK;
}

static int ss_stream_write_frame(ss_stream_impl_t *stream,
                                 const uint8_t *data,
                                 size_t len)
{
    if (stream == NULL || stream->raw_stream == NULL ||
        (data == NULL && len > 0u) ||
        len > ss_stream_max_frame_size(stream)) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    int rc = ss_stream_init_writer(stream);
    if (rc != APROXY_OK) {
        return rc;
    }

    const size_t tag_len = EVP_AEAD_max_overhead(stream->writer_aead);
    const size_t out_len = SS_AEAD_LEN_SIZE + tag_len + len + tag_len;
    aproxy_buffer_clear(&stream->crypto_scratch);
    rc = aproxy_buffer_reserve(&stream->crypto_scratch,
                               out_len == 0u ? 1u : out_len);
    if (rc != APROXY_OK) {
        return rc;
    }
    uint8_t *out = stream->crypto_scratch.data;

    uint8_t len_plain[SS_AEAD_LEN_SIZE];
    put_u16(len_plain, (uint16_t)len);
    size_t sealed_len = 0u;
    int ok = EVP_AEAD_CTX_seal(
        &stream->writer_ctx, out, &sealed_len, out_len, stream->writer_nonce,
        stream->writer_nonce_len, len_plain, sizeof(len_plain), NULL, 0u);
    if (!ok || sealed_len != SS_AEAD_LEN_SIZE + tag_len) {
        return APROXY_ERR_CRYPTO;
    }
    increase_nonce(stream->writer_nonce, stream->writer_nonce_len);

    size_t payload_sealed = 0u;
    ok = EVP_AEAD_CTX_seal(&stream->writer_ctx, out + sealed_len,
                           &payload_sealed, out_len - sealed_len,
                           stream->writer_nonce, stream->writer_nonce_len,
                           data, len, NULL, 0u);
    if (!ok || payload_sealed != len + tag_len) {
        return APROXY_ERR_CRYPTO;
    }
    increase_nonce(stream->writer_nonce, stream->writer_nonce_len);

    rc = aproxy_stream_write(stream->raw_stream, out,
                             sealed_len + payload_sealed);
    return rc;
}

static int ss_stream_write_raw_chunk(ss_stream_impl_t *stream,
                                     const uint8_t *data,
                                     size_t len)
{
    if (stream == NULL || stream->raw_stream == NULL ||
        (data == NULL && len > 0u) || len > SS_2022_MAX_FRAME_SIZE) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    int rc = ss_stream_init_writer(stream);
    if (rc != APROXY_OK) {
        return rc;
    }

    const size_t tag_len = EVP_AEAD_max_overhead(stream->writer_aead);
    const size_t out_len = len + tag_len;
    aproxy_buffer_clear(&stream->crypto_scratch);
    rc = aproxy_buffer_reserve(&stream->crypto_scratch,
                               out_len == 0u ? 1u : out_len);
    if (rc != APROXY_OK) {
        return rc;
    }
    uint8_t *out = stream->crypto_scratch.data;
    size_t sealed_len = 0u;
    const int ok = EVP_AEAD_CTX_seal(
        &stream->writer_ctx, out, &sealed_len, out_len,
        stream->writer_nonce, stream->writer_nonce_len, data, len, NULL,
        0u);
    if (!ok || sealed_len != out_len) {
        return APROXY_ERR_CRYPTO;
    }
    increase_nonce(stream->writer_nonce, stream->writer_nonce_len);
    rc = aproxy_stream_write(stream->raw_stream, out, out_len);
    return rc;
}

static int ss_stream_write_first_2022(ss_stream_impl_t *stream,
                                      const uint8_t *data,
                                      size_t len)
{
    size_t addr_len = 0u;
    int rc = aproxy_addr_encode_socksaddr(&stream->destination, NULL, 0u,
                                          &addr_len);
    if (rc != APROXY_ERR_BUFFER_TOO_SMALL) {
        return rc;
    }

    uint16_t padding_len = 0u;
    if (len < SS_2022_MAX_PADDING_LEN) {
        rc = random_tcp_padding(&padding_len);
        if (rc != APROXY_OK) {
            return rc;
        }
    }
    const size_t base_variable_len = addr_len + 2u + padding_len;
    if (base_variable_len > SS_2022_MAX_FRAME_SIZE) {
        return APROXY_ERR_FRAME_TOO_LARGE;
    }
    const size_t first_payload_room = SS_2022_MAX_FRAME_SIZE -
                                      base_variable_len;
    const size_t first_payload_len = len < first_payload_room
                                         ? len
                                         : first_payload_room;
    const size_t variable_len = base_variable_len + first_payload_len;
    if (variable_len > SS_2022_MAX_FRAME_SIZE) {
        return APROXY_ERR_FRAME_TOO_LARGE;
    }

    uint8_t fixed[SS_2022_REQUEST_FIXED_LEN];
    fixed[0] = SS_2022_HEADER_TYPE_CLIENT;
    put_u64(fixed + 1u, (uint64_t)time(NULL));
    put_u16(fixed + 9u, (uint16_t)variable_len);
    rc = ss_stream_write_raw_chunk(stream, fixed, sizeof(fixed));
    if (rc != APROXY_OK) {
        return rc;
    }

    aproxy_buffer_clear(&stream->plain_scratch);
    rc = aproxy_buffer_reserve(&stream->plain_scratch,
                               variable_len == 0u ? 1u : variable_len);
    if (rc != APROXY_OK) {
        return rc;
    }
    uint8_t *variable = stream->plain_scratch.data;
    size_t pos = 0u;
    rc = aproxy_addr_encode_socksaddr(&stream->destination, variable,
                                      addr_len, &addr_len);
    if (rc == APROXY_OK) {
        pos += addr_len;
        put_u16(variable + pos, padding_len);
        pos += 2u;
        if (padding_len > 0u) {
            if (RAND_bytes(variable + pos, padding_len) != 1) {
                rc = APROXY_ERR_CRYPTO;
            } else {
                pos += padding_len;
            }
        }
    }
    if (rc == APROXY_OK && first_payload_len > 0u) {
        memcpy(variable + pos, data, first_payload_len);
        pos += first_payload_len;
    }
    if (rc == APROXY_OK && pos != variable_len) {
        rc = APROXY_ERR_INVALID_FRAME;
    }
    if (rc == APROXY_OK) {
        rc = ss_stream_write_raw_chunk(stream, variable, variable_len);
    }
    if (rc != APROXY_OK) {
        return rc;
    }

    size_t offset = first_payload_len;
    while (offset < len) {
        const size_t chunk = len - offset < SS_2022_MAX_FRAME_SIZE
                                 ? len - offset
                                 : SS_2022_MAX_FRAME_SIZE;
        rc = ss_stream_write_frame(stream, data + offset, chunk);
        if (rc != APROXY_OK) {
            return rc;
        }
        offset += chunk;
    }
    return APROXY_OK;
}

static int ss_stream_write_first(ss_stream_impl_t *stream,
                                 const uint8_t *data,
                                 size_t len)
{
    if (stream != NULL && stream->outbound != NULL &&
        stream->outbound->is_2022) {
        return ss_stream_write_first_2022(stream, data, len);
    }
    size_t addr_len = 0u;
    int rc = aproxy_addr_encode_socksaddr(&stream->destination, NULL, 0u,
                                          &addr_len);
    if (rc != APROXY_ERR_BUFFER_TOO_SMALL) {
        return rc;
    }
    if (addr_len > SS_AEAD_MAX_FRAME_SIZE) {
        return APROXY_ERR_FRAME_TOO_LARGE;
    }
    rc = ss_stream_init_writer(stream);
    if (rc != APROXY_OK) {
        return rc;
    }
    const size_t first_payload_room = SS_AEAD_MAX_FRAME_SIZE - addr_len;
    const size_t first_payload_len = len < first_payload_room
                                         ? len
                                         : first_payload_room;
    const size_t first_len = addr_len + first_payload_len;
    aproxy_buffer_clear(&stream->plain_scratch);
    rc = aproxy_buffer_reserve(&stream->plain_scratch,
                               first_len == 0u ? 1u : first_len);
    if (rc != APROXY_OK) {
        return rc;
    }
    uint8_t *first = stream->plain_scratch.data;
    rc = aproxy_addr_encode_socksaddr(&stream->destination, first,
                                      addr_len, &addr_len);
    if (rc == APROXY_OK && first_payload_len > 0u) {
        memcpy(first + addr_len, data, first_payload_len);
    }
    if (rc == APROXY_OK) {
        rc = ss_stream_write_frame(stream, first, first_len);
    }
    if (rc != APROXY_OK) {
        return rc;
    }

    size_t offset = first_payload_len;
    while (offset < len) {
        const size_t chunk = len - offset < SS_AEAD_MAX_FRAME_SIZE
                                 ? len - offset
                                 : SS_AEAD_MAX_FRAME_SIZE;
        rc = ss_stream_write_frame(stream, data + offset, chunk);
        if (rc != APROXY_OK) {
            return rc;
        }
        offset += chunk;
    }
    return APROXY_OK;
}

static int ss_stream_write_plain(ss_stream_impl_t *stream,
                                 const uint8_t *data,
                                 size_t len)
{
    if (stream == NULL || (data == NULL && len > 0u)) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    if (!stream->writer_initialized) {
        return ss_stream_write_first(stream, data, len);
    }
    size_t offset = 0u;
    while (offset < len || (len == 0u && offset == 0u)) {
        const size_t remaining = len - offset;
        const size_t max_frame = ss_stream_max_frame_size(stream);
        const size_t chunk = remaining < max_frame
                                 ? remaining
                                 : max_frame;
        const uint8_t *chunk_data = chunk == 0u ? NULL : data + offset;
        const int rc = ss_stream_write_frame(stream, chunk_data, chunk);
        if (rc != APROXY_OK) {
            return rc;
        }
        if (len == 0u) {
            break;
        }
        offset += chunk;
    }
    return APROXY_OK;
}

static int ss_stream_flush_pending(ss_stream_impl_t *stream)
{
    if (stream == NULL || !stream->raw_open) {
        return APROXY_OK;
    }
    if (!stream->writer_initialized) {
        int rc = ss_stream_write_first(stream, NULL, 0u);
        if (rc != APROXY_OK) {
            return rc;
        }
    }
    while (aproxy_ring_size(&stream->pending_plain) > 0u) {
        aproxy_const_span_t spans[2];
        const size_t count = aproxy_ring_read_spans(&stream->pending_plain,
                                                    spans);
        if (count == 0u) {
            return APROXY_ERR_INVALID_FRAME;
        }
        for (size_t i = 0u; i < count; i++) {
            const int rc = ss_stream_write_plain(stream, spans[i].data,
                                                 spans[i].len);
            if (rc != APROXY_OK) {
                return rc;
            }
            aproxy_ring_consume(&stream->pending_plain, spans[i].len);
        }
    }
    return APROXY_OK;
}

static int ss_stream_init_reader(ss_stream_impl_t *stream,
                                 const uint8_t *salt)
{
    uint8_t subkey[SHADOWSOCKS_AEAD_MAX_KEY_LEN];
    int rc = stream->outbound->is_2022
                 ? shadowsocks_2022_session_key(
                       stream->outbound->method, stream->outbound->key,
                       stream->outbound->key_len, salt,
                       stream->outbound->key_len, subkey)
                 : shadowsocks_aead_derive_subkey(
                       stream->outbound->method, stream->outbound->key,
                       stream->outbound->key_len, salt, subkey);
    if (rc != APROXY_OK) {
        return rc;
    }
    rc = shadowsocks_aead_init_ctx(stream->outbound->method, subkey,
                                   &stream->reader_ctx,
                                   &stream->reader_aead);
    if (rc != APROXY_OK) {
        return rc;
    }
    stream->reader_nonce_len = EVP_AEAD_nonce_length(stream->reader_aead);
    memset(stream->reader_nonce, 0, sizeof(stream->reader_nonce));
    stream->reader_initialized = 1;
    return APROXY_OK;
}

static int ss_stream_open_raw_chunk(ss_stream_impl_t *stream,
                                    size_t plaintext_len,
                                    uint8_t *out)
{
    if (stream == NULL || out == NULL || !stream->reader_initialized) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    const size_t tag_len = EVP_AEAD_max_overhead(stream->reader_aead);
    const size_t ciphertext_len = plaintext_len + tag_len;
    if (aproxy_ring_size(&stream->rx_cipher) < ciphertext_len) {
        return APROXY_ERR_BUFFER_TOO_SMALL;
    }
    aproxy_buffer_clear(&stream->rx_cipher_scratch);
    int rc = aproxy_buffer_reserve(&stream->rx_cipher_scratch,
                                   ciphertext_len == 0u ? 1u
                                                        : ciphertext_len);
    if (rc != APROXY_OK) {
        return rc;
    }
    uint8_t *ciphertext = stream->rx_cipher_scratch.data;
    if (aproxy_ring_peek(&stream->rx_cipher, 0u, ciphertext,
                         ciphertext_len) != ciphertext_len) {
        return APROXY_ERR_INVALID_FRAME;
    }
    size_t opened_len = 0u;
    const int ok = EVP_AEAD_CTX_open(
        &stream->reader_ctx, out, &opened_len, plaintext_len,
        stream->reader_nonce, stream->reader_nonce_len, ciphertext,
        ciphertext_len, NULL, 0u);
    if (!ok || opened_len != plaintext_len) {
        return APROXY_ERR_CRYPTO;
    }
    increase_nonce(stream->reader_nonce, stream->reader_nonce_len);
    aproxy_ring_consume(&stream->rx_cipher, ciphertext_len);
    return APROXY_OK;
}

static int ss_stream_process_2022_response_header(ss_stream_impl_t *stream)
{
    const size_t tag_len = EVP_AEAD_max_overhead(stream->reader_aead);
    if (!stream->response_fixed_done) {
        const size_t fixed_len = SS_2022_RESPONSE_FIXED_BASE_LEN +
                                 stream->outbound->key_len;
        if (aproxy_ring_size(&stream->rx_cipher) < fixed_len + tag_len) {
            return APROXY_OK;
        }
        uint8_t fixed[1u + 8u + SHADOWSOCKS_AEAD_MAX_KEY_LEN + 2u];
        int rc = ss_stream_open_raw_chunk(stream, fixed_len, fixed);
        if (rc != APROXY_OK) {
            return rc;
        }
        if (fixed[0] != SS_2022_HEADER_TYPE_SERVER ||
            !timestamp_is_fresh(get_u64(fixed + 1u)) ||
            !stream->request_salt_valid ||
            memcmp(fixed + 9u, stream->request_salt,
                   stream->outbound->key_len) != 0) {
            return APROXY_ERR_INVALID_FRAME;
        }
        stream->response_payload_len =
            get_u16(fixed + 9u + stream->outbound->key_len);
        stream->response_fixed_done = 1;
    }

    if (aproxy_ring_size(&stream->rx_cipher) <
        (size_t)stream->response_payload_len + tag_len) {
        return APROXY_OK;
    }
    aproxy_buffer_clear(&stream->rx_plain);
    int rc = aproxy_buffer_reserve(
        &stream->rx_plain,
        stream->response_payload_len == 0u ? 1u
                                           : stream->response_payload_len);
    if (rc != APROXY_OK) {
        return rc;
    }
    uint8_t *payload = stream->rx_plain.data;
    rc = ss_stream_open_raw_chunk(stream, stream->response_payload_len,
                                  payload);
    if (rc != APROXY_OK) {
        return rc;
    }
    stream->response_header_done = 1;
    stream->request_salt_valid = 0;
    if (stream->response_payload_len > 0u && stream->on_data != NULL &&
        stream->owner != NULL) {
        stream->callback_depth++;
        stream->on_data(stream->owner, payload,
                        stream->response_payload_len, stream->user_data);
        stream->callback_depth--;
    }
    return APROXY_OK;
}

static int ss_stream_process_rx(ss_stream_impl_t *stream)
{
    if (stream == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    const size_t salt_len = stream->outbound->key_len;
    if (!stream->reader_initialized) {
        if (aproxy_ring_size(&stream->rx_cipher) < salt_len) {
            return APROXY_OK;
        }
        uint8_t salt[SHADOWSOCKS_AEAD_MAX_SALT_LEN];
        if (aproxy_ring_peek(&stream->rx_cipher, 0u, salt, salt_len) !=
            salt_len) {
            return APROXY_ERR_INVALID_FRAME;
        }
        int rc = ss_stream_init_reader(stream, salt);
        if (rc != APROXY_OK) {
            return rc;
        }
        aproxy_ring_consume(&stream->rx_cipher, salt_len);
    }

    if (stream->outbound->is_2022 && !stream->response_header_done) {
        const int rc = ss_stream_process_2022_response_header(stream);
        if (rc != APROXY_OK || stream->free_pending ||
            !stream->response_header_done) {
            return rc;
        }
    }

    const size_t tag_len = EVP_AEAD_max_overhead(stream->reader_aead);
    for (;;) {
        const size_t len_cipher_len = SS_AEAD_LEN_SIZE + tag_len;
        if (aproxy_ring_size(&stream->rx_cipher) < len_cipher_len) {
            return APROXY_OK;
        }
        uint8_t encrypted_len[SS_AEAD_LEN_SIZE + SHADOWSOCKS_AEAD_TAG_LEN];
        if (len_cipher_len > sizeof(encrypted_len) ||
            aproxy_ring_peek(&stream->rx_cipher, 0u, encrypted_len,
                             len_cipher_len) != len_cipher_len) {
            return APROXY_ERR_INVALID_FRAME;
        }
        uint8_t len_plain[SS_AEAD_LEN_SIZE];
        size_t len_plain_len = 0u;
        if (!EVP_AEAD_CTX_open(&stream->reader_ctx, len_plain,
                               &len_plain_len, sizeof(len_plain),
                               stream->reader_nonce, stream->reader_nonce_len,
                               encrypted_len, len_cipher_len, NULL, 0u) ||
            len_plain_len != sizeof(len_plain)) {
            return APROXY_ERR_CRYPTO;
        }
        const size_t frame_len = get_u16(len_plain);
        if (frame_len > ss_stream_max_frame_size(stream)) {
            return APROXY_ERR_FRAME_TOO_LARGE;
        }
        const size_t need = len_cipher_len + frame_len + tag_len;
        if (aproxy_ring_size(&stream->rx_cipher) < need) {
            return APROXY_OK;
        }
        increase_nonce(stream->reader_nonce, stream->reader_nonce_len);
        aproxy_ring_consume(&stream->rx_cipher, len_cipher_len);

        aproxy_buffer_clear(&stream->rx_cipher_scratch);
        aproxy_buffer_clear(&stream->rx_plain);
        int rc = aproxy_buffer_reserve(&stream->rx_cipher_scratch,
                                       frame_len + tag_len);
        if (rc == APROXY_OK) {
            rc = aproxy_buffer_reserve(&stream->rx_plain,
                                       frame_len == 0u ? 1u : frame_len);
        }
        if (rc != APROXY_OK) {
            return rc;
        }
        uint8_t *encrypted_payload = stream->rx_cipher_scratch.data;
        uint8_t *payload = stream->rx_plain.data;
        if (aproxy_ring_peek(&stream->rx_cipher, 0u, encrypted_payload,
                             frame_len + tag_len) != frame_len + tag_len) {
            return APROXY_ERR_INVALID_FRAME;
        }
        size_t payload_len = 0u;
        const int ok = EVP_AEAD_CTX_open(
            &stream->reader_ctx, payload, &payload_len, frame_len,
            stream->reader_nonce, stream->reader_nonce_len,
            encrypted_payload, frame_len + tag_len, NULL, 0u);
        if (!ok || payload_len != frame_len) {
            return APROXY_ERR_CRYPTO;
        }
        increase_nonce(stream->reader_nonce, stream->reader_nonce_len);
        aproxy_ring_consume(&stream->rx_cipher, frame_len + tag_len);

        if (stream->on_data != NULL && stream->owner != NULL) {
            stream->callback_depth++;
            stream->on_data(stream->owner, payload, payload_len,
                            stream->user_data);
            stream->callback_depth--;
            if (stream->free_pending) {
                return APROXY_OK;
            }
        }
    }
}

static void ss_stream_start_close(ss_stream_impl_t *stream)
{
    if (stream == NULL || stream->closing) {
        return;
    }
    stream->closing = 1;
    if (stream->raw_stream != NULL) {
        aproxy_stream_t *raw = stream->raw_stream;
        stream->raw_stream = NULL;
        stream->callback_depth++;
        (void)aproxy_stream_close(raw);
        aproxy_stream_free(raw);
        stream->callback_depth--;
    }
    ss_stream_report_close(stream, APROXY_OK);
    if (stream->free_pending) {
        ss_stream_free(stream);
    }
}

static void raw_stream_data_cb(aproxy_stream_t *raw,
                               const uint8_t *data,
                               size_t len,
                               void *user_data)
{
    (void)raw;
    ss_stream_impl_t *stream = (ss_stream_impl_t *)user_data;
    if (stream == NULL || stream->closing || data == NULL) {
        return;
    }
    const int write_rc = aproxy_ring_write(&stream->rx_cipher, data, len);
    const int process_rc = write_rc == APROXY_OK
                               ? ss_stream_process_rx(stream)
                               : write_rc;
    if (stream->free_pending) {
        ss_stream_free(stream);
        return;
    }
    if (process_rc != APROXY_OK) {
        ss_stream_start_close(stream);
    }
}

static void raw_stream_open_cb(aproxy_stream_t *raw,
                               int status,
                               void *user_data)
{
    ss_stream_impl_t *stream = (ss_stream_impl_t *)user_data;
    if (stream == NULL || stream->closing) {
        return;
    }
    if (status != APROXY_OK) {
        if (stream->on_open != NULL && stream->owner != NULL) {
            stream->callback_depth++;
            stream->on_open(stream->owner, status, stream->user_data);
            stream->callback_depth--;
        }
        if (stream->free_pending) {
            ss_stream_free(stream);
            return;
        }
        ss_stream_start_close(stream);
        return;
    }
    if (stream->raw_stream == NULL) {
        stream->raw_stream = raw;
    }
    stream->raw_open = 1;
    status = ss_stream_flush_pending(stream);
    if (stream->on_open != NULL && stream->owner != NULL) {
        stream->callback_depth++;
        stream->on_open(stream->owner, status, stream->user_data);
        stream->callback_depth--;
    }
    if (stream->free_pending) {
        ss_stream_free(stream);
        return;
    }
    if (status != APROXY_OK) {
        ss_stream_start_close(stream);
    }
}

static void raw_stream_close_cb(aproxy_stream_t *raw,
                                int status,
                                void *user_data)
{
    ss_stream_impl_t *stream = (ss_stream_impl_t *)user_data;
    if (stream == NULL) {
        return;
    }
    if (stream->raw_stream == raw) {
        stream->raw_stream = NULL;
        aproxy_stream_free(raw);
    }
    ss_stream_report_close(stream, status);
    if (stream->free_pending) {
        ss_stream_free(stream);
    }
}

static int ss_stream_write(void *impl, const uint8_t *data, size_t len)
{
    ss_stream_impl_t *stream = (ss_stream_impl_t *)impl;
    if (stream == NULL || (data == NULL && len > 0u) || stream->closing) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    if (!stream->raw_open) {
        if (aproxy_size_add_exceeds(
                aproxy_ring_size(&stream->pending_plain), len,
                stream->outbound->max_pending_bytes)) {
            return APROXY_ERR_FRAME_TOO_LARGE;
        }
        return aproxy_ring_write(&stream->pending_plain, data, len);
    }
    return ss_stream_write_plain(stream, data, len);
}

static int ss_stream_close(void *impl)
{
    ss_stream_impl_t *stream = (ss_stream_impl_t *)impl;
    if (stream == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    ss_stream_start_close(stream);
    return APROXY_OK;
}

static uint32_t ss_stream_id(const void *impl)
{
    const ss_stream_impl_t *stream = (const ss_stream_impl_t *)impl;
    return stream == NULL ? 0u : stream->id;
}

static void *ss_stream_native(const void *impl)
{
    return (void *)impl;
}

static void ss_stream_destroy(ss_stream_impl_t *stream)
{
    ss_outbound_impl_t *outbound = stream->outbound;
    stream_list_remove(stream);
    if (stream->raw_stream != NULL) {
        aproxy_stream_t *raw = stream->raw_stream;
        stream->raw_stream = NULL;
        stream->callback_depth++;
        (void)aproxy_stream_close(raw);
        aproxy_stream_free(raw);
        stream->callback_depth--;
    }
    if (stream->writer_initialized) {
        EVP_AEAD_CTX_cleanup(&stream->writer_ctx);
    }
    if (stream->reader_initialized) {
        EVP_AEAD_CTX_cleanup(&stream->reader_ctx);
    }
    aproxy_ring_free(&stream->pending_plain);
    aproxy_ring_free(&stream->rx_cipher);
    aproxy_buffer_free(&stream->plain_scratch);
    aproxy_buffer_free(&stream->crypto_scratch);
    aproxy_buffer_free(&stream->rx_plain);
    aproxy_buffer_free(&stream->rx_cipher_scratch);
    free(stream);
    ss_outbound_maybe_destroy(outbound);
}

static void ss_stream_free(void *impl)
{
    ss_stream_impl_t *stream = (ss_stream_impl_t *)impl;
    if (stream == NULL) {
        return;
    }
    if (!stream->free_pending) {
        stream->free_pending = 1;
        stream->owner = NULL;
        stream->on_data = NULL;
        stream->on_open = NULL;
        stream->on_close = NULL;
        stream->user_data = NULL;
    }
    if (stream->callback_depth == 0u) {
        ss_stream_destroy(stream);
    }
}

static const aproxy_stream_vtable_t ss_stream_vtable = {
    .write = ss_stream_write,
    .close = ss_stream_close,
    .id = ss_stream_id,
    .native = ss_stream_native,
    .free = ss_stream_free,
};

static int ss_packet_seal(ss_packet_impl_t *packet,
                          const aproxy_addr_t *destination,
                          const uint8_t *data,
                          size_t len,
                          uint8_t **sealed,
                          size_t *sealed_len,
                          size_t *sealed_capacity)
{
    if (sealed != NULL) {
        *sealed = NULL;
    }
    if (sealed_len != NULL) {
        *sealed_len = 0u;
    }
    if (sealed_capacity != NULL) {
        *sealed_capacity = 0u;
    }
    if (packet == NULL || destination == NULL || sealed == NULL ||
        sealed_len == NULL || sealed_capacity == NULL ||
        (data == NULL && len > 0u)) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    size_t addr_len = 0u;
    int rc = aproxy_addr_encode_socksaddr(destination, NULL, 0u,
                                          &addr_len);
    if (rc != APROXY_ERR_BUFFER_TOO_SMALL) {
        return rc;
    }
    if (packet->outbound->is_2022) {
        if (!packet->udp_session_initialized) {
            rc = shadowsocks_2022_udp_session_new(
                packet->outbound->method, packet->outbound->key,
                packet->outbound->key_len, &packet->session_id,
                &packet->next_packet_id, packet->session_key,
                sizeof(packet->session_key));
            if (rc != APROXY_OK) {
                return rc;
            }
            packet->udp_session_initialized = 1;
        }
        const size_t identity_len =
            packet->outbound->psks.count > 1u
                ? (packet->outbound->psks.count - 1u) * 16u
                : 0u;
        const size_t out_cap = SHADOWSOCKS_2022_MAX_PACKET_OVERHEAD +
                               identity_len +
                               1u + 8u + 2u + SS_2022_MAX_PADDING_LEN +
                               addr_len + len;
        uint8_t *out = aproxy_bufpool_acquire(
            &packet->outbound->packet_pool, out_cap == 0u ? 1u : out_cap,
            sealed_capacity);
        if (out == NULL) {
            return APROXY_ERR_NO_MEMORY;
        }
        const uint64_t packet_id = packet->next_packet_id++;
        rc = shadowsocks_2022_udp_seal_multi(
            packet->outbound->method, &packet->outbound->psks,
            packet->session_id, packet_id,
            packet->session_key, destination, data, len, out, out_cap,
            sealed_len);
        if (rc != APROXY_OK) {
            aproxy_bufpool_release(&packet->outbound->packet_pool, out,
                                   *sealed_capacity);
            *sealed_capacity = 0u;
            *sealed_len = 0u;
            return rc;
        }
        *sealed = out;
        return APROXY_OK;
    }
    const size_t out_cap = packet->outbound->key_len + addr_len + len +
                           SHADOWSOCKS_AEAD_TAG_LEN;
    uint8_t *out = aproxy_bufpool_acquire(
        &packet->outbound->packet_pool, out_cap == 0u ? 1u : out_cap,
        sealed_capacity);
    if (out == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    rc = shadowsocks_aead_udp_seal(
        packet->outbound->method, packet->outbound->key,
        packet->outbound->key_len, NULL, destination, data, len, out,
        out_cap, sealed_len);
    if (rc != APROXY_OK) {
        aproxy_bufpool_release(&packet->outbound->packet_pool, out,
                               *sealed_capacity);
        *sealed_capacity = 0u;
        *sealed_len = 0u;
        return rc;
    }
    *sealed = out;
    return APROXY_OK;
}

static int ss_packet_send(void *impl,
                          const aproxy_addr_t *destination,
                          const uint8_t *data,
                          size_t len)
{
    ss_packet_impl_t *packet = (ss_packet_impl_t *)impl;
    if (packet == NULL || destination == NULL ||
        (data == NULL && len > 0u) || packet->closing ||
        packet->raw_flow == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    uint8_t *sealed = NULL;
    size_t sealed_len = 0u;
    size_t sealed_capacity = 0u;
    int rc = ss_packet_seal(packet, destination, data, len, &sealed,
                            &sealed_len, &sealed_capacity);
    if (rc == APROXY_OK) {
        rc = aproxy_packet_flow_send(packet->raw_flow,
                                     &packet->outbound->server,
                                     sealed, sealed_len);
    }
    aproxy_bufpool_release(&packet->outbound->packet_pool, sealed,
                           sealed_capacity);
    return rc;
}

static int ss_packet_send_batch(
    void *impl,
    const aproxy_packet_flow_datagram_t *datagrams,
    size_t count,
    size_t *accepted)
{
    ss_packet_impl_t *packet = (ss_packet_impl_t *)impl;
    if (accepted != NULL) {
        *accepted = 0u;
    }
    if (packet == NULL || datagrams == NULL || count == 0u ||
        accepted == NULL || packet->closing || packet->raw_flow == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    size_t offset = 0u;
    while (offset < count) {
        const size_t remaining = count - offset;
        const size_t batch_count =
            remaining > SS_UDP_SEND_BATCH_SIZE
                ? SS_UDP_SEND_BATCH_SIZE
                : remaining;
        aproxy_packet_flow_datagram_t sealed_datagrams[
            SS_UDP_SEND_BATCH_SIZE];
        uint8_t *sealed[SS_UDP_SEND_BATCH_SIZE] = {0};
        size_t capacities[SS_UDP_SEND_BATCH_SIZE] = {0};
        size_t prepared = 0u;
        int rc = APROXY_OK;
        for (; prepared < batch_count; prepared++) {
            const aproxy_packet_flow_datagram_t *datagram =
                &datagrams[offset + prepared];
            size_t sealed_len = 0u;
            rc = ss_packet_seal(packet, datagram->destination,
                                datagram->data, datagram->len,
                                &sealed[prepared], &sealed_len,
                                &capacities[prepared]);
            if (rc != APROXY_OK) {
                break;
            }
            sealed_datagrams[prepared].destination =
                &packet->outbound->server;
            sealed_datagrams[prepared].data = sealed[prepared];
            sealed_datagrams[prepared].len = sealed_len;
        }
        size_t batch_accepted = 0u;
        if (rc == APROXY_OK) {
            rc = aproxy_packet_flow_send_batch(
                packet->raw_flow, sealed_datagrams, batch_count,
                &batch_accepted);
        }
        for (size_t i = 0u; i < prepared; i++) {
            aproxy_bufpool_release(&packet->outbound->packet_pool,
                                   sealed[i], capacities[i]);
        }
        *accepted += batch_accepted;
        if (rc != APROXY_OK) {
            return rc;
        }
        if (batch_accepted != batch_count) {
            return APROXY_ERR_INVALID_FRAME;
        }
        offset += batch_count;
    }
    return APROXY_OK;
}

static int ss_packet_close(void *impl)
{
    ss_packet_impl_t *packet = (ss_packet_impl_t *)impl;
    if (packet == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    packet->closing = 1;
    if (packet->raw_flow != NULL) {
        aproxy_packet_flow_t *raw = packet->raw_flow;
        packet->raw_flow = NULL;
        packet->callback_depth++;
        (void)aproxy_packet_flow_close(raw);
        aproxy_packet_flow_free(raw);
        packet->callback_depth--;
    }
    ss_packet_report_close(packet, APROXY_OK);
    if (packet->free_pending) {
        ss_packet_free(packet);
    }
    return APROXY_OK;
}

static uint32_t ss_packet_id(const void *impl)
{
    const ss_packet_impl_t *packet = (const ss_packet_impl_t *)impl;
    return packet == NULL ? 0u : packet->id;
}

static void *ss_packet_native(const void *impl)
{
    return (void *)impl;
}

static void ss_packet_destroy(ss_packet_impl_t *packet)
{
    ss_outbound_impl_t *outbound = packet->outbound;
    packet_list_remove(packet);
    if (packet->raw_flow != NULL) {
        aproxy_packet_flow_t *raw = packet->raw_flow;
        packet->raw_flow = NULL;
        packet->callback_depth++;
        (void)aproxy_packet_flow_close(raw);
        aproxy_packet_flow_free(raw);
        packet->callback_depth--;
    }
    if (outbound != NULL && outbound->packets == NULL) {
        aproxy_bufpool_trim(&outbound->packet_pool);
    }
    free(packet);
    ss_outbound_maybe_destroy(outbound);
}

static void ss_packet_free(void *impl)
{
    ss_packet_impl_t *packet = (ss_packet_impl_t *)impl;
    if (packet == NULL) {
        return;
    }
    if (!packet->free_pending) {
        packet->free_pending = 1;
        packet->owner = NULL;
        packet->on_data = NULL;
        packet->on_open = NULL;
        packet->on_close = NULL;
        packet->user_data = NULL;
    }
    if (packet->callback_depth == 0u) {
        ss_packet_destroy(packet);
    }
}

static const aproxy_packet_flow_vtable_t ss_packet_vtable = {
    .send = ss_packet_send,
    .send_batch = ss_packet_send_batch,
    .close = ss_packet_close,
    .id = ss_packet_id,
    .native = ss_packet_native,
    .free = ss_packet_free,
};

static int ss_packet_accept_2022_response(
    ss_packet_impl_t *packet,
    uint64_t session_id,
    uint64_t packet_id,
    const uint8_t *session_key)
{
    shadowsocks_2022_replay_window_t *window = NULL;
    if (packet->remote_session_valid &&
        session_id == packet->remote_session_id) {
        window = &packet->remote_window;
    } else if (packet->last_remote_session_valid &&
               session_id == packet->last_remote_session_id) {
        window = &packet->last_remote_window;
        packet->last_remote_seen = (int64_t)time(NULL);
    } else {
        const int64_t now = (int64_t)time(NULL);
        if (packet->remote_session_valid && packet->last_remote_seen > 0 &&
            now - packet->last_remote_seen < 60) {
            return APROXY_ERR_INVALID_FRAME;
        }
        if (packet->remote_session_valid) {
            packet->last_remote_session_id = packet->remote_session_id;
            memcpy(packet->last_remote_session_key,
                   packet->remote_session_key,
                   packet->outbound->key_len);
            packet->last_remote_window = packet->remote_window;
            packet->last_remote_session_valid = 1;
            packet->last_remote_seen = now;
        }
        packet->remote_session_id = session_id;
        memcpy(packet->remote_session_key, session_key,
               packet->outbound->key_len);
        shadowsocks_2022_replay_reset(&packet->remote_window);
        packet->remote_session_valid = 1;
        window = &packet->remote_window;
    }

    if (!shadowsocks_2022_replay_check(window, packet_id)) {
        return APROXY_ERR_INVALID_FRAME;
    }
    shadowsocks_2022_replay_add(window, packet_id);
    return APROXY_OK;
}

static void raw_packet_data_cb(aproxy_packet_flow_t *raw,
                               const aproxy_addr_t *source,
                               const uint8_t *data,
                               size_t len,
                               void *user_data)
{
    (void)raw;
    (void)source;
    ss_packet_impl_t *packet = (ss_packet_impl_t *)user_data;
    if (packet == NULL || packet->closing || data == NULL) {
        return;
    }
    size_t capacity = 0u;
    uint8_t *payload = aproxy_bufpool_acquire(
        &packet->outbound->packet_pool, len == 0u ? 1u : len, &capacity);
    if (payload == NULL) {
        (void)ss_packet_close(packet);
        return;
    }
    aproxy_addr_t decoded_source;
    size_t payload_len = 0u;
    int rc = APROXY_OK;
    if (packet->outbound->is_2022) {
        uint64_t session_id = packet->remote_session_id;
        uint64_t packet_id = 0u;
        uint8_t session_key[SHADOWSOCKS_AEAD_MAX_KEY_LEN];
        memcpy(session_key, packet->remote_session_key,
               packet->outbound->key_len);
        rc = shadowsocks_2022_udp_open_ex(
            packet->outbound->method, packet->outbound->key,
            packet->outbound->key_len, data, len, packet->session_id,
            &session_id, &packet_id, session_key, sizeof(session_key),
            &decoded_source, payload, len, &payload_len);
        if (rc == APROXY_OK) {
            rc = ss_packet_accept_2022_response(packet, session_id,
                                                packet_id, session_key);
        }
    } else {
        rc = shadowsocks_aead_udp_open(
            packet->outbound->method, packet->outbound->key,
            packet->outbound->key_len, data, len, &decoded_source,
            payload, len, &payload_len);
    }
    if (rc == APROXY_OK && packet->on_data != NULL &&
        packet->owner != NULL) {
        packet->callback_depth++;
        packet->on_data(packet->owner, &decoded_source, payload,
                        payload_len, packet->user_data);
        packet->callback_depth--;
    }
    aproxy_bufpool_release(&packet->outbound->packet_pool, payload, capacity);
    if (packet->free_pending) {
        ss_packet_free(packet);
    }
}

static void raw_packet_open_cb(aproxy_packet_flow_t *raw,
                               int status,
                               void *user_data)
{
    ss_packet_impl_t *packet = (ss_packet_impl_t *)user_data;
    if (packet == NULL || packet->closing) {
        return;
    }
    if (status == APROXY_OK) {
        if (packet->raw_flow == NULL) {
            packet->raw_flow = raw;
        }
        packet->raw_open = 1;
    }
    if (packet->on_open != NULL && packet->owner != NULL) {
        packet->callback_depth++;
        packet->on_open(packet->owner, status, packet->user_data);
        packet->callback_depth--;
    }
    if (packet->free_pending) {
        ss_packet_free(packet);
        return;
    }
    if (status != APROXY_OK) {
        (void)ss_packet_close(packet);
    }
}

static void raw_packet_close_cb(aproxy_packet_flow_t *raw,
                                int status,
                                void *user_data)
{
    ss_packet_impl_t *packet = (ss_packet_impl_t *)user_data;
    if (packet == NULL) {
        return;
    }
    if (packet->raw_flow == raw) {
        packet->raw_flow = NULL;
        aproxy_packet_flow_free(raw);
    }
    ss_packet_report_close(packet, status);
    if (packet->free_pending) {
        ss_packet_free(packet);
    }
}

static int ss_connect(void *impl)
{
    ss_outbound_impl_t *outbound = (ss_outbound_impl_t *)impl;
    if (outbound == NULL || outbound->transport == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    return aproxy_outbound_connect(outbound->transport);
}

static int ss_open_stream(void *impl,
                          const aproxy_addr_t *destination,
                          aproxy_stream_data_cb on_data,
                          aproxy_stream_event_cb on_open,
                          aproxy_stream_event_cb on_close,
                          void *user_data,
                          aproxy_stream_t **out)
{
    ss_outbound_impl_t *outbound = (ss_outbound_impl_t *)impl;
    if (outbound == NULL || destination == NULL || out == NULL ||
        outbound->closing) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    *out = NULL;
    ss_stream_impl_t *stream =
        (ss_stream_impl_t *)calloc(1u, sizeof(*stream));
    if (stream == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    stream->outbound = outbound;
    stream->destination = *destination;
    stream->on_data = on_data;
    stream->on_open = on_open;
    stream->on_close = on_close;
    stream->user_data = user_data;
    stream->id = ++outbound->next_stream_id;
    aproxy_ring_init(&stream->pending_plain);
    aproxy_ring_init(&stream->rx_cipher);
    aproxy_buffer_init(&stream->plain_scratch);
    aproxy_buffer_init(&stream->crypto_scratch);
    aproxy_buffer_init(&stream->rx_plain);
    aproxy_buffer_init(&stream->rx_cipher_scratch);

    int rc = aproxy_stream_new(&ss_stream_vtable, stream, &stream->owner);
    if (rc != APROXY_OK) {
        ss_stream_free(stream);
        return rc;
    }
    stream_list_add(outbound, stream);
    *out = stream->owner;

    rc = aproxy_outbound_open_stream(
        outbound->transport, &outbound->server, raw_stream_data_cb,
        raw_stream_open_cb, raw_stream_close_cb, stream,
        &stream->raw_stream);
    if (rc != APROXY_OK) {
        aproxy_stream_free(*out);
        *out = NULL;
        return rc;
    }
    return APROXY_OK;
}

static int ss_open_packet(void *impl,
                          const aproxy_addr_t *initial_destination,
                          aproxy_packet_flow_data_cb on_data,
                          aproxy_packet_flow_event_cb on_open,
                          aproxy_packet_flow_event_cb on_close,
                          void *user_data,
                          aproxy_packet_flow_t **out)
{
    ss_outbound_impl_t *outbound = (ss_outbound_impl_t *)impl;
    if (outbound == NULL || initial_destination == NULL || out == NULL ||
        outbound->closing) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    *out = NULL;
    ss_packet_impl_t *packet =
        (ss_packet_impl_t *)calloc(1u, sizeof(*packet));
    if (packet == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    packet->outbound = outbound;
    packet->on_data = on_data;
    packet->on_open = on_open;
    packet->on_close = on_close;
    packet->user_data = user_data;
    packet->id = ++outbound->next_packet_id;

    int rc = aproxy_packet_flow_new(&ss_packet_vtable, packet,
                                    &packet->owner);
    if (rc != APROXY_OK) {
        ss_packet_free(packet);
        return rc;
    }
    packet_list_add(outbound, packet);
    *out = packet->owner;

    rc = aproxy_outbound_open_packet(
        outbound->transport, &outbound->server, raw_packet_data_cb,
        raw_packet_open_cb, raw_packet_close_cb, packet,
        &packet->raw_flow);
    if (rc != APROXY_OK) {
        aproxy_packet_flow_free(*out);
        *out = NULL;
        return rc;
    }
    return APROXY_OK;
}

static void ss_close(void *impl)
{
    ss_outbound_impl_t *outbound = (ss_outbound_impl_t *)impl;
    if (outbound == NULL || outbound->closing) {
        return;
    }
    outbound->closing = 1;
    ss_stream_impl_t *stream = outbound->streams;
    while (stream != NULL) {
        ss_stream_impl_t *next = stream->next;
        ss_stream_start_close(stream);
        stream = next;
    }
    ss_packet_impl_t *packet = outbound->packets;
    while (packet != NULL) {
        ss_packet_impl_t *next = packet->next;
        (void)ss_packet_close(packet);
        packet = next;
    }
    if (outbound->transport != NULL) {
        aproxy_outbound_close(outbound->transport);
    }
}

static void ss_outbound_destroy(ss_outbound_impl_t *outbound)
{
    if (outbound->transport != NULL) {
        aproxy_outbound_free(outbound->transport);
    }
    shadowsocks_2022_psk_list_free(&outbound->psks);
    aproxy_bufpool_destroy(&outbound->packet_pool);
    memset(outbound->key, 0, sizeof(outbound->key));
    free(outbound->tag);
    free(outbound);
}

static void ss_outbound_maybe_destroy(ss_outbound_impl_t *outbound)
{
    if (outbound != NULL && outbound->free_pending &&
        outbound->streams == NULL && outbound->packets == NULL) {
        ss_outbound_destroy(outbound);
    }
}

static void ss_free(void *impl)
{
    ss_outbound_impl_t *outbound = (ss_outbound_impl_t *)impl;
    if (outbound == NULL || outbound->free_pending) {
        return;
    }
    outbound->free_pending = 1;
    ss_close(outbound);
    for (ss_stream_impl_t *stream = outbound->streams; stream != NULL;) {
        ss_stream_impl_t *next = stream->next;
        if (stream->owner != NULL) {
            aproxy_stream_free(stream->owner);
        } else {
            ss_stream_free(stream);
        }
        stream = next;
    }
    for (ss_packet_impl_t *packet = outbound->packets; packet != NULL;) {
        ss_packet_impl_t *next = packet->next;
        if (packet->owner != NULL) {
            aproxy_packet_flow_free(packet->owner);
        } else {
            ss_packet_free(packet);
        }
        packet = next;
    }
    ss_outbound_maybe_destroy(outbound);
}

static const aproxy_outbound_vtable_t ss_outbound_vtable = {
    .connect = ss_connect,
    .open_stream = ss_open_stream,
    .open_packet = ss_open_packet,
    .close = ss_close,
    .free = ss_free,
};

int shadowsocks_outbound_new(const shadowsocks_outbound_config_t *config,
                             aproxy_outbound_t **out)
{
    if (config == NULL || out == NULL || config->loop == NULL ||
        config->server_host == NULL || config->server_port == NULL ||
        config->method == NULL || config->password == NULL ||
        (config->udp_transport != APROXY_OUTBOUND_UDP_PACKET &&
         config->udp_transport != APROXY_OUTBOUND_UDP_UOT) ||
        (config->udp_transport == APROXY_OUTBOUND_UDP_UOT &&
         config->uot_version != APROXY_UOT_VERSION_DEFAULT &&
         config->uot_version != APROXY_UOT_VERSION_1 &&
         config->uot_version != APROXY_UOT_VERSION_2)) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    *out = NULL;

    ss_outbound_impl_t *impl =
        (ss_outbound_impl_t *)calloc(1u, sizeof(*impl));
    if (impl == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    impl->loop = config->loop;
    impl->max_pending_bytes =
        aproxy_stream_pending_limit(config->max_pending_bytes);
    aproxy_bufpool_init(&impl->packet_pool, 9216u,
                        SS_PACKET_POOL_MAX_FREE);
    impl->tag = copy_string(config->tag != NULL ? config->tag
                                                : "shadowsocks");
    if (impl->tag == NULL) {
        ss_free(impl);
        return APROXY_ERR_NO_MEMORY;
    }
    int rc = parse_server_addr(config->server_host, config->server_port,
                               &impl->server);
    if (rc == APROXY_OK) {
        rc = shadowsocks_aead_method_from_name(config->method,
                                               &impl->method);
        impl->is_2022 = shadowsocks_aead_method_is_2022(impl->method);
    }
    if (rc == APROXY_OK) {
        if (impl->is_2022) {
            rc = shadowsocks_2022_psk_list_parse(
                impl->method, config->password, &impl->psks);
            if (rc == APROXY_OK) {
                impl->key_len = impl->psks.key_len;
                memcpy(impl->key,
                       shadowsocks_2022_psk_at(&impl->psks,
                                               impl->psks.count - 1u),
                       impl->key_len);
            }
        } else {
            rc = shadowsocks_aead_key_from_password(
                impl->method, config->password, impl->key,
                sizeof(impl->key), &impl->key_len);
        }
    }
    if (rc != APROXY_OK) {
        ss_free(impl);
        return rc;
    }

    aproxy_direct_outbound_config_t transport_config = {
        .loop = config->loop,
        .tag = "shadowsocks-transport",
        .resolver = config->resolver,
        .read_buffer_size = config->read_buffer_size,
        .max_pending_bytes = impl->max_pending_bytes,
        .socket_protector = config->socket_protector,
    };
    rc = aproxy_direct_outbound_new(&transport_config, &impl->transport);
    if (rc != APROXY_OK) {
        ss_free(impl);
        return rc;
    }

    aproxy_outbound_t *outbound =
        (aproxy_outbound_t *)calloc(1u, sizeof(*outbound));
    if (outbound == NULL) {
        ss_free(impl);
        return APROXY_ERR_NO_MEMORY;
    }
    outbound->tag = impl->tag;
    outbound->vtable = &ss_outbound_vtable;
    outbound->impl = impl;
    outbound->udp_transport = config->udp_transport;
    outbound->uot_version =
        config->uot_version == APROXY_UOT_VERSION_DEFAULT
            ? APROXY_UOT_VERSION_2
            : config->uot_version;
    *out = outbound;
    return APROXY_OK;
}
