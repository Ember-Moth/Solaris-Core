#include "anytls/client.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/sha.h>

#include "anytls/frame.h"
#include "anytls/padding.h"
#include "buffer.h"
#include "byteorder.h"
#include "aproxy/limits.h"
#include "aproxy/ring.h"
#include "tls_uv.h"

#define ANYTLS_CLIENT_NAME "aproxy-core/0.1"
#define ANYTLS_AUTH_HEADER_SIZE 34u
#define ANYTLS_STREAM_HANDSHAKE_TIMEOUT_MS 3000u
#define ANYTLS_DEFAULT_HEARTBEAT_INTERVAL_MS 30000u
#define ANYTLS_DEFAULT_HEARTBEAT_TIMEOUT_MS 10000u
#define ANYTLS_STREAM_INITIAL_BUCKETS 64u
#define ANYTLS_STREAM_MAX_LOAD_NUM 3u
#define ANYTLS_STREAM_MAX_LOAD_DEN 4u

struct anytls_stream {
    anytls_client_t *client;
    uint32_t id;
    int closed;
    int waiting_synack;
    uv_timer_t handshake_timer;
    int timer_initialized;
    int timer_closing;
    int timer_closed;
    int free_pending;
    unsigned int callback_depth;
    anytls_stream_data_cb on_data;
    anytls_stream_event_cb on_open;
    anytls_stream_event_cb on_close;
    void *user_data;
    struct anytls_stream *prev;
    struct anytls_stream *next;
    struct anytls_stream *hash_next;
    int indexed;
};

struct anytls_client {
    uv_loop_t *loop;
    anytls_tls_client_t *tls;
    anytls_padding_store_t *padding_store;
    aproxy_ring_t rx;
    anytls_buffer_t rx_scratch;
    anytls_buffer_t tx_frame;
    anytls_buffer_t padding_write;
    anytls_buffer_t pending_write;
    size_t max_pending_bytes;
    uint8_t password_sha256[SHA256_DIGEST_LENGTH];
    uint32_t next_stream_id;
    uint32_t peer_version;
    uint32_t pkt_counter;
    uv_timer_t heartbeat_timer;
    uv_timer_t heartbeat_timeout_timer;
    uint64_t heartbeat_interval_ms;
    uint64_t heartbeat_timeout_ms;
    uint64_t last_activity_ms;
    int ready;
    int closed;
    int buffering;
    int send_padding;
    int heartbeat_enabled;
    int heartbeat_waiting;
    int heartbeat_timer_initialized;
    int heartbeat_timeout_timer_initialized;
    int heartbeat_timer_closed;
    int heartbeat_timeout_timer_closed;
    int free_pending;
    unsigned int callback_depth;
    int owns_padding_store;
    anytls_stream_t *streams;
    anytls_stream_t **stream_buckets;
    size_t stream_bucket_count;
    size_t stream_count;
    anytls_client_ready_cb on_ready;
    anytls_client_close_cb on_close;
    void *user_data;
};

static const anytls_padding_factory_t *client_padding(
    const anytls_client_t *client)
{
    return client == NULL ? NULL : anytls_padding_store_get(
                                      client->padding_store);
}

static void client_maybe_destroy(anytls_client_t *client);

static void client_callback_enter(anytls_client_t *client)
{
    client->callback_depth++;
}

static void client_callback_leave(anytls_client_t *client)
{
    if (client->callback_depth > 0u) {
        client->callback_depth--;
    }
    client_maybe_destroy(client);
}

static void heartbeat_close_cb(uv_handle_t *handle)
{
    anytls_client_t *client = (anytls_client_t *)handle->data;
    if (client == NULL) {
        return;
    }
    if (handle == (uv_handle_t *)&client->heartbeat_timer) {
        client->heartbeat_timer_closed = 1;
    } else if (handle == (uv_handle_t *)&client->heartbeat_timeout_timer) {
        client->heartbeat_timeout_timer_closed = 1;
    }
    client_maybe_destroy(client);
}

static uint64_t client_now_ms(anytls_client_t *client)
{
    if (client == NULL || client->loop == NULL) {
        return 0u;
    }
    uv_update_time(client->loop);
    return uv_now(client->loop);
}

static void client_touch_activity(anytls_client_t *client)
{
    if (client != NULL) {
        client->last_activity_ms = client_now_ms(client);
    }
}

static void stop_heartbeat_timeout(anytls_client_t *client)
{
    if (client == NULL || !client->heartbeat_timeout_timer_initialized) {
        return;
    }
    uv_timer_stop(&client->heartbeat_timeout_timer);
}

static void close_heartbeat_timers(anytls_client_t *client)
{
    if (client == NULL) {
        return;
    }
    if (client->heartbeat_timer_initialized &&
        !uv_is_closing((uv_handle_t *)&client->heartbeat_timer)) {
        uv_timer_stop(&client->heartbeat_timer);
        uv_close((uv_handle_t *)&client->heartbeat_timer,
                 heartbeat_close_cb);
    }
    if (client->heartbeat_timeout_timer_initialized &&
        !uv_is_closing((uv_handle_t *)&client->heartbeat_timeout_timer)) {
        uv_timer_stop(&client->heartbeat_timeout_timer);
        uv_close((uv_handle_t *)&client->heartbeat_timeout_timer,
                 heartbeat_close_cb);
    }
}

static anytls_stream_t *find_stream(anytls_client_t *client, uint32_t sid)
{
    const size_t bucket = ((size_t)(sid * UINT32_C(2654435761))) &
                          (client->stream_bucket_count - 1u);
    for (anytls_stream_t *stream = client->stream_buckets[bucket];
         stream != NULL; stream = stream->hash_next) {
        if (stream->id == sid) {
            return stream;
        }
    }
    return NULL;
}

static size_t stream_bucket(const anytls_client_t *client, uint32_t sid)
{
    return ((size_t)(sid * UINT32_C(2654435761))) &
           (client->stream_bucket_count - 1u);
}

static int resize_stream_buckets(anytls_client_t *client, size_t next_count)
{
    anytls_stream_t **next =
        (anytls_stream_t **)calloc(next_count, sizeof(*next));
    if (next == NULL) {
        return ANYTLS_ERR_NO_MEMORY;
    }
    anytls_stream_t **old = client->stream_buckets;
    client->stream_buckets = next;
    client->stream_bucket_count = next_count;
    for (anytls_stream_t *stream = client->streams; stream != NULL;
         stream = stream->next) {
        const size_t bucket = stream_bucket(client, stream->id);
        stream->hash_next = client->stream_buckets[bucket];
        client->stream_buckets[bucket] = stream;
    }
    free(old);
    return ANYTLS_OK;
}

static int ensure_stream_capacity(anytls_client_t *client)
{
    if (client->stream_count * ANYTLS_STREAM_MAX_LOAD_DEN <
        client->stream_bucket_count * ANYTLS_STREAM_MAX_LOAD_NUM) {
        return ANYTLS_OK;
    }
    if (client->stream_bucket_count > SIZE_MAX / 2u) {
        return ANYTLS_ERR_NO_MEMORY;
    }
    return resize_stream_buckets(client, client->stream_bucket_count * 2u);
}

static void link_stream(anytls_client_t *client, anytls_stream_t *stream)
{
    stream->prev = NULL;
    stream->next = client->streams;
    if (client->streams != NULL) {
        client->streams->prev = stream;
    }
    client->streams = stream;

    const size_t bucket = stream_bucket(client, stream->id);
    stream->hash_next = client->stream_buckets[bucket];
    client->stream_buckets[bucket] = stream;
    stream->indexed = 1;
    client->stream_count++;
}

static void unlink_stream(anytls_client_t *client, anytls_stream_t *stream)
{
    if (client == NULL || stream == NULL || !stream->indexed) {
        return;
    }
    const size_t bucket = stream_bucket(client, stream->id);
    anytls_stream_t **cursor = &client->stream_buckets[bucket];
    while (*cursor != NULL && *cursor != stream) {
        cursor = &(*cursor)->hash_next;
    }
    if (*cursor == stream) {
        *cursor = stream->hash_next;
    }
    if (stream->prev != NULL) {
        stream->prev->next = stream->next;
    } else if (client->streams == stream) {
        client->streams = stream->next;
    }
    if (stream->next != NULL) {
        stream->next->prev = stream->prev;
    }
    stream->prev = NULL;
    stream->next = NULL;
    stream->hash_next = NULL;
    stream->indexed = 0;
    if (client->stream_count > 0u) {
        client->stream_count--;
    }
}

static void stream_timer_close_cb(uv_handle_t *handle)
{
    anytls_stream_t *stream = (anytls_stream_t *)handle->data;
    if (stream == NULL) {
        return;
    }
    stream->timer_closed = 1;
    if (stream->free_pending && stream->callback_depth == 0u) {
        free(stream);
    }
}

static void stream_free(anytls_stream_t *stream)
{
    if (stream == NULL) {
        return;
    }
    stream->free_pending = 1;
    if (stream->timer_initialized && !stream->timer_closing) {
        stream->timer_closing = 1;
        uv_timer_stop(&stream->handshake_timer);
        uv_close((uv_handle_t *)&stream->handshake_timer,
                 stream_timer_close_cb);
    }
    if (stream->callback_depth == 0u && stream->timer_closed) {
        free(stream);
    }
}

static void close_stream_local(anytls_stream_t *stream, int status)
{
    if (stream == NULL || stream->closed) {
        return;
    }
    stream->closed = 1;
    unlink_stream(stream->client, stream);
    if (stream->on_close != NULL) {
        stream->callback_depth++;
        stream->on_close(stream, status, stream->user_data);
        stream->callback_depth--;
    }
    stream_free(stream);
}

static int build_frame(uint8_t command,
                       uint32_t sid,
                       const uint8_t *payload,
                       size_t payload_len,
                       anytls_buffer_t *out)
{
    if ((payload == NULL && payload_len > 0u) ||
        payload_len > ANYTLS_MAX_FRAME_PAYLOAD) {
        return ANYTLS_ERR_INVALID_ARGUMENT;
    }
    anytls_buffer_clear(out);
    const int reserve_rc =
        anytls_buffer_reserve(out, ANYTLS_FRAME_HEADER_SIZE + payload_len);
    if (reserve_rc != ANYTLS_OK) {
        return reserve_rc;
    }
    anytls_frame_encode_header(out->data, command, sid,
                               (uint16_t)payload_len);
    if (payload_len > 0u) {
        memcpy(out->data + ANYTLS_FRAME_HEADER_SIZE, payload, payload_len);
    }
    out->len = ANYTLS_FRAME_HEADER_SIZE + payload_len;
    return ANYTLS_OK;
}

static int tls_write_all(anytls_client_t *client, const uint8_t *data, size_t len)
{
    if (len == 0u) {
        return ANYTLS_OK;
    }
    return anytls_tls_client_write(client->tls, data, len);
}

static int write_with_padding(anytls_client_t *client,
                              const uint8_t *data,
                              size_t len)
{
    const anytls_padding_factory_t *padding = client_padding(client);
    if (padding == NULL) {
        return ANYTLS_ERR_INVALID_ARGUMENT;
    }
    if (client->send_padding) {
        client->pkt_counter++;
        if (client->pkt_counter < anytls_padding_stop(padding)) {
            int sizes[ANYTLS_PADDING_MAX_RANGES_PER_PACKET];
            size_t count = 0u;
            int rc = anytls_padding_generate_record_payload_sizes(
                padding, client->pkt_counter, sizes,
                ANYTLS_PADDING_MAX_RANGES_PER_PACKET, &count);
            if (rc != ANYTLS_OK) {
                return rc;
            }

            size_t offset = 0u;
            for (size_t i = 0; i < count; i++) {
                const int target = sizes[i];
                const size_t remain = len - offset;

                if (target == ANYTLS_PADDING_CHECK_MARK) {
                    if (remain == 0u) {
                        break;
                    }
                    continue;
                }
                if (target <= 0) {
                    continue;
                }

                if (remain > (size_t)target) {
                    rc = tls_write_all(client, data + offset, (size_t)target);
                    if (rc != ANYTLS_OK) {
                        return rc;
                    }
                    offset += (size_t)target;
                } else if (remain > 0u) {
                    const int padding_len =
                        target - (int)remain - (int)ANYTLS_FRAME_HEADER_SIZE;
                    if (padding_len > 0) {
                        anytls_buffer_t *combined = &client->padding_write;
                        anytls_buffer_clear(combined);
                        rc = anytls_buffer_append(combined, data + offset,
                                                  remain);
                        if (rc == ANYTLS_OK) {
                            uint8_t header[ANYTLS_FRAME_HEADER_SIZE];
                            anytls_frame_encode_header(
                                header, ANYTLS_CMD_WASTE, 0u,
                                (uint16_t)padding_len);
                            rc = anytls_buffer_append(combined, header,
                                                      sizeof(header));
                        }
                        if (rc == ANYTLS_OK) {
                            rc = anytls_buffer_append_zero(
                                combined, (size_t)padding_len);
                        }
                        if (rc == ANYTLS_OK) {
                            rc = tls_write_all(client, combined->data,
                                               combined->len);
                        }
                        if (rc != ANYTLS_OK) {
                            return rc;
                        }
                    } else {
                        rc = tls_write_all(client, data + offset, remain);
                        if (rc != ANYTLS_OK) {
                            return rc;
                        }
                    }
                    offset = len;
                } else {
                    anytls_buffer_t *waste = &client->padding_write;
                    anytls_buffer_clear(waste);
                    uint8_t header[ANYTLS_FRAME_HEADER_SIZE];
                    anytls_frame_encode_header(header, ANYTLS_CMD_WASTE, 0u,
                                               (uint16_t)target);
                    rc = anytls_buffer_append(waste, header, sizeof(header));
                    if (rc == ANYTLS_OK) {
                        rc = anytls_buffer_append_zero(waste, (size_t)target);
                    }
                    if (rc == ANYTLS_OK) {
                        rc = tls_write_all(client, waste->data, waste->len);
                    }
                    if (rc != ANYTLS_OK) {
                        return rc;
                    }
                }
            }

            if (offset == len) {
                return ANYTLS_OK;
            }
            return tls_write_all(client, data + offset, len - offset);
        }
        client->send_padding = 0;
    }

    return tls_write_all(client, data, len);
}

static int write_session_bytes(anytls_client_t *client,
                               const uint8_t *data,
                               size_t len)
{
    if (client->buffering) {
        if (aproxy_size_add_exceeds(client->pending_write.len, len,
                                    client->max_pending_bytes)) {
            return ANYTLS_ERR_FRAME_TOO_LARGE;
        }
        return anytls_buffer_append(&client->pending_write, data, len);
    }
    if (client->pending_write.len > 0u) {
        if (aproxy_size_add_exceeds(client->pending_write.len, len,
                                    client->max_pending_bytes)) {
            return ANYTLS_ERR_FRAME_TOO_LARGE;
        }
        int rc = anytls_buffer_append(&client->pending_write, data, len);
        if (rc != ANYTLS_OK) {
            return rc;
        }
        rc = write_with_padding(client, client->pending_write.data,
                                client->pending_write.len);
        if (rc == ANYTLS_OK) {
            client_touch_activity(client);
        }
        anytls_buffer_clear(&client->pending_write);
        return rc;
    }
    const int rc = write_with_padding(client, data, len);
    if (rc == ANYTLS_OK) {
        client_touch_activity(client);
    }
    return rc;
}

static int write_control_frame(anytls_client_t *client,
                               uint8_t command,
                               uint32_t sid,
                               const uint8_t *payload,
                               size_t payload_len)
{
    anytls_buffer_t *frame = &client->tx_frame;
    const int rc = build_frame(command, sid, payload, payload_len, frame);
    if (rc == ANYTLS_OK) {
        return write_session_bytes(client, frame->data, frame->len);
    }
    return rc;
}

static int write_data_frame(anytls_client_t *client,
                            uint32_t sid,
                            const uint8_t *data,
                            size_t len)
{
    size_t offset = 0u;
    while (offset < len) {
        const size_t chunk =
            len - offset > ANYTLS_MAX_FRAME_PAYLOAD
                ? ANYTLS_MAX_FRAME_PAYLOAD
                : len - offset;
        anytls_buffer_t *frame = &client->tx_frame;
        int rc = build_frame(ANYTLS_CMD_PSH, sid, data + offset, chunk, frame);
        if (rc == ANYTLS_OK) {
            rc = write_session_bytes(client, frame->data, frame->len);
        }
        if (rc != ANYTLS_OK) {
            return rc;
        }
        offset += chunk;
    }
    return ANYTLS_OK;
}

static int send_auth_packet(anytls_client_t *client)
{
    const anytls_padding_factory_t *padding = client_padding(client);
    if (padding == NULL) {
        return ANYTLS_ERR_INVALID_ARGUMENT;
    }
    uint16_t padding_len = 0u;
    int rc = anytls_padding_auth_length(padding, &padding_len);
    if (rc != ANYTLS_OK) {
        return rc;
    }

    anytls_buffer_t auth;
    anytls_buffer_init(&auth);
    rc = anytls_buffer_reserve(&auth, ANYTLS_AUTH_HEADER_SIZE + padding_len);
    if (rc == ANYTLS_OK) {
        rc = anytls_buffer_append(&auth, client->password_sha256,
                                  SHA256_DIGEST_LENGTH);
    }
    if (rc == ANYTLS_OK) {
        uint8_t len_bytes[2];
        anytls_put_u16_be(len_bytes, padding_len);
        rc = anytls_buffer_append(&auth, len_bytes, sizeof(len_bytes));
    }
    if (rc == ANYTLS_OK && padding_len > 0u) {
        rc = anytls_buffer_append_zero(&auth, padding_len);
    }
    if (rc == ANYTLS_OK) {
        rc = anytls_tls_client_write(client->tls, auth.data, auth.len);
    }
    anytls_buffer_free(&auth);
    return rc;
}

static int send_initial_settings(anytls_client_t *client)
{
    const anytls_padding_factory_t *padding = client_padding(client);
    if (padding == NULL) {
        return ANYTLS_ERR_INVALID_ARGUMENT;
    }
    char settings[256];
    const int n = snprintf(settings, sizeof(settings),
                           "v=2\nclient=%s\npadding-md5=%s",
                           ANYTLS_CLIENT_NAME,
                           anytls_padding_md5_hex(padding));
    if (n < 0 || (size_t)n >= sizeof(settings)) {
        return ANYTLS_ERR_BUFFER_TOO_SMALL;
    }
    client->buffering = 1;
    return write_control_frame(client, ANYTLS_CMD_SETTINGS, 0u,
                               (const uint8_t *)settings, (size_t)n);
}

static uint32_t parse_settings_version(const uint8_t *data, size_t len)
{
    const char needle[] = "v=";
    for (size_t i = 0u; i + 2u <= len; i++) {
        if ((i == 0u || data[i - 1u] == '\n') &&
            memcmp(data + i, needle, 2u) == 0) {
            uint32_t version = 0u;
            size_t j = i + 2u;
            while (j < len && data[j] >= '0' && data[j] <= '9') {
                version = version * 10u + (uint32_t)(data[j] - '0');
                j++;
            }
            return version;
        }
    }
    return 0u;
}

static void heartbeat_timeout_cb(uv_timer_t *timer)
{
    anytls_client_t *client = (anytls_client_t *)timer->data;
    if (client == NULL || client->closed || !client->heartbeat_waiting) {
        return;
    }
    client->heartbeat_waiting = 0;
    anytls_client_close(client);
}

static void heartbeat_timer_cb(uv_timer_t *timer)
{
    anytls_client_t *client = (anytls_client_t *)timer->data;
    if (client == NULL || client->closed || !client->ready ||
        !client->heartbeat_enabled || client->peer_version < 2u ||
        client->heartbeat_waiting) {
        return;
    }

    const uint64_t now = client_now_ms(client);
    if (now - client->last_activity_ms < client->heartbeat_interval_ms) {
        return;
    }

    client->heartbeat_waiting = 1;
    const int rc = write_control_frame(client, ANYTLS_CMD_HEART_REQUEST, 0u,
                                       NULL, 0u);
    if (rc != ANYTLS_OK) {
        client->heartbeat_waiting = 0;
        anytls_client_close(client);
        return;
    }

    if (!client->heartbeat_timeout_timer_initialized) {
        const int init_rc =
            uv_timer_init(client->loop, &client->heartbeat_timeout_timer);
        if (init_rc != 0) {
            client->heartbeat_waiting = 0;
            anytls_client_close(client);
            return;
        }
        client->heartbeat_timeout_timer_initialized = 1;
        client->heartbeat_timeout_timer_closed = 0;
        client->heartbeat_timeout_timer.data = client;
    }
    const int start_rc = uv_timer_start(
        &client->heartbeat_timeout_timer, heartbeat_timeout_cb,
        client->heartbeat_timeout_ms, 0u);
    if (start_rc != 0) {
        client->heartbeat_waiting = 0;
        anytls_client_close(client);
    }
}

static int start_heartbeat(anytls_client_t *client)
{
    if (client == NULL || !client->heartbeat_enabled ||
        client->heartbeat_timer_initialized) {
        return ANYTLS_OK;
    }
    const int init_rc = uv_timer_init(client->loop, &client->heartbeat_timer);
    if (init_rc != 0) {
        return init_rc;
    }
    client->heartbeat_timer_initialized = 1;
    client->heartbeat_timer_closed = 0;
    client->heartbeat_timer.data = client;
    const int start_rc =
        uv_timer_start(&client->heartbeat_timer, heartbeat_timer_cb,
                       client->heartbeat_interval_ms,
                       client->heartbeat_interval_ms);
    return start_rc == 0 ? ANYTLS_OK : start_rc;
}

static void notify_heartbeat(anytls_client_t *client)
{
    if (client == NULL) {
        return;
    }
    client->heartbeat_waiting = 0;
    stop_heartbeat_timeout(client);
}

static void handshake_timer_cb(uv_timer_t *timer)
{
    anytls_stream_t *stream = (anytls_stream_t *)timer->data;
    if (stream == NULL || stream->closed || !stream->waiting_synack) {
        return;
    }
    anytls_client_t *client = stream->client;
    close_stream_local(stream, ANYTLS_ERR_INVALID_FRAME);
    anytls_client_close(client);
}

static int start_stream_handshake_timer(anytls_stream_t *stream)
{
    const int rc = uv_timer_init(stream->client->loop, &stream->handshake_timer);
    if (rc != 0) {
        return rc;
    }
    stream->timer_initialized = 1;
    stream->timer_closed = 0;
    stream->handshake_timer.data = stream;
    return uv_timer_start(&stream->handshake_timer, handshake_timer_cb,
                          ANYTLS_STREAM_HANDSHAKE_TIMEOUT_MS, 0u);
}

static void stop_stream_handshake_timer(anytls_stream_t *stream)
{
    if (stream == NULL || !stream->timer_initialized) {
        return;
    }
    uv_timer_stop(&stream->handshake_timer);
}

static int handle_frame(anytls_client_t *client,
                        const anytls_frame_header_t *header,
                        const uint8_t *payload)
{
    const uint32_t sid = header->stream_id;
    const size_t payload_len = header->length;

    switch (header->command) {
    case ANYTLS_CMD_PSH: {
        anytls_stream_t *stream = find_stream(client, sid);
        if (stream != NULL && !stream->closed && stream->on_data != NULL) {
            stream->callback_depth++;
            stream->on_data(stream, payload, payload_len, stream->user_data);
            stream->callback_depth--;
            if (stream->free_pending) {
                stream_free(stream);
            }
        }
        return ANYTLS_OK;
    }
    case ANYTLS_CMD_FIN: {
        anytls_stream_t *stream = find_stream(client, sid);
        if (stream != NULL) {
            close_stream_local(stream, ANYTLS_OK);
        }
        return ANYTLS_OK;
    }
    case ANYTLS_CMD_WASTE:
        return ANYTLS_OK;
    case ANYTLS_CMD_SYNACK: {
        anytls_stream_t *stream = find_stream(client, sid);
        if (stream == NULL) {
            return ANYTLS_OK;
        }
        if (!stream->waiting_synack) {
            return ANYTLS_OK;
        }
        stop_stream_handshake_timer(stream);
        stream->waiting_synack = 0;
        if (payload_len > 0u) {
            close_stream_local(stream, ANYTLS_ERR_INVALID_FRAME);
        } else if (stream->on_open != NULL) {
            stream->callback_depth++;
            stream->on_open(stream, ANYTLS_OK, stream->user_data);
            stream->callback_depth--;
            if (stream->free_pending) {
                stream_free(stream);
            }
        }
        return ANYTLS_OK;
    }
    case ANYTLS_CMD_ALERT:
        anytls_client_close(client);
        return ANYTLS_OK;
    case ANYTLS_CMD_UPDATE_PADDING_SCHEME: {
        (void)anytls_padding_store_update(client->padding_store, payload,
                                          payload_len);
        return ANYTLS_OK;
    }
    case ANYTLS_CMD_HEART_REQUEST:
        return write_control_frame(client, ANYTLS_CMD_HEART_RESPONSE, 0u, NULL,
                                   0u);
    case ANYTLS_CMD_HEART_RESPONSE:
        notify_heartbeat(client);
        return ANYTLS_OK;
    case ANYTLS_CMD_SERVER_SETTINGS:
        client->peer_version = parse_settings_version(payload, payload_len);
        return ANYTLS_OK;
    default:
        return ANYTLS_ERR_INVALID_FRAME;
    }
}

static int process_plaintext(anytls_client_t *client,
                             const uint8_t *data,
                             size_t len)
{
    int rc = aproxy_ring_write(&client->rx, data, len);
    if (rc != ANYTLS_OK) {
        return rc;
    }

    while (aproxy_ring_size(&client->rx) >= ANYTLS_FRAME_HEADER_SIZE) {
        uint8_t encoded_header[ANYTLS_FRAME_HEADER_SIZE];
        if (aproxy_ring_peek(&client->rx, 0u, encoded_header,
                             sizeof(encoded_header)) !=
            sizeof(encoded_header)) {
            return ANYTLS_ERR_INVALID_FRAME;
        }
        anytls_frame_header_t header;
        anytls_frame_decode_header(encoded_header, &header);
        rc = anytls_frame_validate(&header, true);
        if (rc != ANYTLS_OK) {
            return rc;
        }
        const size_t frame_len = ANYTLS_FRAME_HEADER_SIZE + header.length;
        if (aproxy_ring_size(&client->rx) < frame_len) {
            break;
        }
        const uint8_t *payload = NULL;
        if (header.length > 0u) {
            aproxy_const_span_t spans[2];
            const size_t count = aproxy_ring_read_spans_at(
                &client->rx, ANYTLS_FRAME_HEADER_SIZE, header.length, spans);
            if (count == 1u) {
                payload = spans[0].data;
            } else {
                anytls_buffer_clear(&client->rx_scratch);
                rc = anytls_buffer_reserve(&client->rx_scratch, header.length);
                if (rc != ANYTLS_OK) {
                    return rc;
                }
                if (aproxy_ring_peek(&client->rx, ANYTLS_FRAME_HEADER_SIZE,
                                     client->rx_scratch.data,
                                     header.length) != header.length) {
                    return ANYTLS_ERR_INVALID_FRAME;
                }
                client->rx_scratch.len = header.length;
                payload = client->rx_scratch.data;
            }
        }
        rc = handle_frame(client, &header, payload);
        if (rc != ANYTLS_OK) {
            return rc;
        }
        aproxy_ring_consume(&client->rx, frame_len);
    }
    return ANYTLS_OK;
}

static void tls_ready_cb(anytls_tls_client_t *tls, int status, void *user_data)
{
    (void)tls;
    anytls_client_t *client = (anytls_client_t *)user_data;
    client_callback_enter(client);
    if (status != ANYTLS_OK) {
        if (client->on_ready != NULL) {
            client->on_ready(client, status, client->user_data);
        }
        client_callback_leave(client);
        return;
    }

    int rc = send_auth_packet(client);
    if (rc == ANYTLS_OK) {
        rc = send_initial_settings(client);
    }
    client->ready = rc == ANYTLS_OK;
    if (rc == ANYTLS_OK) {
        rc = start_heartbeat(client);
        client->ready = rc == ANYTLS_OK;
    }
    if (client->on_ready != NULL) {
        if (rc != ANYTLS_OK) {
            anytls_client_close(client);
        }
        client->on_ready(client, rc, client->user_data);
    } else if (rc != ANYTLS_OK) {
        anytls_client_close(client);
    }
    client_callback_leave(client);
}

static void tls_data_cb(anytls_tls_client_t *tls,
                        const uint8_t *data,
                        size_t len,
                        void *user_data)
{
    (void)tls;
    anytls_client_t *client = (anytls_client_t *)user_data;
    client_callback_enter(client);
    client_touch_activity(client);
    const int rc = process_plaintext(client, data, len);
    if (rc != ANYTLS_OK) {
        anytls_client_close(client);
    }
    client_callback_leave(client);
}

static void tls_close_cb(anytls_tls_client_t *tls, int status, void *user_data)
{
    (void)tls;
    anytls_client_t *client = (anytls_client_t *)user_data;
    client_callback_enter(client);
    close_heartbeat_timers(client);
    if (client->closed) {
        if (client->on_close != NULL) {
            client->on_close(client, status, client->user_data);
        }
        client_callback_leave(client);
        return;
    }
    client->closed = 1;
    while (client->streams != NULL) {
        close_stream_local(client->streams, status);
    }
    if (client->on_close != NULL) {
        client->on_close(client, status, client->user_data);
    }
    client_callback_leave(client);
}

int anytls_client_new(const anytls_client_config_t *config,
                      anytls_client_t **out)
{
    if (config == NULL || out == NULL || config->loop == NULL ||
        config->server_host == NULL || config->server_port == NULL ||
        config->password == NULL) {
        return ANYTLS_ERR_INVALID_ARGUMENT;
    }
    *out = NULL;

    anytls_client_t *client = (anytls_client_t *)calloc(1u, sizeof(*client));
    if (client == NULL) {
        return ANYTLS_ERR_NO_MEMORY;
    }
    client->stream_buckets = (anytls_stream_t **)calloc(
        ANYTLS_STREAM_INITIAL_BUCKETS, sizeof(*client->stream_buckets));
    if (client->stream_buckets == NULL) {
        free(client);
        return ANYTLS_ERR_NO_MEMORY;
    }
    client->stream_bucket_count = ANYTLS_STREAM_INITIAL_BUCKETS;
    client->loop = config->loop;
    client->on_ready = config->on_ready;
    client->on_close = config->on_close;
    client->user_data = config->user_data;
    client->send_padding = 1;
    client->heartbeat_timer_closed = 1;
    client->heartbeat_timeout_timer_closed = 1;
    client->max_pending_bytes =
        aproxy_stream_pending_limit(config->max_pending_bytes);
    client->heartbeat_enabled = config->heartbeat_interval_ms >= 0;
    if (config->heartbeat_interval_ms == 0) {
        client->heartbeat_interval_ms = ANYTLS_DEFAULT_HEARTBEAT_INTERVAL_MS;
    } else if (config->heartbeat_interval_ms > 0) {
        client->heartbeat_interval_ms = (uint64_t)config->heartbeat_interval_ms;
    }
    if (config->heartbeat_timeout_ms <= 0) {
        client->heartbeat_timeout_ms = ANYTLS_DEFAULT_HEARTBEAT_TIMEOUT_MS;
    } else {
        client->heartbeat_timeout_ms = (uint64_t)config->heartbeat_timeout_ms;
    }
    client_touch_activity(client);
    aproxy_ring_init(&client->rx);
    anytls_buffer_init(&client->rx_scratch);
    anytls_buffer_init(&client->tx_frame);
    anytls_buffer_init(&client->padding_write);
    anytls_buffer_init(&client->pending_write);
    SHA256((const uint8_t *)config->password, strlen(config->password),
           client->password_sha256);

    int rc = ANYTLS_OK;
    if (config->padding_store != NULL) {
        client->padding_store = config->padding_store;
    } else {
        rc = anytls_padding_store_new_default(&client->padding_store);
        client->owns_padding_store = rc == ANYTLS_OK;
    }
    if (rc != ANYTLS_OK) {
        anytls_client_free(client);
        return rc;
    }

    anytls_tls_client_config_t tls_config;
    memset(&tls_config, 0, sizeof(tls_config));
    tls_config.loop = config->loop;
    tls_config.host = config->server_host;
    tls_config.port = config->server_port;
    tls_config.sni = config->sni;
    tls_config.resolver = config->resolver;
    tls_config.context = config->tls_context;
    tls_config.alpn = config->alpn;
    tls_config.ech = config->ech;
    tls_config.max_pending_bytes = client->max_pending_bytes;
    tls_config.socket_protector = config->socket_protector;
    tls_config.insecure_skip_verify = config->insecure_skip_verify;
    tls_config.reality = config->reality;
    tls_config.on_ready = tls_ready_cb;
    tls_config.on_data = tls_data_cb;
    tls_config.on_close = tls_close_cb;
    tls_config.user_data = client;

    rc = anytls_tls_client_new(&tls_config, &client->tls);
    if (rc != ANYTLS_OK) {
        anytls_client_free(client);
        return rc;
    }

    *out = client;
    return ANYTLS_OK;
}

static void client_destroy(anytls_client_t *client)
{
    if (client->owns_padding_store) {
        anytls_padding_store_free(client->padding_store);
    }
    aproxy_ring_free(&client->rx);
    anytls_buffer_free(&client->rx_scratch);
    anytls_buffer_free(&client->tx_frame);
    anytls_buffer_free(&client->padding_write);
    anytls_buffer_free(&client->pending_write);
    free(client->stream_buckets);
    free(client);
}

static void client_maybe_destroy(anytls_client_t *client)
{
    if (client != NULL && client->free_pending &&
        client->callback_depth == 0u && client->heartbeat_timer_closed &&
        client->heartbeat_timeout_timer_closed) {
        client_destroy(client);
    }
}

void anytls_client_free(anytls_client_t *client)
{
    if (client == NULL || client->free_pending) {
        return;
    }
    client->free_pending = 1;
    client->on_ready = NULL;
    client->on_close = NULL;
    client->user_data = NULL;
    while (client->streams != NULL) {
        anytls_stream_t *stream = client->streams;
        client->streams = stream->next;
        stream_free(stream);
    }
    close_heartbeat_timers(client);
    anytls_tls_client_t *tls = client->tls;
    client->tls = NULL;
    anytls_tls_client_free(tls);
    client_maybe_destroy(client);
}

int anytls_client_connect(anytls_client_t *client)
{
    if (client == NULL) {
        return ANYTLS_ERR_INVALID_ARGUMENT;
    }
    return anytls_tls_client_connect(client->tls);
}

void anytls_client_close(anytls_client_t *client)
{
    if (client == NULL || client->closed) {
        return;
    }
    client->closed = 1;
    client->heartbeat_waiting = 0;
    close_heartbeat_timers(client);
    while (client->streams != NULL) {
        close_stream_local(client->streams, ANYTLS_ERR_INVALID_ARGUMENT);
    }
    anytls_tls_client_close(client->tls);
}

int anytls_client_open_stream(anytls_client_t *client,
                              const anytls_socksaddr_t *destination,
                              anytls_stream_data_cb on_data,
                              anytls_stream_event_cb on_open,
                              anytls_stream_event_cb on_close,
                              void *user_data,
                              anytls_stream_t **out)
{
    if (client == NULL || destination == NULL || out == NULL ||
        !client->ready || client->closed) {
        return ANYTLS_ERR_INVALID_ARGUMENT;
    }
    *out = NULL;

    anytls_stream_t *stream = (anytls_stream_t *)calloc(1u, sizeof(*stream));
    if (stream == NULL) {
        return ANYTLS_ERR_NO_MEMORY;
    }
    stream->client = client;
    stream->timer_closed = 1;
    stream->id = ++client->next_stream_id;
    stream->on_data = on_data;
    stream->on_open = on_open;
    stream->on_close = on_close;
    stream->user_data = user_data;
    if (stream->id == 0u) {
        free(stream);
        return ANYTLS_ERR_INVALID_FRAME;
    }
    if (stream->id >= 2u && client->peer_version >= 2u) {
        stream->waiting_synack = 1;
    }

    int rc = ensure_stream_capacity(client);
    if (rc != ANYTLS_OK) {
        free(stream);
        return rc;
    }
    link_stream(client, stream);

    rc = write_control_frame(client, ANYTLS_CMD_SYN, stream->id, NULL, 0u);
    if (rc == ANYTLS_OK) {
        client->buffering = 0;
        uint8_t encoded[ANYTLS_SOCKSADDR_MAX_ENCODED];
        size_t encoded_len = 0u;
        rc = anytls_socksaddr_encode(destination, encoded, sizeof(encoded),
                                     &encoded_len);
        if (rc == ANYTLS_OK) {
            rc = write_data_frame(client, stream->id, encoded, encoded_len);
        }
    }
    if (rc == ANYTLS_OK && stream->waiting_synack) {
        rc = start_stream_handshake_timer(stream);
    }
    if (rc != ANYTLS_OK) {
        close_stream_local(stream, rc);
        return rc;
    }
    *out = stream;
    if (!stream->waiting_synack && stream->on_open != NULL) {
        stream->callback_depth++;
        stream->on_open(stream, ANYTLS_OK, stream->user_data);
        const int closed = stream->closed;
        stream->callback_depth--;
        if (stream->free_pending) {
            stream_free(stream);
        }
        if (closed) {
            *out = NULL;
            return ANYTLS_ERR_INVALID_ARGUMENT;
        }
    }
    return ANYTLS_OK;
}

int anytls_stream_write(anytls_stream_t *stream,
                        const uint8_t *data,
                        size_t len)
{
    if (stream == NULL || (data == NULL && len > 0u) || stream->closed) {
        return ANYTLS_ERR_INVALID_ARGUMENT;
    }
    return write_data_frame(stream->client, stream->id, data, len);
}

int anytls_stream_close(anytls_stream_t *stream)
{
    if (stream == NULL || stream->closed) {
        return ANYTLS_ERR_INVALID_ARGUMENT;
    }
    const int rc =
        write_control_frame(stream->client, ANYTLS_CMD_FIN, stream->id, NULL,
                            0u);
    close_stream_local(stream, rc);
    return rc;
}

uint32_t anytls_stream_id(const anytls_stream_t *stream)
{
    return stream == NULL ? 0u : stream->id;
}
