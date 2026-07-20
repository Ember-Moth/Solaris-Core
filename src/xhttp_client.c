/*
 * Wire-compatible XHTTP/XMUX HTTP/2 behavior based on Xray-core
 * b17a88f9b46d. This file is licensed under MPL-2.0.
 */

#include "aproxy/xhttp.h"

#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <nghttp2/nghttp2.h>
#include <openssl/rand.h>

#include "aproxy/buffer.h"
#include "aproxy/bufpool.h"
#include "aproxy/ring.h"
#include "framework/stream_internal.h"
#include "tls_uv.h"
#include "xhttp_internal.h"
#include "xhttp_h1.h"
#include "xhttp_request.h"

#define XHTTP_PACKET_POOL_CHUNK (16u * 1024u)
#define XHTTP_PACKET_POOL_MAX_FREE 64u
#define XHTTP_H2_REQUEST_POOL_MAX_FREE 128u
#define XHTTP_H2_PING_TIMEOUT_MS 15000u

typedef struct xhttp_h2_conn xhttp_h2_conn_t;
typedef struct xhttp_stream xhttp_stream_t;
typedef struct xhttp_h2_request xhttp_h2_request_t;

typedef enum xhttp_request_role {
    XHTTP_ROLE_DOWNLOAD = 0,
    XHTTP_ROLE_LONG_UPLOAD,
    XHTTP_ROLE_STREAM_ONE,
    XHTTP_ROLE_PACKET_UPLOAD,
} xhttp_request_role_t;

struct aproxy_xhttp_client {
    xhttp_h1_client_t *h1;
    int is_h1;
    aproxy_xhttp_config_t config;
    aproxy_xhttp_header_t *headers;
    aproxy_tls_context_t *tls_context;
    aproxy_bufpool_t packet_pool;
    xhttp_h2_request_t *free_requests;
    size_t free_request_count;
    xhttp_h2_conn_t *connections;
    xhttp_stream_t *streams;
    uint32_t next_stream_id;
    int32_t xmux_concurrency;
    int32_t xmux_connections;
    size_t connection_count;
    int closing;
    int free_pending;
};

struct xhttp_h2_conn {
    aproxy_xhttp_client_t *client;
    anytls_tls_client_t *tls;
    nghttp2_session *session;
    xhttp_h2_request_t *requests;
    xhttp_h2_conn_t *prev;
    xhttp_h2_conn_t *next;
    int32_t left_usage;
    int32_t left_requests;
    uint64_t expires_at_ms;
    uint64_t last_read_ms;
    uint64_t ping_sent_ms;
    uv_timer_t ping_timer;
    uint8_t ping_opaque[8];
    size_t active_streams;
    size_t request_count;
    int ready;
    int retired;
    int closing;
    int destroying;
    int destroy_status;
    int ping_outstanding;
    int ping_timer_initialized;
    int ping_timer_closing;
    int ping_timer_closed;
};

struct xhttp_h2_request {
    xhttp_h2_conn_t *connection;
    xhttp_stream_t *stream;
    xhttp_request_role_t role;
    int32_t stream_id;
    int response_status;
    uint8_t *payload;
    size_t payload_len;
    size_t payload_offset;
    size_t payload_capacity;
    xhttp_h2_request_t *prev;
    xhttp_h2_request_t *next;
    xhttp_h2_request_t *next_free;
};

struct xhttp_stream {
    aproxy_xhttp_client_t *client;
    aproxy_stream_t *owner;
    xhttp_h2_conn_t *download_connection;
    xhttp_h2_conn_t *upload_connection;
    xhttp_h2_request_t *download_request;
    xhttp_h2_request_t *upload_request;
    aproxy_stream_data_cb on_data;
    aproxy_stream_event_cb on_open;
    aproxy_stream_event_cb on_close;
    void *user_data;
    aproxy_ring_t upload;
    uv_timer_t post_timer;
    char *session_id;
    uint64_t sequence;
    uint64_t last_post_ms;
    uint32_t id;
    size_t request_refs;
    size_t pending_posts;
    unsigned int callback_depth;
    int mode;
    int started;
    int open_reported;
    int close_reported;
    int closing;
    int free_pending;
    int timer_initialized;
    int timer_closing;
    int timer_closed;
    int attached;
    xhttp_stream_t *prev;
    xhttp_stream_t *next;
};

static void xhttp_stream_free_impl(void *impl);
static void xhttp_stream_close_with(xhttp_stream_t *stream, int status);
static int h2_flush(xhttp_h2_conn_t *connection);
static void h2_ping_timer_cb(uv_timer_t *timer);
static void client_maybe_destroy(aproxy_xhttp_client_t *client);
static void connection_destroy(xhttp_h2_conn_t *connection, int status);

static char *copy_string(const char *value)
{
    if (value == NULL) {
        return NULL;
    }
    const size_t len = strlen(value);
    char *copy = (char *)malloc(len + 1u);
    if (copy != NULL) {
        memcpy(copy, value, len + 1u);
    }
    return copy;
}

static uint64_t now_ms(void)
{
    return uv_hrtime() / UINT64_C(1000000);
}

static uint64_t h2_keepalive_ms(const xhttp_h2_conn_t *connection)
{
    const int64_t seconds =
        connection->client->config.xmux.h_keep_alive_period;
    if (seconds <= 0) {
        return 0u;
    }
    if ((uint64_t)seconds > UINT64_MAX / 1000u) {
        return UINT64_MAX;
    }
    return (uint64_t)seconds * 1000u;
}

static void stream_list_add(xhttp_stream_t *stream)
{
    stream->prev = NULL;
    stream->next = stream->client->streams;
    if (stream->next != NULL) {
        stream->next->prev = stream;
    }
    stream->client->streams = stream;
}

static void stream_list_remove(xhttp_stream_t *stream)
{
    if (stream->prev != NULL) {
        stream->prev->next = stream->next;
    } else if (stream->client != NULL &&
               stream->client->streams == stream) {
        stream->client->streams = stream->next;
    }
    if (stream->next != NULL) {
        stream->next->prev = stream->prev;
    }
    stream->prev = NULL;
    stream->next = NULL;
}

static void connection_list_add(aproxy_xhttp_client_t *client,
                                xhttp_h2_conn_t *connection)
{
    connection->prev = NULL;
    connection->next = client->connections;
    if (connection->next != NULL) {
        connection->next->prev = connection;
    }
    client->connections = connection;
    client->connection_count++;
}

static void connection_list_remove(xhttp_h2_conn_t *connection)
{
    aproxy_xhttp_client_t *client = connection->client;
    if (connection->prev != NULL) {
        connection->prev->next = connection->next;
    } else if (client != NULL && client->connections == connection) {
        client->connections = connection->next;
    }
    if (connection->next != NULL) {
        connection->next->prev = connection->prev;
    }
    connection->prev = NULL;
    connection->next = NULL;
    if (client != NULL && client->connection_count > 0u) {
        client->connection_count--;
    }
}

static void request_list_add(xhttp_h2_conn_t *connection,
                             xhttp_h2_request_t *request)
{
    request->prev = NULL;
    request->next = connection->requests;
    if (request->next != NULL) {
        request->next->prev = request;
    }
    connection->requests = request;
    connection->request_count++;
}

static void request_list_remove(xhttp_h2_request_t *request)
{
    xhttp_h2_conn_t *connection = request->connection;
    if (request->prev != NULL) {
        request->prev->next = request->next;
    } else if (connection != NULL && connection->requests == request) {
        connection->requests = request->next;
    }
    if (request->next != NULL) {
        request->next->prev = request->prev;
    }
    request->prev = NULL;
    request->next = NULL;
    if (connection != NULL && connection->request_count > 0u) {
        connection->request_count--;
    }
}

static void stream_report_open(xhttp_stream_t *stream, int status)
{
    if (stream->open_reported) {
        return;
    }
    stream->open_reported = 1;
    if (stream->on_open != NULL && stream->owner != NULL) {
        stream->callback_depth++;
        stream->on_open(stream->owner, status, stream->user_data);
        stream->callback_depth--;
    }
}

static void stream_report_close(xhttp_stream_t *stream, int status)
{
    if (stream->close_reported) {
        return;
    }
    stream->close_reported = 1;
    if (stream->on_close != NULL && stream->owner != NULL) {
        stream->callback_depth++;
        stream->on_close(stream->owner, status, stream->user_data);
        stream->callback_depth--;
    }
}

static void stream_dispatch_data(xhttp_stream_t *stream,
                                 const uint8_t *data,
                                 size_t len)
{
    if (len == 0u || stream->on_data == NULL || stream->owner == NULL) {
        return;
    }
    stream->callback_depth++;
    stream->on_data(stream->owner, data, len, stream->user_data);
    stream->callback_depth--;
}

static void stream_destroy(xhttp_stream_t *stream)
{
    aproxy_xhttp_client_t *client = stream->client;
    stream_list_remove(stream);
    aproxy_ring_free(&stream->upload);
    free(stream->session_id);
    memset(stream, 0, sizeof(*stream));
    free(stream);
    client_maybe_destroy(client);
}

static void stream_maybe_destroy(xhttp_stream_t *stream)
{
    if (stream == NULL || !stream->free_pending ||
        stream->callback_depth > 0u || stream->request_refs > 0u ||
        (stream->timer_initialized && !stream->timer_closed)) {
        return;
    }
    stream_destroy(stream);
}

static void stream_timer_closed(uv_handle_t *handle)
{
    xhttp_stream_t *stream = (xhttp_stream_t *)handle->data;
    if (stream != NULL) {
        stream->timer_closed = 1;
        stream_maybe_destroy(stream);
    }
}

static void stream_close_timer(xhttp_stream_t *stream)
{
    if (!stream->timer_initialized || stream->timer_closing) {
        return;
    }
    stream->timer_closing = 1;
    uv_timer_stop(&stream->post_timer);
    uv_close((uv_handle_t *)&stream->post_timer, stream_timer_closed);
}

static void connection_close_if_unused(xhttp_h2_conn_t *connection)
{
    if (connection == NULL || connection->closing ||
        !connection->retired || connection->active_streams > 0u ||
        connection->request_count > 0u) {
        return;
    }
    connection->closing = 1;
    if (connection->tls != NULL) {
        anytls_tls_client_close(connection->tls);
    }
}

static void stream_detach(xhttp_stream_t *stream)
{
    if (!stream->attached || stream->download_connection == NULL) {
        return;
    }
    xhttp_h2_conn_t *connection = stream->download_connection;
    stream->attached = 0;
    if (connection->active_streams > 0u) {
        connection->active_streams--;
    }
    connection_close_if_unused(connection);
}

static xhttp_h2_request_t *request_acquire(aproxy_xhttp_client_t *client)
{
    xhttp_h2_request_t *request = client->free_requests;
    if (request != NULL) {
        client->free_requests = request->next_free;
        client->free_request_count--;
        memset(request, 0, sizeof(*request));
        return request;
    }
    return (xhttp_h2_request_t *)calloc(1u, sizeof(*request));
}

static void request_recycle(aproxy_xhttp_client_t *client,
                            xhttp_h2_request_t *request)
{
    if (client->free_request_count >= XHTTP_H2_REQUEST_POOL_MAX_FREE) {
        free(request);
        return;
    }
    memset(request, 0, sizeof(*request));
    request->next_free = client->free_requests;
    client->free_requests = request;
    client->free_request_count++;
}

static void request_release(xhttp_h2_request_t *request)
{
    if (request == NULL) {
        return;
    }
    xhttp_h2_conn_t *connection = request->connection;
    aproxy_xhttp_client_t *client = connection->client;
    xhttp_stream_t *stream = request->stream;
    request_list_remove(request);
    if (request->payload != NULL) {
        aproxy_bufpool_release(&connection->client->packet_pool,
                               request->payload,
                               request->payload_capacity);
    }
    if (stream != NULL) {
        if (stream->download_request == request) {
            stream->download_request = NULL;
        }
        if (stream->upload_request == request) {
            stream->upload_request = NULL;
        }
        if (request->role == XHTTP_ROLE_PACKET_UPLOAD &&
            stream->pending_posts > 0u) {
            stream->pending_posts--;
        }
        if (stream->request_refs > 0u) {
            stream->request_refs--;
        }
    }
    request_recycle(client, request);
    if (stream != NULL) {
        stream_maybe_destroy(stream);
    }
    connection_close_if_unused(connection);
}

static void connection_fail_requests(xhttp_h2_conn_t *connection,
                                     int status)
{
    xhttp_h2_request_t *request = connection->requests;
    while (request != NULL) {
        xhttp_h2_request_t *next = request->next;
        xhttp_stream_t *stream = request->stream;
        if (stream != NULL) {
            stream->callback_depth++;
        }
        request_release(request);
        if (stream != NULL && !stream->closing) {
            xhttp_stream_close_with(stream, status);
        }
        if (stream != NULL) {
            stream->callback_depth--;
            stream_maybe_destroy(stream);
        }
        request = next;
    }
}

static void connection_ping_timer_closed(uv_handle_t *handle)
{
    xhttp_h2_conn_t *connection = (xhttp_h2_conn_t *)handle->data;
    if (connection == NULL) {
        return;
    }
    connection->ping_timer_closed = 1;
    connection_destroy(connection, connection->destroy_status);
}

static void connection_close_ping_timer(xhttp_h2_conn_t *connection)
{
    if (!connection->ping_timer_initialized ||
        connection->ping_timer_closing) {
        return;
    }
    connection->ping_timer_closing = 1;
    uv_timer_stop(&connection->ping_timer);
    uv_close((uv_handle_t *)&connection->ping_timer,
             connection_ping_timer_closed);
}

static void connection_destroy(xhttp_h2_conn_t *connection, int status)
{
    aproxy_xhttp_client_t *client = connection->client;
    if (!connection->destroying) {
        connection->destroying = 1;
        connection->destroy_status = status;
        connection->closing = 1;
        connection_fail_requests(connection, status);
        if (connection->session != NULL) {
            nghttp2_session_del(connection->session);
            connection->session = NULL;
        }
        for (xhttp_stream_t *stream = client->streams; stream != NULL;) {
            xhttp_stream_t *next = stream->next;
            if (stream->upload_connection == connection) {
                stream->upload_connection = NULL;
            }
            if (stream->download_connection == connection) {
                if (!stream->closing) {
                    xhttp_stream_close_with(stream, status);
                }
                stream->download_connection = NULL;
            }
            stream = next;
        }
        connection_close_ping_timer(connection);
    }
    if (connection->ping_timer_initialized &&
        !connection->ping_timer_closed) {
        return;
    }
    connection_list_remove(connection);
    free(connection);
    client_maybe_destroy(client);
}

static void h2_tls_close(anytls_tls_client_t *tls,
                         int status,
                         void *user_data)
{
    xhttp_h2_conn_t *connection = (xhttp_h2_conn_t *)user_data;
    if (connection == NULL) {
        return;
    }
    if (connection->tls == tls) {
        connection->tls = NULL;
        anytls_tls_client_free(tls);
    }
    connection_destroy(connection,
                       status == APROXY_OK ? APROXY_ERR_INVALID_FRAME
                                           : status);
}

static int h2_flush(xhttp_h2_conn_t *connection)
{
    if (connection == NULL || connection->session == NULL ||
        connection->tls == NULL || connection->closing) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    for (;;) {
        const uint8_t *data = NULL;
        const ssize_t len = nghttp2_session_mem_send(connection->session,
                                                     &data);
        if (len < 0) {
            return APROXY_ERR_INVALID_FRAME;
        }
        if (len == 0) {
            return APROXY_OK;
        }
        const int rc = anytls_tls_client_write(connection->tls, data,
                                               (size_t)len);
        if (rc != APROXY_OK) {
            return rc;
        }
    }
}

static void h2_schedule_ping_timer(xhttp_h2_conn_t *connection,
                                   uint64_t delay_ms)
{
    if (!connection->ping_timer_initialized ||
        connection->ping_timer_closing || connection->closing) {
        return;
    }
    if (delay_ms == 0u) {
        delay_ms = 1u;
    }
    uv_timer_start(&connection->ping_timer, h2_ping_timer_cb,
                   delay_ms, 0u);
}

static void h2_retire_connection(xhttp_h2_conn_t *connection)
{
    if (connection == NULL || connection->closing) {
        return;
    }
    connection->retired = 1;
    connection->closing = 1;
    if (connection->tls != NULL) {
        anytls_tls_client_close(connection->tls);
    }
}

static void h2_ping_timer_cb(uv_timer_t *timer)
{
    xhttp_h2_conn_t *connection = (xhttp_h2_conn_t *)timer->data;
    if (connection == NULL || connection->closing || !connection->ready ||
        connection->session == NULL || connection->tls == NULL) {
        return;
    }
    const uint64_t current = now_ms();
    if (connection->ping_outstanding) {
        const uint64_t elapsed = current - connection->ping_sent_ms;
        if (elapsed >= XHTTP_H2_PING_TIMEOUT_MS) {
            h2_retire_connection(connection);
            return;
        }
        h2_schedule_ping_timer(connection,
                               XHTTP_H2_PING_TIMEOUT_MS - elapsed);
        return;
    }
    const uint64_t keepalive = h2_keepalive_ms(connection);
    const uint64_t idle = current - connection->last_read_ms;
    if (keepalive == 0u) {
        return;
    }
    if (idle < keepalive) {
        h2_schedule_ping_timer(connection, keepalive - idle);
        return;
    }
    if (RAND_bytes(connection->ping_opaque,
                   sizeof(connection->ping_opaque)) != 1 ||
        nghttp2_submit_ping(connection->session, NGHTTP2_FLAG_NONE,
                            connection->ping_opaque) != 0 ||
        h2_flush(connection) != APROXY_OK) {
        h2_retire_connection(connection);
        return;
    }
    connection->ping_outstanding = 1;
    connection->ping_sent_ms = current;
    h2_schedule_ping_timer(connection, XHTTP_H2_PING_TIMEOUT_MS);
}

static ssize_t h2_data_read(nghttp2_session *session,
                            int32_t stream_id,
                            uint8_t *buffer,
                            size_t length,
                            uint32_t *data_flags,
                            nghttp2_data_source *source,
                            void *user_data)
{
    (void)session;
    (void)stream_id;
    (void)user_data;
    xhttp_h2_request_t *request =
        (xhttp_h2_request_t *)source->ptr;
    if (request == NULL || request->stream == NULL) {
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }
    if (request->role == XHTTP_ROLE_PACKET_UPLOAD) {
        size_t remaining = request->payload_len - request->payload_offset;
        if (remaining > length) {
            remaining = length;
        }
        if (remaining > 0u) {
            memcpy(buffer, request->payload + request->payload_offset,
                   remaining);
            request->payload_offset += remaining;
        }
        if (request->payload_offset == request->payload_len) {
            *data_flags |= NGHTTP2_DATA_FLAG_EOF;
        }
        return (ssize_t)remaining;
    }
    xhttp_stream_t *stream = request->stream;
    const size_t available = aproxy_ring_size(&stream->upload);
    if (available == 0u) {
        if (stream->closing) {
            *data_flags |= NGHTTP2_DATA_FLAG_EOF;
            return 0;
        }
        return NGHTTP2_ERR_DEFERRED;
    }
    size_t count = available > length ? length : available;
    count = aproxy_ring_read(&stream->upload, buffer, count);
    return (ssize_t)count;
}

static int h2_on_header(nghttp2_session *session,
                        const nghttp2_frame *frame,
                        const uint8_t *name,
                        size_t name_len,
                        const uint8_t *value,
                        size_t value_len,
                        uint8_t flags,
                        void *user_data)
{
    (void)flags;
    (void)user_data;
    if (frame->hd.type != NGHTTP2_HEADERS || name_len != 7u ||
        memcmp(name, ":status", 7u) != 0) {
        return 0;
    }
    xhttp_h2_request_t *request = (xhttp_h2_request_t *)
        nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
    if (request == NULL || value_len != 3u || value[0] < '0' ||
        value[0] > '9' || value[1] < '0' || value[1] > '9' ||
        value[2] < '0' || value[2] > '9') {
        return 0;
    }
    request->response_status = (value[0] - '0') * 100 +
                               (value[1] - '0') * 10 +
                               (value[2] - '0');
    return 0;
}

static int h2_on_frame_recv(nghttp2_session *session,
                            const nghttp2_frame *frame,
                            void *user_data)
{
    xhttp_h2_conn_t *connection = (xhttp_h2_conn_t *)user_data;
    if (frame->hd.type == NGHTTP2_PING &&
        (frame->hd.flags & NGHTTP2_FLAG_ACK) != 0u &&
        connection != NULL && connection->ping_outstanding &&
        memcmp(frame->ping.opaque_data, connection->ping_opaque,
               sizeof(connection->ping_opaque)) == 0) {
        connection->ping_outstanding = 0;
        h2_schedule_ping_timer(connection, h2_keepalive_ms(connection));
        return 0;
    }
    if (frame->hd.type != NGHTTP2_HEADERS ||
        frame->headers.cat != NGHTTP2_HCAT_RESPONSE) {
        return 0;
    }
    xhttp_h2_request_t *request = (xhttp_h2_request_t *)
        nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
    if (request != NULL && request->response_status != 200 &&
        request->stream != NULL && !request->stream->closing) {
        xhttp_stream_close_with(request->stream,
                                APROXY_ERR_INVALID_FRAME);
    }
    return 0;
}

static int h2_on_data(nghttp2_session *session,
                      uint8_t flags,
                      int32_t stream_id,
                      const uint8_t *data,
                      size_t len,
                      void *user_data)
{
    (void)flags;
    (void)user_data;
    xhttp_h2_request_t *request = (xhttp_h2_request_t *)
        nghttp2_session_get_stream_user_data(session, stream_id);
    if (request == NULL || request->stream == NULL ||
        request->stream->closing ||
        (request->role != XHTTP_ROLE_DOWNLOAD &&
         request->role != XHTTP_ROLE_STREAM_ONE)) {
        return 0;
    }
    xhttp_stream_t *stream = request->stream;
    stream_dispatch_data(stream, data, len);
    stream_maybe_destroy(stream);
    return 0;
}

static int h2_on_stream_close(nghttp2_session *session,
                              int32_t stream_id,
                              uint32_t error_code,
                              void *user_data)
{
    (void)user_data;
    xhttp_h2_request_t *request = (xhttp_h2_request_t *)
        nghttp2_session_get_stream_user_data(session, stream_id);
    if (request == NULL) {
        return 0;
    }
    xhttp_stream_t *stream = request->stream;
    const int closes_virtual = request->role == XHTTP_ROLE_DOWNLOAD ||
                               request->role == XHTTP_ROLE_STREAM_ONE;
    if (stream != NULL) {
        stream->callback_depth++;
    }
    request_release(request);
    if (closes_virtual && stream != NULL && !stream->closing) {
        xhttp_stream_close_with(
            stream, error_code == NGHTTP2_NO_ERROR
                        ? APROXY_OK
                        : APROXY_ERR_INVALID_FRAME);
    }
    if (stream != NULL) {
        stream->callback_depth--;
        stream_maybe_destroy(stream);
    }
    return 0;
}

static int h2_session_new(xhttp_h2_conn_t *connection)
{
    nghttp2_session_callbacks *callbacks = NULL;
    if (nghttp2_session_callbacks_new(&callbacks) != 0) {
        return APROXY_ERR_NO_MEMORY;
    }
    nghttp2_session_callbacks_set_on_header_callback(callbacks,
                                                      h2_on_header);
    nghttp2_session_callbacks_set_on_frame_recv_callback(
        callbacks, h2_on_frame_recv);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
        callbacks, h2_on_data);
    nghttp2_session_callbacks_set_on_stream_close_callback(
        callbacks, h2_on_stream_close);
    const int rc = nghttp2_session_client_new(&connection->session,
                                               callbacks, connection);
    nghttp2_session_callbacks_del(callbacks);
    if (rc != 0) {
        return APROXY_ERR_NO_MEMORY;
    }
    const nghttp2_settings_entry settings[] = {
        {NGHTTP2_SETTINGS_ENABLE_PUSH, 0u},
        {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, 16u * 1024u * 1024u},
    };
    if (nghttp2_submit_settings(connection->session, NGHTTP2_FLAG_NONE,
                                settings,
                                sizeof(settings) / sizeof(settings[0])) !=
        0) {
        return APROXY_ERR_INVALID_FRAME;
    }
    return APROXY_OK;
}

static int submit_request(xhttp_h2_conn_t *connection,
                          xhttp_stream_t *stream,
                          xhttp_request_role_t role,
                          const char *sequence,
                          uint8_t *payload,
                          size_t payload_len,
                          size_t payload_capacity,
                          xhttp_h2_request_t **out)
{
    if (connection == NULL || !connection->ready ||
        connection->session == NULL || stream == NULL || out == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    *out = NULL;
    xhttp_h2_request_t *request = request_acquire(connection->client);
    if (request == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    request->connection = connection;
    request->stream = stream;
    request->role = role;
    request->payload = payload;
    request->payload_len = payload_len;
    request->payload_capacity = payload_capacity;

    xhttp_request_kind_t kind = XHTTP_REQUEST_DOWNLOAD;
    if (role == XHTTP_ROLE_LONG_UPLOAD) {
        kind = XHTTP_REQUEST_STREAM_UPLOAD;
    } else if (role == XHTTP_ROLE_STREAM_ONE) {
        kind = XHTTP_REQUEST_STREAM_ONE;
    } else if (role == XHTTP_ROLE_PACKET_UPLOAD) {
        kind = XHTTP_REQUEST_PACKET_UPLOAD;
    }
    xhttp_request_headers_t headers;
    xhttp_request_headers_init(&headers);
    const char *session_id = role == XHTTP_ROLE_STREAM_ONE
                                 ? ""
                                 : stream->session_id;
    int rc = xhttp_request_headers_build(
        &connection->client->config, kind, session_id, sequence,
        payload, payload_len, &headers);
    if (rc != APROXY_OK) {
        request_recycle(connection->client, request);
        return rc;
    }
    nghttp2_data_provider provider;
    memset(&provider, 0, sizeof(provider));
    nghttp2_data_provider *provider_ptr = NULL;
    if (role == XHTTP_ROLE_LONG_UPLOAD || role == XHTTP_ROLE_STREAM_ONE ||
        (role == XHTTP_ROLE_PACKET_UPLOAD &&
         connection->client->config.uplink_data_placement ==
             APROXY_XHTTP_PLACEMENT_BODY)) {
        provider.source.ptr = request;
        provider.read_callback = h2_data_read;
        provider_ptr = &provider;
    }
    const int32_t stream_id = nghttp2_submit_request(
        connection->session, NULL, headers.fields, headers.count,
        provider_ptr, request);
    xhttp_request_headers_free(&headers);
    if (stream_id < 0) {
        request_recycle(connection->client, request);
        return APROXY_ERR_INVALID_FRAME;
    }
    request->stream_id = stream_id;
    request_list_add(connection, request);
    stream->request_refs++;
    if (connection->left_requests > 0) {
        connection->left_requests--;
        if (connection->left_requests == 0) {
            connection->retired = 1;
        }
    }
    rc = h2_flush(connection);
    if (rc != APROXY_OK) {
        (void)nghttp2_submit_rst_stream(connection->session,
                                        NGHTTP2_FLAG_NONE, stream_id,
                                        NGHTTP2_INTERNAL_ERROR);
        nghttp2_session_set_stream_user_data(connection->session,
                                             stream_id, NULL);
        request->payload = NULL;
        request_release(request);
        return rc;
    }
    *out = request;
    return APROXY_OK;
}

static int stream_start_requests(xhttp_stream_t *stream)
{
    if (stream->started || stream->closing ||
        stream->download_connection == NULL ||
        !stream->download_connection->ready) {
        return APROXY_OK;
    }
    xhttp_h2_conn_t *connection = stream->download_connection;
    int rc;
    if (stream->mode == APROXY_XHTTP_MODE_STREAM_ONE) {
        rc = submit_request(connection, stream, XHTTP_ROLE_STREAM_ONE, NULL,
                            NULL, 0u, 0u, &stream->download_request);
        stream->upload_request = stream->download_request;
    } else {
        rc = submit_request(connection, stream, XHTTP_ROLE_DOWNLOAD, NULL,
                            NULL, 0u, 0u, &stream->download_request);
        if (rc == APROXY_OK &&
            stream->mode == APROXY_XHTTP_MODE_STREAM_UP) {
            rc = submit_request(connection, stream,
                                XHTTP_ROLE_LONG_UPLOAD, NULL,
                                NULL, 0u, 0u, &stream->upload_request);
        }
    }
    if (rc != APROXY_OK) {
        stream_report_open(stream, rc);
        xhttp_stream_close_with(stream, rc);
        return rc;
    }
    stream->started = 1;
    stream_report_open(stream, APROXY_OK);
    return APROXY_OK;
}

static void h2_tls_ready(anytls_tls_client_t *tls,
                         int status,
                         void *user_data)
{
    xhttp_h2_conn_t *connection = (xhttp_h2_conn_t *)user_data;
    if (connection == NULL || connection->closing) {
        return;
    }
    if (status == APROXY_OK && !anytls_tls_client_alpn_is(tls, "h2")) {
        status = APROXY_ERR_UNSUPPORTED;
    }
    if (status == APROXY_OK) {
        status = h2_session_new(connection);
    }
    if (status == APROXY_OK) {
        connection->ready = 1;
        connection->last_read_ms = now_ms();
        status = h2_flush(connection);
        if (status == APROXY_OK && h2_keepalive_ms(connection) > 0u) {
            h2_schedule_ping_timer(connection,
                                   h2_keepalive_ms(connection));
        }
    }
    if (status != APROXY_OK) {
        connection->retired = 1;
        connection->closing = 1;
        for (xhttp_stream_t *stream = connection->client->streams;
             stream != NULL;) {
            xhttp_stream_t *next = stream->next;
            if (stream->download_connection == connection &&
                !stream->closing) {
                stream_report_open(stream, status);
                xhttp_stream_close_with(stream, status);
            }
            stream = next;
        }
        anytls_tls_client_close(tls);
        return;
    }
    for (xhttp_stream_t *stream = connection->client->streams;
         stream != NULL;) {
        xhttp_stream_t *next = stream->next;
        if (stream->download_connection == connection && !stream->started) {
            (void)stream_start_requests(stream);
        }
        stream = next;
    }
}

static void h2_tls_data(anytls_tls_client_t *tls,
                        const uint8_t *data,
                        size_t len,
                        void *user_data)
{
    (void)tls;
    xhttp_h2_conn_t *connection = (xhttp_h2_conn_t *)user_data;
    if (connection == NULL || connection->session == NULL ||
        connection->closing) {
        return;
    }
    connection->last_read_ms = now_ms();
    const ssize_t consumed = nghttp2_session_mem_recv(connection->session,
                                                      data, len);
    if (consumed < 0 || (size_t)consumed != len ||
        h2_flush(connection) != APROXY_OK) {
        connection->retired = 1;
        connection->closing = 1;
        anytls_tls_client_close(connection->tls);
    }
}

static xhttp_h2_conn_t *connection_new(aproxy_xhttp_client_t *client)
{
    xhttp_h2_conn_t *connection =
        (xhttp_h2_conn_t *)calloc(1u, sizeof(*connection));
    if (connection == NULL) {
        return NULL;
    }
    connection->client = client;
    connection->ping_timer_closed = 1;
    connection->left_usage = -1;
    connection->left_requests = INT32_MAX;
    int32_t value = 0;
    if (aproxy_xhttp_range_random(client->config.xmux.c_max_reuse_times,
                                  &value) != APROXY_OK) {
        free(connection);
        return NULL;
    }
    if (value > 0) {
        connection->left_usage = value - 1;
        if (connection->left_usage == 0) {
            connection->retired = 1;
        }
    }
    if (aproxy_xhttp_range_random(client->config.xmux.h_max_request_times,
                                  &value) != APROXY_OK) {
        free(connection);
        return NULL;
    }
    if (value > 0) {
        connection->left_requests = value;
    }
    if (aproxy_xhttp_range_random(client->config.xmux.h_max_reusable_secs,
                                  &value) != APROXY_OK) {
        free(connection);
        return NULL;
    }
    if (value > 0) {
        connection->expires_at_ms = now_ms() + (uint64_t)value * 1000u;
    }
    const anytls_tls_client_config_t tls_config = {
        .loop = client->config.loop,
        .host = client->config.server_host,
        .port = client->config.server_port,
        .sni = client->config.sni != NULL ? client->config.sni
                                          : client->config.host,
        .resolver = client->config.resolver,
        .context = client->tls_context,
        .alpn = "h2",
        .ech = client->config.ech,
        .socket_protector = client->config.socket_protector,
        .insecure_skip_verify = client->config.insecure_skip_verify,
        .reality = client->config.reality,
        .on_ready = h2_tls_ready,
        .on_data = h2_tls_data,
        .on_close = h2_tls_close,
        .user_data = connection,
    };
    int rc = anytls_tls_client_new(&tls_config, &connection->tls);
    if (rc != APROXY_OK) {
        free(connection);
        return NULL;
    }
    if (h2_keepalive_ms(connection) > 0u) {
        rc = uv_timer_init(client->config.loop, &connection->ping_timer);
        if (rc != 0) {
            anytls_tls_client_free(connection->tls);
            free(connection);
            return NULL;
        }
        connection->ping_timer_initialized = 1;
        connection->ping_timer_closed = 0;
        connection->ping_timer.data = connection;
    }
    connection_list_add(client, connection);
    rc = anytls_tls_client_connect(connection->tls);
    if (rc != APROXY_OK) {
        connection->retired = 1;
        connection->closing = 1;
        anytls_tls_client_close(connection->tls);
        return NULL;
    }
    return connection;
}

static int connection_reusable(xhttp_h2_conn_t *connection)
{
    if (connection->closing || connection->retired ||
        connection->left_usage == 0 || connection->left_requests == 0 ||
        (connection->expires_at_ms > 0u &&
         now_ms() >= connection->expires_at_ms)) {
        connection->retired = 1;
        return 0;
    }
    return 1;
}

static xhttp_h2_conn_t *xmux_get(aproxy_xhttp_client_t *client,
                                 int virtual_stream)
{
    if (client->closing) {
        return NULL;
    }
    size_t candidates = 0u;
    for (xhttp_h2_conn_t *item = client->connections; item != NULL;) {
        xhttp_h2_conn_t *next = item->next;
        if (connection_reusable(item) &&
            (client->xmux_concurrency <= 0 || !virtual_stream ||
             item->active_streams < (size_t)client->xmux_concurrency)) {
            candidates++;
        } else {
            connection_close_if_unused(item);
        }
        item = next;
    }
    if (client->xmux_connections > 0 &&
        client->connection_count < (size_t)client->xmux_connections) {
        return connection_new(client);
    }
    if (candidates == 0u) {
        return connection_new(client);
    }
    uint64_t random = 0u;
    if (RAND_bytes((uint8_t *)&random, sizeof(random)) != 1) {
        random = 0u;
    }
    size_t selected = (size_t)(random % candidates);
    for (xhttp_h2_conn_t *item = client->connections; item != NULL;
         item = item->next) {
        if (!connection_reusable(item) ||
            (client->xmux_concurrency > 0 && virtual_stream &&
             item->active_streams >= (size_t)client->xmux_concurrency)) {
            continue;
        }
        if (selected-- == 0u) {
            if (virtual_stream && item->left_usage > 0) {
                item->left_usage--;
                if (item->left_usage == 0) {
                    item->retired = 1;
                }
            }
            return item;
        }
    }
    return NULL;
}

static void packet_timer_cb(uv_timer_t *timer);

static void schedule_packet_flush(xhttp_stream_t *stream, uint64_t delay)
{
    if (stream->timer_initialized && !stream->timer_closing &&
        !stream->closing) {
        uv_timer_start(&stream->post_timer, packet_timer_cb, delay, 0u);
    }
}

static int stream_flush_packet(xhttp_stream_t *stream)
{
    if (stream->closing || aproxy_ring_size(&stream->upload) == 0u) {
        return APROXY_OK;
    }
    if (stream->pending_posts >=
        (size_t)stream->client->config.max_buffered_posts) {
        schedule_packet_flush(stream, 1u);
        return APROXY_OK;
    }
    int32_t interval = 0;
    int rc = aproxy_xhttp_range_random(
        stream->client->config.min_posts_interval_ms, &interval);
    if (rc != APROXY_OK) {
        return rc;
    }
    const uint64_t current = now_ms();
    if (interval > 0 && stream->last_post_ms > 0u &&
        current < stream->last_post_ms + (uint64_t)interval) {
        schedule_packet_flush(
            stream, stream->last_post_ms + (uint64_t)interval - current);
        return APROXY_OK;
    }
    xhttp_h2_conn_t *connection = stream->upload_connection;
    if (connection == NULL || !connection_reusable(connection)) {
        connection = xmux_get(stream->client, 0);
        stream->upload_connection = connection;
    }
    if (connection == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    if (!connection->ready) {
        schedule_packet_flush(stream, 10u);
        return APROXY_OK;
    }
    int32_t maximum = 0;
    rc = aproxy_xhttp_range_random(
        stream->client->config.max_each_post_bytes, &maximum);
    if (rc != APROXY_OK || maximum <= 0) {
        return rc != APROXY_OK ? rc : APROXY_ERR_PARSE;
    }
    size_t payload_len = aproxy_ring_size(&stream->upload);
    if (payload_len > (size_t)maximum) {
        payload_len = (size_t)maximum;
    }
    size_t capacity = 0u;
    uint8_t *payload = aproxy_bufpool_acquire(
        &stream->client->packet_pool, payload_len, &capacity);
    if (payload == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    if (aproxy_ring_peek(&stream->upload, 0u, payload, payload_len) !=
        payload_len) {
        aproxy_bufpool_release(&stream->client->packet_pool, payload,
                               capacity);
        return APROXY_ERR_INVALID_FRAME;
    }
    char sequence[32];
    const int written = snprintf(sequence, sizeof(sequence), "%" PRIu64,
                                 stream->sequence);
    if (written < 0 || (size_t)written >= sizeof(sequence)) {
        aproxy_bufpool_release(&stream->client->packet_pool, payload,
                               capacity);
        return APROXY_ERR_FRAME_TOO_LARGE;
    }
    xhttp_h2_request_t *request = NULL;
    rc = submit_request(connection, stream, XHTTP_ROLE_PACKET_UPLOAD,
                        sequence, payload, payload_len, capacity, &request);
    if (rc != APROXY_OK) {
        aproxy_bufpool_release(&stream->client->packet_pool, payload,
                               capacity);
        return rc;
    }
    (void)request;
    aproxy_ring_consume(&stream->upload, payload_len);
    stream->pending_posts++;
    stream->sequence++;
    stream->last_post_ms = now_ms();
    if (aproxy_ring_size(&stream->upload) > 0u) {
        schedule_packet_flush(stream,
                              interval > 0 ? (uint64_t)interval : 0u);
    }
    return APROXY_OK;
}

static void packet_timer_cb(uv_timer_t *timer)
{
    xhttp_stream_t *stream = (xhttp_stream_t *)timer->data;
    if (stream != NULL && !stream->closing &&
        stream_flush_packet(stream) != APROXY_OK) {
        xhttp_stream_close_with(stream, APROXY_ERR_INVALID_FRAME);
    }
}

static void xhttp_stream_close_with(xhttp_stream_t *stream, int status)
{
    if (stream == NULL || stream->closing) {
        return;
    }
    stream->closing = 1;
    stream_close_timer(stream);
    if (!stream->open_reported) {
        stream_report_open(stream, status);
    }
    stream_report_close(stream, status);
    stream_detach(stream);
    for (xhttp_h2_conn_t *connection = stream->client->connections;
         connection != NULL; connection = connection->next) {
        for (xhttp_h2_request_t *request = connection->requests;
             request != NULL; request = request->next) {
            if (request->stream == stream && request->stream_id > 0 &&
                connection->session != NULL) {
                (void)nghttp2_submit_rst_stream(
                    connection->session, NGHTTP2_FLAG_NONE,
                    request->stream_id, NGHTTP2_CANCEL);
            }
        }
        if (connection->ready) {
            (void)h2_flush(connection);
        }
    }
    stream_maybe_destroy(stream);
}

static int xhttp_stream_write_impl(void *impl,
                                   const uint8_t *data,
                                   size_t len)
{
    xhttp_stream_t *stream = (xhttp_stream_t *)impl;
    if (stream == NULL || (data == NULL && len > 0u) || stream->closing) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    const size_t buffered = aproxy_ring_size(&stream->upload);
    if (len > (size_t)stream->client->config.max_buffered_bytes ||
        buffered >
            (size_t)stream->client->config.max_buffered_bytes - len) {
        return APROXY_ERR_FRAME_TOO_LARGE;
    }
    int rc = aproxy_ring_write(&stream->upload, data, len);
    if (rc != APROXY_OK || len == 0u) {
        return rc;
    }
    if (stream->mode == APROXY_XHTTP_MODE_PACKET_UP) {
        schedule_packet_flush(stream, 1u);
        return APROXY_OK;
    }
    if (stream->upload_request != NULL &&
        stream->upload_request->connection->session != NULL) {
        rc = nghttp2_session_resume_data(
            stream->upload_request->connection->session,
            stream->upload_request->stream_id);
        if (rc == 0) {
            rc = h2_flush(stream->upload_request->connection);
        }
        return rc == 0 ? APROXY_OK : APROXY_ERR_INVALID_FRAME;
    }
    return APROXY_OK;
}

static int xhttp_stream_close_impl(void *impl)
{
    xhttp_stream_t *stream = (xhttp_stream_t *)impl;
    if (stream == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    xhttp_stream_close_with(stream, APROXY_OK);
    return APROXY_OK;
}

static uint32_t xhttp_stream_id_impl(const void *impl)
{
    const xhttp_stream_t *stream = (const xhttp_stream_t *)impl;
    return stream == NULL ? 0u : stream->id;
}

static void *xhttp_stream_native_impl(const void *impl)
{
    const xhttp_stream_t *stream = (const xhttp_stream_t *)impl;
    return stream == NULL ? NULL : (void *)stream->download_connection;
}

static void xhttp_stream_free_impl(void *impl)
{
    xhttp_stream_t *stream = (xhttp_stream_t *)impl;
    if (stream == NULL) {
        return;
    }
    stream->owner = NULL;
    stream->on_data = NULL;
    stream->on_open = NULL;
    stream->on_close = NULL;
    stream->user_data = NULL;
    stream->free_pending = 1;
    xhttp_stream_close_with(stream, APROXY_OK);
    stream_maybe_destroy(stream);
}

static const aproxy_stream_vtable_t xhttp_stream_vtable = {
    .write = xhttp_stream_write_impl,
    .close = xhttp_stream_close_impl,
    .id = xhttp_stream_id_impl,
    .native = xhttp_stream_native_impl,
    .free = xhttp_stream_free_impl,
};

static int copy_config(aproxy_xhttp_client_t *client,
                       const aproxy_xhttp_config_t *source)
{
    client->config = *source;
    client->config.ech.config_list = NULL;
#define COPY_CONFIG_STRING(field)                                             \
    do {                                                                      \
        client->config.field = copy_string(source->field);                    \
        if (source->field != NULL && client->config.field == NULL) {          \
            return APROXY_ERR_NO_MEMORY;                                      \
        }                                                                     \
    } while (0)
    COPY_CONFIG_STRING(server_host);
    COPY_CONFIG_STRING(server_port);
    COPY_CONFIG_STRING(host);
    COPY_CONFIG_STRING(path);
    COPY_CONFIG_STRING(sni);
    COPY_CONFIG_STRING(x_padding_key);
    COPY_CONFIG_STRING(x_padding_header);
    COPY_CONFIG_STRING(uplink_http_method);
    COPY_CONFIG_STRING(session_id_key);
    COPY_CONFIG_STRING(session_id_table);
    COPY_CONFIG_STRING(seq_key);
    COPY_CONFIG_STRING(uplink_data_key);
#undef COPY_CONFIG_STRING
    if (source->ech.config_list_len > 0u) {
        uint8_t *ech_config =
            (uint8_t *)malloc(source->ech.config_list_len);
        if (ech_config == NULL) {
            return APROXY_ERR_NO_MEMORY;
        }
        memcpy(ech_config, source->ech.config_list,
               source->ech.config_list_len);
        client->config.ech.config_list = ech_config;
    }
    if (source->header_count > 0u) {
        client->headers = (aproxy_xhttp_header_t *)calloc(
            source->header_count, sizeof(*client->headers));
        if (client->headers == NULL) {
            return APROXY_ERR_NO_MEMORY;
        }
        client->config.headers = client->headers;
        for (size_t i = 0u; i < source->header_count; i++) {
            client->headers[i].name = copy_string(source->headers[i].name);
            client->headers[i].value = copy_string(source->headers[i].value);
            if (client->headers[i].name == NULL ||
                client->headers[i].value == NULL) {
                return APROXY_ERR_NO_MEMORY;
            }
        }
    }
    return APROXY_OK;
}

static void free_config(aproxy_xhttp_client_t *client)
{
    free((char *)client->config.server_host);
    free((char *)client->config.server_port);
    free((char *)client->config.host);
    free((char *)client->config.path);
    free((char *)client->config.sni);
    free((char *)client->config.x_padding_key);
    free((char *)client->config.x_padding_header);
    free((char *)client->config.uplink_http_method);
    free((char *)client->config.session_id_key);
    free((char *)client->config.session_id_table);
    free((char *)client->config.seq_key);
    free((char *)client->config.uplink_data_key);
    free((uint8_t *)client->config.ech.config_list);
    for (size_t i = 0u; i < client->config.header_count; i++) {
        free((char *)client->headers[i].name);
        free((char *)client->headers[i].value);
    }
    free(client->headers);
}

static void client_destroy(aproxy_xhttp_client_t *client)
{
    while (client->free_requests != NULL) {
        xhttp_h2_request_t *next = client->free_requests->next_free;
        free(client->free_requests);
        client->free_requests = next;
    }
    aproxy_bufpool_destroy(&client->packet_pool);
    aproxy_tls_context_free(client->tls_context);
    free_config(client);
    free(client);
}

static void client_maybe_destroy(aproxy_xhttp_client_t *client)
{
    if (client != NULL && client->free_pending &&
        client->connections == NULL && client->streams == NULL) {
        client_destroy(client);
    }
}

int aproxy_xhttp_client_new(const aproxy_xhttp_config_t *config,
                            aproxy_xhttp_client_t **out)
{
    if (config == NULL || out == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    *out = NULL;
    aproxy_xhttp_config_t normalized = *config;
    int rc = aproxy_xhttp_config_normalize(&normalized);
    if (rc != APROXY_OK) {
        return rc;
    }
    const int use_h1 =
        normalized.http_version == APROXY_XHTTP_HTTP_1_1 ||
        (normalized.http_version == APROXY_XHTTP_HTTP_AUTO &&
         !normalized.tls_enabled);
    if (use_h1) {
        aproxy_xhttp_client_t *client =
            (aproxy_xhttp_client_t *)calloc(1u, sizeof(*client));
        if (client == NULL) {
            return APROXY_ERR_NO_MEMORY;
        }
        client->is_h1 = 1;
        rc = xhttp_h1_client_new(&normalized, &client->h1);
        if (rc != APROXY_OK) {
            free(client);
            return rc;
        }
        *out = client;
        return APROXY_OK;
    }
    if (!normalized.tls_enabled) {
        return APROXY_ERR_UNSUPPORTED;
    }
    aproxy_xhttp_client_t *client =
        (aproxy_xhttp_client_t *)calloc(1u, sizeof(*client));
    if (client == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    aproxy_bufpool_init(&client->packet_pool, XHTTP_PACKET_POOL_CHUNK,
                        XHTTP_PACKET_POOL_MAX_FREE);
    rc = copy_config(client, &normalized);
    if (rc != APROXY_OK) {
        client_destroy(client);
        return rc;
    }
    rc = aproxy_tls_context_new(client->config.insecure_skip_verify,
                                &client->tls_context);
    if (rc != APROXY_OK) {
        client_destroy(client);
        return rc;
    }
    rc = aproxy_xhttp_range_random(client->config.xmux.max_concurrency,
                                   &client->xmux_concurrency);
    if (rc == APROXY_OK) {
        rc = aproxy_xhttp_range_random(client->config.xmux.max_connections,
                                       &client->xmux_connections);
    }
    if (rc != APROXY_OK) {
        client_destroy(client);
        return rc;
    }
    *out = client;
    return APROXY_OK;
}

static int generate_session_id(const aproxy_xhttp_config_t *config,
                               char **out)
{
    *out = NULL;
    if (config->session_id_table != NULL &&
        config->session_id_table[0] != '\0') {
        int32_t length = 0;
        int rc = aproxy_xhttp_range_random(config->session_id_length,
                                           &length);
        if (rc != APROXY_OK || length <= 0) {
            return rc != APROXY_OK ? rc : APROXY_ERR_PARSE;
        }
        char *output = (char *)malloc((size_t)length + 1u);
        uint8_t *random = (uint8_t *)malloc((size_t)length);
        if (output == NULL || random == NULL) {
            free(output);
            free(random);
            return APROXY_ERR_NO_MEMORY;
        }
        if (RAND_bytes(random, length) != 1) {
            free(output);
            free(random);
            return APROXY_ERR_CRYPTO;
        }
        const size_t table_len = strlen(config->session_id_table);
        for (int32_t i = 0; i < length; i++) {
            output[i] = config->session_id_table[random[i] % table_len];
        }
        output[length] = '\0';
        free(random);
        *out = output;
        return APROXY_OK;
    }
    uint8_t random[16];
    if (RAND_bytes(random, sizeof(random)) != 1) {
        return APROXY_ERR_CRYPTO;
    }
    random[6] = (uint8_t)((random[6] & 0x0fu) | 0x40u);
    random[8] = (uint8_t)((random[8] & 0x3fu) | 0x80u);
    char *output = (char *)malloc(37u);
    if (output == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    const int written = snprintf(
        output, 37u,
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-"
        "%02x%02x%02x%02x%02x%02x",
        random[0], random[1], random[2], random[3], random[4], random[5],
        random[6], random[7], random[8], random[9], random[10], random[11],
        random[12], random[13], random[14], random[15]);
    if (written != 36) {
        free(output);
        return APROXY_ERR_INVALID_FRAME;
    }
    *out = output;
    return APROXY_OK;
}

int aproxy_xhttp_client_open_stream(aproxy_xhttp_client_t *client,
                                    aproxy_stream_data_cb on_data,
                                    aproxy_stream_event_cb on_open,
                                    aproxy_stream_event_cb on_close,
                                    void *user_data,
                                    aproxy_stream_t **out)
{
    if (client == NULL || out == NULL || client->closing) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    if (client->is_h1) {
        return xhttp_h1_client_open_stream(client->h1, on_data, on_open,
                                           on_close, user_data, out);
    }
    *out = NULL;
    xhttp_h2_conn_t *connection = xmux_get(client, 1);
    if (connection == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    xhttp_stream_t *stream =
        (xhttp_stream_t *)calloc(1u, sizeof(*stream));
    if (stream == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    stream->client = client;
    stream->download_connection = connection;
    stream->on_data = on_data;
    stream->on_open = on_open;
    stream->on_close = on_close;
    stream->user_data = user_data;
    stream->id = ++client->next_stream_id;
    stream->mode = client->config.mode == APROXY_XHTTP_MODE_AUTO
                       ? APROXY_XHTTP_MODE_PACKET_UP
                       : client->config.mode;
    aproxy_ring_init(&stream->upload);
    int rc = generate_session_id(&client->config, &stream->session_id);
    if (rc != APROXY_OK) {
        aproxy_ring_free(&stream->upload);
        free(stream);
        return rc;
    }
    if (stream->mode == APROXY_XHTTP_MODE_PACKET_UP) {
        rc = uv_timer_init(client->config.loop, &stream->post_timer);
        if (rc != 0) {
            aproxy_ring_free(&stream->upload);
            free(stream->session_id);
            free(stream);
            return rc;
        }
        stream->timer_initialized = 1;
        stream->post_timer.data = stream;
    } else {
        stream->timer_closed = 1;
    }
    rc = aproxy_stream_new(&xhttp_stream_vtable, stream, &stream->owner);
    if (rc != APROXY_OK) {
        stream->free_pending = 1;
        stream_close_timer(stream);
        stream_maybe_destroy(stream);
        return rc;
    }
    stream_list_add(stream);
    stream->attached = 1;
    connection->active_streams++;
    *out = stream->owner;
    rc = stream_start_requests(stream);
    if (rc != APROXY_OK && !stream->closing) {
        aproxy_stream_free(*out);
        *out = NULL;
        return rc;
    }
    return APROXY_OK;
}

void aproxy_xhttp_client_close(aproxy_xhttp_client_t *client)
{
    if (client == NULL || client->closing) {
        return;
    }
    if (client->is_h1) {
        client->closing = 1;
        xhttp_h1_client_close(client->h1);
        return;
    }
    client->closing = 1;
    for (xhttp_stream_t *stream = client->streams; stream != NULL;) {
        xhttp_stream_t *next = stream->next;
        xhttp_stream_close_with(stream, APROXY_OK);
        stream = next;
    }
    for (xhttp_h2_conn_t *connection = client->connections;
         connection != NULL;) {
        xhttp_h2_conn_t *next = connection->next;
        connection->retired = 1;
        if (!connection->closing) {
            connection->closing = 1;
            anytls_tls_client_close(connection->tls);
        }
        connection = next;
    }
}

void aproxy_xhttp_client_free(aproxy_xhttp_client_t *client)
{
    if (client == NULL) {
        return;
    }
    if (client->is_h1) {
        xhttp_h1_client_free(client->h1);
        free(client);
        return;
    }
    client->free_pending = 1;
    aproxy_xhttp_client_close(client);
    client_maybe_destroy(client);
}
