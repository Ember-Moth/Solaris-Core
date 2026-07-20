/*
 * Wire-compatible XHTTP/XMUX HTTP/1.1 behavior based on Xray-core
 * b17a88f9b46d. This file is licensed under MPL-2.0.
 */

#include "xhttp_h1.h"
#include "platform.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <strings.h>
#endif

#include <llhttp.h>
#include <openssl/rand.h>

#include "aproxy/buffer.h"
#include "aproxy/bufpool.h"
#include "aproxy/direct_outbound.h"
#include "aproxy/ring.h"
#include "framework/stream_internal.h"
#include "tls_uv.h"
#include "xhttp_internal.h"
#include "xhttp_request.h"

#define XHTTP_H1_PACKET_POOL_CHUNK (16u * 1024u)
#define XHTTP_H1_PACKET_POOL_MAX_FREE 64u

typedef struct xhttp_h1_stream xhttp_h1_stream_t;
typedef struct xhttp_h1_request xhttp_h1_request_t;

typedef enum xhttp_h1_role {
    XHTTP_H1_DOWNLOAD = 0,
    XHTTP_H1_LONG_UPLOAD,
    XHTTP_H1_STREAM_ONE,
    XHTTP_H1_PACKET_UPLOAD,
} xhttp_h1_role_t;

struct xhttp_h1_client {
    aproxy_xhttp_config_t config;
    aproxy_xhttp_header_t *headers;
    aproxy_tls_context_t *tls_context;
    aproxy_outbound_t *direct;
    aproxy_addr_t server;
    aproxy_bufpool_t packet_pool;
    xhttp_h1_stream_t *streams;
    xhttp_h1_request_t *idle_packets;
    size_t idle_packet_count;
    size_t request_count;
    uint32_t next_stream_id;
    int closing;
    int free_pending;
};

struct xhttp_h1_request {
    xhttp_h1_client_t *client;
    xhttp_h1_stream_t *stream;
    xhttp_h1_request_t *prev;
    xhttp_h1_request_t *next;
    xhttp_h1_request_t *idle_prev;
    xhttp_h1_request_t *idle_next;
    anytls_tls_client_t *tls;
    aproxy_stream_t *raw;
    llhttp_t parser;
    llhttp_settings_t settings;
    aproxy_buffer_t wire;
    uint8_t *payload;
    size_t payload_len;
    size_t payload_capacity;
    uint64_t sequence;
    uint64_t expires_at_ms;
    int32_t requests_left;
    xhttp_h1_role_t role;
    int response_status;
    int ready;
    int message_complete;
    int response_keep_alive;
    int closing;
    int failure_status;
    int in_idle_pool;
};

struct xhttp_h1_stream {
    xhttp_h1_client_t *client;
    aproxy_stream_t *owner;
    xhttp_h1_request_t *requests;
    xhttp_h1_request_t *download_request;
    xhttp_h1_request_t *upload_request;
    aproxy_stream_data_cb on_data;
    aproxy_stream_event_cb on_open;
    aproxy_stream_event_cb on_close;
    void *user_data;
    aproxy_ring_t upload;
    aproxy_buffer_t chunk_wire;
    uv_timer_t post_timer;
    char *session_id;
    uint64_t sequence;
    uint64_t last_post_ms;
    uint32_t id;
    size_t request_refs;
    size_t pending_posts;
    unsigned int callback_depth;
    int mode;
    int open_reported;
    int close_reported;
    int closing;
    int upload_closed;
    int free_pending;
    int timer_initialized;
    int timer_closing;
    int timer_closed;
    xhttp_h1_stream_t *prev;
    xhttp_h1_stream_t *next;
};

static void h1_stream_close_with(xhttp_h1_stream_t *stream, int status);
static void h1_stream_maybe_destroy(xhttp_h1_stream_t *stream);
static void h1_client_maybe_destroy(xhttp_h1_client_t *client);
static int h1_flush_upload(xhttp_h1_stream_t *stream);
static void h1_request_close(xhttp_h1_request_t *request);
static void schedule_packet_flush(xhttp_h1_stream_t *stream, uint64_t delay);

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

static void stream_list_add(xhttp_h1_stream_t *stream)
{
    stream->prev = NULL;
    stream->next = stream->client->streams;
    if (stream->next != NULL) {
        stream->next->prev = stream;
    }
    stream->client->streams = stream;
}

static void stream_list_remove(xhttp_h1_stream_t *stream)
{
    if (stream->prev != NULL) {
        stream->prev->next = stream->next;
    } else if (stream->client != NULL && stream->client->streams == stream) {
        stream->client->streams = stream->next;
    }
    if (stream->next != NULL) {
        stream->next->prev = stream->prev;
    }
    stream->prev = NULL;
    stream->next = NULL;
}

static void request_list_add(xhttp_h1_stream_t *stream,
                             xhttp_h1_request_t *request)
{
    request->prev = NULL;
    request->next = stream->requests;
    if (request->next != NULL) {
        request->next->prev = request;
    }
    stream->requests = request;
    stream->request_refs++;
}

static void request_list_remove(xhttp_h1_request_t *request)
{
    xhttp_h1_stream_t *stream = request->stream;
    if (request->prev != NULL) {
        request->prev->next = request->next;
    } else if (stream != NULL && stream->requests == request) {
        stream->requests = request->next;
    }
    if (request->next != NULL) {
        request->next->prev = request->prev;
    }
    request->prev = NULL;
    request->next = NULL;
    if (stream != NULL && stream->request_refs > 0u) {
        stream->request_refs--;
    }
}

static void idle_packet_add(xhttp_h1_request_t *request)
{
    xhttp_h1_client_t *client = request->client;
    request->idle_prev = NULL;
    request->idle_next = client->idle_packets;
    if (request->idle_next != NULL) {
        request->idle_next->idle_prev = request;
    }
    client->idle_packets = request;
    client->idle_packet_count++;
    request->in_idle_pool = 1;
}

static void idle_packet_remove(xhttp_h1_request_t *request)
{
    if (request == NULL || !request->in_idle_pool) {
        return;
    }
    xhttp_h1_client_t *client = request->client;
    if (request->idle_prev != NULL) {
        request->idle_prev->idle_next = request->idle_next;
    } else if (client->idle_packets == request) {
        client->idle_packets = request->idle_next;
    }
    if (request->idle_next != NULL) {
        request->idle_next->idle_prev = request->idle_prev;
    }
    request->idle_prev = NULL;
    request->idle_next = NULL;
    request->in_idle_pool = 0;
    if (client->idle_packet_count > 0u) {
        client->idle_packet_count--;
    }
}

static void stream_report_open(xhttp_h1_stream_t *stream, int status)
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

static void stream_report_close(xhttp_h1_stream_t *stream, int status)
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

static void stream_dispatch_data(xhttp_h1_stream_t *stream,
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

static void stream_destroy(xhttp_h1_stream_t *stream)
{
    xhttp_h1_client_t *client = stream->client;
    stream_list_remove(stream);
    aproxy_ring_free(&stream->upload);
    aproxy_buffer_free(&stream->chunk_wire);
    free(stream->session_id);
    free(stream);
    h1_client_maybe_destroy(client);
}

static void h1_stream_maybe_destroy(xhttp_h1_stream_t *stream)
{
    if (stream == NULL || !stream->free_pending ||
        stream->callback_depth > 0u || stream->request_refs > 0u ||
        (stream->timer_initialized && !stream->timer_closed)) {
        return;
    }
    stream_destroy(stream);
}

static void timer_closed_cb(uv_handle_t *handle)
{
    xhttp_h1_stream_t *stream = (xhttp_h1_stream_t *)handle->data;
    if (stream != NULL) {
        stream->timer_closed = 1;
        h1_stream_maybe_destroy(stream);
    }
}

static void stream_close_timer(xhttp_h1_stream_t *stream)
{
    if (!stream->timer_initialized || stream->timer_closing) {
        return;
    }
    stream->timer_closing = 1;
    uv_timer_stop(&stream->post_timer);
    uv_close((uv_handle_t *)&stream->post_timer, timer_closed_cb);
}

static int buffer_append_text(aproxy_buffer_t *buffer, const char *text)
{
    return aproxy_buffer_append(buffer, (const uint8_t *)text, strlen(text));
}

static int request_write(xhttp_h1_request_t *request,
                         const uint8_t *data,
                         size_t len)
{
    if (request == NULL || request->closing) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    if (request->tls != NULL) {
        return anytls_tls_client_write(request->tls, data, len);
    }
    return request->raw != NULL
               ? aproxy_stream_write(request->raw, data, len)
               : APROXY_ERR_INVALID_ARGUMENT;
}

static int request_write_chunk(xhttp_h1_request_t *request,
                               const uint8_t *data,
                               size_t len)
{
    char prefix[32];
    const int prefix_len = snprintf(prefix, sizeof(prefix), "%zx\r\n", len);
    if (prefix_len < 0 || (size_t)prefix_len >= sizeof(prefix)) {
        return APROXY_ERR_FRAME_TOO_LARGE;
    }
    aproxy_buffer_t *wire = &request->stream->chunk_wire;
    aproxy_buffer_clear(wire);
    int rc = aproxy_buffer_append(wire, (const uint8_t *)prefix,
                                  (size_t)prefix_len);
    if (rc == APROXY_OK) {
        rc = aproxy_buffer_append(wire, data, len);
    }
    if (rc == APROXY_OK) {
        rc = buffer_append_text(wire, "\r\n");
    }
    if (rc == APROXY_OK) {
        rc = request_write(request, wire->data, wire->len);
    }
    return rc;
}

static int header_name_is(const nghttp2_nv *field, const char *name)
{
    const size_t len = strlen(name);
    return field->namelen == len &&
           strncasecmp((const char *)field->name, name, len) == 0;
}

static int append_h1_headers(const aproxy_xhttp_config_t *config,
                             xhttp_request_kind_t kind,
                             const char *session_id,
                             const char *sequence,
                             const uint8_t *payload,
                             size_t payload_len,
                             int chunked,
                             int keep_alive,
                             aproxy_buffer_t *wire)
{
    xhttp_request_headers_t headers;
    xhttp_request_headers_init(&headers);
    int rc = xhttp_request_headers_build(config, kind, session_id, sequence,
                                         payload, payload_len, &headers);
    const char *method = xhttp_request_header_find(&headers, ":method");
    const char *path = xhttp_request_header_find(&headers, ":path");
    const char *authority =
        xhttp_request_header_find(&headers, ":authority");
    if (rc != APROXY_OK || method == NULL || path == NULL ||
        authority == NULL) {
        xhttp_request_headers_free(&headers);
        return rc != APROXY_OK ? rc : APROXY_ERR_INVALID_FRAME;
    }
    rc = buffer_append_text(wire, method);
    if (rc == APROXY_OK) {
        rc = buffer_append_text(wire, " ");
    }
    if (rc == APROXY_OK) {
        rc = buffer_append_text(wire, path);
    }
    if (rc == APROXY_OK) {
        rc = buffer_append_text(wire, " HTTP/1.1\r\nHost: ");
    }
    if (rc == APROXY_OK) {
        rc = buffer_append_text(wire, authority);
    }
    if (rc == APROXY_OK) {
        rc = buffer_append_text(wire, "\r\n");
    }
    for (size_t i = 0u; rc == APROXY_OK && i < headers.count; i++) {
        const nghttp2_nv *field = &headers.fields[i];
        if (field->namelen == 0u || field->name[0] == ':' ||
            header_name_is(field, "host") ||
            header_name_is(field, "content-length") ||
            header_name_is(field, "transfer-encoding") ||
            header_name_is(field, "connection")) {
            continue;
        }
        rc = aproxy_buffer_append(wire, field->name, field->namelen);
        if (rc == APROXY_OK) {
            rc = buffer_append_text(wire, ": ");
        }
        if (rc == APROXY_OK) {
            rc = aproxy_buffer_append(wire, field->value, field->valuelen);
        }
        if (rc == APROXY_OK) {
            rc = buffer_append_text(wire, "\r\n");
        }
    }
    if (rc == APROXY_OK && chunked) {
        rc = buffer_append_text(wire, "Transfer-Encoding: chunked\r\n");
    } else if (rc == APROXY_OK && kind == XHTTP_REQUEST_PACKET_UPLOAD &&
               config->uplink_data_placement ==
                   APROXY_XHTTP_PLACEMENT_BODY) {
        char length[64];
        const int written = snprintf(length, sizeof(length),
                                     "Content-Length: %zu\r\n", payload_len);
        if (written < 0 || (size_t)written >= sizeof(length)) {
            rc = APROXY_ERR_FRAME_TOO_LARGE;
        } else {
            rc = aproxy_buffer_append(wire, (const uint8_t *)length,
                                      (size_t)written);
        }
    }
    if (rc == APROXY_OK) {
        rc = buffer_append_text(wire, keep_alive
                                          ? "Connection: keep-alive\r\n\r\n"
                                          : "Connection: close\r\n\r\n");
    }
    if (rc == APROXY_OK && kind == XHTTP_REQUEST_PACKET_UPLOAD &&
        config->uplink_data_placement == APROXY_XHTTP_PLACEMENT_BODY) {
        rc = aproxy_buffer_append(wire, payload, payload_len);
    }
    xhttp_request_headers_free(&headers);
    return rc;
}

static void stream_maybe_open(xhttp_h1_stream_t *stream)
{
    if (stream->open_reported || stream->closing ||
        stream->download_request == NULL ||
        !stream->download_request->ready) {
        return;
    }
    if (stream->mode == APROXY_XHTTP_MODE_STREAM_UP &&
        (stream->upload_request == NULL || !stream->upload_request->ready)) {
        return;
    }
    stream_report_open(stream, APROXY_OK);
}

static void request_release_payload(xhttp_h1_request_t *request)
{
    if (request->payload == NULL) {
        return;
    }
    aproxy_bufpool_release(&request->client->packet_pool,
                           request->payload, request->payload_capacity);
    request->payload = NULL;
    request->payload_len = 0u;
    request->payload_capacity = 0u;
}

static int request_send_headers(xhttp_h1_request_t *request)
{
    xhttp_h1_stream_t *stream = request->stream;
    xhttp_request_kind_t kind = XHTTP_REQUEST_DOWNLOAD;
    int chunked = 0;
    const char *session_id = stream->session_id;
    const char *sequence = NULL;
    char sequence_text[32];
    if (request->role == XHTTP_H1_LONG_UPLOAD) {
        kind = XHTTP_REQUEST_STREAM_UPLOAD;
        chunked = 1;
    } else if (request->role == XHTTP_H1_STREAM_ONE) {
        kind = XHTTP_REQUEST_STREAM_ONE;
        session_id = "";
        chunked = 1;
    } else if (request->role == XHTTP_H1_PACKET_UPLOAD) {
        kind = XHTTP_REQUEST_PACKET_UPLOAD;
        const int written = snprintf(sequence_text, sizeof(sequence_text),
                                     "%" PRIu64, request->sequence);
        if (written < 0 || (size_t)written >= sizeof(sequence_text)) {
            return APROXY_ERR_FRAME_TOO_LARGE;
        }
        sequence = sequence_text;
    }
    aproxy_buffer_t *wire = &request->wire;
    aproxy_buffer_clear(wire);
    int rc = append_h1_headers(&stream->client->config, kind, session_id,
                               sequence, request->payload,
                               request->payload_len, chunked,
                               request->role == XHTTP_H1_PACKET_UPLOAD,
                               wire);
    if (rc == APROXY_OK) {
        rc = request_write(request, wire->data, wire->len);
    }
    if (rc != APROXY_OK) {
        return rc;
    }
    if (request->requests_left > 0) {
        request->requests_left--;
    }
    request_release_payload(request);
    request->ready = 1;
    if (request->role == XHTTP_H1_LONG_UPLOAD ||
        request->role == XHTTP_H1_STREAM_ONE) {
        rc = h1_flush_upload(stream);
    }
    stream_maybe_open(stream);
    return rc;
}

static int parser_headers_complete(llhttp_t *parser)
{
    xhttp_h1_request_t *request = (xhttp_h1_request_t *)parser->data;
    request->response_status = llhttp_get_status_code(parser);
    return request->response_status == 200 ? 0 : -1;
}

static int parser_body(llhttp_t *parser, const char *data, size_t len)
{
    xhttp_h1_request_t *request = (xhttp_h1_request_t *)parser->data;
    if (request->role == XHTTP_H1_DOWNLOAD ||
        request->role == XHTTP_H1_STREAM_ONE) {
        stream_dispatch_data(request->stream, (const uint8_t *)data, len);
    }
    return 0;
}

static int parser_message_complete(llhttp_t *parser)
{
    xhttp_h1_request_t *request = (xhttp_h1_request_t *)parser->data;
    request->message_complete = 1;
    request->response_keep_alive = llhttp_should_keep_alive(parser);
    return 0;
}

static void request_parser_init(xhttp_h1_request_t *request)
{
    llhttp_settings_init(&request->settings);
    request->settings.on_headers_complete = parser_headers_complete;
    request->settings.on_body = parser_body;
    request->settings.on_message_complete = parser_message_complete;
    llhttp_init(&request->parser, HTTP_RESPONSE, &request->settings);
    request->parser.data = request;
}

static int request_packet_reusable(xhttp_h1_request_t *request)
{
    xhttp_h1_client_t *client = request->client;
    if (request->role != XHTTP_H1_PACKET_UPLOAD || request->closing ||
        request->stream == NULL || request->stream->closing ||
        client->closing || request->response_status != 200 ||
        !request->message_complete || !request->response_keep_alive ||
        request->requests_left == 0 ||
        (request->expires_at_ms > 0u &&
         now_ms() >= request->expires_at_ms) ||
        client->idle_packet_count >=
            (size_t)client->config.max_buffered_posts) {
        return 0;
    }
    return request->tls != NULL || request->raw != NULL;
}

static void request_destroy(xhttp_h1_request_t *request)
{
    xhttp_h1_client_t *client = request->client;
    idle_packet_remove(request);
    request_release_payload(request);
    aproxy_buffer_free(&request->wire);
    free(request);
    if (client->request_count > 0u) {
        client->request_count--;
    }
    h1_client_maybe_destroy(client);
}

static void packet_response_complete(xhttp_h1_request_t *request)
{
    xhttp_h1_stream_t *stream = request->stream;
    if (!request_packet_reusable(request)) {
        h1_request_close(request);
        return;
    }
    if (stream->pending_posts > 0u) {
        stream->pending_posts--;
    }
    request_list_remove(request);
    request_release_payload(request);
    request->stream = NULL;
    request->ready = 1;
    idle_packet_add(request);
    if (!stream->closing && aproxy_ring_size(&stream->upload) > 0u) {
        schedule_packet_flush(stream, 0u);
    }
    h1_stream_maybe_destroy(stream);
}

static void request_handle_data(xhttp_h1_request_t *request,
                                const uint8_t *data,
                                size_t len)
{
    if (request == NULL || request->closing) {
        return;
    }
    const llhttp_errno_t rc =
        llhttp_execute(&request->parser, (const char *)data, len);
    if (rc != HPE_OK) {
        request->failure_status = APROXY_ERR_INVALID_FRAME;
        h1_stream_close_with(request->stream, APROXY_ERR_INVALID_FRAME);
        return;
    }
    if (request->message_complete) {
        if (request->role == XHTTP_H1_PACKET_UPLOAD) {
            packet_response_complete(request);
        } else {
            if (!request->stream->closing) {
                h1_stream_close_with(request->stream, APROXY_OK);
            }
            h1_request_close(request);
        }
    }
}

static void request_carrier_closed(xhttp_h1_request_t *request, int status)
{
    if (!request->closing) {
        const llhttp_errno_t finish = llhttp_finish(&request->parser);
        if (finish != HPE_OK) {
            status = APROXY_ERR_INVALID_FRAME;
        }
    }
    if (request->failure_status != 0) {
        status = request->failure_status;
    }
    if (request->stream == NULL) {
        request_destroy(request);
        return;
    }
    xhttp_h1_stream_t *stream = request->stream;
    const int packet_complete =
        request->role == XHTTP_H1_PACKET_UPLOAD &&
        request->message_complete && request->response_status == 200;
    const int stream_complete =
        request->role != XHTTP_H1_PACKET_UPLOAD &&
        request->message_complete && request->response_status == 200;
    const int upload_accepted =
        request->role == XHTTP_H1_LONG_UPLOAD &&
        (request->response_status == 200 ||
         (stream->open_reported &&
          aproxy_ring_size(&stream->upload) == 0u));
    if (stream->download_request == request) {
        stream->download_request = NULL;
    }
    if (stream->upload_request == request) {
        stream->upload_request = NULL;
        if (request->role == XHTTP_H1_LONG_UPLOAD) {
            stream->upload_closed = 1;
        }
    }
    if (request->role == XHTTP_H1_PACKET_UPLOAD &&
        stream->pending_posts > 0u) {
        stream->pending_posts--;
    }
    request_list_remove(request);
    request_release_payload(request);
    request_destroy(request);
    if (!stream->closing && !packet_complete && !upload_accepted) {
        h1_stream_close_with(stream,
                             stream_complete ? APROXY_OK
                                             : (status == APROXY_OK
                                                    ? APROXY_ERR_INVALID_FRAME
                                                    : status));
    } else if (!stream->closing && packet_complete &&
               aproxy_ring_size(&stream->upload) > 0u) {
        schedule_packet_flush(stream, 0u);
    }
    h1_stream_maybe_destroy(stream);
}

static void tls_ready_cb(anytls_tls_client_t *tls,
                         int status,
                         void *user_data)
{
    xhttp_h1_request_t *request = (xhttp_h1_request_t *)user_data;
    if (request == NULL || request->closing) {
        return;
    }
    if (status == APROXY_OK &&
        !anytls_tls_client_alpn_is(tls, "http/1.1")) {
        status = APROXY_ERR_UNSUPPORTED;
    }
    if (status == APROXY_OK) {
        status = request_send_headers(request);
    }
    if (status != APROXY_OK) {
        request->failure_status = status;
        h1_stream_close_with(request->stream, status);
    }
}

static void tls_data_cb(anytls_tls_client_t *tls,
                        const uint8_t *data,
                        size_t len,
                        void *user_data)
{
    (void)tls;
    xhttp_h1_request_t *request = (xhttp_h1_request_t *)user_data;
    request_handle_data(request, data, len);
}

static void tls_close_cb(anytls_tls_client_t *tls,
                         int status,
                         void *user_data)
{
    xhttp_h1_request_t *request = (xhttp_h1_request_t *)user_data;
    if (request == NULL) {
        return;
    }
    if (request->tls == tls) {
        request->tls = NULL;
        anytls_tls_client_free(tls);
    }
    request_carrier_closed(request, status);
}

static void raw_open_cb(aproxy_stream_t *raw,
                        int status,
                        void *user_data)
{
    (void)raw;
    xhttp_h1_request_t *request = (xhttp_h1_request_t *)user_data;
    if (request == NULL || request->closing) {
        return;
    }
    if (status == APROXY_OK) {
        status = request_send_headers(request);
    }
    if (status != APROXY_OK) {
        request->failure_status = status;
        h1_stream_close_with(request->stream, status);
    }
}

static void raw_data_cb(aproxy_stream_t *raw,
                        const uint8_t *data,
                        size_t len,
                        void *user_data)
{
    (void)raw;
    request_handle_data((xhttp_h1_request_t *)user_data, data, len);
}

static void raw_close_cb(aproxy_stream_t *raw,
                         int status,
                         void *user_data)
{
    xhttp_h1_request_t *request = (xhttp_h1_request_t *)user_data;
    if (request == NULL) {
        return;
    }
    if (request->raw == raw) {
        request->raw = NULL;
        aproxy_stream_free(raw);
    }
    request_carrier_closed(request, status);
}

static void h1_request_close(xhttp_h1_request_t *request)
{
    if (request == NULL || request->closing) {
        return;
    }
    if ((request->role == XHTTP_H1_LONG_UPLOAD ||
         request->role == XHTTP_H1_STREAM_ONE) &&
        request->ready) {
        static const uint8_t end_chunk[] = "0\r\n\r\n";
        (void)request_write(request, end_chunk, sizeof(end_chunk) - 1u);
    }
    request->closing = 1;
    if (request->tls != NULL) {
        anytls_tls_client_close(request->tls);
    } else if (request->raw != NULL) {
        (void)aproxy_stream_close(request->raw);
    } else {
        request_carrier_closed(request, APROXY_OK);
    }
}

static int request_start(xhttp_h1_stream_t *stream,
                         xhttp_h1_role_t role,
                         uint8_t *payload,
                         size_t payload_len,
                         size_t payload_capacity,
                         xhttp_h1_request_t **out)
{
    xhttp_h1_client_t *client = stream->client;
    xhttp_h1_request_t *request = NULL;
    int reused = 0;
    if (role == XHTTP_H1_PACKET_UPLOAD) {
        while (client->idle_packets != NULL) {
            request = client->idle_packets;
            idle_packet_remove(request);
            if (request->requests_left != 0 &&
                (request->expires_at_ms == 0u ||
                 now_ms() < request->expires_at_ms)) {
                reused = 1;
                break;
            }
            h1_request_close(request);
            request = NULL;
        }
    }
    if (request == NULL) {
        request = (xhttp_h1_request_t *)calloc(1u, sizeof(*request));
        if (request == NULL) {
            return APROXY_ERR_NO_MEMORY;
        }
        request->client = client;
        request->requests_left = INT32_MAX;
        aproxy_buffer_init(&request->wire);
        client->request_count++;
        int32_t budget = 0;
        int rc = aproxy_xhttp_range_random(
            client->config.xmux.h_max_request_times, &budget);
        if (rc == APROXY_OK && budget > 0) {
            request->requests_left = budget;
        }
        if (rc == APROXY_OK) {
            rc = aproxy_xhttp_range_random(
                client->config.xmux.h_max_reusable_secs, &budget);
        }
        if (rc != APROXY_OK) {
            request_destroy(request);
            return rc;
        }
        if (budget > 0) {
            request->expires_at_ms =
                now_ms() + (uint64_t)budget * UINT64_C(1000);
        }
    }
    request->stream = stream;
    request->role = role;
    request->payload = payload;
    request->payload_len = payload_len;
    request->payload_capacity = payload_capacity;
    request->response_status = 0;
    request->ready = 0;
    request->message_complete = 0;
    request->response_keep_alive = 0;
    request->closing = 0;
    request->failure_status = 0;
    if (role == XHTTP_H1_PACKET_UPLOAD) {
        request->sequence = stream->sequence++;
    }
    request_parser_init(request);
    request_list_add(stream, request);
    *out = request;

    int rc = APROXY_OK;
    if (reused) {
        rc = request_send_headers(request);
        if (rc != APROXY_OK) {
            request->failure_status = rc;
            h1_request_close(request);
        }
        return rc;
    }
    if (stream->client->config.tls_enabled) {
        const anytls_tls_client_config_t tls_config = {
            .loop = stream->client->config.loop,
            .host = stream->client->config.server_host,
            .port = stream->client->config.server_port,
            .sni = stream->client->config.sni != NULL
                       ? stream->client->config.sni
                       : stream->client->config.host,
            .resolver = stream->client->config.resolver,
            .context = stream->client->tls_context,
            .alpn = "http/1.1",
            .ech = stream->client->config.ech,
            .socket_protector = stream->client->config.socket_protector,
            .insecure_skip_verify =
                stream->client->config.insecure_skip_verify,
            .reality = stream->client->config.reality,
            .on_ready = tls_ready_cb,
            .on_data = tls_data_cb,
            .on_close = tls_close_cb,
            .user_data = request,
        };
        rc = anytls_tls_client_new(&tls_config, &request->tls);
        if (rc == APROXY_OK) {
            rc = anytls_tls_client_connect(request->tls);
        }
    } else {
        rc = aproxy_outbound_open_stream(
            stream->client->direct, &stream->client->server, raw_data_cb,
            raw_open_cb, raw_close_cb, request, &request->raw);
    }
    if (rc != APROXY_OK) {
        request->failure_status = rc;
        h1_request_close(request);
    }
    return rc;
}

static void packet_timer_cb(uv_timer_t *timer);

static void schedule_packet_flush(xhttp_h1_stream_t *stream, uint64_t delay)
{
    if (stream->timer_initialized && !stream->timer_closing &&
        !stream->closing) {
        uv_timer_start(&stream->post_timer, packet_timer_cb, delay, 0u);
    }
}

static int flush_packet(xhttp_h1_stream_t *stream)
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
    xhttp_h1_request_t *request = NULL;
    rc = request_start(stream, XHTTP_H1_PACKET_UPLOAD, payload, payload_len,
                       capacity, &request);
    if (rc != APROXY_OK) {
        return rc;
    }
    (void)request;
    aproxy_ring_consume(&stream->upload, payload_len);
    stream->pending_posts++;
    stream->last_post_ms = now_ms();
    if (aproxy_ring_size(&stream->upload) > 0u) {
        schedule_packet_flush(stream,
                              interval > 0 ? (uint64_t)interval : 0u);
    }
    return APROXY_OK;
}

static void packet_timer_cb(uv_timer_t *timer)
{
    xhttp_h1_stream_t *stream = (xhttp_h1_stream_t *)timer->data;
    if (stream != NULL && !stream->closing &&
        flush_packet(stream) != APROXY_OK) {
        h1_stream_close_with(stream, APROXY_ERR_INVALID_FRAME);
    }
}

static int h1_flush_upload(xhttp_h1_stream_t *stream)
{
    if (stream->mode == APROXY_XHTTP_MODE_PACKET_UP) {
        schedule_packet_flush(stream, 0u);
        return APROXY_OK;
    }
    xhttp_h1_request_t *request = stream->upload_request;
    if (request == NULL || !request->ready || request->closing) {
        return APROXY_OK;
    }
    while (aproxy_ring_size(&stream->upload) > 0u) {
        aproxy_const_span_t spans[2];
        const size_t count =
            aproxy_ring_read_spans(&stream->upload, spans);
        if (count == 0u || spans[0].len == 0u) {
            return APROXY_ERR_INVALID_FRAME;
        }
        int rc = request_write_chunk(request, spans[0].data, spans[0].len);
        if (rc != APROXY_OK) {
            return rc;
        }
        aproxy_ring_consume(&stream->upload, spans[0].len);
    }
    return APROXY_OK;
}

static void h1_stream_close_with(xhttp_h1_stream_t *stream, int status)
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
    for (xhttp_h1_request_t *request = stream->requests; request != NULL;) {
        xhttp_h1_request_t *next = request->next;
        h1_request_close(request);
        request = next;
    }
    h1_stream_maybe_destroy(stream);
}

static int h1_stream_write_impl(void *impl,
                                const uint8_t *data,
                                size_t len)
{
    xhttp_h1_stream_t *stream = (xhttp_h1_stream_t *)impl;
    if (stream == NULL || (data == NULL && len > 0u) || stream->closing) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    if (stream->mode == APROXY_XHTTP_MODE_STREAM_UP &&
        stream->upload_closed) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    const size_t buffered = aproxy_ring_size(&stream->upload);
    if (len > (size_t)stream->client->config.max_buffered_bytes ||
        buffered >
            (size_t)stream->client->config.max_buffered_bytes - len) {
        return APROXY_ERR_FRAME_TOO_LARGE;
    }
    if (len == 0u) {
        return APROXY_OK;
    }
    if (stream->mode != APROXY_XHTTP_MODE_PACKET_UP && buffered == 0u &&
        stream->upload_request != NULL && stream->upload_request->ready &&
        !stream->upload_request->closing) {
        return request_write_chunk(stream->upload_request, data, len);
    }
    int rc = aproxy_ring_write(&stream->upload, data, len);
    if (rc == APROXY_OK) {
        rc = h1_flush_upload(stream);
    }
    return rc;
}

static int h1_stream_close_impl(void *impl)
{
    xhttp_h1_stream_t *stream = (xhttp_h1_stream_t *)impl;
    if (stream == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    h1_stream_close_with(stream, APROXY_OK);
    return APROXY_OK;
}

static uint32_t h1_stream_id_impl(const void *impl)
{
    const xhttp_h1_stream_t *stream = (const xhttp_h1_stream_t *)impl;
    return stream == NULL ? 0u : stream->id;
}

static void *h1_stream_native_impl(const void *impl)
{
    const xhttp_h1_stream_t *stream = (const xhttp_h1_stream_t *)impl;
    return stream == NULL ? NULL : (void *)stream->download_request;
}

static void h1_stream_free_impl(void *impl)
{
    xhttp_h1_stream_t *stream = (xhttp_h1_stream_t *)impl;
    if (stream == NULL) {
        return;
    }
    stream->owner = NULL;
    stream->on_data = NULL;
    stream->on_open = NULL;
    stream->on_close = NULL;
    stream->user_data = NULL;
    stream->free_pending = 1;
    h1_stream_close_with(stream, APROXY_OK);
    h1_stream_maybe_destroy(stream);
}

static const aproxy_stream_vtable_t h1_stream_vtable = {
    .write = h1_stream_write_impl,
    .close = h1_stream_close_impl,
    .id = h1_stream_id_impl,
    .native = h1_stream_native_impl,
    .free = h1_stream_free_impl,
};

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

static int copy_config(xhttp_h1_client_t *client,
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

static void free_config(xhttp_h1_client_t *client)
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

static void h1_client_destroy(xhttp_h1_client_t *client)
{
    aproxy_outbound_free(client->direct);
    aproxy_bufpool_destroy(&client->packet_pool);
    aproxy_tls_context_free(client->tls_context);
    free_config(client);
    free(client);
}

static void h1_client_maybe_destroy(xhttp_h1_client_t *client)
{
    if (client != NULL && client->free_pending && client->streams == NULL &&
        client->request_count == 0u) {
        h1_client_destroy(client);
    }
}

int xhttp_h1_client_new(const aproxy_xhttp_config_t *config,
                        xhttp_h1_client_t **out)
{
    if (config == NULL || out == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    *out = NULL;
    xhttp_h1_client_t *client =
        (xhttp_h1_client_t *)calloc(1u, sizeof(*client));
    if (client == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    aproxy_bufpool_init(&client->packet_pool, XHTTP_H1_PACKET_POOL_CHUNK,
                        XHTTP_H1_PACKET_POOL_MAX_FREE);
    int rc = copy_config(client, config);
    if (rc == APROXY_OK && config->tls_enabled) {
        rc = aproxy_tls_context_new(config->insecure_skip_verify,
                                    &client->tls_context);
    }
    if (rc == APROXY_OK && !config->tls_enabled) {
        aproxy_direct_outbound_config_t direct_config = {
            .loop = config->loop,
            .tag = "xhttp-h1",
            .resolver = config->resolver,
            .max_pending_bytes = (size_t)config->max_buffered_bytes,
            .socket_protector = config->socket_protector,
        };
        rc = aproxy_direct_outbound_new(&direct_config, &client->direct);
        if (rc == APROXY_OK) {
            rc = aproxy_outbound_connect(client->direct);
        }
        if (rc == APROXY_OK) {
            char *end = NULL;
            const unsigned long parsed =
                strtoul(config->server_port, &end, 10);
            if (end == config->server_port || *end != '\0' || parsed == 0u ||
                parsed > UINT16_MAX) {
                rc = APROXY_ERR_PARSE;
            } else {
                rc = aproxy_addr_set_fqdn(&client->server,
                                          config->server_host,
                                          (uint16_t)parsed);
            }
        }
    }
    if (rc != APROXY_OK) {
        h1_client_destroy(client);
        return rc;
    }
    *out = client;
    return APROXY_OK;
}

int xhttp_h1_client_open_stream(xhttp_h1_client_t *client,
                                aproxy_stream_data_cb on_data,
                                aproxy_stream_event_cb on_open,
                                aproxy_stream_event_cb on_close,
                                void *user_data,
                                aproxy_stream_t **out)
{
    if (client == NULL || out == NULL || client->closing) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    *out = NULL;
    xhttp_h1_stream_t *stream =
        (xhttp_h1_stream_t *)calloc(1u, sizeof(*stream));
    if (stream == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    stream->client = client;
    stream->on_data = on_data;
    stream->on_open = on_open;
    stream->on_close = on_close;
    stream->user_data = user_data;
    stream->id = ++client->next_stream_id;
    stream->mode = client->config.mode == APROXY_XHTTP_MODE_AUTO
                       ? APROXY_XHTTP_MODE_PACKET_UP
                       : client->config.mode;
    aproxy_ring_init(&stream->upload);
    aproxy_buffer_init(&stream->chunk_wire);
    int rc = generate_session_id(&client->config, &stream->session_id);
    if (rc != APROXY_OK) {
        aproxy_ring_free(&stream->upload);
        aproxy_buffer_free(&stream->chunk_wire);
        free(stream);
        return rc;
    }
    if (stream->mode == APROXY_XHTTP_MODE_PACKET_UP) {
        rc = uv_timer_init(client->config.loop, &stream->post_timer);
        if (rc != 0) {
            aproxy_ring_free(&stream->upload);
            aproxy_buffer_free(&stream->chunk_wire);
            free(stream->session_id);
            free(stream);
            return rc;
        }
        stream->timer_initialized = 1;
        stream->post_timer.data = stream;
    } else {
        stream->timer_closed = 1;
    }
    rc = aproxy_stream_new(&h1_stream_vtable, stream, &stream->owner);
    if (rc != APROXY_OK) {
        stream->free_pending = 1;
        stream_close_timer(stream);
        h1_stream_maybe_destroy(stream);
        return rc;
    }
    stream_list_add(stream);
    *out = stream->owner;
    if (stream->mode == APROXY_XHTTP_MODE_STREAM_ONE) {
        rc = request_start(stream, XHTTP_H1_STREAM_ONE, NULL, 0u, 0u,
                           &stream->download_request);
        stream->upload_request = stream->download_request;
    } else {
        rc = request_start(stream, XHTTP_H1_DOWNLOAD, NULL, 0u, 0u,
                           &stream->download_request);
        if (rc == APROXY_OK &&
            stream->mode == APROXY_XHTTP_MODE_STREAM_UP) {
            rc = request_start(stream, XHTTP_H1_LONG_UPLOAD, NULL, 0u, 0u,
                               &stream->upload_request);
        }
    }
    if (rc != APROXY_OK && !stream->closing) {
        h1_stream_close_with(stream, rc);
    }
    return APROXY_OK;
}

void xhttp_h1_client_close(xhttp_h1_client_t *client)
{
    if (client == NULL || client->closing) {
        return;
    }
    client->closing = 1;
    for (xhttp_h1_stream_t *stream = client->streams; stream != NULL;) {
        xhttp_h1_stream_t *next = stream->next;
        h1_stream_close_with(stream, APROXY_OK);
        stream = next;
    }
    while (client->idle_packets != NULL) {
        xhttp_h1_request_t *request = client->idle_packets;
        idle_packet_remove(request);
        h1_request_close(request);
    }
    aproxy_outbound_close(client->direct);
}

void xhttp_h1_client_free(xhttp_h1_client_t *client)
{
    if (client == NULL) {
        return;
    }
    client->free_pending = 1;
    xhttp_h1_client_close(client);
    h1_client_maybe_destroy(client);
}
