#include "vless/outbound.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "aproxy/buffer.h"
#include "aproxy/bufpool.h"
#include "aproxy/direct_outbound.h"
#include "aproxy/limits.h"
#include "aproxy/ring.h"
#include "aproxy/xudp.h"
#include "framework/packet_flow_internal.h"
#include "framework/stream_internal.h"
#include "platform.h"
#include "tls_uv.h"
#include "vless/encryption.h"
#include "vless/protocol.h"
#include "vless/vision.h"

#define VLESS_PACKET_POOL_CHUNK 9216u
#define VLESS_PACKET_POOL_MAX_FREE 64u

typedef struct vless_outbound_impl vless_outbound_impl_t;
typedef struct vless_stream_impl vless_stream_impl_t;
typedef struct vless_packet_impl vless_packet_impl_t;

struct vless_outbound_impl {
    uv_loop_t *loop;
    char *tag;
    char *server_host;
    char *server_port;
    char *sni;
    char *alpn;
    aproxy_ech_config_t ech;
    aproxy_addr_t server;
    uint8_t uuid[VLESS_UUID_LEN];
    char flow[VLESS_MAX_FLOW_LEN + 1u];
    int tls_enabled;
    int insecure_skip_verify;
    aproxy_reality_config_t reality;
    aproxy_dns_resolver_t *resolver;
    aproxy_socket_protector_t socket_protector;
    aproxy_tls_context_t *tls_context;
    size_t max_pending_bytes;
    int closing;
    uint32_t next_stream_id;
    uint32_t next_packet_id;
    aproxy_outbound_t *direct;
    aproxy_xhttp_client_t *xhttp;
    vless_encryption_client_config_t *encryption_config;
    aproxy_bufpool_t packet_pool;
    vless_stream_impl_t *streams;
    vless_packet_impl_t *packets;
    unsigned int lifecycle_depth;
    int free_pending;
};

struct vless_stream_impl {
    vless_outbound_impl_t *outbound;
    aproxy_stream_t *owner;
    aproxy_stream_t *raw_stream;
    anytls_tls_client_t *tls;
    vless_encryption_client_t *encryption;
    vless_vision_t *vision;
    aproxy_addr_t destination;
    aproxy_stream_data_cb on_data;
    aproxy_stream_event_cb on_open;
    aproxy_stream_event_cb on_close;
    void *user_data;
    aproxy_ring_t pending_plain;
    aproxy_ring_t response_rx;
    aproxy_buffer_t tx_scratch;
    aproxy_buffer_t wire_scratch;
    aproxy_buffer_t decrypted_scratch;
    aproxy_buffer_t vision_scratch;
    uint32_t id;
    uint8_t command;
    int raw_open;
    int request_sent;
    int response_read;
    int direct_write;
    int direct_read;
    int closing;
    int close_reported;
    unsigned int callback_depth;
    int free_pending;
    int internal_packet_stream;
    vless_stream_impl_t *prev;
    vless_stream_impl_t *next;
};

struct vless_packet_impl {
    vless_outbound_impl_t *outbound;
    aproxy_packet_flow_t *owner;
    aproxy_stream_t *stream;
    aproxy_xudp_encoder_t encoder;
    aproxy_xudp_decoder_t decoder;
    aproxy_packet_flow_data_cb on_data;
    aproxy_packet_flow_event_cb on_open;
    aproxy_packet_flow_event_cb on_close;
    void *user_data;
    uint32_t id;
    int closing;
    int close_reported;
    unsigned int callback_depth;
    int free_pending;
    vless_packet_impl_t *prev;
    vless_packet_impl_t *next;
};

static void vless_stream_free(void *impl);
static void vless_packet_free(void *impl);
static void outbound_maybe_destroy(vless_outbound_impl_t *outbound);

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

static int parse_port(const char *text, uint16_t *out)
{
    if (text == NULL || out == NULL || text[0] == '\0') {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    errno = 0;
    char *end = NULL;
    const unsigned long value = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value == 0ul ||
        value > UINT16_MAX) {
        return APROXY_ERR_PARSE;
    }
    *out = (uint16_t)value;
    return APROXY_OK;
}

static int parse_server_addr(const char *host,
                             const char *port_text,
                             aproxy_addr_t *out)
{
    uint16_t port = 0u;
    int rc = parse_port(port_text, &port);
    if (rc != APROXY_OK) {
        return rc;
    }
    uint8_t address[16];
    if (inet_pton(AF_INET, host, address) == 1) {
        aproxy_addr_set_ipv4(out, address, port);
        return APROXY_OK;
    }
    if (inet_pton(AF_INET6, host, address) == 1) {
        aproxy_addr_set_ipv6(out, address, port);
        return APROXY_OK;
    }
    return aproxy_addr_set_fqdn(out, host, port);
}

static void stream_list_add(vless_stream_impl_t *stream)
{
    stream->prev = NULL;
    stream->next = stream->outbound->streams;
    if (stream->next != NULL) {
        stream->next->prev = stream;
    }
    stream->outbound->streams = stream;
}

static void stream_list_remove(vless_stream_impl_t *stream)
{
    if (stream->prev != NULL) {
        stream->prev->next = stream->next;
    } else if (stream->outbound != NULL &&
               stream->outbound->streams == stream) {
        stream->outbound->streams = stream->next;
    }
    if (stream->next != NULL) {
        stream->next->prev = stream->prev;
    }
    stream->prev = NULL;
    stream->next = NULL;
}

static void packet_list_add(vless_packet_impl_t *packet)
{
    packet->prev = NULL;
    packet->next = packet->outbound->packets;
    if (packet->next != NULL) {
        packet->next->prev = packet;
    }
    packet->outbound->packets = packet;
}

static void packet_list_remove(vless_packet_impl_t *packet)
{
    if (packet->prev != NULL) {
        packet->prev->next = packet->next;
    } else if (packet->outbound != NULL &&
               packet->outbound->packets == packet) {
        packet->outbound->packets = packet->next;
    }
    if (packet->next != NULL) {
        packet->next->prev = packet->prev;
    }
    packet->prev = NULL;
    packet->next = NULL;
}

static void stream_destroy(vless_stream_impl_t *stream)
{
    if (stream == NULL) {
        return;
    }
    vless_outbound_impl_t *outbound = stream->outbound;
    stream_list_remove(stream);
    aproxy_ring_free(&stream->pending_plain);
    aproxy_ring_free(&stream->response_rx);
    aproxy_buffer_free(&stream->tx_scratch);
    aproxy_buffer_free(&stream->wire_scratch);
    aproxy_buffer_free(&stream->decrypted_scratch);
    aproxy_buffer_free(&stream->vision_scratch);
    vless_encryption_client_free(stream->encryption);
    vless_vision_free(stream->vision);
    free(stream);
    outbound_maybe_destroy(outbound);
}

static void stream_report_open(vless_stream_impl_t *stream, int status)
{
    if (stream == NULL || stream->on_open == NULL || stream->owner == NULL) {
        return;
    }
    stream->callback_depth++;
    stream->on_open(stream->owner, status, stream->user_data);
    stream->callback_depth--;
}

static void stream_report_close(vless_stream_impl_t *stream, int status)
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

static int stream_dispatch_data(vless_stream_impl_t *stream,
                                const uint8_t *data,
                                size_t len)
{
    if (stream->on_data == NULL || stream->owner == NULL || len == 0u) {
        return APROXY_OK;
    }
    stream->callback_depth++;
    stream->on_data(stream->owner, data, len, stream->user_data);
    stream->callback_depth--;
    return stream->free_pending ? APROXY_ERR_INVALID_ARGUMENT : APROXY_OK;
}

static int stream_raw_write(vless_stream_impl_t *stream,
                            const uint8_t *data,
                            size_t len)
{
    if (stream->tls != NULL) {
        return anytls_tls_client_write(stream->tls, data, len);
    }
    if (stream->raw_stream != NULL) {
        return aproxy_stream_write(stream->raw_stream, data, len);
    }
    return APROXY_ERR_INVALID_ARGUMENT;
}

static int stream_plain_write(vless_stream_impl_t *stream,
                              const uint8_t *data,
                              size_t len)
{
    if (stream->encryption == NULL) {
        return stream_raw_write(stream, data, len);
    }
    aproxy_buffer_clear(&stream->wire_scratch);
    int rc = vless_encryption_client_seal(
        stream->encryption, data, len, &stream->wire_scratch);
    if (rc == APROXY_OK && stream->wire_scratch.len > 0u) {
        rc = stream_raw_write(stream, stream->wire_scratch.data,
                              stream->wire_scratch.len);
    }
    return rc;
}

static int stream_direct_write(vless_stream_impl_t *stream,
                               const uint8_t *data,
                               size_t len)
{
    if (stream->encryption != NULL) {
        return stream_raw_write(stream, data, len);
    }
    if (stream->outbound->xhttp != NULL && stream->raw_stream != NULL) {
        return aproxy_stream_write(stream->raw_stream, data, len);
    }
    if (stream->tls == NULL) {
        return APROXY_ERR_UNSUPPORTED;
    }
    return anytls_tls_client_write_raw(stream->tls, data, len);
}

static void stream_start_close(vless_stream_impl_t *stream)
{
    if (stream == NULL || stream->closing) {
        return;
    }
    stream->closing = 1;
    if (stream->raw_stream != NULL) {
        (void)aproxy_stream_close(stream->raw_stream);
        return;
    }
    if (stream->tls != NULL) {
        anytls_tls_client_close(stream->tls);
        return;
    }
    stream_report_close(stream, APROXY_OK);
    if (stream->free_pending && stream->callback_depth == 0u) {
        stream_destroy(stream);
    }
}

static int stream_send_request(vless_stream_impl_t *stream)
{
    vless_request_t request;
    memset(&request, 0, sizeof(request));
    memcpy(request.uuid, stream->outbound->uuid, sizeof(request.uuid));
    request.command = stream->command;
    request.destination = stream->destination;
    memcpy(request.flow, stream->outbound->flow,
           strlen(stream->outbound->flow) + 1u);

    const size_t request_len = vless_request_encoded_len(&request);
    const size_t pending_len = aproxy_ring_size(&stream->pending_plain);
    if (request_len == 0u || pending_len > SIZE_MAX - request_len) {
        return APROXY_ERR_FRAME_TOO_LARGE;
    }
    const size_t total = request_len + pending_len;
    int rc = aproxy_buffer_reserve(&stream->tx_scratch,
                                   total == 0u ? 1u : total);
    if (rc != APROXY_OK) {
        return rc;
    }
    size_t encoded_len = 0u;
    rc = vless_request_encode(&request, stream->tx_scratch.data,
                              stream->tx_scratch.cap, &encoded_len);
    if (rc != APROXY_OK) {
        return rc;
    }
    aproxy_const_span_t spans[2];
    const size_t count = aproxy_ring_read_spans(&stream->pending_plain, spans);
    size_t pos = encoded_len;
    for (size_t i = 0u; i < count; i++) {
        memcpy(stream->tx_scratch.data + pos, spans[i].data, spans[i].len);
        pos += spans[i].len;
    }
    stream->tx_scratch.len = pos;
    if (stream->vision != NULL && pending_len > 0u) {
        aproxy_buffer_clear(&stream->vision_scratch);
        size_t consumed = 0u;
        int direct = 0;
        rc = vless_vision_encode(stream->vision,
                                 stream->tx_scratch.data + encoded_len,
                                 pending_len, &stream->vision_scratch,
                                 &consumed, &direct);
        if (rc != APROXY_OK || consumed != pending_len || direct) {
            return rc != APROXY_OK ? rc : APROXY_ERR_UNSUPPORTED;
        }
        if (encoded_len > SIZE_MAX - stream->vision_scratch.len) {
            return APROXY_ERR_FRAME_TOO_LARGE;
        }
        rc = aproxy_buffer_reserve(
            &stream->tx_scratch,
            encoded_len + stream->vision_scratch.len);
        if (rc != APROXY_OK) {
            return rc;
        }
        memcpy(stream->tx_scratch.data + encoded_len,
               stream->vision_scratch.data, stream->vision_scratch.len);
        stream->tx_scratch.len = encoded_len + stream->vision_scratch.len;
    }
    rc = stream_plain_write(stream, stream->tx_scratch.data,
                            stream->tx_scratch.len);
    if (rc != APROXY_OK) {
        return rc;
    }
    aproxy_ring_consume(&stream->pending_plain, pending_len);
    stream->request_sent = 1;
    return APROXY_OK;
}

static void stream_raw_ready(vless_stream_impl_t *stream, int status)
{
    if (stream == NULL || stream->closing) {
        return;
    }
    if (status == APROXY_OK) {
        stream->raw_open = 1;
        if (stream->encryption != NULL) {
            aproxy_buffer_clear(&stream->wire_scratch);
            status = vless_encryption_client_start(
                stream->encryption, &stream->wire_scratch);
            if (status == APROXY_OK && stream->wire_scratch.len > 0u) {
                status = stream_raw_write(stream, stream->wire_scratch.data,
                                          stream->wire_scratch.len);
            }
            if (status == APROXY_OK &&
                !vless_encryption_client_send_ready(stream->encryption)) {
                return;
            }
        }
        if (status == APROXY_OK) {
            status = stream_send_request(stream);
        }
    }
    stream_report_open(stream, status);
    if (status != APROXY_OK && !stream->free_pending) {
        stream_start_close(stream);
    }
}

static int stream_enable_direct_read(vless_stream_impl_t *stream)
{
    if (stream->direct_read) {
        return APROXY_OK;
    }
    stream->direct_read = 1;
    if (stream->encryption != NULL) {
        aproxy_buffer_clear(&stream->decrypted_scratch);
        int rc = vless_encryption_client_take_buffered(
            stream->encryption, &stream->decrypted_scratch);
        if (rc == APROXY_OK && stream->decrypted_scratch.len > 0u) {
            rc = stream_dispatch_data(stream, stream->decrypted_scratch.data,
                                      stream->decrypted_scratch.len);
        }
        return rc;
    }
    if (stream->outbound->xhttp != NULL) {
        return APROXY_OK;
    }
    if (stream->tls == NULL) {
        return APROXY_ERR_UNSUPPORTED;
    }
    return anytls_tls_client_enable_raw_read(stream->tls);
}

static int stream_process_response(vless_stream_impl_t *stream,
                                   const uint8_t *data,
                                   size_t len)
{
    if (stream->direct_read) {
        return stream_dispatch_data(stream, data, len);
    }
    if (stream->response_read) {
        if (stream->vision == NULL) {
            return stream_dispatch_data(stream, data, len);
        }
        aproxy_buffer_clear(&stream->vision_scratch);
        int direct = 0;
        int rc = vless_vision_decode(stream->vision, data, len,
                                     &stream->vision_scratch, &direct);
        if (rc != APROXY_OK) {
            return rc;
        }
        rc = stream_dispatch_data(stream, stream->vision_scratch.data,
                                  stream->vision_scratch.len);
        if (rc == APROXY_OK && direct) {
            rc = stream_enable_direct_read(stream);
        }
        return rc;
    }
    int rc = aproxy_ring_write(&stream->response_rx, data, len);
    if (rc != APROXY_OK) {
        return rc;
    }
    if (aproxy_ring_size(&stream->response_rx) < 2u) {
        return APROXY_OK;
    }
    uint8_t first[2];
    if (aproxy_ring_peek(&stream->response_rx, 0u, first, sizeof(first)) !=
        sizeof(first)) {
        return APROXY_ERR_INVALID_FRAME;
    }
    const size_t header_len = 2u + first[1];
    if (aproxy_ring_size(&stream->response_rx) < header_len) {
        return APROXY_OK;
    }
    uint8_t header[2u + UINT8_MAX];
    if (aproxy_ring_peek(&stream->response_rx, 0u, header, header_len) !=
        header_len) {
        return APROXY_ERR_INVALID_FRAME;
    }
    size_t consumed = 0u;
    rc = vless_response_header_decode(header, header_len, &consumed);
    if (rc != APROXY_OK) {
        return rc;
    }
    aproxy_ring_consume(&stream->response_rx, consumed);
    stream->response_read = 1;

    aproxy_const_span_t spans[2];
    const size_t count = aproxy_ring_read_spans(&stream->response_rx, spans);
    for (size_t i = 0u; i < count; i++) {
        if (stream->vision == NULL) {
            rc = stream_dispatch_data(stream, spans[i].data, spans[i].len);
        } else {
            aproxy_buffer_clear(&stream->vision_scratch);
            int direct = 0;
            rc = vless_vision_decode(stream->vision, spans[i].data,
                                     spans[i].len, &stream->vision_scratch,
                                     &direct);
            if (rc == APROXY_OK) {
                rc = stream_dispatch_data(stream,
                                          stream->vision_scratch.data,
                                          stream->vision_scratch.len);
            }
            if (rc == APROXY_OK && direct) {
                rc = stream_enable_direct_read(stream);
            }
        }
        if (rc != APROXY_OK) {
            return rc;
        }
    }
    aproxy_ring_clear(&stream->response_rx);
    return APROXY_OK;
}

static int stream_process_wire_data(vless_stream_impl_t *stream,
                                    const uint8_t *data,
                                    size_t len)
{
    if (stream->direct_read) {
        return stream_dispatch_data(stream, data, len);
    }
    if (stream->encryption == NULL) {
        return stream_process_response(stream, data, len);
    }
    const uint8_t *wire = data;
    size_t wire_len = len;
    for (;;) {
        aproxy_buffer_clear(&stream->decrypted_scratch);
        int became_ready = 0;
        int rc = vless_encryption_client_feed_once(
            stream->encryption, wire, wire_len, &stream->decrypted_scratch,
            &became_ready);
        if (rc != APROXY_OK) {
            return rc;
        }
        wire = NULL;
        wire_len = 0u;
        if (became_ready && !stream->request_sent) {
            rc = stream_send_request(stream);
            stream_report_open(stream, rc);
            if (rc != APROXY_OK) {
                return rc;
            }
        }
        if (stream->decrypted_scratch.len == 0u) {
            return APROXY_OK;
        }
        rc = stream_process_response(stream,
                                     stream->decrypted_scratch.data,
                                     stream->decrypted_scratch.len);
        if (rc != APROXY_OK || stream->direct_read) {
            return rc;
        }
    }
}

static void direct_data_cb(aproxy_stream_t *raw,
                           const uint8_t *data,
                           size_t len,
                           void *user_data)
{
    (void)raw;
    vless_stream_impl_t *stream = (vless_stream_impl_t *)user_data;
    if (stream != NULL && !stream->closing &&
        stream_process_wire_data(stream, data, len) != APROXY_OK &&
        !stream->free_pending) {
        stream_start_close(stream);
    }
}

static void direct_open_cb(aproxy_stream_t *raw,
                           int status,
                           void *user_data)
{
    (void)raw;
    stream_raw_ready((vless_stream_impl_t *)user_data, status);
}

static void direct_close_cb(aproxy_stream_t *raw,
                            int status,
                            void *user_data)
{
    vless_stream_impl_t *stream = (vless_stream_impl_t *)user_data;
    if (stream == NULL) {
        return;
    }
    if (stream->raw_stream == raw) {
        stream->raw_stream = NULL;
        aproxy_stream_free(raw);
    }
    stream_report_close(stream, status);
    if (stream->free_pending && stream->callback_depth == 0u) {
        stream_destroy(stream);
    }
}

static void tls_ready_cb(anytls_tls_client_t *tls,
                         int status,
                         void *user_data)
{
    (void)tls;
    stream_raw_ready((vless_stream_impl_t *)user_data, status);
}

static void tls_data_cb(anytls_tls_client_t *tls,
                        const uint8_t *data,
                        size_t len,
                        void *user_data)
{
    (void)tls;
    vless_stream_impl_t *stream = (vless_stream_impl_t *)user_data;
    if (stream != NULL && !stream->closing &&
        stream_process_wire_data(stream, data, len) != APROXY_OK &&
        !stream->free_pending) {
        stream_start_close(stream);
    }
}

static void tls_close_cb(anytls_tls_client_t *tls,
                         int status,
                         void *user_data)
{
    vless_stream_impl_t *stream = (vless_stream_impl_t *)user_data;
    if (stream == NULL) {
        return;
    }
    if (stream->tls == tls) {
        stream->tls = NULL;
        anytls_tls_client_free(tls);
    }
    stream_report_close(stream, status);
    if (stream->free_pending && stream->callback_depth == 0u) {
        stream_destroy(stream);
    }
}

static int vless_stream_write(void *impl,
                              const uint8_t *data,
                              size_t len)
{
    vless_stream_impl_t *stream = (vless_stream_impl_t *)impl;
    if (stream == NULL || (data == NULL && len > 0u) || stream->closing) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    if (!stream->request_sent) {
        if (aproxy_size_add_exceeds(
                aproxy_ring_size(&stream->pending_plain), len,
                stream->outbound->max_pending_bytes)) {
            return APROXY_ERR_FRAME_TOO_LARGE;
        }
        return aproxy_ring_write(&stream->pending_plain, data, len);
    }
    if (stream->direct_write) {
        return stream_direct_write(stream, data, len);
    }
    if (stream->vision != NULL) {
        aproxy_buffer_clear(&stream->vision_scratch);
        size_t consumed = 0u;
        int direct = 0;
        int rc = vless_vision_encode(stream->vision, data, len,
                                     &stream->vision_scratch, &consumed,
                                     &direct);
        if (rc != APROXY_OK) {
            return rc;
        }
        if (stream->vision_scratch.len > 0u) {
            rc = stream_plain_write(stream, stream->vision_scratch.data,
                                    stream->vision_scratch.len);
            if (rc != APROXY_OK) {
                return rc;
            }
        }
        if (direct) {
            if (stream->encryption == NULL && stream->tls == NULL) {
                return APROXY_ERR_UNSUPPORTED;
            }
            stream->direct_write = 1;
        }
        if (consumed < len) {
            return stream_direct_write(stream, data + consumed,
                                       len - consumed);
        }
        return APROXY_OK;
    }
    return stream_plain_write(stream, data, len);
}

static int vless_stream_close(void *impl)
{
    vless_stream_impl_t *stream = (vless_stream_impl_t *)impl;
    if (stream == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    stream_start_close(stream);
    return APROXY_OK;
}

static uint32_t vless_stream_id(const void *impl)
{
    const vless_stream_impl_t *stream = (const vless_stream_impl_t *)impl;
    return stream == NULL ? 0u : stream->id;
}

static void *vless_stream_native(const void *impl)
{
    const vless_stream_impl_t *stream = (const vless_stream_impl_t *)impl;
    if (stream == NULL) {
        return NULL;
    }
    return stream->tls != NULL ? (void *)stream->tls
                               : (void *)stream->raw_stream;
}

static void vless_stream_free(void *impl)
{
    vless_stream_impl_t *stream = (vless_stream_impl_t *)impl;
    if (stream == NULL) {
        return;
    }
    stream->owner = NULL;
    stream->on_data = NULL;
    stream->on_open = NULL;
    stream->on_close = NULL;
    stream->user_data = NULL;
    stream->free_pending = 1;
    if (stream->raw_stream != NULL || stream->tls != NULL) {
        stream_start_close(stream);
        return;
    }
    if (stream->callback_depth == 0u) {
        stream_destroy(stream);
    }
}

static const aproxy_stream_vtable_t vless_stream_vtable = {
    .write = vless_stream_write,
    .close = vless_stream_close,
    .id = vless_stream_id,
    .native = vless_stream_native,
    .free = vless_stream_free,
};

static int stream_open_transport(vless_stream_impl_t *stream)
{
    vless_outbound_impl_t *outbound = stream->outbound;
    if (outbound->xhttp != NULL) {
        return aproxy_xhttp_client_open_stream(
            outbound->xhttp, direct_data_cb, direct_open_cb,
            direct_close_cb, stream, &stream->raw_stream);
    }
    if (!outbound->tls_enabled) {
        return aproxy_outbound_open_stream(
            outbound->direct, &outbound->server, direct_data_cb,
            direct_open_cb, direct_close_cb, stream, &stream->raw_stream);
    }
    anytls_tls_client_config_t config = {
        .loop = outbound->loop,
        .host = outbound->server_host,
        .port = outbound->server_port,
        .sni = outbound->sni,
        .resolver = outbound->resolver,
        .context = outbound->tls_context,
        .alpn = outbound->alpn,
        .ech = outbound->ech,
        .max_pending_bytes = outbound->max_pending_bytes,
        .socket_protector = outbound->socket_protector,
        .insecure_skip_verify = outbound->insecure_skip_verify,
        .reality = outbound->reality,
        .on_ready = tls_ready_cb,
        .on_data = tls_data_cb,
        .on_close = tls_close_cb,
        .user_data = stream,
    };
    int rc = anytls_tls_client_new(&config, &stream->tls);
    if (rc == APROXY_OK) {
        rc = anytls_tls_client_connect(stream->tls);
    }
    if (rc != APROXY_OK && stream->tls != NULL) {
        anytls_tls_client_free(stream->tls);
        stream->tls = NULL;
    }
    return rc;
}

static int create_stream(vless_outbound_impl_t *outbound,
                         const aproxy_addr_t *destination,
                         uint8_t command,
                         aproxy_stream_data_cb on_data,
                         aproxy_stream_event_cb on_open,
                         aproxy_stream_event_cb on_close,
                         void *user_data,
                         aproxy_stream_t **out)
{
    *out = NULL;
    vless_stream_impl_t *stream =
        (vless_stream_impl_t *)calloc(1u, sizeof(*stream));
    if (stream == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    stream->outbound = outbound;
    stream->destination = *destination;
    stream->command = command;
    stream->on_data = on_data;
    stream->on_open = on_open;
    stream->on_close = on_close;
    stream->user_data = user_data;
    stream->id = ++outbound->next_stream_id;
    aproxy_ring_init(&stream->pending_plain);
    aproxy_ring_init(&stream->response_rx);
    aproxy_buffer_init(&stream->tx_scratch);
    aproxy_buffer_init(&stream->wire_scratch);
    aproxy_buffer_init(&stream->decrypted_scratch);
    aproxy_buffer_init(&stream->vision_scratch);

    int rc = APROXY_OK;
    if (outbound->encryption_config != NULL) {
        rc = vless_encryption_client_new(outbound->encryption_config,
                                         &stream->encryption);
        if (rc != APROXY_OK) {
            stream_destroy(stream);
            return rc;
        }
    }
    if (strcmp(outbound->flow, VLESS_VISION_FLOW) == 0) {
        rc = vless_vision_new(outbound->uuid,
                              outbound->tls_enabled ||
                                  outbound->encryption_config != NULL,
                              &stream->vision);
        if (rc != APROXY_OK) {
            stream_destroy(stream);
            return rc;
        }
    }

    rc = aproxy_stream_new(&vless_stream_vtable, stream, &stream->owner);
    if (rc != APROXY_OK) {
        stream_destroy(stream);
        return rc;
    }
    stream_list_add(stream);
    *out = stream->owner;
    rc = stream_open_transport(stream);
    if (rc != APROXY_OK) {
        aproxy_stream_free(*out);
        *out = NULL;
        return rc;
    }
    return APROXY_OK;
}

static int packet_decoder_cb(const aproxy_addr_t *source,
                             const uint8_t *payload,
                             size_t payload_len,
                             void *user_data)
{
    vless_packet_impl_t *packet = (vless_packet_impl_t *)user_data;
    if (packet == NULL || packet->on_data == NULL || packet->owner == NULL) {
        return APROXY_OK;
    }
    packet->callback_depth++;
    packet->on_data(packet->owner, source, payload, payload_len,
                    packet->user_data);
    packet->callback_depth--;
    return packet->free_pending ? APROXY_ERR_INVALID_ARGUMENT : APROXY_OK;
}

static void packet_stream_data_cb(aproxy_stream_t *stream,
                                  const uint8_t *data,
                                  size_t len,
                                  void *user_data)
{
    (void)stream;
    vless_packet_impl_t *packet = (vless_packet_impl_t *)user_data;
    if (packet != NULL && !packet->closing &&
        aproxy_xudp_decoder_feed(&packet->decoder, data, len,
                                 packet_decoder_cb, packet) != APROXY_OK &&
        !packet->free_pending) {
        packet->closing = 1;
        if (packet->stream != NULL) {
            (void)aproxy_stream_close(packet->stream);
        }
    }
}

static void packet_stream_open_cb(aproxy_stream_t *stream,
                                  int status,
                                  void *user_data)
{
    (void)stream;
    vless_packet_impl_t *packet = (vless_packet_impl_t *)user_data;
    if (packet == NULL || packet->on_open == NULL || packet->owner == NULL) {
        return;
    }
    packet->callback_depth++;
    packet->on_open(packet->owner, status, packet->user_data);
    packet->callback_depth--;
}

static void packet_destroy(vless_packet_impl_t *packet)
{
    if (packet == NULL) {
        return;
    }
    vless_outbound_impl_t *outbound = packet->outbound;
    packet_list_remove(packet);
    aproxy_xudp_decoder_free(&packet->decoder);
    free(packet);
    outbound_maybe_destroy(outbound);
}

static void packet_stream_close_cb(aproxy_stream_t *stream,
                                   int status,
                                   void *user_data)
{
    vless_packet_impl_t *packet = (vless_packet_impl_t *)user_data;
    if (packet == NULL) {
        return;
    }
    if (packet->stream == stream) {
        packet->stream = NULL;
        aproxy_stream_free(stream);
    }
    if (!packet->close_reported) {
        packet->close_reported = 1;
        if (packet->on_close != NULL && packet->owner != NULL) {
            packet->callback_depth++;
            packet->on_close(packet->owner, status, packet->user_data);
            packet->callback_depth--;
        }
    }
    if (packet->free_pending && packet->callback_depth == 0u) {
        packet_destroy(packet);
    }
}

static int vless_packet_send(void *impl,
                             const aproxy_addr_t *destination,
                             const uint8_t *data,
                             size_t len)
{
    vless_packet_impl_t *packet = (vless_packet_impl_t *)impl;
    if (packet == NULL || destination == NULL ||
        (data == NULL && len > 0u) || packet->closing ||
        packet->stream == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    const size_t need = aproxy_xudp_packet_encoded_len(destination, len);
    if (need == 0u) {
        return len > UINT16_MAX ? APROXY_ERR_FRAME_TOO_LARGE
                               : APROXY_ERR_UNSUPPORTED;
    }
    size_t capacity = 0u;
    uint8_t *encoded = aproxy_bufpool_acquire(
        &packet->outbound->packet_pool, need, &capacity);
    if (encoded == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    size_t encoded_len = 0u;
    int rc = aproxy_xudp_encode_packet(&packet->encoder, destination, data,
                                       len, encoded, capacity, &encoded_len);
    if (rc == APROXY_OK) {
        rc = aproxy_stream_write(packet->stream, encoded, encoded_len);
    }
    aproxy_bufpool_release(&packet->outbound->packet_pool, encoded, capacity);
    return rc;
}

static int vless_packet_close(void *impl)
{
    vless_packet_impl_t *packet = (vless_packet_impl_t *)impl;
    if (packet == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    if (packet->closing) {
        return APROXY_OK;
    }
    packet->closing = 1;
    if (packet->stream != NULL) {
        return aproxy_stream_close(packet->stream);
    }
    packet_stream_close_cb(NULL, APROXY_OK, packet);
    return APROXY_OK;
}

static uint32_t vless_packet_id(const void *impl)
{
    const vless_packet_impl_t *packet = (const vless_packet_impl_t *)impl;
    return packet == NULL ? 0u : packet->id;
}

static void *vless_packet_native(const void *impl)
{
    const vless_packet_impl_t *packet = (const vless_packet_impl_t *)impl;
    return packet == NULL ? NULL : packet->stream;
}

static void vless_packet_free(void *impl)
{
    vless_packet_impl_t *packet = (vless_packet_impl_t *)impl;
    if (packet == NULL) {
        return;
    }
    packet->owner = NULL;
    packet->on_data = NULL;
    packet->on_open = NULL;
    packet->on_close = NULL;
    packet->user_data = NULL;
    packet->free_pending = 1;
    if (packet->stream != NULL) {
        (void)vless_packet_close(packet);
        return;
    }
    if (packet->callback_depth == 0u) {
        packet_destroy(packet);
    }
}

static const aproxy_packet_flow_vtable_t vless_packet_vtable = {
    .send = vless_packet_send,
    .close = vless_packet_close,
    .id = vless_packet_id,
    .native = vless_packet_native,
    .free = vless_packet_free,
};

static int vless_connect(void *impl)
{
    vless_outbound_impl_t *outbound = (vless_outbound_impl_t *)impl;
    if (outbound == NULL || outbound->closing) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    return aproxy_outbound_connect(outbound->direct);
}

static int vless_open_stream(void *impl,
                             const aproxy_addr_t *destination,
                             aproxy_stream_data_cb on_data,
                             aproxy_stream_event_cb on_open,
                             aproxy_stream_event_cb on_close,
                             void *user_data,
                             aproxy_stream_t **out)
{
    vless_outbound_impl_t *outbound = (vless_outbound_impl_t *)impl;
    if (outbound == NULL || destination == NULL || out == NULL ||
        outbound->closing) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    return create_stream(outbound, destination, VLESS_COMMAND_TCP, on_data,
                         on_open, on_close, user_data, out);
}

static int vless_open_packet(void *impl,
                             const aproxy_addr_t *initial_destination,
                             aproxy_packet_flow_data_cb on_data,
                             aproxy_packet_flow_event_cb on_open,
                             aproxy_packet_flow_event_cb on_close,
                             void *user_data,
                             aproxy_packet_flow_t **out)
{
    vless_outbound_impl_t *outbound = (vless_outbound_impl_t *)impl;
    if (outbound == NULL || initial_destination == NULL || out == NULL ||
        outbound->closing) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    *out = NULL;
    vless_packet_impl_t *packet =
        (vless_packet_impl_t *)calloc(1u, sizeof(*packet));
    if (packet == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    packet->outbound = outbound;
    packet->on_data = on_data;
    packet->on_open = on_open;
    packet->on_close = on_close;
    packet->user_data = user_data;
    packet->id = ++outbound->next_packet_id;
    aproxy_xudp_encoder_init(&packet->encoder);
    aproxy_xudp_decoder_init(&packet->decoder, initial_destination);

    int rc = aproxy_packet_flow_new(&vless_packet_vtable, packet,
                                    &packet->owner);
    if (rc != APROXY_OK) {
        packet_destroy(packet);
        return rc;
    }
    packet_list_add(packet);
    *out = packet->owner;
    rc = create_stream(outbound, initial_destination, VLESS_COMMAND_MUX,
                       packet_stream_data_cb, packet_stream_open_cb,
                       packet_stream_close_cb, packet, &packet->stream);
    if (rc != APROXY_OK) {
        aproxy_packet_flow_free(*out);
        *out = NULL;
        return rc;
    }
    ((vless_stream_impl_t *)packet->stream->impl)->internal_packet_stream = 1;
    return APROXY_OK;
}

static void vless_close(void *impl)
{
    vless_outbound_impl_t *outbound = (vless_outbound_impl_t *)impl;
    if (outbound == NULL || outbound->closing) {
        return;
    }
    outbound->closing = 1;
    for (vless_packet_impl_t *packet = outbound->packets; packet != NULL;) {
        vless_packet_impl_t *next = packet->next;
        (void)vless_packet_close(packet);
        packet = next;
    }
    for (vless_stream_impl_t *stream = outbound->streams; stream != NULL;) {
        vless_stream_impl_t *next = stream->next;
        stream_start_close(stream);
        stream = next;
    }
    aproxy_outbound_close(outbound->direct);
    aproxy_xhttp_client_close(outbound->xhttp);
}

static void outbound_destroy(vless_outbound_impl_t *outbound)
{
    aproxy_outbound_free(outbound->direct);
    aproxy_xhttp_client_free(outbound->xhttp);
    aproxy_tls_context_free(outbound->tls_context);
    vless_encryption_client_config_free(outbound->encryption_config);
    aproxy_bufpool_destroy(&outbound->packet_pool);
    memset(outbound->uuid, 0, sizeof(outbound->uuid));
    free(outbound->tag);
    free(outbound->server_host);
    free(outbound->server_port);
    free(outbound->sni);
    free(outbound->alpn);
    free((uint8_t *)outbound->ech.config_list);
    free(outbound);
}

static void outbound_maybe_destroy(vless_outbound_impl_t *outbound)
{
    if (outbound != NULL && outbound->free_pending &&
        outbound->lifecycle_depth == 0u && outbound->streams == NULL &&
        outbound->packets == NULL) {
        outbound_destroy(outbound);
    }
}

static void vless_free(void *impl)
{
    vless_outbound_impl_t *outbound = (vless_outbound_impl_t *)impl;
    if (outbound == NULL || outbound->free_pending) {
        return;
    }
    outbound->free_pending = 1;
    outbound->lifecycle_depth++;
    vless_close(outbound);
    for (vless_packet_impl_t *packet = outbound->packets; packet != NULL;) {
        vless_packet_impl_t *next = packet->next;
        if (packet->owner != NULL) {
            aproxy_packet_flow_free(packet->owner);
        } else if (packet->stream == NULL) {
            packet_destroy(packet);
        }
        packet = next;
    }
    for (vless_stream_impl_t *stream = outbound->streams; stream != NULL;) {
        vless_stream_impl_t *next = stream->next;
        if (!stream->internal_packet_stream && stream->owner != NULL) {
            aproxy_stream_free(stream->owner);
        } else if (!stream->internal_packet_stream &&
                   stream->raw_stream == NULL && stream->tls == NULL) {
            stream_destroy(stream);
        }
        stream = next;
    }
    outbound->lifecycle_depth--;
    outbound_maybe_destroy(outbound);
}

static const aproxy_outbound_vtable_t vless_outbound_vtable = {
    .connect = vless_connect,
    .open_stream = vless_open_stream,
    .open_packet = vless_open_packet,
    .close = vless_close,
    .free = vless_free,
};

int vless_outbound_new(const vless_outbound_config_t *config,
                       aproxy_outbound_t **out)
{
    if (config == NULL || out == NULL || config->loop == NULL ||
        config->server_host == NULL || config->server_port == NULL ||
        config->uuid == NULL ||
        ((config->ech.config_list == NULL) !=
         (config->ech.config_list_len == 0u)) ||
        (config->reality.enabled &&
         (config->ech.config_list_len > 0u || config->ech.grease ||
          config->ech.required))) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    *out = NULL;
    const char *flow = config->flow == NULL ? "" : config->flow;
    const char *encryption =
        config->encryption == NULL ? "none" : config->encryption;
    if (flow[0] != '\0' && strcmp(flow, VLESS_VISION_FLOW) != 0) {
        return APROXY_ERR_UNSUPPORTED;
    }
    if (strcmp(flow, VLESS_VISION_FLOW) == 0 && !config->tls_enabled &&
        !config->reality.enabled &&
        strcmp(encryption, "none") == 0) {
        return APROXY_ERR_UNSUPPORTED;
    }

    vless_outbound_impl_t *impl =
        (vless_outbound_impl_t *)calloc(1u, sizeof(*impl));
    if (impl == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    impl->loop = config->loop;
    impl->tls_enabled = config->tls_enabled || config->reality.enabled;
    impl->insecure_skip_verify = config->insecure_skip_verify;
    impl->reality = config->reality;
    impl->resolver = config->resolver;
    impl->socket_protector = config->socket_protector;
    impl->max_pending_bytes =
        aproxy_stream_pending_limit(config->max_pending_bytes);
    aproxy_bufpool_init(&impl->packet_pool, VLESS_PACKET_POOL_CHUNK,
                        VLESS_PACKET_POOL_MAX_FREE);
    impl->tag = copy_string(config->tag != NULL ? config->tag : "vless");
    impl->server_host = copy_string(config->server_host);
    impl->server_port = copy_string(config->server_port);
    impl->sni = copy_string(config->sni != NULL ? config->sni
                                               : config->server_host);
    impl->alpn = copy_string(config->alpn);
    impl->ech = config->ech;
    impl->ech.config_list = NULL;
    if (config->ech.config_list_len > 0u) {
        uint8_t *ech_config =
            (uint8_t *)malloc(config->ech.config_list_len);
        if (ech_config == NULL) {
            vless_free(impl);
            return APROXY_ERR_NO_MEMORY;
        }
        memcpy(ech_config, config->ech.config_list,
               config->ech.config_list_len);
        impl->ech.config_list = ech_config;
    }
    if (impl->tag == NULL || impl->server_host == NULL ||
        impl->server_port == NULL || impl->sni == NULL ||
        (config->alpn != NULL && impl->alpn == NULL)) {
        vless_free(impl);
        return APROXY_ERR_NO_MEMORY;
    }
    int rc = parse_server_addr(config->server_host, config->server_port,
                               &impl->server);
    if (rc == APROXY_OK) {
        rc = vless_uuid_parse(config->uuid, impl->uuid);
    }
    if (rc == APROXY_OK && strcmp(encryption, "none") != 0) {
        rc = vless_encryption_client_config_parse(
            encryption, &impl->encryption_config);
    }
    if (rc == APROXY_OK) {
        memcpy(impl->flow, flow, strlen(flow) + 1u);
    }
    if (rc == APROXY_OK && impl->tls_enabled && config->xhttp == NULL) {
        rc = aproxy_tls_context_new(config->insecure_skip_verify,
                                    &impl->tls_context);
    }
    if (rc != APROXY_OK) {
        vless_free(impl);
        return rc;
    }

    aproxy_direct_outbound_config_t direct_config = {
        .loop = config->loop,
        .tag = "vless-transport",
        .resolver = config->resolver,
        .read_buffer_size = config->read_buffer_size,
        .max_pending_bytes = impl->max_pending_bytes,
        .socket_protector = config->socket_protector,
    };
    rc = aproxy_direct_outbound_new(&direct_config, &impl->direct);
    if (rc != APROXY_OK) {
        vless_free(impl);
        return rc;
    }
    if (config->xhttp != NULL) {
        aproxy_xhttp_config_t xhttp_config = *config->xhttp;
        xhttp_config.loop = config->loop;
        xhttp_config.server_host = config->server_host;
        xhttp_config.server_port = config->server_port;
        xhttp_config.sni = config->sni != NULL ? config->sni
                                               : config->server_host;
        xhttp_config.tls_enabled = impl->tls_enabled;
        xhttp_config.insecure_skip_verify =
            config->insecure_skip_verify;
        xhttp_config.reality = config->reality;
        xhttp_config.ech = impl->ech;
        xhttp_config.resolver = config->resolver;
        xhttp_config.socket_protector = config->socket_protector;
        rc = aproxy_xhttp_client_new(&xhttp_config, &impl->xhttp);
        if (rc != APROXY_OK) {
            vless_free(impl);
            return rc;
        }
    }

    aproxy_outbound_t *outbound =
        (aproxy_outbound_t *)calloc(1u, sizeof(*outbound));
    if (outbound == NULL) {
        vless_free(impl);
        return APROXY_ERR_NO_MEMORY;
    }
    outbound->tag = impl->tag;
    outbound->vtable = &vless_outbound_vtable;
    outbound->impl = impl;
    /* open_packet implements the VLESS XUDP packet flow. */
    outbound->udp_transport = APROXY_OUTBOUND_UDP_PACKET;
    *out = outbound;
    return APROXY_OK;
}
