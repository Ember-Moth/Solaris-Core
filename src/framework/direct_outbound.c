#include "aproxy/direct_outbound.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "aproxy/buffer.h"
#include "aproxy/bufpool.h"
#include "aproxy/limits.h"
#include "packet_flow_internal.h"
#include "framework/stream_internal.h"
#include "platform.h"

typedef struct direct_outbound_impl direct_outbound_impl_t;
typedef struct direct_stream_impl direct_stream_impl_t;
typedef struct direct_packet_impl direct_packet_impl_t;

typedef struct direct_write_req {
    uv_write_t req;
    uv_buf_t buf;
    direct_outbound_impl_t *outbound;
    uint8_t *data;
    size_t length;
    size_t capacity;
    struct direct_write_req *next_free;
} direct_write_req_t;

typedef struct direct_packet_send_req {
    uv_udp_send_t req;
    uv_buf_t buf;
    direct_outbound_impl_t *outbound;
    uint8_t *data;
    size_t capacity;
    struct direct_packet_send_req *next_free;
} direct_packet_send_req_t;

#define DIRECT_REQUEST_POOL_MAX_FREE 64u
#define DIRECT_UDP_DATAGRAM_BYTES (64u * 1024u)
#define DIRECT_UDP_RECV_BATCH_SIZE 2u
#define DIRECT_UDP_RECV_BATCH_BYTES \
    (DIRECT_UDP_DATAGRAM_BYTES * DIRECT_UDP_RECV_BATCH_SIZE)
#define DIRECT_UDP_READ_POOL_MAX_FREE 1u
#define DIRECT_UDP_SEND_BATCH_SIZE 16u
#define DIRECT_UDP_WRITE_POOL_MAX_FREE DIRECT_UDP_SEND_BATCH_SIZE

struct direct_outbound_impl {
    uv_loop_t *loop;
    char *tag;
    aproxy_dns_resolver_t *resolver;
    int owns_resolver;
    int closing;
    int free_after_streams;
    size_t read_buffer_size;
    size_t max_pending_bytes;
    aproxy_socket_protector_t socket_protector;
    aproxy_bufpool_t read_pool;
    aproxy_bufpool_t write_pool;
    aproxy_bufpool_t udp_read_pool;
    aproxy_bufpool_t udp_batch_pool;
    aproxy_bufpool_t udp_write_pool;
    direct_write_req_t *free_write_reqs;
    direct_packet_send_req_t *free_packet_reqs;
    size_t free_write_req_count;
    size_t free_packet_req_count;
    size_t udp_sends_pending;
    uint32_t next_stream_id;
    uint32_t next_packet_id;
    direct_stream_impl_t *streams;
    direct_packet_impl_t *packets;
};

static void direct_outbound_destroy(direct_outbound_impl_t *outbound)
{
    if (outbound == NULL) {
        return;
    }
    if (outbound->owns_resolver) {
        aproxy_dns_resolver_free(outbound->resolver);
    }
    aproxy_bufpool_destroy(&outbound->read_pool);
    aproxy_bufpool_destroy(&outbound->write_pool);
    aproxy_bufpool_destroy(&outbound->udp_read_pool);
    aproxy_bufpool_destroy(&outbound->udp_batch_pool);
    aproxy_bufpool_destroy(&outbound->udp_write_pool);
    while (outbound->free_write_reqs != NULL) {
        direct_write_req_t *next =
            outbound->free_write_reqs->next_free;
        free(outbound->free_write_reqs);
        outbound->free_write_reqs = next;
    }
    while (outbound->free_packet_reqs != NULL) {
        direct_packet_send_req_t *next =
            outbound->free_packet_reqs->next_free;
        free(outbound->free_packet_reqs);
        outbound->free_packet_reqs = next;
    }
    free(outbound->tag);
    free(outbound);
}

static direct_write_req_t *write_req_acquire(
    direct_outbound_impl_t *outbound)
{
    direct_write_req_t *request = outbound->free_write_reqs;
    if (request != NULL) {
        outbound->free_write_reqs = request->next_free;
        outbound->free_write_req_count--;
        memset(request, 0, sizeof(*request));
        return request;
    }
    return (direct_write_req_t *)calloc(1u, sizeof(*request));
}

static void write_req_release(direct_outbound_impl_t *outbound,
                              direct_write_req_t *request)
{
    if (outbound->free_write_req_count >= DIRECT_REQUEST_POOL_MAX_FREE) {
        free(request);
        return;
    }
    request->next_free = outbound->free_write_reqs;
    outbound->free_write_reqs = request;
    outbound->free_write_req_count++;
}

static direct_packet_send_req_t *packet_req_acquire(
    direct_outbound_impl_t *outbound)
{
    direct_packet_send_req_t *request = outbound->free_packet_reqs;
    if (request != NULL) {
        outbound->free_packet_reqs = request->next_free;
        outbound->free_packet_req_count--;
        memset(request, 0, sizeof(*request));
        return request;
    }
    return (direct_packet_send_req_t *)calloc(1u, sizeof(*request));
}

static void packet_req_release(direct_outbound_impl_t *outbound,
                               direct_packet_send_req_t *request)
{
    if (outbound->free_packet_req_count >= DIRECT_REQUEST_POOL_MAX_FREE) {
        free(request);
        return;
    }
    request->next_free = outbound->free_packet_reqs;
    outbound->free_packet_reqs = request;
    outbound->free_packet_req_count++;
}

static void packet_req_pool_trim(direct_outbound_impl_t *outbound)
{
    while (outbound != NULL && outbound->free_packet_reqs != NULL) {
        direct_packet_send_req_t *next =
            outbound->free_packet_reqs->next_free;
        free(outbound->free_packet_reqs);
        outbound->free_packet_reqs = next;
    }
    if (outbound != NULL) {
        outbound->free_packet_req_count = 0u;
    }
}

static void direct_udp_send_pool_trim_if_idle(
    direct_outbound_impl_t *outbound)
{
    if (outbound == NULL || outbound->udp_sends_pending != 0u) {
        return;
    }
    aproxy_bufpool_trim(&outbound->udp_write_pool);
    packet_req_pool_trim(outbound);
}

struct direct_stream_impl {
    direct_outbound_impl_t *outbound;
    aproxy_stream_t *owner;
    uv_tcp_t tcp;
    uv_connect_t connect_req;
    aproxy_buffer_t pending_write;
    aproxy_addr_t destination;
    struct sockaddr_storage connect_address;
    aproxy_stream_data_cb on_data;
    aproxy_stream_event_cb on_open;
    aproxy_stream_event_cb on_close;
    void *user_data;
    uint32_t id;
    int tcp_initialized;
    int tcp_closed;
    int connecting;
    int connected;
    int closing;
    int close_reported;
    int dns_pending;
    int protect_pending;
    int free_after_close;
    unsigned int callback_depth;
    size_t writes_pending;
    size_t write_bytes_pending;
    direct_stream_impl_t *prev;
    direct_stream_impl_t *next;
};

struct direct_packet_impl {
    direct_outbound_impl_t *outbound;
    aproxy_packet_flow_t *owner;
    uv_udp_t udp;
    aproxy_addr_t initial_destination;
    aproxy_addr_t resolved_destination;
    aproxy_packet_flow_data_cb on_data;
    aproxy_packet_flow_event_cb on_open;
    aproxy_packet_flow_event_cb on_close;
    void *user_data;
    uint32_t id;
    int udp_initialized;
    int udp_closed;
    int closing;
    int close_reported;
    int dns_pending;
    int protect_pending;
    int bind_family;
    int has_resolved_destination;
    int free_after_close;
    uint8_t *udp_recv_buffer;
    size_t udp_recv_capacity;
    aproxy_bufpool_t *udp_recv_pool;
    unsigned int callback_depth;
    direct_packet_impl_t *prev;
    direct_packet_impl_t *next;
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

static void stream_list_add(direct_outbound_impl_t *outbound,
                            direct_stream_impl_t *stream)
{
    stream->prev = NULL;
    stream->next = outbound->streams;
    if (outbound->streams != NULL) {
        outbound->streams->prev = stream;
    }
    outbound->streams = stream;
}

static void stream_list_remove(direct_stream_impl_t *stream)
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

static void packet_list_add(direct_outbound_impl_t *outbound,
                            direct_packet_impl_t *packet)
{
    packet->prev = NULL;
    packet->next = outbound->packets;
    if (outbound->packets != NULL) {
        outbound->packets->prev = packet;
    }
    outbound->packets = packet;
}

static void packet_list_remove(direct_packet_impl_t *packet)
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

static void direct_outbound_free_if_idle(direct_outbound_impl_t *outbound)
{
    if (outbound != NULL && outbound->free_after_streams &&
        outbound->streams == NULL && outbound->packets == NULL) {
        direct_outbound_destroy(outbound);
    }
}

static void stream_report_close(direct_stream_impl_t *stream, int status)
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

static void stream_destroy(direct_stream_impl_t *stream)
{
    if (stream == NULL) {
        return;
    }
    direct_outbound_impl_t *outbound = stream->outbound;
    stream_list_remove(stream);
    aproxy_buffer_free(&stream->pending_write);
    free(stream);
    direct_outbound_free_if_idle(outbound);
}

static int addr_to_sockaddr(const aproxy_addr_t *addr,
                            struct sockaddr_storage *storage,
                            int *out_len)
{
    if (addr == NULL || storage == NULL || out_len == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    memset(storage, 0, sizeof(*storage));
    if (addr->family == APROXY_ADDR_IPV4) {
        struct sockaddr_in *sa = (struct sockaddr_in *)storage;
        sa->sin_family = AF_INET;
        sa->sin_port = htons(addr->port);
        memcpy(&sa->sin_addr.s_addr, addr->addr, 4u);
        *out_len = sizeof(*sa);
        return APROXY_OK;
    }
    if (addr->family == APROXY_ADDR_IPV6) {
        struct sockaddr_in6 *sa = (struct sockaddr_in6 *)storage;
        sa->sin6_family = AF_INET6;
        sa->sin6_port = htons(addr->port);
        memcpy(&sa->sin6_addr, addr->addr, 16u);
        *out_len = sizeof(*sa);
        return APROXY_OK;
    }
    return APROXY_ERR_UNSUPPORTED;
}

static int sockaddr_to_addr(const struct sockaddr *sa, aproxy_addr_t *out)
{
    if (sa == NULL || out == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    if (sa->sa_family == AF_INET) {
        const struct sockaddr_in *addr = (const struct sockaddr_in *)sa;
        uint8_t ip[4];
        memcpy(ip, &addr->sin_addr.s_addr, sizeof(ip));
        aproxy_addr_set_ipv4(out, ip, ntohs(addr->sin_port));
        return APROXY_OK;
    }
    if (sa->sa_family == AF_INET6) {
        const struct sockaddr_in6 *addr = (const struct sockaddr_in6 *)sa;
        uint8_t ip[16];
        memcpy(ip, &addr->sin6_addr, sizeof(ip));
        aproxy_addr_set_ipv6(out, ip, ntohs(addr->sin6_port));
        return APROXY_OK;
    }
    return APROXY_ERR_UNSUPPORTED;
}

static void direct_tcp_close_cb(uv_handle_t *handle)
{
    direct_stream_impl_t *stream = (direct_stream_impl_t *)handle->data;
    if (stream == NULL) {
        return;
    }
    stream->tcp_closed = 1;
    stream->connecting = 0;
    stream->connected = 0;
    stream_report_close(stream, APROXY_OK);
    if (stream->free_after_close && !stream->protect_pending) {
        stream_destroy(stream);
    }
}

static void direct_stream_finish_close(direct_stream_impl_t *stream)
{
    if (stream->tcp_initialized && !stream->tcp_closed &&
        !uv_is_closing((uv_handle_t *)&stream->tcp)) {
        uv_read_stop((uv_stream_t *)&stream->tcp);
        uv_close((uv_handle_t *)&stream->tcp, direct_tcp_close_cb);
        return;
    }
    stream_report_close(stream, APROXY_OK);
    if (stream->free_after_close && !stream->dns_pending &&
        !stream->protect_pending && stream->callback_depth == 0u) {
        stream_destroy(stream);
    }
}

static void direct_stream_start_close(direct_stream_impl_t *stream)
{
    if (stream == NULL || stream->closing) {
        return;
    }
    stream->closing = 1;
    if (stream->protect_pending) {
        return;
    }
    direct_stream_finish_close(stream);
}

static void direct_write_cb(uv_write_t *req, int status)
{
    direct_write_req_t *write_req = (direct_write_req_t *)req;
    direct_stream_impl_t *stream = (direct_stream_impl_t *)req->data;
    if (stream != NULL && stream->writes_pending > 0u) {
        stream->writes_pending--;
    }
    if (stream != NULL) {
        stream->write_bytes_pending =
            stream->write_bytes_pending >= write_req->length
                ? stream->write_bytes_pending - write_req->length
                : 0u;
    }
    aproxy_bufpool_release(&write_req->outbound->write_pool,
                           write_req->data, write_req->capacity);
    write_req_release(write_req->outbound, write_req);
    if (status != 0 && stream != NULL) {
        direct_stream_start_close(stream);
    }
}

static int direct_write_now(direct_stream_impl_t *stream,
                            const uint8_t *data,
                            size_t len)
{
    if (stream == NULL || (data == NULL && len > 0u) ||
        !stream->connected || stream->closing) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    if (len == 0u) {
        return APROXY_OK;
    }
    if (len > UINT_MAX) {
        return APROXY_ERR_FRAME_TOO_LARGE;
    }

    int written = UV_EAGAIN;
    uv_buf_t direct = uv_buf_init((char *)(uintptr_t)data, (unsigned int)len);
    if (stream->writes_pending == 0u) {
        written = uv_try_write((uv_stream_t *)&stream->tcp, &direct, 1u);
    }
    if (written == (int)direct.len && (size_t)written == len) {
        return APROXY_OK;
    }
    size_t offset = 0u;
    if (written > 0) {
        offset = (size_t)written;
    } else if (written != UV_EAGAIN && written != UV_ENOSYS) {
        return written;
    }

    direct_write_req_t *req = write_req_acquire(stream->outbound);
    if (req == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    const size_t pending = len - offset;
    if (aproxy_size_add_exceeds(stream->write_bytes_pending, pending,
                                stream->outbound->max_pending_bytes)) {
        write_req_release(stream->outbound, req);
        return APROXY_ERR_FRAME_TOO_LARGE;
    }
    req->data = aproxy_bufpool_acquire(&stream->outbound->write_pool, pending,
                                       &req->capacity);
    if (req->data == NULL) {
        write_req_release(stream->outbound, req);
        return APROXY_ERR_NO_MEMORY;
    }
    memcpy(req->data, data + offset, pending);
    req->buf = uv_buf_init((char *)req->data, (unsigned int)pending);
    req->outbound = stream->outbound;
    req->length = pending;
    req->req.data = stream;
    const int rc = uv_write(&req->req, (uv_stream_t *)&stream->tcp,
                            &req->buf, 1u, direct_write_cb);
    if (rc != 0) {
        aproxy_bufpool_release(&stream->outbound->write_pool, req->data,
                               req->capacity);
        write_req_release(stream->outbound, req);
        return rc;
    }
    stream->writes_pending++;
    stream->write_bytes_pending += pending;
    return APROXY_OK;
}

static int direct_flush_pending(direct_stream_impl_t *stream)
{
    if (stream == NULL || stream->pending_write.len == 0u) {
        return APROXY_OK;
    }
    const int rc = direct_write_now(stream, stream->pending_write.data,
                                    stream->pending_write.len);
    if (rc == APROXY_OK) {
        aproxy_buffer_clear(&stream->pending_write);
    }
    return rc;
}

static void direct_alloc_cb(uv_handle_t *handle,
                            size_t suggested_size,
                            uv_buf_t *buf)
{
    (void)suggested_size;
    direct_stream_impl_t *stream = (direct_stream_impl_t *)handle->data;
    const size_t size = stream == NULL || stream->outbound == NULL
                            ? 16384u
                            : stream->outbound->read_buffer_size;
    size_t capacity = 0u;
    uint8_t *data = stream == NULL || stream->outbound == NULL
                        ? NULL
                        : aproxy_bufpool_acquire(&stream->outbound->read_pool,
                                                 size, &capacity);
    buf->base = (char *)data;
    buf->len = data == NULL ? 0u : capacity;
}

static void direct_read_cb(uv_stream_t *handle,
                           ssize_t nread,
                           const uv_buf_t *buf)
{
    direct_stream_impl_t *stream = (direct_stream_impl_t *)handle->data;
    if (stream == NULL) {
        free(buf->base);
        return;
    }
    if (nread > 0) {
        if (stream->on_data != NULL && stream->owner != NULL) {
            stream->callback_depth++;
            stream->on_data(stream->owner, (const uint8_t *)buf->base,
                            (size_t)nread, stream->user_data);
            stream->callback_depth--;
        }
    } else if (nread < 0) {
        direct_stream_start_close(stream);
    }
    aproxy_bufpool_release(&stream->outbound->read_pool,
                           (uint8_t *)buf->base, buf->len);
}

static void direct_connect_cb(uv_connect_t *req, int status)
{
    direct_stream_impl_t *stream = (direct_stream_impl_t *)req->data;
    if (stream == NULL || stream->closing) {
        return;
    }
    stream->connecting = 0;
    if (status != 0) {
        if (stream->on_open != NULL && stream->owner != NULL) {
            stream->callback_depth++;
            stream->on_open(stream->owner, status, stream->user_data);
            stream->callback_depth--;
        }
        direct_stream_start_close(stream);
        return;
    }

    stream->connected = 1;
    status = uv_read_start((uv_stream_t *)&stream->tcp, direct_alloc_cb,
                           direct_read_cb);
    if (status == 0) {
        status = direct_flush_pending(stream);
    }
    if (stream->on_open != NULL && stream->owner != NULL) {
        stream->callback_depth++;
        stream->on_open(stream->owner, status, stream->user_data);
        stream->callback_depth--;
    }
    if (status != 0) {
        direct_stream_start_close(stream);
    }
}

static int direct_start_connect(direct_stream_impl_t *stream)
{
    stream->connecting = 1;
    stream->connect_req.data = stream;
    const int rc = uv_tcp_connect(
        &stream->connect_req, &stream->tcp,
        (const struct sockaddr *)&stream->connect_address,
        direct_connect_cb);
    if (rc != 0) {
        stream->connecting = 0;
    }
    return rc == 0 ? APROXY_OK : rc;
}

static void direct_stream_protect_result(void *context, int status)
{
    direct_stream_impl_t *stream = (direct_stream_impl_t *)context;
    if (stream == NULL || !stream->protect_pending) {
        return;
    }
    stream->protect_pending = 0;
    if (stream->closing) {
        direct_stream_finish_close(stream);
        return;
    }
    if (status == APROXY_OK) {
        status = direct_start_connect(stream);
    }
    if (status == APROXY_OK) {
        return;
    }
    if (stream->on_open != NULL && stream->owner != NULL) {
        stream->callback_depth++;
        stream->on_open(stream->owner, status, stream->user_data);
        stream->callback_depth--;
    }
    direct_stream_start_close(stream);
}

static int direct_connect_addr(direct_stream_impl_t *stream,
                               const aproxy_addr_t *addr)
{
    if (stream == NULL || addr == NULL || stream->closing) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    struct sockaddr_storage storage;
    int socklen = 0;
    int rc = addr_to_sockaddr(addr, &storage, &socklen);
    if (rc != APROXY_OK) {
        return rc;
    }
    (void)socklen;
    if (!stream->tcp_initialized) {
        const int init_rc =
            stream->outbound->socket_protector.submit == NULL
                ? uv_tcp_init(stream->outbound->loop, &stream->tcp)
                : uv_tcp_init_ex(stream->outbound->loop, &stream->tcp,
                                 storage.ss_family);
        if (init_rc != 0) {
            return init_rc;
        }
        stream->tcp_initialized = 1;
        stream->tcp.data = stream;
    }
    stream->connect_address = storage;
    if (stream->outbound->socket_protector.submit != NULL) {
        stream->protect_pending = 1;
        rc = aproxy_socket_protector_submit(
            &stream->outbound->socket_protector,
            (const uv_handle_t *)&stream->tcp,
            direct_stream_protect_result, stream);
        if (rc != APROXY_OK) {
            stream->protect_pending = 0;
        }
        return rc;
    }
    return direct_start_connect(stream);
}

static void direct_dns_cb(aproxy_dns_resolver_t *resolver,
                          int status,
                          const aproxy_addr_t *addresses,
                          size_t count,
                          void *user_data)
{
    (void)resolver;
    direct_stream_impl_t *stream = (direct_stream_impl_t *)user_data;
    if (stream == NULL) {
        return;
    }
    stream->dns_pending = 0;
    if (stream->closing || stream->free_after_close) {
        if (stream->free_after_close) {
            stream_destroy(stream);
        }
        return;
    }
    if (status != APROXY_OK || addresses == NULL || count == 0u) {
        if (stream->on_open != NULL && stream->owner != NULL) {
            stream->callback_depth++;
            stream->on_open(stream->owner, status, stream->user_data);
            stream->callback_depth--;
        }
        if (stream->free_after_close) {
            stream_destroy(stream);
            return;
        }
        direct_stream_start_close(stream);
        return;
    }
    status = direct_connect_addr(stream, &addresses[0]);
    if (status != APROXY_OK) {
        if (stream->on_open != NULL && stream->owner != NULL) {
            stream->callback_depth++;
            stream->on_open(stream->owner, status, stream->user_data);
            stream->callback_depth--;
        }
        direct_stream_start_close(stream);
    }
}

static int direct_stream_write(void *impl,
                               const uint8_t *data,
                               size_t len)
{
    direct_stream_impl_t *stream = (direct_stream_impl_t *)impl;
    if (stream == NULL || (data == NULL && len > 0u) || stream->closing) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    if (!stream->connected) {
        if (aproxy_size_add_exceeds(stream->pending_write.len, len,
                                    stream->outbound->max_pending_bytes)) {
            return APROXY_ERR_FRAME_TOO_LARGE;
        }
        return aproxy_buffer_append(&stream->pending_write, data, len);
    }
    return direct_write_now(stream, data, len);
}

static int direct_stream_close(void *impl)
{
    direct_stream_impl_t *stream = (direct_stream_impl_t *)impl;
    if (stream == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    direct_stream_start_close(stream);
    return APROXY_OK;
}

static uint32_t direct_stream_id(const void *impl)
{
    const direct_stream_impl_t *stream = (const direct_stream_impl_t *)impl;
    return stream == NULL ? 0u : stream->id;
}

static void *direct_stream_native(const void *impl)
{
    return (void *)impl;
}

static void direct_stream_free(void *impl)
{
    direct_stream_impl_t *stream = (direct_stream_impl_t *)impl;
    if (stream == NULL) {
        return;
    }
    stream->owner = NULL;
    stream->on_data = NULL;
    stream->on_open = NULL;
    stream->on_close = NULL;
    stream->user_data = NULL;
    if (stream->dns_pending) {
        stream->closing = 1;
        stream->free_after_close = 1;
        return;
    }
    if (stream->tcp_initialized && !stream->tcp_closed) {
        stream->free_after_close = 1;
        direct_stream_start_close(stream);
        return;
    }
    if (stream->callback_depth > 0u) {
        stream->free_after_close = 1;
        return;
    }
    stream_destroy(stream);
}

static const aproxy_stream_vtable_t direct_stream_vtable = {
    .write = direct_stream_write,
    .close = direct_stream_close,
    .id = direct_stream_id,
    .native = direct_stream_native,
    .free = direct_stream_free,
};

static void direct_packet_report_close(direct_packet_impl_t *packet,
                                       int status)
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

static void direct_packet_report_open(direct_packet_impl_t *packet,
                                      int status)
{
    if (packet->on_open != NULL && packet->owner != NULL) {
        packet->callback_depth++;
        packet->on_open(packet->owner, status, packet->user_data);
        packet->callback_depth--;
    }
}

static void direct_packet_release_recv_buffer(direct_packet_impl_t *packet)
{
    if (packet == NULL || packet->udp_recv_buffer == NULL) {
        return;
    }
    aproxy_bufpool_release(packet->udp_recv_pool,
                           packet->udp_recv_buffer,
                           packet->udp_recv_capacity);
    packet->udp_recv_buffer = NULL;
    packet->udp_recv_capacity = 0u;
    packet->udp_recv_pool = NULL;
}

static void direct_packet_destroy(direct_packet_impl_t *packet)
{
    if (packet == NULL) {
        return;
    }
    direct_outbound_impl_t *outbound = packet->outbound;
    direct_packet_release_recv_buffer(packet);
    packet_list_remove(packet);
    if (outbound != NULL && outbound->packets == NULL) {
        aproxy_bufpool_trim(&outbound->udp_read_pool);
        aproxy_bufpool_trim(&outbound->udp_batch_pool);
    }
    free(packet);
    direct_outbound_free_if_idle(outbound);
}

static void direct_udp_close_cb(uv_handle_t *handle)
{
    direct_packet_impl_t *packet = (direct_packet_impl_t *)handle->data;
    if (packet == NULL) {
        return;
    }
    packet->udp_closed = 1;
    direct_packet_report_close(packet, APROXY_OK);
    if (packet->free_after_close && !packet->protect_pending) {
        direct_packet_destroy(packet);
    }
}

static void direct_packet_finish_close(direct_packet_impl_t *packet)
{
    if (packet->udp_initialized && !packet->udp_closed &&
        !uv_is_closing((uv_handle_t *)&packet->udp)) {
        uv_udp_recv_stop(&packet->udp);
        uv_close((uv_handle_t *)&packet->udp, direct_udp_close_cb);
        return;
    }
    direct_packet_report_close(packet, APROXY_OK);
    if (packet->free_after_close && !packet->dns_pending &&
        !packet->protect_pending && packet->callback_depth == 0u) {
        direct_packet_destroy(packet);
    }
}

static void direct_packet_start_close(direct_packet_impl_t *packet)
{
    if (packet == NULL || packet->closing) {
        return;
    }
    packet->closing = 1;
    if (packet->protect_pending) {
        return;
    }
    direct_packet_finish_close(packet);
}

static void direct_packet_alloc_cb(uv_handle_t *handle,
                                   size_t suggested_size,
                                   uv_buf_t *buf)
{
    (void)suggested_size;
    direct_packet_impl_t *packet = (direct_packet_impl_t *)handle->data;
    if (packet == NULL || packet->outbound == NULL) {
        buf->base = NULL;
        buf->len = 0u;
        return;
    }
    direct_packet_release_recv_buffer(packet);

    const int use_batch = uv_udp_using_recvmmsg(&packet->udp);
    size_t size = DIRECT_UDP_DATAGRAM_BYTES;
    aproxy_bufpool_t *pool = &packet->outbound->udp_read_pool;
    if (use_batch) {
        size = DIRECT_UDP_RECV_BATCH_BYTES;
        pool = &packet->outbound->udp_batch_pool;
    }
    size_t capacity = 0u;
    uint8_t *data = aproxy_bufpool_acquire(pool, size, &capacity);
    if (data == NULL && use_batch) {
        pool = &packet->outbound->udp_read_pool;
        data = aproxy_bufpool_acquire(pool, DIRECT_UDP_DATAGRAM_BYTES,
                                      &capacity);
    }
    packet->udp_recv_buffer = data;
    packet->udp_recv_capacity = capacity;
    packet->udp_recv_pool = data == NULL ? NULL : pool;
    buf->base = (char *)data;
    buf->len = data == NULL ? 0u : capacity;
}

static void direct_packet_recv_cb(uv_udp_t *handle,
                                  ssize_t nread,
                                  const uv_buf_t *buf,
                                  const struct sockaddr *addr,
                                  unsigned int flags)
{
    direct_packet_impl_t *packet = (direct_packet_impl_t *)handle->data;
    if (packet == NULL) {
        if ((flags & UV_UDP_MMSG_CHUNK) == 0u) {
            free(buf->base);
        }
        return;
    }
    if ((flags & UV_UDP_MMSG_FREE) != 0u) {
        direct_packet_release_recv_buffer(packet);
        return;
    }
    if (nread > 0 && addr != NULL && (flags & UV_UDP_PARTIAL) == 0u) {
        aproxy_addr_t source;
        if (sockaddr_to_addr(addr, &source) == APROXY_OK &&
            packet->on_data != NULL && packet->owner != NULL) {
            packet->callback_depth++;
            packet->on_data(packet->owner, &source,
                            (const uint8_t *)buf->base, (size_t)nread,
                            packet->user_data);
            packet->callback_depth--;
        }
    } else if (nread < 0) {
        direct_packet_start_close(packet);
    }
    if ((flags & UV_UDP_MMSG_CHUNK) == 0u || packet->closing) {
        direct_packet_release_recv_buffer(packet);
    }
}

static void direct_packet_send_cb(uv_udp_send_t *req, int status)
{
    direct_packet_send_req_t *send_req =
        (direct_packet_send_req_t *)req;
    direct_packet_impl_t *packet =
        (direct_packet_impl_t *)req->data;
    direct_outbound_impl_t *outbound = send_req->outbound;
    aproxy_bufpool_release(&outbound->udp_write_pool, send_req->data,
                           send_req->capacity);
    packet_req_release(outbound, send_req);
    if (outbound->udp_sends_pending > 0u) {
        outbound->udp_sends_pending--;
    }
    direct_udp_send_pool_trim_if_idle(outbound);
    if (status != 0 && packet != NULL) {
        direct_packet_start_close(packet);
    }
}

static int packet_destination_matches_initial(
    const direct_packet_impl_t *packet,
    const aproxy_addr_t *destination)
{
    if (packet == NULL || destination == NULL) {
        return 0;
    }
    if (packet->initial_destination.family != APROXY_ADDR_FQDN ||
        destination->family != APROXY_ADDR_FQDN) {
        return 0;
    }
    return packet->initial_destination.port == destination->port &&
           packet->initial_destination.fqdn_len == destination->fqdn_len &&
           strcmp(packet->initial_destination.fqdn, destination->fqdn) == 0;
}

static int direct_packet_prepare_destination(
    const direct_packet_impl_t *packet,
    const aproxy_addr_t *destination,
    struct sockaddr_storage *storage)
{
    if (packet == NULL || destination == NULL || storage == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    const aproxy_addr_t *send_destination = destination;
    if (destination->family == APROXY_ADDR_FQDN) {
        if (!packet->has_resolved_destination ||
            !packet_destination_matches_initial(packet, destination)) {
            return APROXY_ERR_UNSUPPORTED;
        }
        send_destination = &packet->resolved_destination;
    }
    int socklen = 0;
    const int rc = addr_to_sockaddr(send_destination, storage, &socklen);
    (void)socklen;
    return rc;
}

static int direct_packet_send(void *impl,
                              const aproxy_addr_t *destination,
                              const uint8_t *data,
                              size_t len)
{
    direct_packet_impl_t *packet = (direct_packet_impl_t *)impl;
    if (packet == NULL || destination == NULL ||
        (data == NULL && len > 0u) || packet->closing ||
        packet->protect_pending || !packet->udp_initialized ||
        packet->udp_closed) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    if (len > UINT_MAX) {
        return APROXY_ERR_FRAME_TOO_LARGE;
    }

    struct sockaddr_storage storage;
    int rc = direct_packet_prepare_destination(packet, destination, &storage);
    if (rc != APROXY_OK) {
        return rc;
    }

    uv_buf_t direct = uv_buf_init((char *)(uintptr_t)data, (unsigned int)len);
    rc = uv_udp_try_send(&packet->udp, &direct, 1u,
                         (const struct sockaddr *)&storage);
    if (rc >= 0) {
        return (size_t)rc == len ? APROXY_OK : APROXY_ERR_INVALID_FRAME;
    }
    if (rc != UV_EAGAIN && rc != UV_ENOSYS) {
        return rc;
    }

    direct_packet_send_req_t *req = packet_req_acquire(packet->outbound);
    if (req == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    const size_t alloc_len = len == 0u ? 1u : len;
    req->data = aproxy_bufpool_acquire(&packet->outbound->udp_write_pool,
                                       alloc_len, &req->capacity);
    if (req->data == NULL) {
        packet_req_release(packet->outbound, req);
        direct_udp_send_pool_trim_if_idle(packet->outbound);
        return APROXY_ERR_NO_MEMORY;
    }
    if (len > 0u) {
        memcpy(req->data, data, len);
    }
    req->buf = uv_buf_init((char *)req->data, (unsigned int)len);
    req->outbound = packet->outbound;
    req->req.data = packet;
    rc = uv_udp_send(&req->req, &packet->udp, &req->buf, 1u,
                     (const struct sockaddr *)&storage,
                     direct_packet_send_cb);
    if (rc != 0) {
        aproxy_bufpool_release(&packet->outbound->udp_write_pool, req->data,
                               req->capacity);
        packet_req_release(packet->outbound, req);
        direct_udp_send_pool_trim_if_idle(packet->outbound);
        return rc;
    }
    packet->outbound->udp_sends_pending++;
    return APROXY_OK;
}

static int direct_packet_send_batch(
    void *impl,
    const aproxy_packet_flow_datagram_t *datagrams,
    size_t count,
    size_t *accepted)
{
    direct_packet_impl_t *packet = (direct_packet_impl_t *)impl;
    if (accepted != NULL) {
        *accepted = 0u;
    }
    if (packet == NULL || datagrams == NULL || count == 0u ||
        accepted == NULL || packet->closing || packet->protect_pending ||
        !packet->udp_initialized || packet->udp_closed) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    size_t offset = 0u;
    while (offset < count) {
        const size_t remaining = count - offset;
        const unsigned int batch_count =
            (unsigned int)(remaining > DIRECT_UDP_SEND_BATCH_SIZE
                               ? DIRECT_UDP_SEND_BATCH_SIZE
                               : remaining);
        uv_buf_t buffers[DIRECT_UDP_SEND_BATCH_SIZE];
        uv_buf_t *buffer_lists[DIRECT_UDP_SEND_BATCH_SIZE];
        unsigned int buffer_counts[DIRECT_UDP_SEND_BATCH_SIZE];
        struct sockaddr_storage storage[DIRECT_UDP_SEND_BATCH_SIZE];
        struct sockaddr *addresses[DIRECT_UDP_SEND_BATCH_SIZE];
        for (unsigned int i = 0u; i < batch_count; i++) {
            const aproxy_packet_flow_datagram_t *datagram =
                &datagrams[offset + i];
            if (datagram->destination == NULL ||
                (datagram->data == NULL && datagram->len > 0u) ||
                datagram->len > UINT_MAX) {
                return APROXY_ERR_INVALID_ARGUMENT;
            }
            const int rc = direct_packet_prepare_destination(
                packet, datagram->destination, &storage[i]);
            if (rc != APROXY_OK) {
                return rc;
            }
            buffers[i] = uv_buf_init(
                (char *)(uintptr_t)datagram->data,
                (unsigned int)datagram->len);
            buffer_lists[i] = &buffers[i];
            buffer_counts[i] = 1u;
            addresses[i] = (struct sockaddr *)&storage[i];
        }

        int rc = uv_udp_try_send2(&packet->udp, batch_count, buffer_lists,
                                  buffer_counts, addresses, 0u);
        unsigned int sent = 0u;
        if (rc > 0) {
            sent = (unsigned int)rc;
            if (sent > batch_count) {
                return APROXY_ERR_INVALID_FRAME;
            }
            *accepted += sent;
        } else if (rc < 0 && rc != UV_EAGAIN && rc != UV_ENOSYS) {
            return rc;
        }

        for (unsigned int i = sent; i < batch_count; i++) {
            const aproxy_packet_flow_datagram_t *datagram =
                &datagrams[offset + i];
            rc = direct_packet_send(packet, datagram->destination,
                                    datagram->data, datagram->len);
            if (rc != APROXY_OK) {
                return rc;
            }
            (*accepted)++;
        }
        offset += batch_count;
    }
    return APROXY_OK;
}

static int direct_packet_close(void *impl)
{
    direct_packet_impl_t *packet = (direct_packet_impl_t *)impl;
    if (packet == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    direct_packet_start_close(packet);
    return APROXY_OK;
}

static uint32_t direct_packet_id(const void *impl)
{
    const direct_packet_impl_t *packet =
        (const direct_packet_impl_t *)impl;
    return packet == NULL ? 0u : packet->id;
}

static void *direct_packet_native(const void *impl)
{
    return (void *)impl;
}

static void direct_packet_free(void *impl)
{
    direct_packet_impl_t *packet = (direct_packet_impl_t *)impl;
    if (packet == NULL) {
        return;
    }
    packet->owner = NULL;
    packet->on_data = NULL;
    packet->on_open = NULL;
    packet->on_close = NULL;
    packet->user_data = NULL;
    if (packet->dns_pending) {
        packet->closing = 1;
        packet->free_after_close = 1;
        return;
    }
    if (packet->udp_initialized && !packet->udp_closed) {
        packet->free_after_close = 1;
        direct_packet_start_close(packet);
        return;
    }
    if (packet->callback_depth > 0u) {
        packet->free_after_close = 1;
        return;
    }
    direct_packet_destroy(packet);
}

static const aproxy_packet_flow_vtable_t direct_packet_vtable = {
    .send = direct_packet_send,
    .send_batch = direct_packet_send_batch,
    .close = direct_packet_close,
    .id = direct_packet_id,
    .native = direct_packet_native,
    .free = direct_packet_free,
};

static int direct_packet_finish_udp_start(direct_packet_impl_t *packet)
{
    if (packet == NULL || packet->closing) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    int rc = APROXY_OK;
    if (packet->bind_family == AF_INET6) {
        struct sockaddr_in6 bind6;
        rc = uv_ip6_addr("::", 0, &bind6);
        if (rc == 0) {
            rc = uv_udp_bind(&packet->udp,
                             (const struct sockaddr *)&bind6, 0u);
        }
    } else {
        struct sockaddr_in bind4;
        rc = uv_ip4_addr("0.0.0.0", 0, &bind4);
        if (rc == 0) {
            rc = uv_udp_bind(&packet->udp,
                             (const struct sockaddr *)&bind4, 0u);
        }
    }
    if (rc == 0) {
        rc = uv_udp_recv_start(&packet->udp, direct_packet_alloc_cb,
                               direct_packet_recv_cb);
    }
    return rc == 0 ? APROXY_OK : rc;
}

static void direct_packet_protect_result(void *context, int status)
{
    direct_packet_impl_t *packet = (direct_packet_impl_t *)context;
    if (packet == NULL || !packet->protect_pending) {
        return;
    }
    packet->protect_pending = 0;
    if (packet->closing) {
        direct_packet_finish_close(packet);
        return;
    }
    if (status == APROXY_OK) {
        status = direct_packet_finish_udp_start(packet);
    }
    direct_packet_report_open(packet, status);
    if (status != APROXY_OK) {
        direct_packet_start_close(packet);
    }
}

static int direct_packet_start_udp(direct_packet_impl_t *packet,
                                   const aproxy_addr_t *bind_hint)
{
    if (packet == NULL || bind_hint == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    packet->bind_family = bind_hint->family == APROXY_ADDR_IPV6
                              ? AF_INET6
                              : AF_INET;
    const unsigned int udp_flags =
        (unsigned int)packet->bind_family | UV_UDP_RECVMMSG;
    int rc = uv_udp_init_ex(packet->outbound->loop, &packet->udp,
                            udp_flags);
    if (rc != 0) {
        return rc;
    }
    packet->udp_initialized = 1;
    packet->udp.data = packet;
    if (packet->outbound->socket_protector.submit == NULL) {
        return direct_packet_finish_udp_start(packet);
    }
    packet->protect_pending = 1;
    rc = aproxy_socket_protector_submit(
        &packet->outbound->socket_protector,
        (const uv_handle_t *)&packet->udp,
        direct_packet_protect_result, packet);
    if (rc != APROXY_OK) {
        packet->protect_pending = 0;
    }
    return rc;
}

static void direct_packet_dns_cb(aproxy_dns_resolver_t *resolver,
                                 int status,
                                 const aproxy_addr_t *addresses,
                                 size_t count,
                                 void *user_data)
{
    (void)resolver;
    direct_packet_impl_t *packet = (direct_packet_impl_t *)user_data;
    if (packet == NULL) {
        return;
    }
    packet->dns_pending = 0;
    if (packet->closing || packet->free_after_close) {
        if (packet->free_after_close) {
            direct_packet_destroy(packet);
        }
        return;
    }
    if (status == APROXY_OK && addresses != NULL && count > 0u) {
        packet->resolved_destination = addresses[0];
        packet->has_resolved_destination = 1;
        status = direct_packet_start_udp(packet, &packet->resolved_destination);
    } else if (status == APROXY_OK) {
        status = APROXY_ERR_PARSE;
    }
    if (packet->protect_pending) {
        return;
    }
    direct_packet_report_open(packet, status);
    if (packet->free_after_close && !packet->udp_initialized) {
        direct_packet_destroy(packet);
        return;
    }
    if (status != APROXY_OK) {
        direct_packet_start_close(packet);
    }
}

static int direct_outbound_connect(void *impl)
{
    return impl == NULL ? APROXY_ERR_INVALID_ARGUMENT : APROXY_OK;
}

static int direct_outbound_open_stream(void *impl_ptr,
                                      const aproxy_addr_t *destination,
                                      aproxy_stream_data_cb on_data,
                                      aproxy_stream_event_cb on_open,
                                      aproxy_stream_event_cb on_close,
                                      void *user_data,
                                      aproxy_stream_t **out)
{
    direct_outbound_impl_t *impl = (direct_outbound_impl_t *)impl_ptr;
    if (impl == NULL || destination == NULL || out == NULL || impl->closing) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    *out = NULL;

    direct_stream_impl_t *stream =
        (direct_stream_impl_t *)calloc(1u, sizeof(*stream));
    if (stream == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    stream->outbound = impl;
    stream->destination = *destination;
    stream->on_data = on_data;
    stream->on_open = on_open;
    stream->on_close = on_close;
    stream->user_data = user_data;
    stream->id = ++impl->next_stream_id;
    aproxy_buffer_init(&stream->pending_write);

    int rc = aproxy_stream_new(&direct_stream_vtable, stream, &stream->owner);
    if (rc != APROXY_OK) {
        stream_destroy(stream);
        return rc;
    }
    stream_list_add(impl, stream);
    *out = stream->owner;

    if (destination->family == APROXY_ADDR_FQDN) {
        if (impl->resolver == NULL) {
            return APROXY_ERR_UNSUPPORTED;
        }
        stream->dns_pending = 1;
        rc = aproxy_dns_resolve(impl->resolver, destination->fqdn,
                                destination->port, direct_dns_cb, stream);
        if (rc != APROXY_OK) {
            stream->dns_pending = 0;
            aproxy_stream_free(*out);
            *out = NULL;
            return rc;
        }
        return APROXY_OK;
    }

    rc = direct_connect_addr(stream, destination);
    if (rc != APROXY_OK) {
        aproxy_stream_free(*out);
        *out = NULL;
        return rc;
    }
    return APROXY_OK;
}

static int direct_outbound_open_packet(void *impl_ptr,
                                       const aproxy_addr_t *initial_destination,
                                       aproxy_packet_flow_data_cb on_data,
                                       aproxy_packet_flow_event_cb on_open,
                                       aproxy_packet_flow_event_cb on_close,
                                       void *user_data,
                                       aproxy_packet_flow_t **out)
{
    direct_outbound_impl_t *impl = (direct_outbound_impl_t *)impl_ptr;
    if (impl == NULL || initial_destination == NULL || out == NULL ||
        impl->closing) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    *out = NULL;

    direct_packet_impl_t *packet =
        (direct_packet_impl_t *)calloc(1u, sizeof(*packet));
    if (packet == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    packet->outbound = impl;
    packet->initial_destination = *initial_destination;
    packet->on_data = on_data;
    packet->on_open = on_open;
    packet->on_close = on_close;
    packet->user_data = user_data;
    packet->id = ++impl->next_packet_id;

    int rc = aproxy_packet_flow_new(&direct_packet_vtable, packet,
                                    &packet->owner);
    if (rc != APROXY_OK) {
        direct_packet_destroy(packet);
        return rc;
    }

    packet_list_add(impl, packet);
    *out = packet->owner;
    if (initial_destination->family == APROXY_ADDR_FQDN) {
        if (impl->resolver == NULL) {
            aproxy_packet_flow_free(*out);
            *out = NULL;
            return APROXY_ERR_UNSUPPORTED;
        }
        packet->dns_pending = 1;
        rc = aproxy_dns_resolve(impl->resolver, initial_destination->fqdn,
                                initial_destination->port,
                                direct_packet_dns_cb, packet);
        if (rc != APROXY_OK) {
            packet->dns_pending = 0;
            aproxy_packet_flow_free(*out);
            *out = NULL;
            return rc;
        }
        return APROXY_OK;
    }

    rc = direct_packet_start_udp(packet, initial_destination);
    if (rc != APROXY_OK) {
        aproxy_packet_flow_free(*out);
        *out = NULL;
        return rc;
    }
    if (packet->protect_pending) {
        return APROXY_OK;
    }
    if (on_open != NULL) {
        packet->callback_depth++;
        on_open(packet->owner, APROXY_OK, user_data);
        packet->callback_depth--;
    }
    return APROXY_OK;
}

static void direct_outbound_close(void *impl_ptr)
{
    direct_outbound_impl_t *impl = (direct_outbound_impl_t *)impl_ptr;
    if (impl == NULL || impl->closing) {
        return;
    }
    impl->closing = 1;
    direct_stream_impl_t *stream = impl->streams;
    while (stream != NULL) {
        direct_stream_impl_t *next = stream->next;
        direct_stream_start_close(stream);
        stream = next;
    }
    direct_packet_impl_t *packet = impl->packets;
    while (packet != NULL) {
        direct_packet_impl_t *next = packet->next;
        direct_packet_start_close(packet);
        packet = next;
    }
}

static void direct_outbound_free(void *impl_ptr)
{
    direct_outbound_impl_t *impl = (direct_outbound_impl_t *)impl_ptr;
    if (impl == NULL) {
        return;
    }
    direct_outbound_close(impl);
    if (impl->streams != NULL || impl->packets != NULL) {
        impl->free_after_streams = 1;
        return;
    }
    direct_outbound_destroy(impl);
}

static const aproxy_outbound_vtable_t direct_outbound_vtable = {
    .connect = direct_outbound_connect,
    .open_stream = direct_outbound_open_stream,
    .open_packet = direct_outbound_open_packet,
    .close = direct_outbound_close,
    .free = direct_outbound_free,
};

int aproxy_direct_outbound_new(const aproxy_direct_outbound_config_t *config,
                               aproxy_outbound_t **out)
{
    if (config == NULL || config->loop == NULL || out == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    *out = NULL;

    aproxy_outbound_t *outbound =
        (aproxy_outbound_t *)calloc(1u, sizeof(*outbound));
    if (outbound == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    direct_outbound_impl_t *impl =
        (direct_outbound_impl_t *)calloc(1u, sizeof(*impl));
    if (impl == NULL) {
        free(outbound);
        return APROXY_ERR_NO_MEMORY;
    }

    impl->loop = config->loop;
    impl->read_buffer_size =
        config->read_buffer_size == 0u ? 16384u : config->read_buffer_size;
    impl->max_pending_bytes =
        aproxy_stream_pending_limit(config->max_pending_bytes);
    impl->socket_protector = config->socket_protector;
    aproxy_bufpool_init(&impl->read_pool, impl->read_buffer_size, 64u);
    aproxy_bufpool_init(&impl->write_pool, 16384u, 64u);
    aproxy_bufpool_init(&impl->udp_read_pool, DIRECT_UDP_DATAGRAM_BYTES,
                        DIRECT_UDP_READ_POOL_MAX_FREE);
    aproxy_bufpool_init(&impl->udp_batch_pool,
                        DIRECT_UDP_RECV_BATCH_BYTES,
                        DIRECT_UDP_READ_POOL_MAX_FREE);
    aproxy_bufpool_init(&impl->udp_write_pool, 16384u,
                        DIRECT_UDP_WRITE_POOL_MAX_FREE);
    impl->tag = copy_string(config->tag != NULL ? config->tag : "direct");
    if (impl->tag == NULL) {
        aproxy_bufpool_destroy(&impl->read_pool);
        aproxy_bufpool_destroy(&impl->write_pool);
        aproxy_bufpool_destroy(&impl->udp_read_pool);
        aproxy_bufpool_destroy(&impl->udp_batch_pool);
        aproxy_bufpool_destroy(&impl->udp_write_pool);
        free(impl);
        free(outbound);
        return APROXY_ERR_NO_MEMORY;
    }
    impl->resolver = config->resolver;
    if (impl->resolver == NULL) {
        aproxy_dns_libuv_config_t dns_config = {
            .loop = config->loop,
            .max_cache_entries = 256u,
            .cache_ttl_ms = 60000u,
            .negative_cache_ttl_ms = 5000u,
        };
        const int rc =
            aproxy_dns_resolver_new_libuv(&dns_config, &impl->resolver);
        if (rc != APROXY_OK) {
            direct_outbound_destroy(impl);
            free(outbound);
            return rc;
        }
        impl->owns_resolver = 1;
    }

    outbound->tag = impl->tag;
    outbound->vtable = &direct_outbound_vtable;
    outbound->impl = impl;
    outbound->udp_transport = APROXY_OUTBOUND_UDP_PACKET;
    *out = outbound;
    return APROXY_OK;
}
