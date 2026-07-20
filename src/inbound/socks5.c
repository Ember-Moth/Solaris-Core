#include "aproxy/socks5_inbound.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "aproxy/bufpool.h"
#include "aproxy/limits.h"
#include "aproxy/ring.h"
#include "aproxy/uot.h"
#include "platform.h"

#define SOCKS5_VERSION 0x05u
#define SOCKS5_METHOD_NO_AUTH 0x00u
#define SOCKS5_METHOD_NO_ACCEPTABLE 0xffu
#define SOCKS5_CMD_CONNECT 0x01u
#define SOCKS5_CMD_UDP_ASSOCIATE 0x03u
#define SOCKS5_ATYP_IPV4 0x01u
#define SOCKS5_ATYP_DOMAIN 0x03u
#define SOCKS5_ATYP_IPV6 0x04u
#define SOCKS5_REP_SUCCEEDED 0x00u
#define SOCKS5_REP_GENERAL_FAILURE 0x01u
#define SOCKS5_REP_CONNECTION_NOT_ALLOWED 0x02u
#define SOCKS5_REP_COMMAND_NOT_SUPPORTED 0x07u
#define SOCKS5_REP_ADDRESS_TYPE_NOT_SUPPORTED 0x08u
#define SOCKS5_REQUEST_POOL_MAX_FREE 64u
#define SOCKS5_READ_POOL_MAX_FREE 16u
#define SOCKS5_UDP_DATAGRAM_BYTES (64u * 1024u)
#define SOCKS5_UDP_RECV_BATCH_SIZE 2u
#define SOCKS5_UDP_RECV_BATCH_BYTES \
    (SOCKS5_UDP_DATAGRAM_BYTES * SOCKS5_UDP_RECV_BATCH_SIZE)
#define SOCKS5_UDP_BATCH_POOL_MAX_FREE 1u

typedef enum socks5_state {
    SOCKS5_STATE_GREETING,
    SOCKS5_STATE_REQUEST,
    SOCKS5_STATE_ROUTING,
    SOCKS5_STATE_CONNECTING,
    SOCKS5_STATE_RELAY,
    SOCKS5_STATE_UDP_ASSOCIATE,
    SOCKS5_STATE_CLOSING
} socks5_state_t;

typedef struct socks5_conn socks5_conn_t;
typedef struct socks5_write_req socks5_write_req_t;
typedef struct socks5_udp_send_req socks5_udp_send_req_t;

typedef struct socks5_inbound_impl {
    uv_loop_t *loop;
    uv_tcp_t server;
    aproxy_router_t *router;
    aproxy_dns_resolver_t *resolver;
    char *tag;
    char *listen_host;
    uint16_t listen_port;
    uint8_t udp_uot_version;
    size_t stream_pending_limit;
    size_t udp_pending_tx_limit;
    size_t udp_stream_rx_limit;
    aproxy_socks5_udp_stats_t udp_stats;
    int backlog;
    int server_initialized;
    int listening;
    int server_closing;
    int server_closed;
    int free_after_close;
    socks5_conn_t *connections;
    socks5_write_req_t *free_write_reqs;
    socks5_udp_send_req_t *free_udp_send_reqs;
    size_t free_write_req_count;
    size_t free_udp_send_req_count;
    aproxy_bufpool_t bufpool;
    aproxy_bufpool_t udp_read_pool;
    aproxy_bufpool_t udp_batch_pool;
} socks5_inbound_impl_t;

struct socks5_conn {
    socks5_inbound_impl_t *inbound;
    uv_tcp_t client;
    uv_udp_t udp;
    int client_initialized;
    int client_closed;
    int udp_initialized;
    int udp_closed;
    socks5_state_t state;
    aproxy_ring_t rx;
    aproxy_ring_t udp_stream_rx;
    aproxy_ring_t udp_pending_tx;
    aproxy_stream_t *outbound_stream;
    aproxy_addr_t destination;
    struct sockaddr_storage udp_client_addr;
    int udp_client_addr_set;
    int udp_stream_open;
    int udp_request_sent;
    int tcp_route_pending;
    int udp_route_pending;
    aproxy_addr_t udp_route_destination;
    size_t writes_pending;
    size_t write_bytes_pending;
    uint8_t *udp_recv_buffer;
    size_t udp_recv_capacity;
    aproxy_bufpool_t *udp_recv_pool;
    int attached;
    socks5_conn_t *prev;
    socks5_conn_t *next;
};

struct socks5_write_req {
    uv_write_t req;
    uv_buf_t bufs[2];
    size_t capacities[2];
    aproxy_bufpool_t *pool;
    unsigned int nbufs;
    int close_after;
    socks5_inbound_impl_t *inbound;
    size_t length;
    socks5_write_req_t *next_free;
};

struct socks5_udp_send_req {
    uv_udp_send_t req;
    uv_buf_t buf;
    size_t capacity;
    socks5_inbound_impl_t *inbound;
    aproxy_bufpool_t *pool;
    socks5_udp_send_req_t *next_free;
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

static void conn_close(socks5_conn_t *conn);
static void conn_maybe_free(socks5_conn_t *conn);
static void socks5_impl_free_now(socks5_inbound_impl_t *inbound);
static void socks5_impl_maybe_free(socks5_inbound_impl_t *inbound);
static void socks5_server_close_cb(uv_handle_t *handle);

static void conn_list_add(socks5_inbound_impl_t *inbound,
                          socks5_conn_t *conn)
{
    conn->prev = NULL;
    conn->next = inbound->connections;
    if (conn->next != NULL) {
        conn->next->prev = conn;
    }
    inbound->connections = conn;
    conn->attached = 1;
}

static void conn_list_remove(socks5_conn_t *conn)
{
    if (conn == NULL || !conn->attached || conn->inbound == NULL) {
        return;
    }
    socks5_inbound_impl_t *inbound = conn->inbound;
    if (conn->prev != NULL) {
        conn->prev->next = conn->next;
    } else if (inbound->connections == conn) {
        inbound->connections = conn->next;
    }
    if (conn->next != NULL) {
        conn->next->prev = conn->prev;
    }
    conn->prev = NULL;
    conn->next = NULL;
    conn->attached = 0;
}

static socks5_write_req_t *write_req_acquire(
    socks5_inbound_impl_t *inbound)
{
    socks5_write_req_t *request = inbound->free_write_reqs;
    if (request != NULL) {
        inbound->free_write_reqs = request->next_free;
        inbound->free_write_req_count--;
        memset(request, 0, sizeof(*request));
        return request;
    }
    return (socks5_write_req_t *)calloc(1u, sizeof(*request));
}

static void write_req_release(socks5_inbound_impl_t *inbound,
                              socks5_write_req_t *request)
{
    if (inbound->free_write_req_count >= SOCKS5_REQUEST_POOL_MAX_FREE) {
        free(request);
        return;
    }
    request->next_free = inbound->free_write_reqs;
    inbound->free_write_reqs = request;
    inbound->free_write_req_count++;
}

static socks5_udp_send_req_t *udp_send_req_acquire(
    socks5_inbound_impl_t *inbound)
{
    socks5_udp_send_req_t *request = inbound->free_udp_send_reqs;
    if (request != NULL) {
        inbound->free_udp_send_reqs = request->next_free;
        inbound->free_udp_send_req_count--;
        memset(request, 0, sizeof(*request));
        return request;
    }
    return (socks5_udp_send_req_t *)calloc(1u, sizeof(*request));
}

static void udp_send_req_release(socks5_inbound_impl_t *inbound,
                                 socks5_udp_send_req_t *request)
{
    if (inbound->free_udp_send_req_count >= SOCKS5_REQUEST_POOL_MAX_FREE) {
        free(request);
        return;
    }
    request->next_free = inbound->free_udp_send_reqs;
    inbound->free_udp_send_reqs = request;
    inbound->free_udp_send_req_count++;
}

static void write_cb(uv_write_t *req, int status)
{
    socks5_write_req_t *write_req = (socks5_write_req_t *)req;
    socks5_conn_t *conn = (socks5_conn_t *)req->data;
    for (unsigned int i = 0u; i < write_req->nbufs; i++) {
        aproxy_bufpool_release(write_req->pool,
                               (uint8_t *)write_req->bufs[i].base,
                               write_req->capacities[i]);
    }
    const int close_after = write_req->close_after;
    socks5_inbound_impl_t *inbound = write_req->inbound;
    if (conn->writes_pending > 0u) {
        conn->writes_pending--;
    }
    conn->write_bytes_pending =
        conn->write_bytes_pending >= write_req->length
            ? conn->write_bytes_pending - write_req->length
            : 0u;
    write_req_release(inbound, write_req);
    if (status != 0 || close_after) {
        conn_close(conn);
    }
    conn_maybe_free(conn);
}

static int client_write_copy(socks5_conn_t *conn,
                             const uint8_t *data,
                             size_t len,
                             int close_after)
{
    if (conn == NULL || (data == NULL && len > 0u) ||
        conn->state == SOCKS5_STATE_CLOSING) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    if (len > UINT_MAX) {
        return APROXY_ERR_FRAME_TOO_LARGE;
    }
    int written = UV_EAGAIN;
    if (conn->writes_pending == 0u) {
        uv_buf_t direct =
            uv_buf_init((char *)(uintptr_t)data, (unsigned int)len);
        written = uv_try_write((uv_stream_t *)&conn->client, &direct, 1u);
    }
    if (written == (int)len) {
        if (close_after) {
            conn_close(conn);
        }
        return APROXY_OK;
    }
    size_t offset = 0u;
    if (written > 0) {
        offset = (size_t)written;
    } else if (written != UV_EAGAIN && written != UV_ENOSYS) {
        return written;
    }
    socks5_write_req_t *req = write_req_acquire(conn->inbound);
    if (req == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    req->pool = &conn->inbound->bufpool;
    req->inbound = conn->inbound;
    const size_t pending = len - offset;
    if (aproxy_size_add_exceeds(conn->write_bytes_pending, pending,
                                conn->inbound->stream_pending_limit)) {
        write_req_release(conn->inbound, req);
        return APROXY_ERR_FRAME_TOO_LARGE;
    }
    req->bufs[0].base =
        (char *)aproxy_bufpool_acquire(req->pool, pending == 0u ? 1u : pending,
                                       &req->capacities[0]);
    if (req->bufs[0].base == NULL) {
        write_req_release(conn->inbound, req);
        return APROXY_ERR_NO_MEMORY;
    }
    if (pending > 0u) {
        memcpy(req->bufs[0].base, data + offset, pending);
    }
    req->bufs[0].len = pending;
    req->nbufs = 1u;
    req->close_after = close_after;
    req->length = pending;
    req->req.data = conn;
    const int rc = uv_write(&req->req, (uv_stream_t *)&conn->client,
                            req->bufs, req->nbufs, write_cb);
    if (rc != 0) {
        aproxy_bufpool_release(req->pool, (uint8_t *)req->bufs[0].base,
                               req->capacities[0]);
        write_req_release(conn->inbound, req);
        return rc;
    }
    conn->writes_pending++;
    conn->write_bytes_pending += pending;
    return APROXY_OK;
}

static int send_method_reply(socks5_conn_t *conn, uint8_t method)
{
    const uint8_t reply[2] = {SOCKS5_VERSION, method};
    return client_write_copy(conn, reply, sizeof(reply),
                             method == SOCKS5_METHOD_NO_ACCEPTABLE);
}

static int send_socks_reply(socks5_conn_t *conn,
                            uint8_t rep,
                            const aproxy_addr_t *bind_addr,
                            int close_after)
{
    aproxy_addr_t zero_addr;
    if (bind_addr == NULL) {
        const uint8_t zero_ip[4] = {0u, 0u, 0u, 0u};
        aproxy_addr_set_ipv4(&zero_addr, zero_ip, 0u);
        bind_addr = &zero_addr;
    }

    uint8_t reply[3u + APROXY_ADDR_MAX_ENCODED];
    size_t addr_len = 0u;
    reply[0] = SOCKS5_VERSION;
    reply[1] = rep;
    reply[2] = 0x00u;
    const int rc = aproxy_addr_encode_socksaddr(
        bind_addr, reply + 3u, sizeof(reply) - 3u, &addr_len);
    if (rc != APROXY_OK) {
        return rc;
    }
    return client_write_copy(conn, reply, 3u + addr_len, close_after);
}

static int send_connect_reply(socks5_conn_t *conn, uint8_t rep, int close_after)
{
    return send_socks_reply(conn, rep, NULL, close_after);
}

static void alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf)
{
    (void)suggested_size;
    socks5_conn_t *conn = (socks5_conn_t *)handle->data;
    if (conn == NULL || conn->inbound == NULL) {
        buf->base = NULL;
        buf->len = 0u;
        return;
    }
    size_t capacity = 0u;
    aproxy_bufpool_t *pool = &conn->inbound->bufpool;
    size_t size = 16384u;
    const int is_udp = handle == (uv_handle_t *)&conn->udp;
    const int udp_batch = is_udp && uv_udp_using_recvmmsg(&conn->udp);
    if (is_udp) {
        if (conn->udp_recv_buffer != NULL) {
            aproxy_bufpool_release(conn->udp_recv_pool,
                                   conn->udp_recv_buffer,
                                   conn->udp_recv_capacity);
            conn->udp_recv_buffer = NULL;
            conn->udp_recv_capacity = 0u;
            conn->udp_recv_pool = NULL;
        }
        if (udp_batch) {
            pool = &conn->inbound->udp_batch_pool;
            size = SOCKS5_UDP_RECV_BATCH_BYTES;
        } else {
            pool = &conn->inbound->udp_read_pool;
            size = SOCKS5_UDP_DATAGRAM_BYTES;
        }
    }
    uint8_t *data = aproxy_bufpool_acquire(pool, size, &capacity);
    if (data == NULL && udp_batch) {
        pool = &conn->inbound->udp_read_pool;
        data = aproxy_bufpool_acquire(pool, SOCKS5_UDP_DATAGRAM_BYTES,
                                      &capacity);
    }
    if (is_udp) {
        conn->udp_recv_buffer = data;
        conn->udp_recv_capacity = capacity;
        conn->udp_recv_pool = data == NULL ? NULL : pool;
    }
    buf->base = (char *)data;
    buf->len = capacity;
}

static void udp_recv_buffer_release(socks5_conn_t *conn)
{
    if (conn == NULL || conn->udp_recv_buffer == NULL) {
        return;
    }
    aproxy_bufpool_release(conn->udp_recv_pool, conn->udp_recv_buffer,
                           conn->udp_recv_capacity);
    conn->udp_recv_buffer = NULL;
    conn->udp_recv_capacity = 0u;
    conn->udp_recv_pool = NULL;
}

static int flush_rx_to_outbound(socks5_conn_t *conn)
{
    if (conn == NULL || conn->outbound_stream == NULL) {
        return APROXY_OK;
    }
    while (aproxy_ring_size(&conn->rx) > 0u) {
        aproxy_const_span_t spans[2];
        const size_t count = aproxy_ring_read_spans(&conn->rx, spans);
        if (count == 0u) {
            return APROXY_OK;
        }
        size_t total = 0u;
        for (size_t i = 0u; i < count; i++) {
            const int rc = aproxy_stream_write(conn->outbound_stream,
                                               spans[i].data, spans[i].len);
            if (rc != APROXY_OK) {
                return rc;
            }
            total += spans[i].len;
        }
        aproxy_ring_consume(&conn->rx, total);
    }
    return APROXY_OK;
}

static int flush_udp_pending_to_outbound(socks5_conn_t *conn)
{
    if (conn == NULL || conn->outbound_stream == NULL ||
        !conn->udp_stream_open) {
        return APROXY_OK;
    }
    while (aproxy_ring_size(&conn->udp_pending_tx) > 0u) {
        aproxy_const_span_t spans[2];
        const size_t count =
            aproxy_ring_read_spans(&conn->udp_pending_tx, spans);
        if (count == 0u) {
            return APROXY_OK;
        }
        size_t total = 0u;
        for (size_t i = 0u; i < count; i++) {
            const int rc = aproxy_stream_write(conn->outbound_stream,
                                               spans[i].data, spans[i].len);
            if (rc != APROXY_OK) {
                return rc;
            }
            total += spans[i].len;
        }
        aproxy_ring_consume(&conn->udp_pending_tx, total);
    }
    return APROXY_OK;
}

static int udp_pending_has_capacity(const socks5_conn_t *conn, size_t append_len)
{
    if (conn == NULL) {
        return 0;
    }
    const size_t limit = conn->inbound->udp_pending_tx_limit;
    const size_t pending = aproxy_ring_size(&conn->udp_pending_tx);
    return append_len <= limit && pending <= limit - append_len;
}

static int socks_udp_is_fragment(const uint8_t *data, size_t len)
{
    return len >= 3u && data[0] == 0u && data[1] == 0u && data[2] != 0u;
}

static int sockaddr_equal(const struct sockaddr *a, const struct sockaddr *b)
{
    if (a == NULL || b == NULL || a->sa_family != b->sa_family) {
        return 0;
    }
    if (a->sa_family == AF_INET) {
        const struct sockaddr_in *ia = (const struct sockaddr_in *)a;
        const struct sockaddr_in *ib = (const struct sockaddr_in *)b;
        return ia->sin_port == ib->sin_port &&
               ia->sin_addr.s_addr == ib->sin_addr.s_addr;
    }
    if (a->sa_family == AF_INET6) {
        const struct sockaddr_in6 *ia = (const struct sockaddr_in6 *)a;
        const struct sockaddr_in6 *ib = (const struct sockaddr_in6 *)b;
        return ia->sin6_port == ib->sin6_port &&
               memcmp(&ia->sin6_addr, &ib->sin6_addr,
                      sizeof(ia->sin6_addr)) == 0;
    }
    return 0;
}

static void sockaddr_store(struct sockaddr_storage *storage,
                           const struct sockaddr *addr)
{
    if (storage == NULL || addr == NULL) {
        return;
    }
    memset(storage, 0, sizeof(*storage));
    if (addr->sa_family == AF_INET) {
        memcpy(storage, addr, sizeof(struct sockaddr_in));
    } else if (addr->sa_family == AF_INET6) {
        memcpy(storage, addr, sizeof(struct sockaddr_in6));
    }
}

static int parse_socks_udp_packet(const uint8_t *data,
                                  size_t len,
                                  aproxy_addr_t *destination,
                                  const uint8_t **payload,
                                  size_t *payload_len)
{
    if (data == NULL || destination == NULL || payload == NULL ||
        payload_len == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    *payload = NULL;
    *payload_len = 0u;
    if (len < 4u) {
        return APROXY_ERR_BUFFER_TOO_SMALL;
    }
    if (data[0] != 0u || data[1] != 0u) {
        return APROXY_ERR_INVALID_FRAME;
    }
    if (data[2] != 0u) {
        return APROXY_ERR_UNSUPPORTED;
    }

    size_t consumed = 0u;
    const int rc = aproxy_addr_decode_socksaddr(data + 3u, len - 3u,
                                                destination, &consumed);
    if (rc != APROXY_OK) {
        return rc;
    }
    if (3u + consumed > len) {
        return APROXY_ERR_BUFFER_TOO_SMALL;
    }
    *payload = data + 3u + consumed;
    *payload_len = len - 3u - consumed;
    return APROXY_OK;
}

static void udp_send_cb(uv_udp_send_t *req, int status)
{
    socks5_udp_send_req_t *send_req = (socks5_udp_send_req_t *)req;
    if (send_req->inbound != NULL) {
        if (send_req->inbound->udp_stats.send_in_flight > 0u) {
            send_req->inbound->udp_stats.send_in_flight--;
        }
        if (status != 0) {
            send_req->inbound->udp_stats.send_errors++;
        }
    }
    aproxy_bufpool_release(send_req->pool, (uint8_t *)send_req->buf.base,
                           send_req->capacity);
    udp_send_req_release(send_req->inbound, send_req);
}

static int send_socks_udp_packet_from_ring(socks5_conn_t *conn,
                                           const aproxy_addr_t *destination,
                                           const aproxy_ring_t *payload_ring,
                                           size_t payload_offset,
                                           size_t payload_len)
{
    if (conn == NULL || destination == NULL ||
        (payload_ring == NULL && payload_len > 0u) ||
        !conn->udp_initialized || !conn->udp_client_addr_set ||
        conn->state == SOCKS5_STATE_CLOSING) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }

    size_t addr_len = 0u;
    uint8_t header[3u + APROXY_ADDR_MAX_ENCODED];
    header[0] = 0u;
    header[1] = 0u;
    header[2] = 0u;
    int rc = aproxy_addr_encode_socksaddr(destination, header + 3u,
                                          sizeof(header) - 3u, &addr_len);
    if (rc != APROXY_OK) {
        return rc;
    }

    const size_t packet_len = 3u + addr_len + payload_len;
    uv_buf_t direct[3];
    unsigned int direct_count = 1u;
    direct[0] = uv_buf_init((char *)header, (unsigned int)(3u + addr_len));
    if (payload_len > 0u) {
        aproxy_const_span_t spans[2];
        const size_t count = aproxy_ring_read_spans_at(
            payload_ring, payload_offset, payload_len, spans);
        if (count == 0u) {
            return APROXY_ERR_INVALID_FRAME;
        }
        for (size_t i = 0u; i < count; i++) {
            direct[direct_count++] = uv_buf_init(
                (char *)(uintptr_t)spans[i].data, (unsigned int)spans[i].len);
        }
    }
    rc = uv_udp_try_send(&conn->udp, direct, direct_count,
                         (const struct sockaddr *)&conn->udp_client_addr);
    if (rc >= 0) {
        if ((size_t)rc != packet_len) {
            conn->inbound->udp_stats.send_errors++;
            return APROXY_ERR_INVALID_FRAME;
        }
        conn->inbound->udp_stats.packets_sent++;
        conn->inbound->udp_stats.bytes_sent += payload_len;
        return APROXY_OK;
    }
    if (rc != UV_EAGAIN && rc != UV_ENOSYS) {
        conn->inbound->udp_stats.send_errors++;
        return rc;
    }

    socks5_udp_send_req_t *req = udp_send_req_acquire(conn->inbound);
    if (req == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    req->pool = &conn->inbound->bufpool;
    req->inbound = conn->inbound;
    req->buf.base = (char *)aproxy_bufpool_acquire(req->pool, packet_len,
                                                   &req->capacity);
    if (req->buf.base == NULL) {
        udp_send_req_release(conn->inbound, req);
        return APROXY_ERR_NO_MEMORY;
    }
    req->buf.len = packet_len;
    uint8_t *out = (uint8_t *)req->buf.base;
    memcpy(out, header, 3u + addr_len);
    if (payload_len > 0u &&
        aproxy_ring_peek(payload_ring, payload_offset, out + 3u + addr_len,
                         payload_len) != payload_len) {
        aproxy_bufpool_release(req->pool, (uint8_t *)req->buf.base,
                               req->capacity);
        udp_send_req_release(conn->inbound, req);
        return APROXY_ERR_INVALID_FRAME;
    }

    rc = uv_udp_send(&req->req, &conn->udp, &req->buf, 1u,
                     (const struct sockaddr *)&conn->udp_client_addr,
                     udp_send_cb);
    if (rc != 0) {
        conn->inbound->udp_stats.send_errors++;
        aproxy_bufpool_release(req->pool, (uint8_t *)req->buf.base,
                               req->capacity);
        udp_send_req_release(conn->inbound, req);
        return rc;
    }
    conn->inbound->udp_stats.packets_sent++;
    conn->inbound->udp_stats.bytes_sent += payload_len;
    conn->inbound->udp_stats.send_in_flight++;
    if (conn->inbound->udp_stats.send_in_flight >
        conn->inbound->udp_stats.send_in_flight_peak) {
        conn->inbound->udp_stats.send_in_flight_peak =
            conn->inbound->udp_stats.send_in_flight;
    }
    return APROXY_OK;
}

static int process_udp_stream_rx(socks5_conn_t *conn)
{
    if (conn == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    for (;;) {
        const size_t buffered = aproxy_ring_size(&conn->udp_stream_rx);
        if (buffered == 0u) {
            return APROXY_OK;
        }

        uint8_t header[APROXY_UOT_MAX_PACKET_HEADER];
        const size_t header_probe =
            buffered < sizeof(header) ? buffered : sizeof(header);
        if (aproxy_ring_peek(&conn->udp_stream_rx, 0u, header,
                             header_probe) != header_probe) {
            return APROXY_ERR_INVALID_FRAME;
        }

        aproxy_addr_t destination;
        uint16_t payload_len = 0u;
        size_t header_len = 0u;
        const int rc = aproxy_uot_decode_packet_header(
            conn->inbound->udp_uot_version, 0, header, header_probe,
            &destination, &payload_len, &header_len);
        if (rc == APROXY_ERR_BUFFER_TOO_SMALL) {
            return APROXY_OK;
        }
        if (rc != APROXY_OK) {
            return rc;
        }
        if (buffered < header_len + payload_len) {
            return APROXY_OK;
        }

        const int send_rc = send_socks_udp_packet_from_ring(
            conn, &destination, &conn->udp_stream_rx, header_len, payload_len);
        if (send_rc != APROXY_OK) {
            return send_rc;
        }
        aproxy_ring_consume(&conn->udp_stream_rx, header_len + payload_len);
    }
}

static void outbound_data_cb(aproxy_stream_t *stream,
                             const uint8_t *data,
                             size_t len,
                             void *user_data)
{
    (void)stream;
    socks5_conn_t *conn = (socks5_conn_t *)user_data;
    if (conn == NULL || conn->state == SOCKS5_STATE_CLOSING) {
        return;
    }
    if (conn->state == SOCKS5_STATE_UDP_ASSOCIATE) {
        const size_t buffered = aproxy_ring_size(&conn->udp_stream_rx);
        const size_t limit = conn->inbound->udp_stream_rx_limit;
        if (len > limit || buffered > limit - len) {
            conn->inbound->udp_stats.rx_limit_closes++;
            conn_close(conn);
            return;
        }
        if (aproxy_ring_write(&conn->udp_stream_rx, data, len) != APROXY_OK ||
            process_udp_stream_rx(conn) != APROXY_OK) {
            conn_close(conn);
        }
        return;
    }
    if (client_write_copy(conn, data, len, 0) != APROXY_OK) {
        conn_close(conn);
    }
}

static void outbound_open_cb(aproxy_stream_t *stream, int status, void *user_data)
{
    (void)stream;
    socks5_conn_t *conn = (socks5_conn_t *)user_data;
    if (conn == NULL || conn->state == SOCKS5_STATE_CLOSING) {
        return;
    }
    if (status != APROXY_OK) {
        if (conn->state == SOCKS5_STATE_UDP_ASSOCIATE) {
            conn_close(conn);
            return;
        }
        (void)send_connect_reply(conn, SOCKS5_REP_GENERAL_FAILURE, 1);
        return;
    }
    if (conn->outbound_stream == NULL) {
        conn->outbound_stream = stream;
    }
    if (conn->state == SOCKS5_STATE_UDP_ASSOCIATE) {
        conn->udp_stream_open = 1;
        if (flush_udp_pending_to_outbound(conn) != APROXY_OK) {
            conn_close(conn);
        }
        return;
    }
    conn->state = SOCKS5_STATE_RELAY;
    if (send_connect_reply(conn, SOCKS5_REP_SUCCEEDED, 0) != APROXY_OK ||
        flush_rx_to_outbound(conn) != APROXY_OK) {
        conn_close(conn);
    }
}

static void outbound_close_cb(aproxy_stream_t *stream,
                              int status,
                              void *user_data)
{
    (void)status;
    socks5_conn_t *conn = (socks5_conn_t *)user_data;
    if (conn == NULL) {
        return;
    }
    if (conn->outbound_stream == stream) {
        conn->outbound_stream = NULL;
        aproxy_stream_free(stream);
    }
    conn_close(conn);
}

static int parse_greeting(socks5_conn_t *conn)
{
    if (aproxy_ring_size(&conn->rx) < 2u) {
        return APROXY_OK;
    }
    uint8_t ver = 0u;
    uint8_t nmethods = 0u;
    aproxy_ring_peek_byte(&conn->rx, 0u, &ver);
    aproxy_ring_peek_byte(&conn->rx, 1u, &nmethods);
    if (ver != SOCKS5_VERSION) {
        conn_close(conn);
        return APROXY_ERR_PARSE;
    }
    const size_t need = 2u + nmethods;
    if (aproxy_ring_size(&conn->rx) < need) {
        return APROXY_OK;
    }
    int has_no_auth = 0;
    for (size_t i = 0u; i < nmethods; i++) {
        uint8_t method = 0u;
        aproxy_ring_peek_byte(&conn->rx, 2u + i, &method);
        if (method == SOCKS5_METHOD_NO_AUTH) {
            has_no_auth = 1;
            break;
        }
    }
    aproxy_ring_consume(&conn->rx, need);
    if (!has_no_auth) {
        (void)send_method_reply(conn, SOCKS5_METHOD_NO_ACCEPTABLE);
        return APROXY_OK;
    }
    conn->state = SOCKS5_STATE_REQUEST;
    return send_method_reply(conn, SOCKS5_METHOD_NO_AUTH);
}

static int parse_request_destination(socks5_conn_t *conn,
                                     size_t *request_len,
                                     uint8_t *command,
                                     uint8_t *failure_rep)
{
    uint8_t header[4];
    if (aproxy_ring_peek(&conn->rx, 0u, header, sizeof(header)) !=
        sizeof(header)) {
        return APROXY_ERR_BUFFER_TOO_SMALL;
    }
    if (header[0] != SOCKS5_VERSION) {
        *failure_rep = SOCKS5_REP_GENERAL_FAILURE;
        return APROXY_ERR_PARSE;
    }
    if (header[2] != 0u) {
        *failure_rep = SOCKS5_REP_GENERAL_FAILURE;
        return APROXY_ERR_PARSE;
    }
    if (header[1] != SOCKS5_CMD_CONNECT &&
        header[1] != SOCKS5_CMD_UDP_ASSOCIATE) {
        *failure_rep = SOCKS5_REP_COMMAND_NOT_SUPPORTED;
        return APROXY_ERR_UNSUPPORTED;
    }
    *command = header[1];

    size_t pos = 4u;
    switch (header[3]) {
    case SOCKS5_ATYP_IPV4: {
        if (aproxy_ring_size(&conn->rx) < pos + 4u + 2u) {
            return APROXY_ERR_BUFFER_TOO_SMALL;
        }
        uint8_t ip[4];
        uint8_t port_bytes[2];
        aproxy_ring_peek(&conn->rx, pos, ip, sizeof(ip));
        pos += 4u;
        aproxy_ring_peek(&conn->rx, pos, port_bytes, sizeof(port_bytes));
        pos += 2u;
        aproxy_addr_set_ipv4(&conn->destination, ip,
                             (uint16_t)(((uint16_t)port_bytes[0] << 8) |
                                        port_bytes[1]));
        *request_len = pos;
        return APROXY_OK;
    }
    case SOCKS5_ATYP_IPV6: {
        if (aproxy_ring_size(&conn->rx) < pos + 16u + 2u) {
            return APROXY_ERR_BUFFER_TOO_SMALL;
        }
        uint8_t ip[16];
        uint8_t port_bytes[2];
        aproxy_ring_peek(&conn->rx, pos, ip, sizeof(ip));
        pos += 16u;
        aproxy_ring_peek(&conn->rx, pos, port_bytes, sizeof(port_bytes));
        pos += 2u;
        aproxy_addr_set_ipv6(&conn->destination, ip,
                             (uint16_t)(((uint16_t)port_bytes[0] << 8) |
                                        port_bytes[1]));
        *request_len = pos;
        return APROXY_OK;
    }
    case SOCKS5_ATYP_DOMAIN: {
        uint8_t domain_len = 0u;
        if (aproxy_ring_size(&conn->rx) < pos + 1u) {
            return APROXY_ERR_BUFFER_TOO_SMALL;
        }
        aproxy_ring_peek_byte(&conn->rx, pos, &domain_len);
        pos++;
        if (domain_len == 0u) {
            *failure_rep = SOCKS5_REP_GENERAL_FAILURE;
            return APROXY_ERR_PARSE;
        }
        if (aproxy_ring_size(&conn->rx) < pos + domain_len + 2u) {
            return APROXY_ERR_BUFFER_TOO_SMALL;
        }
        char domain[APROXY_ADDR_MAX_FQDN + 1u];
        uint8_t port_bytes[2];
        aproxy_ring_peek(&conn->rx, pos, (uint8_t *)domain, domain_len);
        domain[domain_len] = '\0';
        pos += domain_len;
        aproxy_ring_peek(&conn->rx, pos, port_bytes, sizeof(port_bytes));
        pos += 2u;
        const int rc = aproxy_addr_set_fqdn(
            &conn->destination, domain,
            (uint16_t)(((uint16_t)port_bytes[0] << 8) | port_bytes[1]));
        if (rc != APROXY_OK) {
            *failure_rep = SOCKS5_REP_GENERAL_FAILURE;
            return rc;
        }
        *request_len = pos;
        return APROXY_OK;
    }
    default:
        *failure_rep = SOCKS5_REP_ADDRESS_TYPE_NOT_SUPPORTED;
        return APROXY_ERR_UNSUPPORTED;
    }
}

static int start_udp_associate(socks5_conn_t *conn)
{
    if (conn == NULL || conn->udp_initialized) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }

    int rc = uv_udp_init_ex(conn->inbound->loop, &conn->udp,
                            AF_INET | UV_UDP_RECVMMSG);
    if (rc != 0) {
        return rc;
    }
    conn->udp_initialized = 1;
    conn->udp.data = conn;

    struct sockaddr_in bind_addr;
    rc = uv_ip4_addr(conn->inbound->listen_host, 0, &bind_addr);
    if (rc != 0) {
        return rc;
    }
    rc = uv_udp_bind(&conn->udp, (const struct sockaddr *)&bind_addr, 0u);
    if (rc != 0) {
        return rc;
    }
    return APROXY_OK;
}

static void udp_recv_cb(uv_udp_t *handle,
                        ssize_t nread,
                        const uv_buf_t *buf,
                        const struct sockaddr *addr,
                        unsigned int flags);

static int start_udp_recv(socks5_conn_t *conn)
{
    if (conn == NULL || !conn->udp_initialized) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    const int rc = uv_udp_recv_start(&conn->udp, alloc_cb, udp_recv_cb);
    return rc == 0 ? APROXY_OK : rc;
}

static int send_udp_associate_reply(socks5_conn_t *conn)
{
    if (conn == NULL || !conn->udp_initialized) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    struct sockaddr_in bound;
    int bound_len = sizeof(bound);
    int rc = uv_udp_getsockname(&conn->udp, (struct sockaddr *)&bound,
                                &bound_len);
    if (rc != 0) {
        return rc;
    }
    aproxy_addr_t reply_addr;
    uint8_t ip[4];
    memcpy(ip, &bound.sin_addr.s_addr, sizeof(ip));
    aproxy_addr_set_ipv4(&reply_addr, ip, ntohs(bound.sin_port));
    return send_socks_reply(conn, SOCKS5_REP_SUCCEEDED, &reply_addr, 0);
}

static int open_tcp_outbound(socks5_conn_t *conn,
                             aproxy_outbound_t *outbound)
{
    if (outbound == NULL) {
        (void)send_connect_reply(conn, SOCKS5_REP_GENERAL_FAILURE, 1);
        return APROXY_OK;
    }
    conn->state = SOCKS5_STATE_CONNECTING;
    const int rc = aproxy_outbound_open_stream(
        outbound, &conn->destination, outbound_data_cb, outbound_open_cb,
        outbound_close_cb, conn, &conn->outbound_stream);
    if (rc != APROXY_OK) {
        const uint8_t reply = rc == APROXY_ERR_UNSUPPORTED
                                  ? SOCKS5_REP_CONNECTION_NOT_ALLOWED
                                  : SOCKS5_REP_GENERAL_FAILURE;
        (void)send_connect_reply(conn, reply, 1);
        return APROXY_OK;
    }
    if (conn->state == SOCKS5_STATE_RELAY &&
        flush_rx_to_outbound(conn) != APROXY_OK) {
        conn_close(conn);
    }
    return APROXY_OK;
}

static void tcp_route_result_cb(aproxy_dns_resolver_t *resolver,
                                int status,
                                const aproxy_addr_t *addresses,
                                size_t count,
                                void *user_data)
{
    (void)resolver;
    socks5_conn_t *conn = (socks5_conn_t *)user_data;
    if (conn == NULL || !conn->tcp_route_pending) {
        return;
    }
    if (conn->state != SOCKS5_STATE_CLOSING) {
        aproxy_outbound_t *outbound = aproxy_router_pick_resolved(
            conn->inbound->router, &conn->destination,
            status == APROXY_OK ? addresses : NULL,
            status == APROXY_OK ? count : 0u);
        (void)open_tcp_outbound(conn, outbound);
    }
    conn->tcp_route_pending = 0;
    conn_maybe_free(conn);
}

static int parse_request(socks5_conn_t *conn)
{
    if (aproxy_ring_size(&conn->rx) < 4u) {
        return APROXY_OK;
    }

    size_t request_len = 0u;
    uint8_t command = 0u;
    uint8_t failure_rep = SOCKS5_REP_GENERAL_FAILURE;
    int rc = parse_request_destination(conn, &request_len, &command,
                                       &failure_rep);
    if (rc == APROXY_ERR_BUFFER_TOO_SMALL) {
        return APROXY_OK;
    }
    if (rc != APROXY_OK) {
        (void)send_connect_reply(conn, failure_rep, 1);
        return APROXY_OK;
    }
    aproxy_ring_consume(&conn->rx, request_len);

    if (command == SOCKS5_CMD_UDP_ASSOCIATE) {
        conn->state = SOCKS5_STATE_UDP_ASSOCIATE;
        rc = start_udp_associate(conn);
        if (rc == APROXY_OK) {
            rc = start_udp_recv(conn);
        }
        if (rc == APROXY_OK) {
            rc = send_udp_associate_reply(conn);
        }
        if (rc != APROXY_OK) {
            (void)send_connect_reply(conn, SOCKS5_REP_GENERAL_FAILURE, 1);
        }
        return APROXY_OK;
    }

    if (conn->inbound->resolver != NULL &&
        aproxy_router_needs_resolution(conn->inbound->router,
                                       &conn->destination)) {
        conn->state = SOCKS5_STATE_ROUTING;
        conn->tcp_route_pending = 1;
        rc = aproxy_dns_resolve(conn->inbound->resolver,
                                conn->destination.fqdn,
                                conn->destination.port,
                                tcp_route_result_cb, conn);
        if (rc != APROXY_OK) {
            conn->tcp_route_pending = 0;
            (void)send_connect_reply(conn, SOCKS5_REP_GENERAL_FAILURE, 1);
        }
        return APROXY_OK;
    }
    return open_tcp_outbound(
        conn, aproxy_router_pick(conn->inbound->router,
                                 &conn->destination));
}

static int process_rx(socks5_conn_t *conn)
{
    for (;;) {
        const socks5_state_t before = conn->state;
        int rc = APROXY_OK;
        switch (conn->state) {
        case SOCKS5_STATE_GREETING:
            rc = parse_greeting(conn);
            break;
        case SOCKS5_STATE_REQUEST:
            rc = parse_request(conn);
            break;
        case SOCKS5_STATE_RELAY:
            return flush_rx_to_outbound(conn);
        case SOCKS5_STATE_UDP_ASSOCIATE:
            aproxy_ring_clear(&conn->rx);
            return APROXY_OK;
        case SOCKS5_STATE_ROUTING:
        case SOCKS5_STATE_CONNECTING:
        case SOCKS5_STATE_CLOSING:
            return APROXY_OK;
        }
        if (rc != APROXY_OK || conn->state == before) {
            return rc;
        }
    }
}

static void conn_close_cb(uv_handle_t *handle)
{
    socks5_conn_t *conn = (socks5_conn_t *)handle->data;
    if (conn == NULL) {
        return;
    }
    conn->client_closed = 1;
    conn_maybe_free(conn);
}

static void udp_close_cb(uv_handle_t *handle)
{
    socks5_conn_t *conn = (socks5_conn_t *)handle->data;
    if (conn == NULL) {
        return;
    }
    conn->udp_closed = 1;
    conn_maybe_free(conn);
}

static void conn_maybe_free(socks5_conn_t *conn)
{
    if (conn == NULL) {
        return;
    }
    if (conn->client_initialized && !conn->client_closed) {
        return;
    }
    if (conn->udp_initialized && !conn->udp_closed) {
        return;
    }
    if (conn->writes_pending > 0u) {
        return;
    }
    if (conn->tcp_route_pending || conn->udp_route_pending) {
        return;
    }
    socks5_inbound_impl_t *inbound = conn->inbound;
    udp_recv_buffer_release(conn);
    conn_list_remove(conn);
    if (inbound->connections == NULL) {
        aproxy_bufpool_trim(&inbound->udp_read_pool);
        aproxy_bufpool_trim(&inbound->udp_batch_pool);
    }
    aproxy_ring_free(&conn->rx);
    aproxy_ring_free(&conn->udp_stream_rx);
    aproxy_ring_free(&conn->udp_pending_tx);
    free(conn);
    socks5_impl_maybe_free(inbound);
}

static void conn_close(socks5_conn_t *conn)
{
    if (conn == NULL || conn->state == SOCKS5_STATE_CLOSING) {
        return;
    }
    conn->state = SOCKS5_STATE_CLOSING;
    if (conn->outbound_stream != NULL) {
        aproxy_stream_t *stream = conn->outbound_stream;
        conn->outbound_stream = NULL;
        (void)aproxy_stream_close(stream);
        aproxy_stream_free(stream);
    }
    if (conn->udp_initialized && !conn->udp_closed &&
        !uv_is_closing((uv_handle_t *)&conn->udp)) {
        uv_udp_recv_stop(&conn->udp);
        uv_close((uv_handle_t *)&conn->udp, udp_close_cb);
    } else if (!conn->udp_initialized) {
        conn->udp_closed = 1;
    }
    if (conn->client_initialized &&
        !uv_is_closing((uv_handle_t *)&conn->client)) {
        uv_close((uv_handle_t *)&conn->client, conn_close_cb);
    } else if (!conn->client_initialized) {
        conn->client_closed = 1;
    }
    conn_maybe_free(conn);
}

static void read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf)
{
    socks5_conn_t *conn = (socks5_conn_t *)stream->data;
    if (nread > 0) {
        if (conn->state == SOCKS5_STATE_RELAY &&
            conn->outbound_stream != NULL) {
            if (aproxy_stream_write(conn->outbound_stream,
                                    (const uint8_t *)buf->base,
                                    (size_t)nread) != APROXY_OK) {
                conn_close(conn);
            }
        } else {
            const size_t length = (size_t)nread;
            if (aproxy_size_add_exceeds(aproxy_ring_size(&conn->rx), length,
                                        conn->inbound->stream_pending_limit) ||
                aproxy_ring_write(&conn->rx, (const uint8_t *)buf->base,
                                  length) != APROXY_OK ||
                process_rx(conn) != APROXY_OK) {
                conn_close(conn);
            }
        }
    } else if (nread < 0) {
        conn_close(conn);
    }
    aproxy_bufpool_release(&conn->inbound->bufpool, (uint8_t *)buf->base,
                           buf->len);
}

static int open_udp_uot_outbound(socks5_conn_t *conn,
                                 aproxy_outbound_t *outbound)
{
    if (conn == NULL || outbound == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    if (conn->outbound_stream != NULL) {
        return APROXY_OK;
    }

    aproxy_addr_t uot_destination;
    int rc = aproxy_uot_request_destination(conn->inbound->udp_uot_version,
                                            &uot_destination);
    if (rc != APROXY_OK) {
        return rc;
    }
    rc = aproxy_outbound_open_stream(outbound, &uot_destination,
                                     outbound_data_cb, outbound_open_cb,
                                     outbound_close_cb, conn,
                                     &conn->outbound_stream);
    if (rc != APROXY_OK) {
        return rc;
    }

    if (conn->inbound->udp_uot_version == APROXY_UOT_VERSION_1) {
        conn->udp_request_sent = 1;
    }

    return APROXY_OK;
}

static void udp_route_result_cb(aproxy_dns_resolver_t *resolver,
                                int status,
                                const aproxy_addr_t *addresses,
                                size_t count,
                                void *user_data)
{
    (void)resolver;
    socks5_conn_t *conn = (socks5_conn_t *)user_data;
    if (conn == NULL || !conn->udp_route_pending) {
        return;
    }
    if (conn->state != SOCKS5_STATE_CLOSING) {
        aproxy_outbound_t *outbound = aproxy_router_pick_resolved(
            conn->inbound->router, &conn->udp_route_destination,
            status == APROXY_OK ? addresses : NULL,
            status == APROXY_OK ? count : 0u);
        if (open_udp_uot_outbound(conn, outbound) != APROXY_OK ||
            flush_udp_pending_to_outbound(conn) != APROXY_OK) {
            conn_close(conn);
        }
    }
    conn->udp_route_pending = 0;
    conn_maybe_free(conn);
}

static int ensure_udp_uot_stream(socks5_conn_t *conn,
                                 const aproxy_addr_t *destination)
{
    if (conn == NULL || destination == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    if (conn->outbound_stream != NULL || conn->udp_route_pending) {
        return APROXY_OK;
    }
    if (conn->inbound->resolver != NULL &&
        aproxy_router_needs_resolution(conn->inbound->router,
                                       destination)) {
        conn->udp_route_destination = *destination;
        conn->udp_route_pending = 1;
        const int rc = aproxy_dns_resolve(
            conn->inbound->resolver, destination->fqdn, destination->port,
            udp_route_result_cb, conn);
        if (rc != APROXY_OK) {
            conn->udp_route_pending = 0;
        }
        return rc;
    }
    return open_udp_uot_outbound(
        conn, aproxy_router_pick(conn->inbound->router, destination));
}

static int queue_udp_packet_to_uot(socks5_conn_t *conn,
                                   const aproxy_addr_t *destination,
                                   const uint8_t *payload,
                                   size_t payload_len)
{
    if (conn == NULL || destination == NULL ||
        (payload == NULL && payload_len > 0u)) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    int rc = ensure_udp_uot_stream(conn, destination);
    if (rc != APROXY_OK) {
        return rc;
    }

    uint8_t request[APROXY_UOT_MAX_REQUEST_ENCODED];
    size_t request_len = 0u;
    if (!conn->udp_request_sent &&
        conn->inbound->udp_uot_version != APROXY_UOT_VERSION_1) {
        rc = aproxy_uot_encode_request(0, destination, request,
                                       sizeof(request), &request_len);
        if (rc != APROXY_OK) {
            return rc;
        }
    }

    uint8_t header[APROXY_UOT_MAX_PACKET_HEADER];
    size_t header_len = 0u;
    rc = aproxy_uot_encode_packet_header(conn->inbound->udp_uot_version, 0,
                                         destination, payload_len, header,
                                         sizeof(header), &header_len);
    if (rc != APROXY_OK) {
        return rc;
    }
    size_t queued_len = request_len;
    if (aproxy_size_add_exceeds(queued_len, header_len, SIZE_MAX)) {
        return APROXY_ERR_FRAME_TOO_LARGE;
    }
    queued_len += header_len;
    if (aproxy_size_add_exceeds(queued_len, payload_len, SIZE_MAX)) {
        return APROXY_ERR_FRAME_TOO_LARGE;
    }
    queued_len += payload_len;
    if (conn->udp_stream_open && conn->outbound_stream != NULL &&
        aproxy_ring_size(&conn->udp_pending_tx) == 0u) {
        if (request_len > 0u) {
            rc = aproxy_stream_write(conn->outbound_stream, request,
                                     request_len);
            if (rc != APROXY_OK) {
                return rc;
            }
            conn->udp_request_sent = 1;
        }
        rc = aproxy_stream_write(conn->outbound_stream, header, header_len);
        if (rc == APROXY_OK && payload_len > 0u) {
            rc = aproxy_stream_write(conn->outbound_stream, payload,
                                     payload_len);
        }
        if (rc != APROXY_OK) {
            return rc;
        }
        conn->inbound->udp_stats.packets_relayed++;
        conn->inbound->udp_stats.bytes_received += payload_len;
        return APROXY_OK;
    }
    if (!udp_pending_has_capacity(conn, queued_len)) {
        conn->inbound->udp_stats.dropped_pending_limit++;
        return APROXY_OK;
    }
    rc = aproxy_ring_reserve(
        &conn->udp_pending_tx,
        aproxy_ring_size(&conn->udp_pending_tx) + queued_len);
    if (rc != APROXY_OK) {
        return rc;
    }
    if (request_len > 0u) {
        rc = aproxy_ring_write(&conn->udp_pending_tx, request, request_len);
        if (rc != APROXY_OK) {
            return rc;
        }
        conn->udp_request_sent = 1;
    }
    rc = aproxy_ring_write(&conn->udp_pending_tx, header, header_len);
    if (rc == APROXY_OK && payload_len > 0u) {
        rc = aproxy_ring_write(&conn->udp_pending_tx, payload, payload_len);
    }
    if (rc != APROXY_OK) {
        return rc;
    }
    conn->inbound->udp_stats.packets_relayed++;
    conn->inbound->udp_stats.bytes_received += payload_len;
    return flush_udp_pending_to_outbound(conn);
}

static void udp_recv_cb(uv_udp_t *handle,
                        ssize_t nread,
                        const uv_buf_t *buf,
                        const struct sockaddr *addr,
                        unsigned int flags)
{
    socks5_conn_t *conn = (socks5_conn_t *)handle->data;
    if (conn == NULL) {
        if ((flags & UV_UDP_MMSG_CHUNK) == 0u) {
            free(buf->base);
        }
        return;
    }
    if ((flags & UV_UDP_MMSG_FREE) != 0u) {
        udp_recv_buffer_release(conn);
        return;
    }
    if (nread > 0) {
        conn->inbound->udp_stats.packets_received++;
    }
    if ((flags & UV_UDP_PARTIAL) != 0u) {
        /* Drop truncated datagrams; forwarding them would corrupt UoT payloads. */
        conn->inbound->udp_stats.dropped_partial++;
    } else if (nread > 0 && addr != NULL &&
        conn->state == SOCKS5_STATE_UDP_ASSOCIATE) {
        if (!conn->udp_client_addr_set) {
            sockaddr_store(&conn->udp_client_addr, addr);
            conn->udp_client_addr_set = 1;
        }
        if (sockaddr_equal((const struct sockaddr *)&conn->udp_client_addr,
                           addr)) {
            aproxy_addr_t destination;
            const uint8_t *payload = NULL;
            size_t payload_len = 0u;
            const int rc = parse_socks_udp_packet(
                (const uint8_t *)buf->base, (size_t)nread, &destination,
                &payload, &payload_len);
            if (rc == APROXY_OK &&
                queue_udp_packet_to_uot(conn, &destination, payload,
                                        payload_len) != APROXY_OK) {
                conn_close(conn);
            } else if (rc != APROXY_OK) {
                if (socks_udp_is_fragment((const uint8_t *)buf->base,
                                          (size_t)nread)) {
                    conn->inbound->udp_stats.dropped_fragments++;
                } else {
                    conn->inbound->udp_stats.dropped_invalid++;
                }
            }
        } else {
            conn->inbound->udp_stats.dropped_foreign_client++;
        }
    } else if (nread < 0) {
        conn_close(conn);
    }
    if ((flags & UV_UDP_MMSG_CHUNK) == 0u ||
        conn->state == SOCKS5_STATE_CLOSING) {
        udp_recv_buffer_release(conn);
    }
}

static void connection_cb(uv_stream_t *server, int status)
{
    if (status != 0) {
        return;
    }
    socks5_inbound_impl_t *inbound =
        (socks5_inbound_impl_t *)server->data;
    if (inbound == NULL || inbound->free_after_close || !inbound->listening) {
        return;
    }
    socks5_conn_t *conn = (socks5_conn_t *)calloc(1u, sizeof(*conn));
    if (conn == NULL) {
        return;
    }
    conn->inbound = inbound;
    conn_list_add(inbound, conn);
    conn->state = SOCKS5_STATE_GREETING;
    aproxy_ring_init(&conn->rx);
    aproxy_ring_init(&conn->udp_stream_rx);
    aproxy_ring_init(&conn->udp_pending_tx);

    if (uv_tcp_init(inbound->loop, &conn->client) != 0) {
        conn_close(conn);
        return;
    }
    conn->client_initialized = 1;
    conn->client.data = conn;

    if (uv_accept(server, (uv_stream_t *)&conn->client) != 0) {
        conn_close(conn);
        return;
    }
    if (uv_read_start((uv_stream_t *)&conn->client, alloc_cb, read_cb) != 0) {
        conn_close(conn);
    }
}

static int socks5_start(void *impl)
{
    socks5_inbound_impl_t *inbound = (socks5_inbound_impl_t *)impl;
    if (inbound == NULL || inbound->router == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    if (!inbound->server_initialized) {
        const int init_rc = uv_tcp_init(inbound->loop, &inbound->server);
        if (init_rc != 0) {
            return init_rc;
        }
        inbound->server_initialized = 1;
        inbound->server.data = inbound;
    }

    struct sockaddr_in addr;
    const int addr_rc =
        uv_ip4_addr(inbound->listen_host, (int)inbound->listen_port, &addr);
    if (addr_rc != 0) {
        return addr_rc;
    }
    int rc = uv_tcp_bind(&inbound->server, (const struct sockaddr *)&addr, 0u);
    if (rc != 0) {
        return rc;
    }
    rc = uv_listen((uv_stream_t *)&inbound->server, inbound->backlog,
                   connection_cb);
    if (rc == 0) {
        inbound->listening = 1;
    }
    return rc;
}

static void socks5_stop(void *impl)
{
    socks5_inbound_impl_t *inbound = (socks5_inbound_impl_t *)impl;
    if (inbound == NULL) {
        return;
    }
    if (inbound->server_initialized && !inbound->server_closed &&
        !uv_is_closing((uv_handle_t *)&inbound->server)) {
        inbound->server_closing = 1;
        uv_close((uv_handle_t *)&inbound->server, socks5_server_close_cb);
    }
    inbound->listening = 0;
    for (socks5_conn_t *conn = inbound->connections; conn != NULL;) {
        socks5_conn_t *next = conn->next;
        conn_close(conn);
        conn = next;
    }
}

static void socks5_server_close_cb(uv_handle_t *handle)
{
    socks5_inbound_impl_t *inbound = (socks5_inbound_impl_t *)handle->data;
    if (inbound == NULL) {
        return;
    }
    inbound->server_closed = 1;
    inbound->server_closing = 0;
    socks5_impl_maybe_free(inbound);
}

static void socks5_impl_free_now(socks5_inbound_impl_t *inbound)
{
    if (inbound == NULL) {
        return;
    }
    aproxy_bufpool_destroy(&inbound->bufpool);
    aproxy_bufpool_destroy(&inbound->udp_read_pool);
    aproxy_bufpool_destroy(&inbound->udp_batch_pool);
    while (inbound->free_write_reqs != NULL) {
        socks5_write_req_t *next = inbound->free_write_reqs->next_free;
        free(inbound->free_write_reqs);
        inbound->free_write_reqs = next;
    }
    while (inbound->free_udp_send_reqs != NULL) {
        socks5_udp_send_req_t *next =
            inbound->free_udp_send_reqs->next_free;
        free(inbound->free_udp_send_reqs);
        inbound->free_udp_send_reqs = next;
    }
    free(inbound->tag);
    free(inbound->listen_host);
    free(inbound);
}

static void socks5_impl_maybe_free(socks5_inbound_impl_t *inbound)
{
    if (inbound == NULL || !inbound->free_after_close ||
        inbound->connections != NULL ||
        (inbound->server_initialized && !inbound->server_closed)) {
        return;
    }
    socks5_impl_free_now(inbound);
}

static void socks5_free(void *impl)
{
    socks5_inbound_impl_t *inbound = (socks5_inbound_impl_t *)impl;
    if (inbound == NULL) {
        return;
    }
    inbound->free_after_close = 1;
    socks5_stop(inbound);
    socks5_impl_maybe_free(inbound);
}

static const aproxy_inbound_vtable_t socks5_vtable = {
    .start = socks5_start,
    .stop = socks5_stop,
    .free = socks5_free,
};

int aproxy_socks5_inbound_new(const aproxy_socks5_inbound_config_t *config,
                              aproxy_inbound_t **out)
{
    if (config == NULL || out == NULL || config->loop == NULL ||
        config->router == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    *out = NULL;

    socks5_inbound_impl_t *impl =
        (socks5_inbound_impl_t *)calloc(1u, sizeof(*impl));
    if (impl == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    impl->loop = config->loop;
    impl->router = config->router;
    impl->resolver = config->resolver;
    impl->listen_port = config->listen_port;
    impl->udp_uot_version =
        config->udp_uot_version == APROXY_UOT_VERSION_DEFAULT
            ? APROXY_UOT_VERSION_2
            : config->udp_uot_version;
    if (impl->udp_uot_version != APROXY_UOT_VERSION_1 &&
        impl->udp_uot_version != APROXY_UOT_VERSION_2) {
        socks5_free(impl);
        return APROXY_ERR_UNSUPPORTED;
    }
    impl->backlog = config->backlog > 0 ? config->backlog : 128;
    impl->stream_pending_limit =
        aproxy_stream_pending_limit(config->stream_pending_limit);
    impl->udp_pending_tx_limit =
        config->udp_pending_tx_limit == 0u
            ? APROXY_SOCKS5_UDP_DEFAULT_PENDING_TX_LIMIT
            : config->udp_pending_tx_limit;
    impl->udp_stream_rx_limit =
        config->udp_stream_rx_limit == 0u
            ? APROXY_SOCKS5_UDP_DEFAULT_STREAM_RX_LIMIT
            : config->udp_stream_rx_limit;
    impl->tag = copy_string(config->tag != NULL ? config->tag : "socks5");
    impl->listen_host =
        copy_string(config->listen_host != NULL ? config->listen_host
                                                : "127.0.0.1");
    aproxy_bufpool_init(&impl->bufpool, 16384u,
                        SOCKS5_READ_POOL_MAX_FREE);
    aproxy_bufpool_init(&impl->udp_read_pool, SOCKS5_UDP_DATAGRAM_BYTES,
                        SOCKS5_UDP_BATCH_POOL_MAX_FREE);
    aproxy_bufpool_init(&impl->udp_batch_pool,
                        SOCKS5_UDP_RECV_BATCH_BYTES,
                        SOCKS5_UDP_BATCH_POOL_MAX_FREE);
    if (impl->tag == NULL || impl->listen_host == NULL) {
        socks5_free(impl);
        return APROXY_ERR_NO_MEMORY;
    }

    aproxy_inbound_t *inbound =
        (aproxy_inbound_t *)calloc(1u, sizeof(*inbound));
    if (inbound == NULL) {
        socks5_free(impl);
        return APROXY_ERR_NO_MEMORY;
    }
    inbound->tag = impl->tag;
    inbound->vtable = &socks5_vtable;
    inbound->impl = impl;
    *out = inbound;
    return APROXY_OK;
}

int aproxy_socks5_inbound_get_bound_port(const aproxy_inbound_t *inbound,
                                         uint16_t *out_port)
{
    if (inbound == NULL || out_port == NULL || inbound->vtable != &socks5_vtable ||
        inbound->impl == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    socks5_inbound_impl_t *impl = (socks5_inbound_impl_t *)inbound->impl;
    struct sockaddr_in addr;
    int len = sizeof(addr);
    const int rc = uv_tcp_getsockname(&impl->server, (struct sockaddr *)&addr,
                                      &len);
    if (rc != 0) {
        return rc;
    }
    *out_port = ntohs(addr.sin_port);
    return APROXY_OK;
}

int aproxy_socks5_inbound_get_udp_stats(
    const aproxy_inbound_t *inbound,
    aproxy_socks5_udp_stats_t *out_stats)
{
    if (inbound == NULL || out_stats == NULL ||
        inbound->vtable != &socks5_vtable || inbound->impl == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    const socks5_inbound_impl_t *impl =
        (const socks5_inbound_impl_t *)inbound->impl;
    *out_stats = impl->udp_stats;
    return APROXY_OK;
}
