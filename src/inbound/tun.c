#include "aproxy/tun_inbound.h"

#include <errno.h>
#if !defined(_WIN32)
#include <fcntl.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <unistd.h>
#include <sys/uio.h>
#endif

#if defined(__linux__)
#include <arpa/inet.h>
#include <linux/if_tun.h>
#include <linux/ipv6.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#endif

#include "aproxy/bufpool.h"
#include "aproxy/ring.h"

#define TUN_READ_FALLBACK_MTU 1500u
#define TUN_WRITE_QUEUE_LIMIT (4u * 1024u * 1024u)
#define TUN_WRITE_HEADER_SIZE 4u
#define TUN_READ_BATCH_SIZE 16u
#define TUN_READ_POOL_MAX_FREE 1u

typedef struct tun_inbound_impl {
    uv_loop_t *loop;
    uv_poll_t poll;
    aproxy_inbound_t *owner;
    char *tag;
    char *requested_name;
    char actual_name[64];
    char *ipv4;
    char *ipv6;
    uint32_t mtu;
    uint8_t ipv4_prefix;
    uint8_t ipv6_prefix;
    int fd;
    int own_fd;
    int configure_device;
    int poll_initialized;
    int poll_started;
    int poll_closing;
    int free_after_close;
    int packet_io;
    int packet_started;
    aproxy_tun_session_cb on_session;
    aproxy_tun_stream_data_cb on_stream_data;
    aproxy_tun_packet_batch_cb on_packet_batch_begin;
    aproxy_tun_packet_batch_cb on_packet_batch_end;
    aproxy_tun_write_packet_cb on_write_packet;
    void *user_data;
    aproxy_tun_stats_t stats;
    aproxy_packet_session_table_t *sessions;
    aproxy_bufpool_t bufpool;
    aproxy_bufpool_t read_fallback_pool;
    aproxy_ring_t write_queue;
} tun_inbound_impl_t;

#if !defined(_WIN32)
static void tun_poll_cb(uv_poll_t *poll, int status, int events);
#endif

#if !defined(_WIN32)
static void put_u32(uint8_t out[4], uint32_t value)
{
    out[0] = (uint8_t)(value >> 24u);
    out[1] = (uint8_t)(value >> 16u);
    out[2] = (uint8_t)(value >> 8u);
    out[3] = (uint8_t)value;
}

static uint32_t get_u32(const uint8_t in[4])
{
    return ((uint32_t)in[0] << 24u) | ((uint32_t)in[1] << 16u) |
           ((uint32_t)in[2] << 8u) | (uint32_t)in[3];
}
#endif

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

#if !defined(_WIN32)
static int set_nonblocking(int fd)
{
    const int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    if ((flags & O_NONBLOCK) != 0) {
        return 0;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}
#endif

static void close_tun_fd(tun_inbound_impl_t *impl)
{
    if (impl != NULL && impl->fd >= 0 && impl->own_fd) {
#if !defined(_WIN32)
        close(impl->fd);
#endif
        impl->fd = -1;
    }
}

#if defined(__linux__)
/*
 * Linux TUN device setup is adapted from heiher/hev-socks5-tunnel
 * src/hev-tunnel-linux.c (MIT). This version is per-instance and libuv based.
 */
static int linux_copy_ifname(char destination[IFNAMSIZ], const char *name)
{
    if (destination == NULL || name == NULL) {
        return -1;
    }
    const size_t len = strnlen(name, IFNAMSIZ);
    if (len == 0u || len >= IFNAMSIZ) {
        return -1;
    }
    memcpy(destination, name, len + 1u);
    return 0;
}

static int linux_tun_open(const char *name,
                          char *actual_name,
                          size_t actual_name_size)
{
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    const int fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK);
    if (fd < 0) {
        return -1;
    }

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (name != NULL && name[0] != '\0') {
        if (linux_copy_ifname(ifr.ifr_name, name) != 0) {
            close(fd);
            return -1;
        }
    }

    if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
        close(fd);
        return -1;
    }

    snprintf(actual_name, actual_name_size, "%s", ifr.ifr_name);
    return fd;
}

static int linux_tun_set_mtu(const char *name, uint32_t mtu)
{
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_mtu = (int)mtu;
    if (linux_copy_ifname(ifr.ifr_name, name) != 0) {
        return -1;
    }

    const int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    const int rc = ioctl(fd, SIOCSIFMTU, (void *)&ifr);
    close(fd);
    return rc;
}

static int linux_tun_set_state(const char *name, int up)
{
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    if (linux_copy_ifname(ifr.ifr_name, name) != 0) {
        return -1;
    }

    const int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    int rc = ioctl(fd, SIOCGIFFLAGS, (void *)&ifr);
    if (rc == 0) {
        if (up) {
            ifr.ifr_flags |= IFF_UP;
        } else {
            ifr.ifr_flags &= (short)~IFF_UP;
        }
        rc = ioctl(fd, SIOCSIFFLAGS, (void *)&ifr);
    }
    close(fd);
    return rc;
}

static int linux_tun_set_ipv4(const char *name,
                              const char *addr,
                              uint8_t prefix)
{
    if (addr == NULL || addr[0] == '\0') {
        return 0;
    }
    if (prefix > 32u) {
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    if (linux_copy_ifname(ifr.ifr_name, name) != 0) {
        return -1;
    }

    const int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }

    struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
    sin->sin_family = AF_INET;
    int rc = inet_pton(AF_INET, addr, &sin->sin_addr);
    if (rc != 1) {
        close(fd);
        return -1;
    }
    rc = ioctl(fd, SIOCSIFADDR, (void *)&ifr);
    if (rc < 0) {
        close(fd);
        return -1;
    }

    sin = (struct sockaddr_in *)&ifr.ifr_netmask;
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr =
        prefix == 0u ? 0u : htonl(UINT32_MAX << (32u - prefix));
    rc = ioctl(fd, SIOCSIFNETMASK, (void *)&ifr);
    close(fd);
    return rc;
}

static int linux_tun_set_ipv6(const char *name,
                              const char *addr,
                              uint8_t prefix)
{
    if (addr == NULL || addr[0] == '\0') {
        return 0;
    }
    if (prefix > 128u) {
        return -1;
    }

    struct ifreq ifr;
    struct in6_ifreq ifr6;
    memset(&ifr, 0, sizeof(ifr));
    memset(&ifr6, 0, sizeof(ifr6));
    if (linux_copy_ifname(ifr.ifr_name, name) != 0) {
        return -1;
    }

    const int fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    int rc = ioctl(fd, SIOCGIFINDEX, (void *)&ifr);
    if (rc < 0) {
        close(fd);
        return -1;
    }

    ifr6.ifr6_prefixlen = prefix;
    ifr6.ifr6_ifindex = ifr.ifr_ifindex;
    rc = inet_pton(AF_INET6, addr, &ifr6.ifr6_addr);
    if (rc != 1) {
        close(fd);
        return -1;
    }
    rc = ioctl(fd, SIOCSIFADDR, (void *)&ifr6);
    close(fd);
    return rc;
}
#endif

#if !defined(_WIN32)
static int tun_open_device(tun_inbound_impl_t *impl)
{
    if (impl == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    if (impl->fd >= 0) {
        return APROXY_OK;
    }

#if defined(__linux__)
    const char *name = impl->requested_name == NULL ? APROXY_TUN_DEFAULT_NAME
                                                    : impl->requested_name;
    const int fd = linux_tun_open(name, impl->actual_name,
                                  sizeof(impl->actual_name));
    if (fd < 0) {
        return APROXY_ERR_UNSUPPORTED;
    }
    impl->fd = fd;
    impl->own_fd = 1;

    if (impl->configure_device) {
        if (linux_tun_set_mtu(impl->actual_name, impl->mtu) < 0 ||
            linux_tun_set_ipv4(impl->actual_name, impl->ipv4,
                               impl->ipv4_prefix) < 0 ||
            linux_tun_set_ipv6(impl->actual_name, impl->ipv6,
                               impl->ipv6_prefix) < 0 ||
            linux_tun_set_state(impl->actual_name, 1) < 0) {
            close_tun_fd(impl);
            return APROXY_ERR_UNSUPPORTED;
        }
    }
    return APROXY_OK;
#else
    (void)impl;
    return APROXY_ERR_UNSUPPORTED;
#endif
}
#endif

static void tun_poll_close_cb(uv_handle_t *handle)
{
    tun_inbound_impl_t *impl = (tun_inbound_impl_t *)handle->data;
    if (impl == NULL) {
        return;
    }
    impl->poll_closing = 0;
    close_tun_fd(impl);
    if (impl->free_after_close) {
        free(impl->tag);
        free(impl->requested_name);
        free(impl->ipv4);
        free(impl->ipv6);
        aproxy_packet_session_table_free(impl->sessions);
        aproxy_bufpool_destroy(&impl->bufpool);
        aproxy_bufpool_destroy(&impl->read_fallback_pool);
        aproxy_ring_free(&impl->write_queue);
        free(impl);
    }
}

static void tun_stop_impl(tun_inbound_impl_t *impl)
{
    if (impl == NULL) {
        return;
    }
    impl->packet_started = 0;
    if (impl->poll_started) {
        uv_poll_stop(&impl->poll);
        impl->poll_started = 0;
    }
    if (impl->poll_initialized && !impl->poll_closing &&
        !uv_is_closing((uv_handle_t *)&impl->poll)) {
        impl->poll_closing = 1;
        uv_close((uv_handle_t *)&impl->poll, tun_poll_close_cb);
    } else if (!impl->poll_initialized) {
        close_tun_fd(impl);
    }
}

static void tun_session_open_cb(aproxy_packet_session_t *session,
                                aproxy_stream_t *stream,
                                const aproxy_packet_flow_key_t *key,
                                void *user_data)
{
    tun_inbound_impl_t *impl = (tun_inbound_impl_t *)user_data;
    if (impl != NULL && impl->on_session != NULL) {
        impl->on_session(impl->owner, session, stream, key,
                         impl->user_data);
    }
}

static void tun_session_data_cb(aproxy_packet_session_t *session,
                                aproxy_stream_t *stream,
                                const uint8_t *packet,
                                size_t packet_len,
                                void *user_data)
{
    tun_inbound_impl_t *impl = (tun_inbound_impl_t *)user_data;
    if (impl == NULL) {
        return;
    }
    if (impl->on_stream_data != NULL) {
        impl->stats.packets_to_sessions++;
        impl->on_stream_data(impl->owner, session, stream, packet,
                             packet_len, impl->user_data);
    } else {
        impl->stats.packets_dropped_no_handler++;
    }
}

static int tun_session_write_cb(aproxy_packet_session_t *session,
                                const uint8_t *packet,
                                size_t packet_len,
                                void *user_data)
{
    (void)session;
    tun_inbound_impl_t *impl = (tun_inbound_impl_t *)user_data;
    if (impl == NULL || (packet == NULL && packet_len > 0u)) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    if (impl->packet_io) {
        if (!impl->packet_started || impl->on_write_packet == NULL) {
            return APROXY_ERR_BUSY;
        }
        const int rc = impl->on_write_packet(
            impl->owner, packet, packet_len, impl->user_data);
        if (rc == APROXY_OK) {
            impl->stats.packets_written++;
            impl->stats.bytes_written += packet_len;
        } else {
            impl->stats.write_errors++;
        }
        return rc;
    }
#if defined(_WIN32)
    return APROXY_ERR_UNSUPPORTED;
#else
    if (impl->fd < 0) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    if (packet_len > UINT32_MAX) {
        return APROXY_ERR_FRAME_TOO_LARGE;
    }
    if (aproxy_ring_size(&impl->write_queue) == 0u) {
        const ssize_t written = write(impl->fd, packet, packet_len);
        if (written == (ssize_t)packet_len) {
            impl->stats.packets_written++;
            impl->stats.bytes_written += packet_len;
            return APROXY_OK;
        }
        if (written >= 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
            impl->stats.write_errors++;
            return APROXY_ERR_UNSUPPORTED;
        }
    }

    const size_t queued = aproxy_ring_size(&impl->write_queue);
    if (packet_len > TUN_WRITE_QUEUE_LIMIT - TUN_WRITE_HEADER_SIZE ||
        queued > TUN_WRITE_QUEUE_LIMIT - TUN_WRITE_HEADER_SIZE - packet_len) {
        impl->stats.packets_write_dropped++;
        return APROXY_ERR_BUFFER_TOO_SMALL;
    }
    int rc = aproxy_ring_reserve(&impl->write_queue,
                                 queued + TUN_WRITE_HEADER_SIZE + packet_len);
    uint8_t header[TUN_WRITE_HEADER_SIZE];
    put_u32(header, (uint32_t)packet_len);
    if (rc == APROXY_OK) {
        rc = aproxy_ring_write(&impl->write_queue, header, sizeof(header));
    }
    if (rc == APROXY_OK) {
        rc = aproxy_ring_write(&impl->write_queue, packet, packet_len);
    }
    if (rc != APROXY_OK) {
        impl->stats.write_errors++;
        return rc;
    }
    impl->stats.packets_write_queued++;
    if (impl->poll_started) {
        rc = uv_poll_start(&impl->poll, UV_READABLE | UV_WRITABLE,
                           tun_poll_cb);
    }
    return rc == 0 ? APROXY_OK : rc;
#endif
}

#if !defined(_WIN32)
static int tun_flush_writes(tun_inbound_impl_t *impl)
{
    while (aproxy_ring_size(&impl->write_queue) >= TUN_WRITE_HEADER_SIZE) {
        uint8_t header[TUN_WRITE_HEADER_SIZE];
        if (aproxy_ring_peek(&impl->write_queue, 0u, header,
                             sizeof(header)) != sizeof(header)) {
            return APROXY_ERR_INVALID_FRAME;
        }
        const size_t packet_len = get_u32(header);
        if (aproxy_ring_size(&impl->write_queue) <
            TUN_WRITE_HEADER_SIZE + packet_len) {
            return APROXY_ERR_INVALID_FRAME;
        }
        aproxy_const_span_t spans[2];
        const size_t count = aproxy_ring_read_spans_at(
            &impl->write_queue, TUN_WRITE_HEADER_SIZE, packet_len, spans);
        struct iovec iov[2];
        for (size_t i = 0u; i < count; i++) {
            iov[i].iov_base = (void *)(uintptr_t)spans[i].data;
            iov[i].iov_len = spans[i].len;
        }
        const ssize_t written = writev(impl->fd, iov, (int)count);
        if (written == (ssize_t)packet_len) {
            aproxy_ring_consume(&impl->write_queue,
                                TUN_WRITE_HEADER_SIZE + packet_len);
            impl->stats.packets_written++;
            impl->stats.bytes_written += packet_len;
            continue;
        }
        if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return APROXY_OK;
        }
        aproxy_ring_consume(&impl->write_queue,
                            TUN_WRITE_HEADER_SIZE + packet_len);
        impl->stats.write_errors++;
    }
    if (impl->poll_started) {
        const int rc = uv_poll_start(&impl->poll, UV_READABLE, tun_poll_cb);
        if (rc != 0) {
            return rc;
        }
    }
    return APROXY_OK;
}
#endif

static int tun_dispatch_packet(tun_inbound_impl_t *impl,
                               const uint8_t *packet,
                               size_t packet_len)
{
    const int rc = aproxy_packet_session_table_dispatch_packet(
        impl->sessions, packet, packet_len);
    if (rc != APROXY_OK) {
        impl->stats.packets_dropped_session++;
    }
    return rc;
}

#if !defined(_WIN32)
static void tun_poll_cb(uv_poll_t *poll, int status, int events)
{
    tun_inbound_impl_t *impl = (tun_inbound_impl_t *)poll->data;
    if (impl == NULL || status < 0) {
        if (impl != NULL) {
            impl->stats.read_errors++;
        }
        return;
    }
    if ((events & UV_WRITABLE) != 0 && tun_flush_writes(impl) != APROXY_OK) {
        impl->stats.write_errors++;
    }
    if ((events & UV_READABLE) == 0) {
        return;
    }

    for (;;) {
        size_t capacity = 0u;
        const size_t slot_size =
            impl->mtu == 0u ? TUN_READ_FALLBACK_MTU : (size_t)impl->mtu;
        const size_t want = slot_size * TUN_READ_BATCH_SIZE;
        aproxy_bufpool_t *pool = &impl->bufpool;
        size_t batch_size = TUN_READ_BATCH_SIZE;
        uint8_t *buf = aproxy_bufpool_acquire(pool, want, &capacity);
        if (buf != NULL) {
            aproxy_bufpool_trim(&impl->read_fallback_pool);
        } else {
            pool = &impl->read_fallback_pool;
            batch_size = 1u;
            buf = aproxy_bufpool_acquire(pool, slot_size, &capacity);
        }
        if (buf == NULL) {
            impl->stats.read_errors++;
            return;
        }

        size_t packet_lengths[TUN_READ_BATCH_SIZE];
        size_t packet_count = 0u;
        int stop_reading = 0;
        while (packet_count < batch_size) {
            uint8_t *slot = buf + packet_count * slot_size;
            const ssize_t nread = read(impl->fd, slot, slot_size);
            if (nread <= 0) {
                if (nread < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                    impl->stats.read_errors++;
                }
                stop_reading = 1;
                break;
            }
            packet_lengths[packet_count++] = (size_t)nread;
            impl->stats.packets_read++;
            impl->stats.bytes_read += (uint64_t)nread;
        }

        if (packet_count > 0u && impl->on_packet_batch_begin != NULL) {
            impl->on_packet_batch_begin(impl->owner, impl->user_data);
        }
        for (size_t i = 0u; i < packet_count; i++) {
            tun_dispatch_packet(impl, buf + i * slot_size,
                                packet_lengths[i]);
        }
        if (packet_count > 0u && impl->on_packet_batch_end != NULL) {
            impl->on_packet_batch_end(impl->owner, impl->user_data);
        }
        aproxy_bufpool_release(pool, buf, capacity);
        if (stop_reading || packet_count < batch_size) {
            return;
        }
    }
}
#endif

static int tun_start(void *data)
{
    tun_inbound_impl_t *impl = (tun_inbound_impl_t *)data;
    if (impl == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    if (impl->poll_started) {
        return APROXY_OK;
    }
    if (impl->packet_io) {
        impl->packet_started = 1;
        return APROXY_OK;
    }

#if defined(_WIN32)
    return APROXY_ERR_UNSUPPORTED;
#else
    int rc = tun_open_device(impl);
    if (rc != APROXY_OK) {
        return rc;
    }
    if (set_nonblocking(impl->fd) < 0) {
        close_tun_fd(impl);
        return APROXY_ERR_UNSUPPORTED;
    }

    rc = uv_poll_init(impl->loop, &impl->poll, impl->fd);
    if (rc != 0) {
        close_tun_fd(impl);
        return rc;
    }
    impl->poll_initialized = 1;
    impl->poll.data = impl;

    const int events = aproxy_ring_size(&impl->write_queue) > 0u
                           ? UV_READABLE | UV_WRITABLE
                           : UV_READABLE;
    rc = uv_poll_start(&impl->poll, events, tun_poll_cb);
    if (rc != 0) {
        tun_stop_impl(impl);
        return rc;
    }
    impl->poll_started = 1;
    return APROXY_OK;
#endif
}

static void tun_stop(void *data)
{
    tun_stop_impl((tun_inbound_impl_t *)data);
}

static void tun_free(void *data)
{
    tun_inbound_impl_t *impl = (tun_inbound_impl_t *)data;
    if (impl == NULL) {
        return;
    }
    if (impl->poll_initialized) {
        impl->free_after_close = 1;
        if (!uv_is_closing((uv_handle_t *)&impl->poll)) {
            tun_stop_impl(impl);
        }
        return;
    }
    close_tun_fd(impl);
    free(impl->tag);
    free(impl->requested_name);
    free(impl->ipv4);
    free(impl->ipv6);
    aproxy_packet_session_table_free(impl->sessions);
    aproxy_bufpool_destroy(&impl->bufpool);
    aproxy_bufpool_destroy(&impl->read_fallback_pool);
    aproxy_ring_free(&impl->write_queue);
    free(impl);
}

static const aproxy_inbound_vtable_t tun_vtable = {
    .start = tun_start,
    .stop = tun_stop,
    .free = tun_free,
};

int aproxy_tun_inbound_new(const aproxy_tun_inbound_config_t *config,
                           aproxy_inbound_t **out)
{
    if (config == NULL || out == NULL || config->loop == NULL ||
        (config->use_fd && config->fd < 0) ||
        (config->use_fd && config->use_packet_io) ||
        (config->use_packet_io && config->on_write_packet == NULL) ||
        ((config->on_packet_batch_begin == NULL) !=
         (config->on_packet_batch_end == NULL)) ||
        config->mtu > UINT16_MAX || config->ipv4_prefix > 32u ||
        config->ipv6_prefix > 128u) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }

    aproxy_inbound_t *inbound =
        (aproxy_inbound_t *)calloc(1u, sizeof(*inbound));
    tun_inbound_impl_t *impl =
        (tun_inbound_impl_t *)calloc(1u, sizeof(*impl));
    if (inbound == NULL || impl == NULL) {
        free(inbound);
        free(impl);
        return APROXY_ERR_NO_MEMORY;
    }

    impl->loop = config->loop;
    impl->owner = inbound;
    impl->tag = copy_string(config->tag == NULL ? "tun" : config->tag);
    impl->requested_name = copy_string(config->name == NULL
                                           ? APROXY_TUN_DEFAULT_NAME
                                           : config->name);
    impl->ipv4 = copy_string(config->ipv4 == NULL ? APROXY_TUN_DEFAULT_IPV4
                                                  : config->ipv4);
    impl->ipv6 = copy_string(config->ipv6 == NULL ? APROXY_TUN_DEFAULT_IPV6
                                                  : config->ipv6);
    if (impl->tag == NULL || impl->requested_name == NULL ||
        impl->ipv4 == NULL || impl->ipv6 == NULL) {
        tun_free(impl);
        free(inbound);
        return APROXY_ERR_NO_MEMORY;
    }

    snprintf(impl->actual_name, sizeof(impl->actual_name), "%s",
             impl->requested_name);
    impl->mtu = config->mtu == 0u ? APROXY_TUN_DEFAULT_MTU : config->mtu;
    impl->ipv4_prefix = config->ipv4 == NULL && config->ipv4_prefix == 0u
                            ? APROXY_TUN_DEFAULT_IPV4_PREFIX
                            : config->ipv4_prefix;
    impl->ipv6_prefix = config->ipv6 == NULL && config->ipv6_prefix == 0u
                            ? APROXY_TUN_DEFAULT_IPV6_PREFIX
                            : config->ipv6_prefix;
    impl->fd = config->use_fd ? config->fd : -1;
    impl->own_fd = config->use_fd ? config->close_fd : 0;
    impl->configure_device = config->use_fd ? 0 : config->configure_device;
    impl->packet_io = config->use_packet_io;
    impl->on_session = config->on_session;
    impl->on_stream_data = config->on_stream_data;
    impl->on_packet_batch_begin = config->on_packet_batch_begin;
    impl->on_packet_batch_end = config->on_packet_batch_end;
    impl->on_write_packet = config->on_write_packet;
    impl->user_data = config->user_data;
    aproxy_bufpool_init(&impl->bufpool,
                        (size_t)impl->mtu * TUN_READ_BATCH_SIZE,
                        TUN_READ_POOL_MAX_FREE);
    aproxy_bufpool_init(&impl->read_fallback_pool, (size_t)impl->mtu,
                        TUN_READ_POOL_MAX_FREE);
    aproxy_ring_init(&impl->write_queue);
    aproxy_packet_session_table_config_t session_config = {
        .on_open = tun_session_open_cb,
        .on_data = tun_session_data_cb,
        .on_write = tun_session_write_cb,
        .user_data = impl,
    };
    int rc = aproxy_packet_session_table_new(&session_config,
                                             &impl->sessions);
    if (rc != APROXY_OK) {
        tun_free(impl);
        free(inbound);
        return rc;
    }

    inbound->tag = impl->tag;
    inbound->vtable = &tun_vtable;
    inbound->impl = impl;
    *out = inbound;
    return APROXY_OK;
}

int aproxy_tun_inbound_submit_packet(aproxy_inbound_t *inbound,
                                     const uint8_t *packet,
                                     size_t packet_len)
{
    if (inbound == NULL || inbound->vtable != &tun_vtable ||
        packet == NULL || packet_len == 0u || packet_len > UINT16_MAX) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    tun_inbound_impl_t *impl = (tun_inbound_impl_t *)inbound->impl;
    if (impl == NULL || !impl->packet_io || !impl->packet_started) {
        return APROXY_ERR_BUSY;
    }
    impl->stats.packets_read++;
    impl->stats.bytes_read += packet_len;
    return tun_dispatch_packet(impl, packet, packet_len);
}

int aproxy_tun_inbound_get_stats(const aproxy_inbound_t *inbound,
                                 aproxy_tun_stats_t *out_stats)
{
    if (inbound == NULL || out_stats == NULL ||
        inbound->vtable != &tun_vtable) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    const tun_inbound_impl_t *impl =
        (const tun_inbound_impl_t *)inbound->impl;
    *out_stats = impl->stats;
    return APROXY_OK;
}

int aproxy_tun_inbound_get_session_stats(
    const aproxy_inbound_t *inbound,
    aproxy_packet_session_stats_t *out_stats)
{
    if (inbound == NULL || out_stats == NULL ||
        inbound->vtable != &tun_vtable) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    const tun_inbound_impl_t *impl =
        (const tun_inbound_impl_t *)inbound->impl;
    aproxy_packet_session_table_get_stats(impl->sessions, out_stats);
    return APROXY_OK;
}

const char *aproxy_tun_inbound_get_name(const aproxy_inbound_t *inbound)
{
    if (inbound == NULL || inbound->vtable != &tun_vtable) {
        return NULL;
    }
    const tun_inbound_impl_t *impl =
        (const tun_inbound_impl_t *)inbound->impl;
    return impl->actual_name;
}
