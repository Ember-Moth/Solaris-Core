#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE 1
#endif
#include "platform/tun/internal.h"
#ifndef _WIN32
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>
#ifdef __APPLE__
#include <TargetConditionals.h>
#if !TARGET_OS_IPHONE
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#endif
#elif defined(__linux__)
#include <linux/if.h>
#include <linux/if_tun.h>
#endif

typedef struct posix_device {
    solaris_tun_device_t device;
    uv_poll_t poll;
    solaris_deferred_t pump;
    uint8_t *receive;
    size_t receive_size;
    int fd, socket, initialized;
} posix_device_t;
static solaris_status_t error_status(int error)
{
    if (error == EACCES || error == EPERM) return SOLARIS_EACCESS;
    if (error == ENOMEM || error == ENOBUFS) return SOLARIS_ENOMEM;
    if (error == EINVAL) return SOLARIS_EINVAL;
    if (error == EBADF || error == ENODEV) return SOLARIS_ECLOSED;
    return SOLARIS_EIO;
}
static void poll_events(posix_device_t *p);
static void flush(posix_device_t *p)
{
    solaris_tun_device_t *d = &p->device;
    for (unsigned int count = 0u; count < 32u && !d->closing && d->head != NULL; ++count) {
        solaris_tun_packet_t *packet = d->head;
        /* Darwin's kernel ABI uses network-order AF_INET=2 / AF_INET6=30,
         * including when an adopted Darwin-framed fd is tested elsewhere. */
        uint8_t prefix[4] = {0u, 0u, 0u, (uint8_t)((packet->data[0] >> 4) == 4u ? 2u : 30u)};
        struct iovec vectors[2] = {{prefix, sizeof(prefix)}, {packet->data, packet->length}};
        int prefixed = d->options.framing == SOLARIS_TUN_FRAMING_DARWIN;
        ssize_t written;
        do {
            if (p->socket) {
                struct msghdr message; memset(&message, 0, sizeof(message));
                message.msg_iov = vectors + (prefixed ? 0 : 1); message.msg_iovlen = prefixed ? 2u : 1u;
                written = sendmsg(p->fd, &message, MSG_NOSIGNAL);
            } else written = writev(p->fd, vectors + (prefixed ? 0 : 1), prefixed ? 2 : 1);
        } while (written < 0 && errno == EINTR);
        if (written < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            solaris_tun_device_fail(d, error_status(errno)); return;
        }
        /* Device writes are packet-atomic. Replaying the suffix would inject
         * a new malformed IP packet and corrupt framing. */
        if ((size_t)written != packet->length + (prefixed ? 4u : 0u)) { solaris_tun_device_fail(d, SOLARIS_EIO); return; }
        solaris_tun_device_pop(d);
    }
    solaris_tun_device_writable(d);
    if (!d->closing) poll_events(p);
}
static void pump(void *context)
{ posix_device_t *p = context; if (!p->device.closing) flush(p); solaris_scope_release(&p->device.scope); }
static void schedule(solaris_tun_device_t *d)
{
    posix_device_t *p = (posix_device_t *)d;
    if (p->pump.queued || d->closing) return;
    solaris_scope_retain(&d->scope);
    solaris_status_t rc = solaris_executor_defer(d->options.owner, &p->pump); assert(rc == SOLARIS_OK); (void)rc;
}
static void poll_ready(uv_poll_t *handle, int status, int events)
{
    posix_device_t *p = handle->data; solaris_tun_device_t *d = &p->device;
    if (d->closing) return;
    if (status < 0) { solaris_tun_device_fail(d, SOLARIS_EIO); return; }
    if ((events & UV_READABLE) != 0) {
        for (unsigned int count = 0u; count < 32u && !d->closing; ++count) {
            ssize_t n;
            do { n = read(p->fd, p->receive, p->receive_size); } while (n < 0 && errno == EINTR);
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                solaris_tun_device_fail(d, error_status(errno)); break;
            }
            if (n == 0) { solaris_tun_device_fail(d, SOLARIS_EIO); break; }
            size_t offset = d->options.framing == SOLARIS_TUN_FRAMING_DARWIN ? 4u : 0u;
            if ((size_t)n < offset || (size_t)n - offset > d->options.mtu) { solaris_tun_device_fail(d, SOLARIS_EMSGSIZE); break; }
            uint8_t *packet = p->receive + offset; size_t length = (size_t)n - offset;
            if (!solaris_tun_device_packet(packet, length)) continue;
            if (offset != 0u && (p->receive[0] != 0u || p->receive[1] != 0u || p->receive[2] != 0u ||
                p->receive[3] != ((packet[0] >> 4) == 4u ? 2u : 30u))) continue;
            d->options.on_packet(d->options.context, packet, length);
        }
    }
    if (!d->closing && (events & UV_WRITABLE) != 0) flush(p);
}
static void poll_events(posix_device_t *p)
{
    int rc = uv_poll_start(&p->poll, UV_READABLE | (p->device.head != NULL ? UV_WRITABLE : 0), poll_ready);
    if (rc != 0) solaris_tun_device_fail(&p->device, SOLARIS_EIO);
}
static void poll_closed(uv_handle_t *handle)
{
    posix_device_t *p = handle->data; p->initialized = 0;
    solaris_scope_release(&p->device.scope);
}
static void cancel(solaris_tun_device_t *d)
{
    posix_device_t *p = (posix_device_t *)d;
    if (p->initialized) { (void)uv_poll_stop(&p->poll); uv_close((uv_handle_t *)&p->poll, poll_closed); }
}
static void dispose(solaris_tun_device_t *d)
{ posix_device_t *p = (posix_device_t *)d; if (p->fd >= 0) close(p->fd); solaris_memory_free(p->receive); }
static const solaris_tun_device_ops_t operations = {schedule, cancel, dispose};

static solaris_status_t native_open(const solaris_tun_device_options_t *options, int *fd, char *name, uint32_t *framing)
{
#if defined(__APPLE__) && !TARGET_OS_IPHONE
    uint32_t unit = 0u;
    if (options->name != NULL && options->name[0] != '\0') {
        if (strncmp(options->name, "utun", 4u) != 0 || options->name[4] < '0' || options->name[4] > '9') return SOLARIS_EINVAL;
        char *end; errno = 0; unsigned long index = strtoul(options->name + 4u, &end, 10);
        if (*end != '\0' || errno != 0 || index >= UINT32_MAX) return SOLARIS_EINVAL;
        unit = (uint32_t)index + 1u;
    }
    int value = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (value < 0) return error_status(errno);
    struct ctl_info info; memset(&info, 0, sizeof(info));
    memcpy(info.ctl_name, "com.apple.net.utun_control", sizeof("com.apple.net.utun_control"));
    struct sockaddr_ctl address; memset(&address, 0, sizeof(address));
    address.sc_len = sizeof(address); address.sc_family = AF_SYSTEM; address.ss_sysaddr = AF_SYS_CONTROL;
    solaris_status_t rc = SOLARIS_OK;
    if (ioctl(value, CTLIOCGINFO, &info) != 0) rc = error_status(errno);
    address.sc_id = info.ctl_id; address.sc_unit = unit;
    if (rc == SOLARIS_OK && connect(value, (struct sockaddr *)&address, sizeof(address)) != 0) rc = error_status(errno);
    socklen_t size = 128u;
    if (rc == SOLARIS_OK && getsockopt(value, SYSPROTO_CONTROL, 2 /* UTUN_OPT_IFNAME */, name, &size) != 0) rc = error_status(errno);
    name[127] = '\0';
    if (rc != SOLARIS_OK) { close(value); return rc; }
    *fd = value; *framing = SOLARIS_TUN_FRAMING_DARWIN; return SOLARIS_OK;
#elif defined(__linux__)
    if (options->name != NULL && strlen(options->name) >= IFNAMSIZ) return SOLARIS_EINVAL;
    int value = open("/dev/net/tun", O_RDWR | O_NONBLOCK | O_CLOEXEC);
    if (value < 0) return error_status(errno);
    struct ifreq request; memset(&request, 0, sizeof(request)); request.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (options->name != NULL) memcpy(request.ifr_name, options->name, strlen(options->name) + 1u);
    if (ioctl(value, TUNSETIFF, &request) != 0) { solaris_status_t rc = error_status(errno); close(value); return rc; }
    memcpy(name, request.ifr_name, IFNAMSIZ); name[IFNAMSIZ] = '\0';
    *fd = value; *framing = SOLARIS_TUN_FRAMING_IP; return SOLARIS_OK;
#else
    (void)options; (void)fd; (void)name; (void)framing; return SOLARIS_ENOTSUP;
#endif
}
solaris_status_t solaris_tun_posix_open(const solaris_tun_device_options_t *options, solaris_tun_device_t **out)
{
    int fd = -1; char name[128] = {0}; uint32_t framing = options->framing;
    if (options->kind == SOLARIS_TUN_DEVICE_FD) {
        if (options->fd < 0 || options->fd > INT_MAX) return SOLARIS_EINVAL;
        int flags = fcntl((int)options->fd, F_GETFL);
        if (flags < 0) return error_status(errno);
        if ((flags & O_NONBLOCK) == 0) return SOLARIS_EINVAL;
        struct stat metadata;
        if (fstat((int)options->fd, &metadata) != 0) return error_status(errno);
        if (!S_ISCHR(metadata.st_mode) && !S_ISSOCK(metadata.st_mode)) return SOLARIS_EINVAL;
        fd = fcntl((int)options->fd, F_DUPFD_CLOEXEC, 0);
        if (fd < 0) return error_status(errno);
        if (options->name != NULL) memcpy(name, options->name, strlen(options->name) + 1u);
    } else {
        solaris_status_t rc = native_open(options, &fd, name, &framing);
        if (rc != SOLARIS_OK) return rc;
        int flags = fcntl(fd, F_GETFL);
        if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0 || fcntl(fd, F_SETFD, FD_CLOEXEC) != 0) {
            rc = error_status(errno); close(fd); return rc;
        }
    }
    solaris_budget_t *budget = solaris_executor_budget(options->owner);
    posix_device_t *p = solaris_memory_allocate(budget, sizeof(*p));
    if (p == NULL) { close(fd); return SOLARIS_ENOMEM; }
    memset(p, 0, sizeof(*p)); p->fd = fd; p->receive_size = options->mtu + 5u;
    p->receive = solaris_memory_allocate(budget, p->receive_size);
    if (p->receive == NULL) { close(fd); solaris_memory_free(p); return SOLARIS_ENOMEM; }
    int type; socklen_t type_size = sizeof(type); p->socket = getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &type_size) == 0;
    p->pump.run = pump; p->pump.context = p;
    solaris_status_t rc = solaris_tun_device_init(&p->device, options, &operations, name);
    if (rc != SOLARIS_OK) { dispose(&p->device); solaris_memory_free(p); return rc; }
    p->device.options.framing = framing;
    if (uv_poll_init(solaris_executor_loop(options->owner), &p->poll, fd) != 0) { solaris_tun_device_fail(&p->device, SOLARIS_EIO); return SOLARIS_EIO; }
    p->initialized = 1; p->poll.data = p; solaris_scope_retain(&p->device.scope);
    poll_events(p);
    if (p->device.closing) return p->device.status;
    p->device.accepted = 1; *out = &p->device; return SOLARIS_OK;
}
#else
solaris_status_t solaris_tun_posix_open(const solaris_tun_device_options_t *options, solaris_tun_device_t **out)
{ (void)options; (void)out; return SOLARIS_ENOTSUP; }
#endif
