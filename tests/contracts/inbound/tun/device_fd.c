#include "contracts/inbound/tun_device.h"
#include "support/runtime/event.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)
enum { RAW, DARWIN, DUPLICATE, MALFORMED, OVERSIZED, CANCEL_QUEUE, STOP_QUEUE, PARTIAL, BLOCKING, ALLOC_OPEN, ALLOC_RECEIVE, ALLOC_WRITE };
typedef struct environment {
    solaris_executor_t *owner;
    solaris_budget_t *budget;
    solaris_tun_device_t *device;
    solaris_test_event_t ready, done, writable;
    solaris_runtime_services_t services;
    int sockets[2], mode, fail_at, allocations;
    unsigned int packets, closes, writable_count;
    solaris_status_t status, submitted;
    uint8_t packet[40];
} environment_t;
static void *allocate(void *context, size_t size)
{
    environment_t *e = context;
    if (e->fail_at != 0 && ++e->allocations == e->fail_at) return NULL;
    return malloc(size);
}
static void writable(void *context)
{ environment_t *e = context; CHECK(e->closes == 0u); e->writable_count++; solaris_test_event_signal(&e->writable); }
static void packet(void *context, const uint8_t *data, size_t length)
{
    environment_t *e = context; CHECK(e->closes == 0u && length == sizeof(e->packet) && memcmp(data, e->packet, length) == 0);
    CHECK(++e->packets == 1u);
    CHECK(solaris_tun_device_write(e->device, data, length) == SOLARIS_OK);
    CHECK(solaris_tun_device_write(e->device, data, length) == SOLARIS_EAGAIN);
}
static void closed(void *context, solaris_status_t status)
{
    environment_t *e = context; CHECK(++e->closes == 1u);
    CHECK(strcmp(solaris_tun_device_name(e->device), "test-fd") == 0);
    e->status = status; e->device = NULL; solaris_test_event_signal(&e->done);
}
static void start(void *context, solaris_status_t status)
{
    environment_t *e = context; CHECK(status == SOLARIS_OK);
    solaris_tun_device_options_t options = {.owner = e->owner, .kind = SOLARIS_TUN_DEVICE_FD,
        .framing = e->mode == DARWIN || e->mode == MALFORMED ? SOLARIS_TUN_FRAMING_DARWIN : SOLARIS_TUN_FRAMING_IP,
        .fd = e->sockets[0], .name = "test-fd", .mtu = e->mode == PARTIAL ? 65535u : 1500u,
        .queue_packet_limit = 1u, .queue_byte_limit = 65535u, .context = e, .on_packet = packet, .on_writable = writable, .on_close = closed};
    if (e->mode == ALLOC_OPEN || e->mode == ALLOC_RECEIVE) { e->allocations = 0; e->fail_at = e->mode == ALLOC_OPEN ? 1 : 2; }
    e->submitted = solaris_tun_device_open(&options, &e->device); e->fail_at = 0;
    if (e->mode == BLOCKING || e->mode == ALLOC_OPEN || e->mode == ALLOC_RECEIVE) {
        CHECK(e->submitted == (e->mode == BLOCKING ? SOLARIS_EINVAL : SOLARIS_ENOMEM) && e->device == NULL);
        solaris_test_event_signal(&e->done);
    } else {
        CHECK(e->submitted == SOLARIS_OK);
        CHECK(solaris_tun_device_write(e->device, e->packet, 0u) == SOLARIS_EINVAL);
        CHECK(solaris_tun_device_write(e->device, e->packet, options.mtu + 1u) == SOLARIS_EMSGSIZE);
        if (e->mode == PARTIAL) {
            uint8_t *large = malloc(options.mtu); CHECK(large != NULL); memset(large, 0, options.mtu); large[0] = 0x45u;
            CHECK(solaris_tun_device_write(e->device, large, options.mtu) == SOLARIS_OK); free(large);
        } else if (e->mode == CANCEL_QUEUE || e->mode == STOP_QUEUE) {
            CHECK(solaris_tun_device_write(e->device, e->packet, sizeof(e->packet)) == SOLARIS_OK);
            if (e->mode == CANCEL_QUEUE) solaris_tun_device_close(e->device);
        } else if (e->mode == ALLOC_WRITE) {
            e->allocations = 0; e->fail_at = 1;
            CHECK(solaris_tun_device_write(e->device, e->packet, sizeof(e->packet)) == SOLARIS_ENOMEM);
            e->fail_at = 0; solaris_tun_device_close(e->device);
        }
    }
    solaris_test_event_signal(&e->ready);
}
static void finish(void *context, solaris_status_t status)
{ environment_t *e = context; CHECK(status == SOLARIS_OK); solaris_tun_device_close(e->device); }
static void run(int mode)
{
    environment_t e; memset(&e, 0, sizeof(e)); e.mode = mode; e.packet[0] = mode == DARWIN ? 0x60u : 0x45u;
    for (size_t i = 1u; i < sizeof(e.packet); ++i) e.packet[i] = (uint8_t)(i * 7u);
    CHECK(socketpair(AF_UNIX, mode == PARTIAL || mode == STOP_QUEUE ? SOCK_STREAM : SOCK_DGRAM, 0, e.sockets) == 0);
    if (mode != BLOCKING) CHECK(fcntl(e.sockets[0], F_SETFL, fcntl(e.sockets[0], F_GETFL) | O_NONBLOCK) == 0);
    int flags = fcntl(e.sockets[0], F_GETFL);
    if (mode == PARTIAL || mode == STOP_QUEUE) {
        int size = 1024; CHECK(setsockopt(e.sockets[0], SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)) == 0);
        if (mode == STOP_QUEUE) {
            while (send(e.sockets[0], e.packet, sizeof(e.packet), MSG_NOSIGNAL) >= 0) {}
            CHECK(errno == EAGAIN || errno == EWOULDBLOCK);
        }
    }
    CHECK(solaris_test_event_init(&e.ready, 0u) == 0 && solaris_test_event_init(&e.done, 0u) == 0 && solaris_test_event_init(&e.writable, 0u) == 0);
    solaris_runtime_services_init(&e.services); e.services.context = &e; e.services.allocate = allocate;
    CHECK(solaris_budget_create(4u * 1024u * 1024u, &e.services, &e.budget) == SOLARIS_OK);
    solaris_executor_options_t options = {.budget = e.budget, .services = &e.services, .queue_capacity = 8u, .resource_limit = 64u};
    CHECK(solaris_executor_create(&options, &e.owner) == SOLARIS_OK && solaris_executor_activate(e.owner, 1u) == SOLARIS_OK);
    CHECK(solaris_executor_post(e.owner, start, &e) == SOLARIS_OK); solaris_test_event_wait(&e.ready);
    if (mode <= MALFORMED) {
        if (mode == DUPLICATE) { close(e.sockets[0]); e.sockets[0] = -1; }
        uint8_t wire[44]; size_t prefix = mode == DARWIN || mode == MALFORMED ? 4u : 0u;
        if (prefix != 0u) { memset(wire, 0, 4u); wire[3] = mode == DARWIN ? 30u : 2u; }
        memcpy(wire + prefix, e.packet, sizeof(e.packet));
        if (mode == MALFORMED) { wire[3] = 30u; CHECK(send(e.sockets[1], wire, 44u, 0) == 44); wire[3] = 2u; }
        CHECK(send(e.sockets[1], wire, prefix + sizeof(e.packet), 0) == (ssize_t)(prefix + sizeof(e.packet)));
        struct pollfd reader = {e.sockets[1], POLLIN, 0}; CHECK(poll(&reader, 1u, 5000) == 1);
        uint8_t received[64]; ssize_t n = recv(e.sockets[1], received, sizeof(received), 0);
        CHECK(n == (ssize_t)(prefix + sizeof(e.packet)) && memcmp(received, wire, (size_t)n) == 0);
        solaris_test_event_wait(&e.writable);
        CHECK(solaris_executor_post(e.owner, finish, &e) == SOLARIS_OK);
    } else if (mode == OVERSIZED) {
        uint8_t large[1501] = {0x45u}; CHECK(send(e.sockets[1], large, sizeof(large), 0) == (ssize_t)sizeof(large));
    } else if (mode == STOP_QUEUE) CHECK(solaris_executor_begin_quiesce(e.owner) == SOLARIS_OK);
    solaris_test_event_wait(&e.done);
    CHECK(solaris_executor_quiesce(e.owner) == SOLARIS_OK && solaris_executor_destroy(e.owner) == SOLARIS_OK);
    if (e.submitted == SOLARIS_OK) {
        CHECK(e.closes == 1u && e.status == (mode == OVERSIZED ? SOLARIS_EMSGSIZE : mode == PARTIAL ? SOLARIS_EIO : mode == STOP_QUEUE ? SOLARIS_ECANCELLED : SOLARIS_OK));
        CHECK(e.packets == (mode <= MALFORMED ? 1u : 0u));
        CHECK(e.writable_count == (mode <= MALFORMED ? 1u : 0u));
    } else CHECK(e.closes == 0u);
    if (e.sockets[0] >= 0) { CHECK(fcntl(e.sockets[0], F_GETFL) == flags); close(e.sockets[0]); }
    close(e.sockets[1]);
    CHECK(solaris_budget_used(e.budget) == 0u); solaris_budget_release(e.budget);
    solaris_test_event_destroy(&e.ready); solaris_test_event_destroy(&e.done); solaris_test_event_destroy(&e.writable);
}
int main(void)
{
    for (int mode = RAW; mode <= ALLOC_WRITE; ++mode) run(mode);
    puts("TUN fd: bare IP/Darwin framing, dup ownership, malformed/oversize input, partial write, backpressure, cancellation and allocation passed"); return 0;
}
