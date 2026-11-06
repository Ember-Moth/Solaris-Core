#include "stack/tun/system/stack.h"
#include "codec/ip/packet.h"
#include "support/runtime/event.h"
#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET test_socket_t;
#define TEST_INVALID_SOCKET INVALID_SOCKET
#define TEST_SHUT_WR SD_SEND
static void close_socket(test_socket_t socket) { (void)closesocket(socket); }
static int reset_error(void) { return WSAGetLastError() == WSAECONNRESET; }
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
typedef int test_socket_t;
#define TEST_INVALID_SOCKET (-1)
#define TEST_SHUT_WR SHUT_WR
static void close_socket(test_socket_t socket) { (void)close(socket); }
static int reset_error(void) { return errno == ECONNRESET; }
#endif

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)
enum { NORMAL, CLOSE_BEFORE_OPEN, CLOSE_IN_ACCEPT, REPLACE_IN_ACCEPT, CANCEL_WRITE, STOP_ACTIVE, IDLE, NATIVE_REJECT, ALLOCATE };
typedef struct environment environment_t;
typedef struct listener_fixture {
    environment_t *env;
    solaris_tcp_accept_fn accept;
    void (*closed)(void *, solaris_status_t);
    void *context;
    solaris_address_t peer;
} listener_fixture_t;
struct environment {
    solaris_executor_t *owner;
    solaris_budget_t *budget;
    solaris_tun_stack_t *stack;
    solaris_stream_t *stream;
    solaris_tun_stack_options_t options;
    solaris_address_t original_source, original_destination, mapped_source, mapped_destination;
    solaris_test_event_t ready, step, opened, child_done, complete;
    solaris_deferred_t cancel;
    listener_fixture_t listeners[2];
    atomic_uint_fast64_t clock;
    atomic_int spoof;
    unsigned int accepted, opens, child_closes, closes, writes, shutdowns, reads, eofs, emitted;
    size_t read_bytes;
    uint8_t received[5];
    int mode, family, fail_at, fail_count, emit_failure, reentrant_emit;
    solaris_status_t submit_status;
    uint16_t old_port;
};
static uint64_t now(void *context) { return atomic_load(&((environment_t *)context)->clock); }
static void *allocate(void *context, size_t size)
{
    environment_t *env = context;
    if (env->fail_at > 0 && ++env->fail_count == env->fail_at) { env->fail_at = 0; return NULL; }
    return malloc(size);
}
static size_t tcp_packet(uint8_t bytes[80], const solaris_address_t *source,
    const solaris_address_t *destination, uint8_t flags, uint32_t sequence)
{
    size_t header = source->family == SOLARIS_ADDRESS_IPV4 ? 20u : 40u, size = header + 20u;
    memset(bytes, 0, size);
    if (header == 20u) { bytes[0] = 0x45; bytes[3] = (uint8_t)size; bytes[8] = 64u; bytes[9] = SOLARIS_IP_TCP; }
    else { bytes[0] = 0x60; bytes[5] = 20u; bytes[6] = SOLARIS_IP_TCP; bytes[7] = 64u; }
    uint8_t *tcp = bytes + header; tcp[12] = 0x50; tcp[13] = flags; tcp[14] = tcp[15] = 255u;
    tcp[4] = (uint8_t)(sequence >> 24u); tcp[5] = (uint8_t)(sequence >> 16u);
    tcp[6] = (uint8_t)(sequence >> 8u); tcp[7] = (uint8_t)sequence;
    CHECK(solaris_ip_rewrite(bytes, size, source, destination) == SOLARIS_OK); return size;
}
static solaris_status_t input(environment_t *env, const solaris_address_t *source,
    const solaris_address_t *destination, uint8_t flags, uint32_t sequence)
{
    uint8_t bytes[80]; size_t size = tcp_packet(bytes, source, destination, flags, sequence);
    return env->stack->ops->input(env->stack->state, bytes, size);
}
static solaris_status_t emit(void *context, const uint8_t *bytes, size_t size)
{
    environment_t *env = context;
    if (env->emit_failure) { env->emit_failure = 0; return SOLARIS_EAGAIN; }
    solaris_ip_packet_t packet; CHECK(solaris_ip_parse(bytes, size, 1, &packet) == SOLARIS_OK);
    if (env->reentrant_emit) CHECK(env->stack->ops->input(env->stack->state, bytes, size) == SOLARIS_EBUSY);
    env->mapped_source = packet.source; env->mapped_destination = packet.destination; env->emitted++;
    return SOLARIS_OK;
}
static void closed(void *context, solaris_status_t status)
{
    environment_t *env = context; CHECK(++env->closes == 1u);
    CHECK(status == SOLARIS_OK || (env->mode == STOP_ACTIVE && status == SOLARIS_ECANCELLED));
    CHECK(env->child_closes == env->accepted && env->opens == env->accepted);
    if (env->mode == CANCEL_WRITE || env->mode == STOP_ACTIVE) CHECK(env->writes == 1u);
    solaris_test_event_signal(&env->complete);
}
static void cancel_deferred(void *context)
{ environment_t *env = context; env->stack->ops->close(env->stack->state); }
static void shutdown_done(void *context, solaris_status_t status)
{ environment_t *env = context; CHECK(status == SOLARIS_OK); env->shutdowns++; }
static void written(void *context, solaris_status_t status)
{
    environment_t *env = context;
    CHECK(status == SOLARIS_OK || env->mode == CANCEL_WRITE || env->mode == STOP_ACTIVE); env->writes++;
    if (env->mode == NORMAL || env->mode == IDLE)
        CHECK(solaris_stream_shutdown_write(env->stream, shutdown_done, env) == SOLARIS_OK);
}
static void child_opened(void *context, solaris_stream_t *stream, solaris_status_t status)
{
    environment_t *env = context; CHECK(++env->opens == 1u); env->stream = stream;
    if (env->mode == CLOSE_BEFORE_OPEN || env->mode == CLOSE_IN_ACCEPT || env->mode == REPLACE_IN_ACCEPT) {
        CHECK(status == SOLARIS_ECANCELLED); solaris_test_event_signal(&env->opened); return;
    }
    CHECK(status == SOLARIS_OK);
    if (env->mode == CANCEL_WRITE || env->mode == STOP_ACTIVE) {
        solaris_buffer_t *buffer; CHECK(solaris_buffer_allocate(env->budget, 65536u, &buffer) == SOLARIS_OK);
        memset(solaris_buffer_mutable_data(buffer), 42, 65536u); CHECK(solaris_buffer_set_length(buffer, 65536u) == SOLARIS_OK);
        solaris_slice_t slice = {buffer, 0u, 65536u}; CHECK(solaris_stream_write(stream, &slice, written, env) == SOLARIS_OK);
        solaris_buffer_release(buffer);
        if (env->mode == CANCEL_WRITE) env->stack->ops->close(env->stack->state);
    } else CHECK(solaris_stream_set_reading(stream, 1) == SOLARIS_OK);
    solaris_test_event_signal(&env->opened);
}
static void child_data(void *context, solaris_stream_t *stream, const solaris_buffer_t *buffer)
{
    environment_t *env = context; CHECK(stream == env->stream); env->reads++;
    size_t size = solaris_buffer_length(buffer); CHECK(size <= sizeof(env->received) - env->read_bytes);
    memcpy(env->received + env->read_bytes, solaris_buffer_data(buffer), size); env->read_bytes += size;
    if (env->read_bytes == sizeof(env->received)) {
        CHECK(memcmp(env->received, "hello", 5u) == 0);
        solaris_buffer_t *reply; CHECK(solaris_buffer_copy(env->budget, env->received, 5u, &reply) == SOLARIS_OK);
        solaris_slice_t slice = {reply, 0u, 5u}; CHECK(solaris_stream_write(stream, &slice, written, env) == SOLARIS_OK);
        solaris_buffer_release(reply);
    }
}
static void child_eof(void *context, solaris_stream_t *stream)
{ environment_t *env = context; CHECK(stream == env->stream); env->eofs++; }
static void child_closed(void *context, solaris_stream_t *stream, solaris_status_t status)
{
    environment_t *env = context; CHECK(stream == env->stream && ++env->child_closes == 1u);
    if (env->mode == NORMAL || env->mode == IDLE) CHECK(status == SOLARIS_OK && env->read_bytes == 5u && env->writes == 1u && env->shutdowns == 1u && env->eofs == 1u);
    solaris_test_event_signal(&env->child_done);
}
static const solaris_stream_callbacks_t stream_callbacks = {child_opened, child_data, child_eof, NULL, child_closed};
static solaris_status_t accept_connection(void *context, const solaris_address_t *source,
    const solaris_address_t *destination, solaris_stream_callbacks_t *callbacks, void **stream_context)
{
    environment_t *env = context;
    CHECK(solaris_address_equal(source, &env->original_source) && solaris_address_equal(destination, &env->original_destination));
    CHECK(++env->accepted == 1u); *callbacks = stream_callbacks; *stream_context = env;
    if (env->mode == CLOSE_IN_ACCEPT) env->stack->ops->close(env->stack->state);
    else if (env->mode == CLOSE_BEFORE_OPEN) {
        env->cancel = (solaris_deferred_t){.run = cancel_deferred, .context = env};
        CHECK(solaris_executor_defer(env->owner, &env->cancel) == SOLARIS_OK);
    } else if (env->mode == REPLACE_IN_ACCEPT) {
        atomic_fetch_add(&env->clock, UINT64_C(2000000000));
        CHECK(input(env, source, destination, 2u, 23u) == SOLARIS_OK);
    }
    return SOLARIS_OK;
}
/* A real loopback TCP socket supplies the accepted stream. Only its peer IP
 * metadata is replaced with the synthetic kernel/TUN peer: Darwin cannot bind
 * an unconfigured adjacent address without changing host network settings. */
static solaris_status_t fixture_accept(void *context, const solaris_address_t *peer, const solaris_address_t *local,
    solaris_stream_t *stream, solaris_stream_callbacks_t *callbacks, void **stream_context)
{
    listener_fixture_t *fixture = context; solaris_address_t mapped = fixture->peer; mapped.port = peer->port;
    if (atomic_load(&fixture->env->spoof)) mapped = *peer;
    return fixture->accept(fixture->context, &mapped, local, stream, callbacks, stream_context);
}
static void fixture_closed(void *context, solaris_status_t status)
{ listener_fixture_t *fixture = context; fixture->closed(fixture->context, status); }
static solaris_status_t fixture_listen(void *context, solaris_executor_t *owner, const solaris_address_t *bind,
    const solaris_dialer_options_t *options, solaris_tcp_accept_fn accept,
    void (*on_close)(void *, solaris_status_t), void *listener_context, solaris_tcp_listener_t **out, solaris_address_t *bound)
{
    environment_t *env = context; listener_fixture_t *fixture = &env->listeners[bind->family == SOLARIS_ADDRESS_IPV6];
    *fixture = (listener_fixture_t){env, accept, on_close, listener_context,
        bind->family == SOLARIS_ADDRESS_IPV4 ? env->options.peer4 : env->options.peer6};
    return solaris_tcp_listener_open(owner, bind, options, fixture_accept, fixture_closed, fixture, out, bound);
}
static void exercise_packets(environment_t *env)
{
    env->reentrant_emit = 1;
    CHECK(input(env, &env->original_source, &env->original_destination, 2u, 17u) == SOLARIS_OK);
    solaris_address_t mapped_source = env->mapped_source, mapped_destination = env->mapped_destination;
    CHECK(mapped_source.port >= 1024u && mapped_destination.port != 0u);
    CHECK(input(env, &env->original_source, &env->original_destination, 2u, 17u) == SOLARIS_OK &&
        solaris_address_equal(&mapped_source, &env->mapped_source));
    CHECK(input(env, &env->original_source, &env->original_destination, 2u, 18u) == SOLARIS_EBUSY);
    CHECK(input(env, &mapped_destination, &mapped_source, 0x12u, 19u) == SOLARIS_OK);
    CHECK(solaris_address_equal(&env->mapped_source, &env->original_destination) &&
        solaris_address_equal(&env->mapped_destination, &env->original_source));
    solaris_address_t wrong = mapped_source; wrong.ip[0] ^= 1u;
    CHECK(input(env, &mapped_destination, &wrong, 0x12u, 19u) == SOLARIS_EACCESS);
    solaris_address_t other = env->original_source; other.port++;
    CHECK(input(env, &other, &env->original_destination, 16u, 17u) == SOLARIS_EACCESS);
    uint8_t bytes[80]; size_t size = tcp_packet(bytes, &other, &env->original_destination, 2u, 17u);
    bytes[size - 1u] ^= 1u; CHECK(env->stack->ops->input(env->stack->state, bytes, size) == SOLARIS_EINVAL);
    /* Two active entries plus one more fill the configured three slots. */
    CHECK(input(env, &other, &env->original_destination, 2u, 17u) == SOLARIS_OK);
    solaris_address_t expired = env->mapped_source;
    other.port++;
    CHECK(input(env, &other, &env->original_destination, 2u, 17u) == SOLARIS_OK);
    other.port++;
    CHECK(input(env, &other, &env->original_destination, 2u, 17u) == SOLARIS_EAGAIN);
    other.port -= 2u;
    CHECK(input(env, &other, &env->original_destination, 4u, 17u) == SOLARIS_OK);
    CHECK(input(env, &mapped_destination, &expired, 16u, 17u) == SOLARIS_OK);
    atomic_fetch_add(&env->clock, UINT64_C(500000000));
    CHECK(input(env, &env->original_source, &env->original_destination, 16u, 17u) == SOLARIS_OK);
    atomic_fetch_add(&env->clock, UINT64_C(600000000));
    CHECK(input(env, &mapped_destination, &expired, 16u, 17u) == SOLARIS_EACCESS);
    other.port += 2u;
    env->emit_failure = 1; CHECK(input(env, &other, &env->original_destination, 2u, 17u) == SOLARIS_EAGAIN);
    CHECK(input(env, &other, &env->original_destination, 2u, 17u) == SOLARIS_OK && env->mapped_source.port != expired.port);
    CHECK(input(env, &other, &env->original_destination, 4u, 17u) == SOLARIS_OK);
    env->mapped_source = mapped_source; env->mapped_destination = mapped_destination;
    env->reentrant_emit = 0;
}
static void start(void *context, solaris_status_t status)
{
    environment_t *env = context; CHECK(status == SOLARIS_OK);
    env->options = (solaris_tun_stack_options_t){.owner = env->owner, .context = env, .emit = emit, .accept = accept_connection,
        .on_close = closed, .flow_limit = 3u, .pending_byte_limit = 65536u, .idle_timeout_ms = 1000u, .mtu = 1500u};
    CHECK(solaris_address_parse("127.0.0.1", 0u, &env->options.address4) == SOLARIS_OK);
    CHECK(solaris_address_parse("127.0.0.2", 0u, &env->options.peer4) == SOLARIS_OK);
    CHECK(solaris_address_parse("::1", 0u, &env->options.address6) == SOLARIS_OK);
    CHECK(solaris_address_parse("fd00::2", 0u, &env->options.peer6) == SOLARIS_OK);
    if (env->mode != ALLOCATE) {
        solaris_tun_stack_options_t invalid = env->options; invalid.include_all_networks = 1;
        CHECK(solaris_tun_system_create(&invalid, &env->stack) == SOLARIS_ENOTSUP && env->stack == NULL);
        invalid = env->options; invalid.peer4 = invalid.address4;
        CHECK(solaris_tun_system_create(&invalid, &env->stack) == SOLARIS_EINVAL && env->stack == NULL);
    }
    solaris_tun_system_services_t services = {env, fixture_listen}; env->fail_count = 0;
    env->submit_status = solaris_tun_system_create_with_services(&env->options,
        env->mode == NATIVE_REJECT || env->mode == ALLOCATE ? NULL : &services, &env->stack);
    if (env->submit_status != SOLARIS_OK) { CHECK(env->mode == ALLOCATE && env->stack == NULL); solaris_test_event_signal(&env->complete); }
    else if (env->mode == ALLOCATE) env->stack->ops->close(env->stack->state);
    else {
        CHECK(solaris_address_parse(env->family == 4 ? "10.0.0.2" : "fd00::10", 40000u, &env->original_source) == SOLARIS_OK);
        CHECK(solaris_address_parse(env->family == 4 ? "8.8.8.8" : "2606:4700:4700::1111", 443u, &env->original_destination) == SOLARIS_OK);
        exercise_packets(env);
    }
    solaris_test_event_signal(&env->ready);
}
static void expire(void *context, solaris_status_t status)
{
    environment_t *env = context; CHECK(status == SOLARIS_OK); env->old_port = env->mapped_source.port;
    CHECK(input(env, &env->mapped_destination, &env->mapped_source, 16u, 17u) == SOLARIS_EACCESS);
    CHECK(input(env, &env->original_source, &env->original_destination, 2u, 17u) == SOLARIS_OK);
    CHECK(env->mapped_source.port != env->old_port); solaris_test_event_signal(&env->step);
}
static void stop(void *context, solaris_status_t status)
{
    environment_t *env = context; CHECK(status == SOLARIS_OK);
    if (env->mode == NORMAL || env->mode == IDLE) {
        /* The application stream has closed, but the OS can still retransmit
         * its final data/FIN and receive the peer's last ACK or duplicate FIN. */
        solaris_address_t peer = env->mapped_source, local = env->mapped_destination;
        CHECK(input(env, &local, &peer, 0x19u, 100u) == SOLARIS_OK);
        CHECK(solaris_address_equal(&env->mapped_source, &env->original_destination));
        CHECK(solaris_address_equal(&env->mapped_destination, &env->original_source));
        CHECK(input(env, &env->original_source, &env->original_destination, 0x11u, 100u) == SOLARIS_OK);
        CHECK(solaris_address_equal(&env->mapped_source, &peer) && solaris_address_equal(&env->mapped_destination, &local));
        CHECK(input(env, &env->original_source, &env->original_destination, 2u, 18u) == SOLARIS_EBUSY);
        atomic_fetch_add(&env->clock, UINT64_C(2000000000));
        CHECK(input(env, &local, &peer, 0x11u, 100u) == SOLARIS_OK);
        if (env->mode == IDLE) {
            atomic_fetch_add(&env->clock, UINT64_C(121000000000));
            CHECK(input(env, &local, &peer, 0x11u, 100u) == SOLARIS_EACCESS);
            CHECK(input(env, &env->original_source, &env->original_destination, 16u, 101u) == SOLARIS_EACCESS);
            CHECK(input(env, &env->original_source, &env->original_destination, 2u, 18u) == SOLARIS_OK);
            CHECK(env->mapped_source.port != peer.port);
        }
    }
    if (env->mode == REPLACE_IN_ACCEPT) {
        CHECK(input(env, &env->mapped_destination, &env->mapped_source, 16u, 29u) == SOLARIS_OK);
        CHECK(solaris_address_equal(&env->mapped_source, &env->original_destination));
    }
    env->stack->ops->close(env->stack->state);
}
static void unverified_reset(void *context, solaris_status_t status)
{
    environment_t *env = context; CHECK(status == SOLARIS_OK);
    CHECK(input(env, &env->original_source, &env->original_destination, 4u, UINT32_MAX) == SOLARIS_OK);
    /* NAT does not validate TCP sequence numbers; only the OS TCP endpoint
     * may decide whether the forwarded reset belongs to its receive window. */
    CHECK(solaris_stream_set_reading(env->stream, 1) == SOLARIS_OK);
    solaris_test_event_signal(&env->step);
}
static test_socket_t connect_client(environment_t *env, uint16_t port)
{
    int family = env->family == 4 ? AF_INET : AF_INET6; test_socket_t fd = socket(family, SOCK_STREAM, 0); CHECK(fd != TEST_INVALID_SOCKET);
    int yes = 1; CHECK(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes, sizeof(yes)) == 0);
#ifdef _WIN32
    DWORD timeout = 2000u;
#else
    struct timeval timeout = {2, 0};
#endif
    CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout)) == 0);
    solaris_address_t source; CHECK(solaris_address_parse(env->family == 4 ? "127.0.0.1" : "::1", port, &source) == SOLARIS_OK);
    struct sockaddr_storage local, peer;
    CHECK(solaris_address_to_sockaddr(&source, &local) == SOLARIS_OK && solaris_address_to_sockaddr(&env->mapped_destination, &peer) == SOLARIS_OK);
    int length = family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
    CHECK(bind(fd, (const struct sockaddr *)&local, length) == 0);
    CHECK(connect(fd, (const struct sockaddr *)&peer, length) == 0); return fd;
}
static void reject_client(environment_t *env, uint16_t port)
{
    test_socket_t fd = connect_client(env, port); char byte;
    int count = (int)recv(fd, &byte, 1u, 0); CHECK(count == 0 || (count < 0 && reset_error())); close_socket(fd);
}
static void run(int mode, int family, int failure)
{
    environment_t env = {.mode = mode, .family = family}; atomic_init(&env.clock, 0u); atomic_init(&env.spoof, 0);
    CHECK(solaris_test_event_init(&env.ready, 0u) == 0 && solaris_test_event_init(&env.step, 0u) == 0 &&
        solaris_test_event_init(&env.opened, 0u) == 0 && solaris_test_event_init(&env.child_done, 0u) == 0 && solaris_test_event_init(&env.complete, 0u) == 0);
    solaris_runtime_services_t services; solaris_runtime_services_init(&services);
    services.context = &env; services.allocate = allocate; services.now_ns = now;
    CHECK(solaris_budget_create(8u * 1024u * 1024u, &services, &env.budget) == SOLARIS_OK);
    solaris_executor_options_t options = {.id = (uint32_t)mode % 2u, .queue_capacity = 8u, .resource_limit = 64u,
        .budget = env.budget, .services = &services};
    CHECK(solaris_executor_create(&options, &env.owner) == SOLARIS_OK && solaris_executor_activate(env.owner, 1u) == SOLARIS_OK);
    env.fail_at = failure; CHECK(solaris_executor_post(env.owner, start, &env) == SOLARIS_OK); solaris_test_event_wait(&env.ready);
    if (mode == NATIVE_REJECT) {
        reject_client(&env, env.mapped_source.port); CHECK(solaris_executor_post(env.owner, stop, &env) == SOLARIS_OK);
    } else if (mode != ALLOCATE) {
        atomic_store(&env.spoof, 1); reject_client(&env, env.mapped_source.port); atomic_store(&env.spoof, 0);
        reject_client(&env, (uint16_t)(env.mapped_source.port + 10u));
        if (mode == IDLE) {
            atomic_store(&env.clock, UINT64_C(2000000000)); solaris_executor_wake(env.owner);
            CHECK(solaris_executor_post(env.owner, expire, &env) == SOLARIS_OK); solaris_test_event_wait(&env.step);
            reject_client(&env, env.old_port);
        }
        test_socket_t fd = connect_client(&env, env.mapped_source.port);
        solaris_test_event_wait(&env.opened);
        if (mode == NORMAL || mode == IDLE) {
            CHECK(solaris_executor_post(env.owner, unverified_reset, &env) == SOLARIS_OK);
            solaris_test_event_wait(&env.step);
            CHECK(send(fd, "hello", 5u, 0) == 5 && shutdown(fd, TEST_SHUT_WR) == 0);
            char reply[5]; size_t count = 0u;
            while (count < sizeof(reply)) { int n = (int)recv(fd, reply + count, (int)(sizeof(reply) - count), 0); CHECK(n > 0); count += (size_t)n; }
            CHECK(memcmp(reply, "hello", 5u) == 0); solaris_test_event_wait(&env.child_done);
            CHECK(solaris_executor_post(env.owner, stop, &env) == SOLARIS_OK);
        } else if (mode == STOP_ACTIVE) CHECK(solaris_executor_begin_quiesce(env.owner) == SOLARIS_OK);
        else if (mode == REPLACE_IN_ACCEPT) { solaris_test_event_wait(&env.child_done); CHECK(solaris_executor_post(env.owner, stop, &env) == SOLARIS_OK); }
        solaris_test_event_wait(&env.complete); close_socket(fd);
    }
    if (mode == NATIVE_REJECT || mode == ALLOCATE) solaris_test_event_wait(&env.complete);
    CHECK(solaris_executor_quiesce(env.owner) == SOLARIS_OK && solaris_executor_destroy(env.owner) == SOLARIS_OK);
    if (env.submit_status == SOLARIS_OK) CHECK(env.closes == 1u);
    else CHECK(env.closes == 0u && env.accepted == 0u);
    CHECK(solaris_budget_used(env.budget) == 0u); solaris_budget_release(env.budget);
    solaris_test_event_destroy(&env.ready); solaris_test_event_destroy(&env.step); solaris_test_event_destroy(&env.opened);
    solaris_test_event_destroy(&env.child_done); solaris_test_event_destroy(&env.complete);
}
int main(void)
{
#ifdef _WIN32
    WSADATA winsock; CHECK(WSAStartup(MAKEWORD(2, 2), &winsock) == 0);
#endif
    for (int family = 4; family <= 6; family += 2)
        for (int mode = NORMAL; mode <= NATIVE_REJECT; ++mode) run(mode, family, 0);
    for (int failure = 1; failure <= 32; ++failure) run(ALLOCATE, 4, failure);
#ifdef _WIN32
    CHECK(WSACleanup() == 0);
#endif
    puts("System TUN: dual-stack NAT, source/port guards, expiry/quarantine, reentrant accept, real loopback stream and stop/allocation barriers passed");
    return 0;
}
