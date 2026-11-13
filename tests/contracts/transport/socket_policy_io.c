#include "transport/socket/socket.h"
#include "support/runtime/event.h"
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)

#ifdef _WIN32
typedef struct windows_case {
    solaris_executor_t *owner;
    solaris_scope_t parent;
    solaris_test_event_t done;
} windows_case_t;
static solaris_status_t unexpected_start(void *context, solaris_socket_token_t *token, uintptr_t handle, uint32_t family, uint32_t kind)
{ (void)context; (void)token; (void)handle; (void)family; (void)kind; CHECK(0); return SOLARIS_EIO; }
static void unexpected_cancel(void *context, solaris_socket_token_t *token) { (void)context; (void)token; CHECK(0); }
static void stream_event(void *context, solaris_stream_t *stream, solaris_status_t status)
{ (void)context; (void)stream; (void)status; CHECK(0); }
static void stream_data(void *context, solaris_stream_t *stream, const solaris_buffer_t *buffer)
{ (void)context; (void)stream; (void)buffer; CHECK(0); }
static void datagram_event(void *context, solaris_datagram_t *datagram, solaris_status_t status)
{ (void)context; (void)datagram; (void)status; CHECK(0); }
static void datagram_data(void *context, solaris_datagram_t *datagram, const solaris_address_t *peer, const solaris_buffer_t *buffer)
{ (void)context; (void)datagram; (void)peer; (void)buffer; CHECK(0); }
static void parent_done(void *context) { solaris_test_event_signal(&((windows_case_t *)context)->done); }
static void windows_start(void *context, solaris_status_t status)
{
    windows_case_t *test = context; CHECK(status == SOLARIS_OK);
    CHECK(solaris_scope_init(&test->parent, test->owner, NULL, parent_done, test) == SOLARIS_OK);
    solaris_dialer_options_t options; solaris_dialer_options_init(&options);
    options.parent_scope = &test->parent; options.async_policy.start = unexpected_start; options.async_policy.cancel = unexpected_cancel;
    solaris_address_t target; CHECK(solaris_address_parse("127.0.0.1", 9u, &target) == SOLARIS_OK);
    solaris_stream_callbacks_t stream_callbacks = {.on_open = stream_event, .on_data = stream_data, .on_close = stream_event};
    solaris_datagram_callbacks_t datagram_callbacks = {.on_open = datagram_event, .on_packet = datagram_data, .on_close = datagram_event};
    solaris_stream_t *stream = NULL; solaris_datagram_t *datagram = NULL;
    CHECK(solaris_dialer_open_stream(test->owner, &options, &target, &stream_callbacks, NULL, &stream) == SOLARIS_ENOTSUP && stream == NULL);
    CHECK(solaris_dialer_open_datagram(test->owner, &options, SOLARIS_ADDRESS_IPV4, &datagram_callbacks, NULL, &datagram) == SOLARIS_ENOTSUP && datagram == NULL);
    solaris_scope_cancel(&test->parent);
}
int main(void)
{
    windows_case_t test = {0}; solaris_budget_t *budget;
    CHECK(solaris_test_event_init(&test.done, 0u) == 0 && solaris_budget_create(1024u * 1024u, NULL, &budget) == SOLARIS_OK);
    solaris_executor_options_t options = {.budget = budget, .queue_capacity = 8u, .resource_limit = 16u};
    CHECK(solaris_executor_create(&options, &test.owner) == SOLARIS_OK && solaris_executor_activate(test.owner, 1u) == SOLARIS_OK);
    CHECK(solaris_executor_post(test.owner, windows_start, &test) == SOLARIS_OK); solaris_test_event_wait(&test.done);
    CHECK(solaris_executor_quiesce(test.owner) == SOLARIS_OK && solaris_executor_destroy(test.owner) == SOLARIS_OK);
    CHECK(solaris_budget_used(budget) == 0u); solaris_budget_release(budget); solaris_test_event_destroy(&test.done);
    puts("socket policy I/O: Windows unsupported TCP/UDP hooks reject without callbacks and drain parents"); return 0;
}
#else
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

enum { SUCCESS, ASYNC_FAILURE, HOST_REJECT, SYNC_REJECT, CANCEL, TIMEOUT, STOP, ALLOC_GATE, RETRY };
typedef struct environment {
    solaris_executor_t *owner;
    solaris_budget_t *budget;
    solaris_runtime_services_t services;
    solaris_scope_t parent;
    solaris_stream_t *stream;
    solaris_datagram_t *datagram;
    solaris_socket_token_t *token;
    solaris_address_t target, local;
    solaris_test_event_t ready, host_ready, opened, closed, cancelled, action, parent_done;
    solaris_deferred_t resolved;
    solaris_resolve_fn resolve_callback;
    void *resolve_context;
    atomic_uint refs, retains, releases, opens, closes, sent, packets, parents, acknowledged;
    atomic_uint_fast64_t clock;
    atomic_int fail_next;
    solaris_status_t submitted, open_status, close_status, resolve_status;
    uint32_t family, kind;
    int mode, peer, retry_guard, reused_fd, original, duplicate, host_calls, sync_calls, resolve_pending;
    size_t received;
} environment_t;
static void *allocate(void *context, size_t size)
{ return atomic_exchange(&((environment_t *)context)->fail_next, 0) ? NULL : malloc(size); }
static uint64_t now_ns(void *context) { return atomic_load(&((environment_t *)context)->clock); }
static void retain(void *context)
{
    environment_t *env = context;
    CHECK(atomic_fetch_add(&env->refs, 1u) > 0u); atomic_fetch_add(&env->retains, 1u);
}
static void release(void *context)
{
    environment_t *env = context; CHECK(atomic_load(&env->parents) == 0u);
    CHECK(atomic_fetch_sub(&env->refs, 1u) > 0u); atomic_fetch_add(&env->releases, 1u);
}
static solaris_status_t synchronous_policy(void *context, uintptr_t handle, uint32_t family, uint32_t kind)
{
    environment_t *env = context;
    uint32_t expected_family = env->mode == RETRY && env->sync_calls == 0 ? SOLARIS_ADDRESS_IPV6 : env->family;
    CHECK(solaris_executor_is_owner(env->owner) && family == expected_family && kind == env->kind);
    env->sync_calls++; env->original = (int)handle;
    if (env->mode == ALLOC_GATE) atomic_store(&env->fail_next, 1);
    return env->mode == SYNC_REJECT ? SOLARIS_EACCESS : SOLARIS_OK;
}
static solaris_status_t host_start(void *context, solaris_socket_token_t *token, uintptr_t handle, uint32_t family, uint32_t kind)
{
    environment_t *env = context; CHECK(solaris_executor_is_owner(env->owner));
    uint32_t expected_family = env->mode == RETRY && env->host_calls == 0 ? SOLARIS_ADDRESS_IPV6 : env->family;
    CHECK(family == expected_family && kind == env->kind && env->sync_calls == env->host_calls + 1);
    CHECK((int)handle != env->original && atomic_load(&env->refs) >= 2u);
    env->host_calls++; env->duplicate = (int)handle; env->token = token;
    CHECK(fcntl(env->duplicate, F_GETFL) == fcntl(env->original, F_GETFL));
    solaris_test_event_signal(&env->host_ready);
    return env->mode == HOST_REJECT ? SOLARIS_EACCESS : SOLARIS_OK;
}
static void host_cancel(void *context, solaris_socket_token_t *token)
{
    environment_t *env = context; CHECK(solaris_executor_is_owner(env->owner) && token == env->token);
    CHECK(fcntl(env->duplicate, F_GETFD) >= 0 && atomic_load(&env->refs) >= 2u);
    solaris_test_event_signal(&env->cancelled);
}
static void parent_finished(void *context)
{
    environment_t *env = context;
    CHECK(atomic_load(&env->refs) == 0u && atomic_load(&env->releases) == atomic_load(&env->retains) + 1u);
    CHECK(atomic_load(&env->closes) == (env->submitted == SOLARIS_OK ? 1u : 0u));
    atomic_fetch_add(&env->parents, 1u); solaris_test_event_signal(&env->parent_done);
}
static void sent(void *context, solaris_status_t status)
{
    environment_t *env = context; CHECK(status == SOLARIS_OK && solaris_executor_is_owner(env->owner));
    CHECK(atomic_load(&env->acknowledged) && atomic_fetch_add(&env->sent, 1u) == 0u);
}
static solaris_status_t send_ping(environment_t *env)
{
    solaris_buffer_t *buffer; CHECK(solaris_buffer_copy(env->budget, "ping", 4u, &buffer) == SOLARIS_OK);
    solaris_slice_t slice = {buffer, 0u, 4u};
    solaris_status_t rc = env->kind == SOLARIS_SOCKET_TCP ? solaris_stream_write(env->stream, &slice, sent, env) :
        solaris_datagram_send(env->datagram, &env->target, &slice, sent, env);
    solaris_buffer_release(buffer); return rc;
}
static void on_open(environment_t *env, solaris_status_t status)
{
    CHECK(solaris_executor_is_owner(env->owner) && atomic_fetch_add(&env->opens, 1u) == 0u);
    env->open_status = status;
    if (status == SOLARIS_OK) { CHECK(atomic_load(&env->acknowledged)); CHECK(send_ping(env) == SOLARIS_OK); }
    solaris_test_event_signal(&env->opened);
}
static void tcp_opened(void *context, solaris_stream_t *stream, solaris_status_t status)
{ environment_t *env = context; CHECK(stream == env->stream); on_open(env, status); }
static void udp_opened(void *context, solaris_datagram_t *datagram, solaris_status_t status)
{ environment_t *env = context; CHECK(datagram == env->datagram); on_open(env, status); }
static void on_close(environment_t *env, solaris_status_t status)
{
    CHECK(solaris_executor_is_owner(env->owner) && atomic_fetch_add(&env->closes, 1u) == 0u && atomic_load(&env->opens) == 1u);
    CHECK(atomic_load(&env->refs) == 1u && fcntl(env->duplicate, F_GETFD) < 0 && errno == EBADF);
    env->close_status = status; solaris_scope_cancel(&env->parent); solaris_test_event_signal(&env->closed);
}
static void tcp_closed(void *context, solaris_stream_t *stream, solaris_status_t status)
{ environment_t *env = context; CHECK(stream == env->stream); env->stream = NULL; on_close(env, status); }
static void udp_closed(void *context, solaris_datagram_t *datagram, solaris_status_t status)
{ environment_t *env = context; CHECK(datagram == env->datagram); env->datagram = NULL; on_close(env, status); }
static void tcp_data(void *context, solaris_stream_t *stream, const solaris_buffer_t *buffer)
{
    environment_t *env = context; CHECK(stream == env->stream && atomic_load(&env->acknowledged));
    size_t n = solaris_buffer_length(buffer); CHECK(n <= 4u - env->received);
    CHECK(memcmp(solaris_buffer_data(buffer), &"pong"[env->received], n) == 0); env->received += n;
    if (env->received == 4u) CHECK(solaris_stream_close(stream) == SOLARIS_OK);
}
static void udp_data(void *context, solaris_datagram_t *datagram, const solaris_address_t *peer, const solaris_buffer_t *buffer)
{
    environment_t *env = context; CHECK(datagram == env->datagram && atomic_load(&env->acknowledged));
    CHECK(solaris_address_equal(peer, &env->target)); atomic_fetch_add(&env->packets, 1u);
    if (solaris_buffer_length(buffer) == 5u) CHECK(memcmp(solaris_buffer_data(buffer), "early", 5u) == 0);
    else { CHECK(solaris_buffer_length(buffer) == 4u && memcmp(solaris_buffer_data(buffer), "pong", 4u) == 0);
        CHECK(solaris_datagram_close(datagram) == SOLARIS_OK); }
}
static const solaris_stream_callbacks_t tcp_callbacks = {.on_open = tcp_opened, .on_data = tcp_data, .on_close = tcp_closed};
static const solaris_datagram_callbacks_t udp_callbacks = {.on_open = udp_opened, .on_packet = udp_data, .on_close = udp_closed};
static void resolve_delivery(void *context)
{
    environment_t *env = context; env->resolve_pending = 0;
    solaris_address_t addresses[2]; CHECK(solaris_address_parse("::1", 0u, &addresses[0]) == SOLARIS_OK);
    CHECK(solaris_address_parse("127.0.0.1", 0u, &addresses[1]) == SOLARIS_OK);
    env->resolve_callback(env->resolve_context, env->resolve_status, addresses, env->resolve_status == SOLARIS_OK ? 2u : 0u);
}
static solaris_status_t resolve_start(void *context, solaris_executor_t *owner, const solaris_dns_lookup_view_t *view,
    const solaris_address_t *target, uint64_t deadline, solaris_resolve_fn callback, void *user, void **out)
{
    environment_t *env = context;
    CHECK(owner == env->owner && view->role == SOLARIS_DNS_PROXY_SERVER && view->network_revision == 7u);
    CHECK(target->family == SOLARIS_ADDRESS_DOMAIN && deadline == UINT64_C(10000000));
    env->resolve_callback = callback; env->resolve_context = user; env->resolve_pending = 1;
    env->resolved = (solaris_deferred_t){.run = resolve_delivery, .context = env}; *out = env;
    return solaris_executor_defer(owner, &env->resolved);
}
static void resolve_cancel(void *context, void *request)
{ environment_t *env = context; CHECK(request == env && env->resolve_pending); env->resolve_status = SOLARIS_ECANCELLED; }
static void start(void *context, solaris_status_t status)
{
    environment_t *env = context; CHECK(status == SOLARIS_OK);
    CHECK(solaris_scope_init(&env->parent, env->owner, NULL, parent_finished, env) == SOLARIS_OK);
    solaris_dialer_options_t options; solaris_dialer_options_init(&options);
    options.open_timeout_ms = 10u; options.parent_scope = &env->parent;
    options.prepare_socket = synchronous_policy; options.policy_context = env;
    options.async_policy = (solaris_socket_policy_t){env, retain, release, host_start, host_cancel};
    solaris_address_t target = env->target;
    if (env->mode == RETRY) {
        CHECK(solaris_address_parse("retry.test", env->target.port, &target) == SOLARIS_OK);
        options.lookup = (solaris_dns_lookup_t){env, resolve_start, resolve_cancel};
        options.lookup_view.role = SOLARIS_DNS_PROXY_SERVER; options.lookup_view.network_revision = 7u;
    }
    env->submitted = env->kind == SOLARIS_SOCKET_TCP ?
        solaris_dialer_open_stream(env->owner, &options, &target, &tcp_callbacks, env, &env->stream) :
        solaris_dialer_open_datagram(env->owner, &options, env->family, &udp_callbacks, env, &env->datagram);
    if (env->submitted == SOLARIS_OK) {
        CHECK(send_ping(env) == SOLARIS_EBUSY);
        if (env->datagram) {
            CHECK(solaris_datagram_set_reading(env->datagram, 1) == SOLARIS_OK);
            CHECK(solaris_datagram_local_address(env->datagram, &env->local) == SOLARIS_OK);
        }
    } else { CHECK(!env->stream && !env->datagram); solaris_scope_cancel(&env->parent); }
    release(env); /* Caller reference ends after open acceptance/rejection. */
    solaris_test_event_signal(&env->ready);
}
static void close_pending(void *context, solaris_status_t status)
{
    environment_t *env = context; CHECK(status == SOLARIS_OK);
    CHECK((env->kind == SOLARIS_SOCKET_TCP ? solaris_stream_close(env->stream) : solaris_datagram_close(env->datagram)) == SOLARIS_OK);
    solaris_test_event_signal(&env->action);
}
static void expire(void *context, solaris_status_t status)
{ environment_t *env = context; CHECK(status == SOLARIS_OK); atomic_store(&env->clock, UINT64_C(11000000)); solaris_test_event_signal(&env->action); }
static int wait_readable(int fd, int timeout)
{ struct pollfd poller = {fd, POLLIN, 0}; return poll(&poller, 1u, timeout); }
static void socket_address(const solaris_address_t *address, struct sockaddr_storage *native, socklen_t *length)
{
    CHECK(solaris_address_to_sockaddr(address, native) == SOLARIS_OK);
    *length = address->family == SOLARIS_ADDRESS_IPV4 ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
}
static void setup_peer(environment_t *env)
{
    env->peer = socket(env->family == SOLARIS_ADDRESS_IPV4 ? AF_INET : AF_INET6,
        env->kind == SOLARIS_SOCKET_TCP ? SOCK_STREAM : SOCK_DGRAM, 0); CHECK(env->peer >= 0);
    CHECK(solaris_address_parse(env->family == SOLARIS_ADDRESS_IPV4 ? "127.0.0.1" : "::1", 0u, &env->target) == SOLARIS_OK);
    struct sockaddr_storage address; socklen_t length; socket_address(&env->target, &address, &length);
    CHECK(bind(env->peer, (struct sockaddr *)&address, length) == 0);
    CHECK(getsockname(env->peer, (struct sockaddr *)&address, &length) == 0);
    CHECK(solaris_address_from_sockaddr((struct sockaddr *)&address, &env->target) == SOLARIS_OK);
    if (env->kind == SOLARIS_SOCKET_TCP) CHECK(listen(env->peer, 2) == 0);
    if (env->mode == RETRY) {
        env->retry_guard = socket(AF_INET6, SOCK_STREAM, 0); CHECK(env->retry_guard >= 0);
        solaris_address_t rejected; CHECK(solaris_address_parse("::1", env->target.port, &rejected) == SOLARIS_OK);
        socket_address(&rejected, &address, &length);
        CHECK(bind(env->retry_guard, (struct sockaddr *)&address, length) == 0); /* Reserved, deliberately not listening. */
    }
}
static void reuse_closed_original(environment_t *env)
{
    for (unsigned int i = 0; fcntl(env->original, F_GETFD) >= 0 && i < 1000u; ++i) uv_sleep(1u);
    CHECK(fcntl(env->original, F_GETFD) < 0 && errno == EBADF);
    int type = env->kind == SOLARIS_SOCKET_TCP ? SOCK_DGRAM : SOCK_STREAM;
    int next = socket(AF_INET, type, 0); CHECK(next >= 0);
    if (next != env->original) { CHECK(dup2(next, env->original) == env->original); close(next); }
    env->reused_fd = env->original;
    int actual = 0; socklen_t size = sizeof(actual);
    CHECK(getsockopt(env->reused_fd, SOL_SOCKET, SO_TYPE, &actual, &size) == 0 && actual == type);
    CHECK(getsockopt(env->duplicate, SOL_SOCKET, SO_TYPE, &actual, &size) == 0 && actual != type);
}
static void run(uint32_t family, uint32_t kind, int mode)
{
    fprintf(stderr, "socket policy I/O: family=%u kind=%u mode=%d\n", family, kind, mode);
    environment_t env; memset(&env, 0, sizeof(env)); env.family = family; env.kind = kind; env.mode = mode;
    env.reused_fd = env.retry_guard = -1;
    atomic_init(&env.refs, 1u); atomic_init(&env.retains, 0u); atomic_init(&env.releases, 0u); atomic_init(&env.opens, 0u);
    atomic_init(&env.closes, 0u); atomic_init(&env.sent, 0u); atomic_init(&env.packets, 0u); atomic_init(&env.parents, 0u);
    atomic_init(&env.acknowledged, 0u); atomic_init(&env.clock, 0u); atomic_init(&env.fail_next, 0);
    setup_peer(&env);
    CHECK(solaris_test_event_init(&env.ready, 0u) == 0 && solaris_test_event_init(&env.host_ready, 0u) == 0 &&
        solaris_test_event_init(&env.opened, 0u) == 0 && solaris_test_event_init(&env.closed, 0u) == 0 &&
        solaris_test_event_init(&env.cancelled, 0u) == 0 && solaris_test_event_init(&env.action, 0u) == 0 &&
        solaris_test_event_init(&env.parent_done, 0u) == 0);
    solaris_runtime_services_init(&env.services); env.services.context = &env; env.services.allocate = allocate; env.services.now_ns = now_ns;
    CHECK(solaris_budget_create(1024u * 1024u, &env.services, &env.budget) == SOLARIS_OK);
    solaris_executor_options_t options = {.budget = env.budget, .services = &env.services, .queue_capacity = 8u, .resource_limit = 32u};
    CHECK(solaris_executor_create(&options, &env.owner) == SOLARIS_OK && solaris_executor_activate(env.owner, 1u) == SOLARIS_OK);
    CHECK(solaris_executor_post(env.owner, start, &env) == SOLARIS_OK); solaris_test_event_wait(&env.ready);
    if (mode == HOST_REJECT || mode == SYNC_REJECT || mode == ALLOC_GATE) {
        CHECK(env.submitted == (mode == ALLOC_GATE ? SOLARIS_ENOMEM : SOLARIS_EACCESS));
        CHECK(env.host_calls == (mode == HOST_REJECT));
    } else {
        CHECK(env.submitted == SOLARIS_OK); solaris_test_event_wait(&env.host_ready);
        CHECK(wait_readable(env.peer, 20) == 0 && atomic_load(&env.opens) == 0u && atomic_load(&env.sent) == 0u);
        if (kind == SOLARIS_SOCKET_UDP && mode == SUCCESS) {
            solaris_address_t local; CHECK(solaris_address_parse(family == SOLARIS_ADDRESS_IPV4 ? "127.0.0.1" : "::1", env.local.port, &local) == SOLARIS_OK);
            struct sockaddr_storage address; socklen_t length; socket_address(&local, &address, &length);
            CHECK(sendto(env.peer, "early", 5u, 0, (struct sockaddr *)&address, length) == 5);
            CHECK(wait_readable(env.peer, 20) == 0 && atomic_load(&env.packets) == 0u);
        }
        if (mode == CANCEL || mode == TIMEOUT) {
            CHECK(solaris_executor_post(env.owner, mode == CANCEL ? close_pending : expire, &env) == SOLARIS_OK);
            solaris_test_event_wait(&env.action); solaris_test_event_wait(&env.cancelled);
        } else if (mode == STOP) {
            CHECK(solaris_executor_begin_quiesce(env.owner) == SOLARIS_OK); solaris_test_event_wait(&env.cancelled);
            CHECK(!solaris_executor_is_quiescent(env.owner));
        }
        if (mode == CANCEL || mode == STOP) reuse_closed_original(&env);
        CHECK(atomic_load(&env.closes) == 0u && atomic_load(&env.parents) == 0u && fcntl(env.duplicate, F_GETFD) >= 0);
        atomic_store(&env.acknowledged, 1u);
        CHECK(solaris_socket_policy_complete(env.token, mode == ASYNC_FAILURE ? SOLARIS_EACCESS : SOLARIS_OK) == SOLARIS_OK);
        if (mode == RETRY) {
            atomic_store(&env.acknowledged, 0u); solaris_test_event_wait(&env.host_ready);
            CHECK(env.host_calls == 2 && wait_readable(env.peer, 20) == 0 && atomic_load(&env.refs) >= 2u);
            atomic_store(&env.acknowledged, 1u); CHECK(solaris_socket_policy_complete(env.token, SOLARIS_OK) == SOLARIS_OK);
        }
        if (mode == SUCCESS || mode == RETRY) {
            CHECK(wait_readable(env.peer, 5000) == 1);
            int connection = env.peer;
            if (kind == SOLARIS_SOCKET_TCP) { connection = accept(env.peer, NULL, NULL); CHECK(connection >= 0 && wait_readable(connection, 5000) == 1); }
            char payload[4]; struct sockaddr_storage source; socklen_t length = sizeof(source);
            ssize_t received = kind == SOLARIS_SOCKET_TCP ? recv(connection, payload, sizeof(payload), 0) :
                recvfrom(connection, payload, sizeof(payload), 0, (struct sockaddr *)&source, &length);
            CHECK(received == 4 && memcmp(payload, "ping", 4u) == 0);
            CHECK((kind == SOLARIS_SOCKET_TCP ? send(connection, "pong", 4u, MSG_NOSIGNAL) :
                sendto(connection, "pong", 4u, 0, (struct sockaddr *)&source, length)) == 4);
            if (connection != env.peer) close(connection);
        }
        solaris_test_event_wait(&env.closed);
        solaris_status_t expected = mode == CANCEL || mode == STOP ? SOLARIS_ECANCELLED : mode == TIMEOUT ? SOLARIS_ETIMEDOUT :
            mode == ASYNC_FAILURE ? SOLARIS_EACCESS : SOLARIS_OK;
        CHECK(env.open_status == expected);
        CHECK(wait_readable(env.peer, 0) == 0);
    }
    solaris_test_event_wait(&env.parent_done);
    CHECK(wait_readable(env.peer, 0) == 0); /* Rejected opens also emit no traffic. */
    CHECK(solaris_executor_quiesce(env.owner) == SOLARIS_OK && solaris_executor_destroy(env.owner) == SOLARIS_OK);
    if (env.reused_fd >= 0) { CHECK(fcntl(env.reused_fd, F_GETFD) >= 0); close(env.reused_fd); }
    close(env.peer);
    if (env.retry_guard >= 0) close(env.retry_guard);
    CHECK(solaris_budget_used(env.budget) == 0u); solaris_budget_release(env.budget);
    solaris_test_event_destroy(&env.ready); solaris_test_event_destroy(&env.host_ready); solaris_test_event_destroy(&env.opened);
    solaris_test_event_destroy(&env.closed); solaris_test_event_destroy(&env.cancelled); solaris_test_event_destroy(&env.action);
    solaris_test_event_destroy(&env.parent_done);
}
int main(void)
{
    for (uint32_t family = SOLARIS_ADDRESS_IPV4; family <= SOLARIS_ADDRESS_IPV6; family += 2u)
        for (uint32_t kind = SOLARIS_SOCKET_TCP; kind <= SOLARIS_SOCKET_UDP; ++kind)
            for (int mode = SUCCESS; mode <= ALLOC_GATE; ++mode) run(family, kind, mode);
    run(SOLARIS_ADDRESS_IPV4, SOLARIS_SOCKET_TCP, RETRY);
    puts("socket policy I/O: IPv4/IPv6 TCP/UDP gate, zero early traffic, FD reuse, retries and parent drain passed"); return 0;
}
#endif
