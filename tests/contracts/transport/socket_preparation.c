#include "transport/socket/preparation.h"
#include "support/runtime/event.h"
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <winsock2.h>
typedef SOCKET test_socket_t;
#define CLOSE_SOCKET closesocket
#else
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>
typedef int test_socket_t;
#define CLOSE_SOCKET close
#endif

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)
enum { NORMAL, SYNC, HOST_FAILURE, REJECT, CANCEL, CANCEL_SYNC, DEADLINE, STOP,
    FULL_QUEUE, ACK_AFTER_DEADLINE, EXPIRED, ALLOC_TOKEN, ALLOC_DEADLINE, WRONG_KIND, CLOSED_PARENT, RETAIN_EXPIRED };
typedef struct environment {
    solaris_runtime_services_t services;
    solaris_budget_t *budget;
    solaris_executor_t *owner;
    solaris_scope_t parent;
    solaris_socket_token_t *request, *host_token;
    solaris_test_event_t ready, action, cancelled, done, parent_done, entered, resume;
    atomic_uint completed, retained, released, cancelled_count, parents;
    atomic_int fail_at, allocations;
    atomic_uint_fast64_t clock;
    test_socket_t original;
    uintptr_t duplicate;
    int mode, in_start, calls;
    solaris_status_t submit_status, result;
} environment_t;
static void *allocate(void *context, size_t size)
{
    environment_t *env = context;
    int fail = atomic_load(&env->fail_at);
    if (fail && atomic_fetch_add(&env->allocations, 1) + 1 == fail) return NULL;
    return malloc(size);
}
static uint64_t now_ns(void *context) { return atomic_load(&((environment_t *)context)->clock); }
static void host_retain(void *context)
{
    environment_t *env = context; atomic_fetch_add(&env->retained, 1u);
    if (env->mode == RETAIN_EXPIRED) atomic_store(&env->clock, UINT64_C(101000000));
}
static void host_release(void *context)
{
    environment_t *env = context; CHECK(solaris_executor_is_owner(env->owner));
    CHECK(atomic_load(&env->parents) == 0u);
    atomic_fetch_add(&env->released, 1u);
}
static solaris_status_t host_start(void *context, solaris_socket_token_t *token, uintptr_t handle, uint32_t family, uint32_t kind)
{
    environment_t *env = context;
    CHECK(solaris_executor_is_owner(env->owner) && env->in_start && family == SOLARIS_ADDRESS_IPV4 && kind == SOLARIS_SOCKET_POLICY_TCP);
    CHECK(handle != (uintptr_t)env->original && atomic_load(&env->retained) == 1u);
    env->calls++; env->host_token = token; env->duplicate = handle;
#ifndef _WIN32
    CHECK((fcntl((int)handle, F_GETFD) & FD_CLOEXEC) != 0);
    CHECK(fcntl((int)handle, F_GETFL) == fcntl(env->original, F_GETFL));
#endif
    if (env->mode == REJECT) return SOLARIS_EACCESS;
    if (env->mode == SYNC) {
        CHECK(solaris_socket_policy_complete(token, SOLARIS_OK) == SOLARIS_OK);
        CHECK(solaris_socket_policy_complete(token, SOLARIS_EIO) == SOLARIS_ECLOSED);
        CHECK(atomic_load(&env->completed) == 0u);
    }
    return SOLARIS_OK;
}
static void host_cancel(void *context, solaris_socket_token_t *token)
{
    environment_t *env = context;
    CHECK(solaris_executor_is_owner(env->owner) && env->host_token == token);
    CHECK(atomic_fetch_add(&env->cancelled_count, 1u) == 0u);
#ifndef _WIN32
    CHECK(fcntl((int)env->duplicate, F_GETFD) >= 0);
#endif
    if (env->mode == CANCEL_SYNC) CHECK(solaris_socket_policy_complete(token, SOLARIS_OK) == SOLARIS_OK);
    solaris_test_event_signal(&env->cancelled);
}
static void parent_finished(void *context)
{
    environment_t *env = context;
    CHECK(atomic_load(&env->retained) == atomic_load(&env->released));
    CHECK(atomic_load(&env->completed) == (env->submit_status == SOLARIS_OK ? 1u : 0u));
#ifndef _WIN32
    if (env->calls) CHECK(fcntl((int)env->duplicate, F_GETFD) < 0 && errno == EBADF);
#endif
    atomic_fetch_add(&env->parents, 1u); solaris_test_event_signal(&env->parent_done);
}
static void completed(void *context, solaris_status_t status)
{
    environment_t *env = context;
    CHECK(solaris_executor_is_owner(env->owner) && !env->in_start);
    CHECK(atomic_fetch_add(&env->completed, 1u) == 0u && atomic_load(&env->released) == 0u);
#ifndef _WIN32
    CHECK(fcntl((int)env->duplicate, F_GETFD) < 0 && errno == EBADF);
#endif
    env->result = status; env->request = NULL;
    solaris_scope_cancel(&env->parent);
    CHECK(atomic_load(&env->parents) == 0u);
    solaris_test_event_signal(&env->done);
}
static void start(void *context, solaris_status_t status)
{
    environment_t *env = context; CHECK(status == SOLARIS_OK);
    CHECK(solaris_scope_init(&env->parent, env->owner, NULL, parent_finished, env) == SOLARIS_OK);
    if (env->mode == CLOSED_PARENT) solaris_scope_cancel(&env->parent);
    solaris_socket_preparation_options_t options = {.owner = env->owner, .parent_scope = &env->parent,
        .policy = {env, host_retain, host_release, host_start, host_cancel}, .handle = (uintptr_t)env->original,
        .family = SOLARIS_ADDRESS_IPV4, .kind = SOLARIS_SOCKET_POLICY_TCP,
        .deadline_ns = env->mode == STOP ? 0u : UINT64_C(100000000)};
    if (env->mode == WRONG_KIND) options.kind = SOLARIS_SOCKET_POLICY_UDP;
    if (env->mode == EXPIRED) atomic_store(&env->clock, options.deadline_ns);
    atomic_store(&env->allocations, 0);
    atomic_store(&env->fail_at, env->mode == ALLOC_TOKEN ? 1 : env->mode == ALLOC_DEADLINE ? 2 : 0);
    env->in_start = 1;
    env->submit_status = solaris_socket_preparation_start(&options, completed, env, &env->request);
    env->in_start = 0; atomic_store(&env->fail_at, 0);
    CHECK(atomic_load(&env->completed) == 0u);
    if (env->submit_status != SOLARIS_OK) {
        CHECK(env->request == NULL); solaris_scope_cancel(&env->parent);
    }
    solaris_test_event_signal(&env->ready);
}
#ifndef _WIN32
static void cancel_request(void *context, solaris_status_t status)
{
    environment_t *env = context; CHECK(status == SOLARIS_OK);
    CHECK(solaris_socket_preparation_cancel(env->request) == SOLARIS_OK);
    CHECK(solaris_socket_preparation_cancel(env->request) == SOLARIS_ECLOSED);
    solaris_test_event_signal(&env->action);
}
static void advance_clock(void *context, solaris_status_t status)
{
    environment_t *env = context; CHECK(status == SOLARIS_OK);
    atomic_store(&env->clock, UINT64_C(101000000)); solaris_test_event_signal(&env->action);
}
static void hold(void *context, solaris_status_t status)
{
    environment_t *env = context; CHECK(status == SOLARIS_OK);
    solaris_test_event_signal(&env->entered); solaris_test_event_wait(&env->resume);
}
static void queued(void *context, solaris_status_t status)
{
    environment_t *env = context; CHECK(status == SOLARIS_ECANCELLED); solaris_test_event_signal(&env->action);
}
#endif
static void run(int mode)
{
    environment_t env; memset(&env, 0, sizeof(env)); env.mode = mode;
    atomic_init(&env.completed, 0u); atomic_init(&env.retained, 0u); atomic_init(&env.released, 0u);
    atomic_init(&env.cancelled_count, 0u); atomic_init(&env.parents, 0u);
    atomic_init(&env.fail_at, 0); atomic_init(&env.allocations, 0); atomic_init(&env.clock, 0u);
    env.original = socket(AF_INET, SOCK_STREAM, 0);
#ifdef _WIN32
    CHECK(env.original != INVALID_SOCKET);
#else
    CHECK(env.original >= 0);
    int original_flags = fcntl(env.original, F_GETFL);
#endif
    CHECK(solaris_test_event_init(&env.ready, 0u) == 0 && solaris_test_event_init(&env.action, 0u) == 0 &&
        solaris_test_event_init(&env.cancelled, 0u) == 0 && solaris_test_event_init(&env.done, 0u) == 0 &&
        solaris_test_event_init(&env.parent_done, 0u) == 0 && solaris_test_event_init(&env.entered, 0u) == 0 &&
        solaris_test_event_init(&env.resume, 0u) == 0);
    solaris_runtime_services_init(&env.services); env.services.context = &env; env.services.allocate = allocate; env.services.now_ns = now_ns;
    CHECK(solaris_budget_create(1024u * 1024u, &env.services, &env.budget) == SOLARIS_OK);
    solaris_executor_options_t options = {.budget = env.budget, .services = &env.services, .queue_capacity = 1u, .resource_limit = 8u};
    CHECK(solaris_executor_create(&options, &env.owner) == SOLARIS_OK && solaris_executor_activate(env.owner, 1u) == SOLARIS_OK);
    CHECK(solaris_executor_post(env.owner, start, &env) == SOLARIS_OK); solaris_test_event_wait(&env.ready);
#ifdef _WIN32
    CHECK(env.submit_status == SOLARIS_ENOTSUP && env.calls == 0 && env.request == NULL);
    int type = 0, type_size = sizeof(type);
    CHECK(getsockopt(env.original, SOL_SOCKET, SO_TYPE, (char *)&type, &type_size) == 0 && type == SOCK_STREAM);
#else
    if (mode == REJECT || mode >= EXPIRED) {
        solaris_status_t expected = mode == REJECT ? SOLARIS_EACCESS : mode == EXPIRED || mode == RETAIN_EXPIRED ? SOLARIS_ETIMEDOUT :
            mode == WRONG_KIND ? SOLARIS_EINVAL : mode == CLOSED_PARENT ? SOLARIS_ECLOSED : SOLARIS_ENOMEM;
        CHECK(env.submit_status == expected && env.calls == (mode == REJECT));
    } else {
        CHECK(env.submit_status == SOLARIS_OK && env.calls == 1);
        CHECK(fcntl(env.original, F_GETFL) == original_flags);
        if (mode == NORMAL) {
            int original = env.original; CHECK(close(original) == 0);
            int replacement = socket(AF_INET, SOCK_DGRAM, 0); CHECK(replacement >= 0);
            if (replacement != original) { CHECK(dup2(replacement, original) == original); close(replacement); }
            int type = 0; socklen_t size = sizeof(type);
            CHECK(getsockopt(original, SOL_SOCKET, SO_TYPE, &type, &size) == 0 && type == SOCK_DGRAM);
            CHECK(getsockopt((int)env.duplicate, SOL_SOCKET, SO_TYPE, &type, &size) == 0 && type == SOCK_STREAM);
        }
        if (mode == CANCEL || mode == CANCEL_SYNC) {
            CHECK(solaris_executor_post(env.owner, cancel_request, &env) == SOLARIS_OK);
            solaris_test_event_wait(&env.action); solaris_test_event_wait(&env.cancelled);
        } else if (mode == DEADLINE) {
            CHECK(solaris_executor_post(env.owner, advance_clock, &env) == SOLARIS_OK);
            solaris_test_event_wait(&env.action); solaris_test_event_wait(&env.cancelled);
        } else if (mode == STOP) {
            CHECK(solaris_executor_begin_quiesce(env.owner) == SOLARIS_OK); solaris_test_event_wait(&env.cancelled);
            CHECK(!solaris_executor_is_quiescent(env.owner));
        } else if (mode == FULL_QUEUE || mode == ACK_AFTER_DEADLINE) {
            CHECK(solaris_executor_post(env.owner, hold, &env) == SOLARIS_OK); solaris_test_event_wait(&env.entered);
            if (mode == FULL_QUEUE) {
                CHECK(solaris_executor_post(env.owner, queued, &env) == SOLARIS_OK);
                CHECK(solaris_executor_post(env.owner, queued, &env) == SOLARIS_EAGAIN);
                CHECK(solaris_executor_begin_quiesce(env.owner) == SOLARIS_OK);
            } else atomic_store(&env.clock, UINT64_C(101000000));
        }
        if (mode != SYNC && mode != CANCEL_SYNC) {
            CHECK(atomic_load(&env.completed) == 0u && atomic_load(&env.parents) == 0u);
            CHECK(fcntl((int)env.duplicate, F_GETFD) >= 0);
            CHECK(solaris_socket_policy_complete(env.host_token, mode == HOST_FAILURE ? SOLARIS_EACCESS : SOLARIS_OK) == SOLARIS_OK);
        }
        if (mode == FULL_QUEUE || mode == ACK_AFTER_DEADLINE) solaris_test_event_signal(&env.resume);
        solaris_test_event_wait(&env.done);
        solaris_status_t expected = mode == CANCEL || mode == CANCEL_SYNC || mode == STOP || mode == FULL_QUEUE ? SOLARIS_ECANCELLED :
            mode == DEADLINE || mode == ACK_AFTER_DEADLINE ? SOLARIS_ETIMEDOUT : mode == HOST_FAILURE ? SOLARIS_EACCESS : SOLARIS_OK;
        CHECK(env.result == expected);
    }
#endif
    solaris_test_event_wait(&env.parent_done);
    CHECK(solaris_executor_quiesce(env.owner) == SOLARIS_OK && solaris_executor_destroy(env.owner) == SOLARIS_OK);
    CHECK(atomic_load(&env.retained) == atomic_load(&env.released));
    CHECK(CLOSE_SOCKET(env.original) == 0);
    CHECK(solaris_budget_used(env.budget) == 0u); solaris_budget_release(env.budget);
    solaris_test_event_destroy(&env.ready); solaris_test_event_destroy(&env.action); solaris_test_event_destroy(&env.cancelled);
    solaris_test_event_destroy(&env.done); solaris_test_event_destroy(&env.parent_done);
    solaris_test_event_destroy(&env.entered); solaris_test_event_destroy(&env.resume);
}
int main(void)
{
#ifdef _WIN32
    WSADATA data; CHECK(WSAStartup(MAKEWORD(2, 2), &data) == 0); run(NORMAL); CHECK(WSACleanup() == 0);
    puts("socket preparation: unsupported Windows path preserves original socket and rejects without callbacks");
#else
    for (int mode = NORMAL; mode <= RETAIN_EXPIRED; ++mode) run(mode);
    puts("socket preparation: real dup/FD reuse, async ACK, parent drain, cancel/deadline/stop and allocation passed");
#endif
    return 0;
}
