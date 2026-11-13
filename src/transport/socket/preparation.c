#include "transport/socket/preparation.h"
#include <assert.h>
#include <string.h>
#include <uv.h>
#ifndef _WIN32
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

struct solaris_socket_token {
    solaris_scope_t scope;
    solaris_deferred_t ack;
    solaris_deadline_t *deadline;
    uv_mutex_t mutex;
    solaris_socket_preparation_options_t options;
    solaris_io_done_fn done;
    void *context;
    uintptr_t duplicate;
    solaris_status_t host_status, result;
    int acknowledged, settled, accepted, cancel_notified, retained, owns_duplicate;
};

static void close_duplicate(solaris_socket_token_t *token)
{
#ifndef _WIN32
    if (token->owns_duplicate) { (void)close((int)token->duplicate); token->owns_duplicate = 0; }
#else
    (void)token;
#endif
}
static solaris_status_t duplicate_socket(const solaris_socket_preparation_options_t *options, uintptr_t *out)
{
#ifdef _WIN32
    (void)options; (void)out; return SOLARIS_ENOTSUP;
#else
    if (options->handle > INT_MAX) return SOLARIS_EINVAL;
    int fd = fcntl((int)options->handle, F_DUPFD_CLOEXEC, 0);
    if (fd < 0) return errno == EBADF ? SOLARIS_ECLOSED : errno == ENOMEM ? SOLARIS_ENOMEM : SOLARIS_EIO;
    int type = 0; socklen_t size = sizeof(type);
    struct sockaddr_storage address; socklen_t address_size = sizeof(address);
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &size) != 0 ||
        getsockname(fd, (struct sockaddr *)&address, &address_size) != 0 ||
        type != (options->kind == SOLARIS_SOCKET_POLICY_TCP ? SOCK_STREAM : SOCK_DGRAM) ||
        address.ss_family != (options->family == SOLARIS_ADDRESS_IPV4 ? AF_INET : AF_INET6)) {
        (void)close(fd); return SOLARIS_EINVAL;
    }
    *out = (uintptr_t)fd; return SOLARIS_OK;
#endif
}
static void settle(solaris_socket_token_t *token, solaris_status_t status)
{
    uv_mutex_lock(&token->mutex);
    if (!token->settled) { token->settled = 1; token->result = status; }
    uv_mutex_unlock(&token->mutex);
}
static void notify_cancel(solaris_socket_token_t *token)
{
    uv_mutex_lock(&token->mutex);
    int notify = token->accepted && !token->acknowledged && !token->cancel_notified;
    if (notify) token->cancel_notified = 1;
    uv_mutex_unlock(&token->mutex);
    if (notify) token->options.policy.cancel(token->options.policy.context, token);
}
static void cancelled(void *context)
{
    solaris_socket_token_t *token = context;
    settle(token, SOLARIS_ECANCELLED);
    if (token->deadline) solaris_deadline_cancel(token->deadline);
    notify_cancel(token);
}
static void finished(void *context)
{
    solaris_socket_token_t *token = context;
    solaris_scope_t *parent = token->options.parent_scope;
    assert(!token->deadline && (!token->accepted || token->acknowledged));
    close_duplicate(token);
    if (token->accepted) token->done(token->context, token->result);
    if (token->retained) token->options.policy.release(token->options.policy.context);
    uv_mutex_destroy(&token->mutex);
    solaris_memory_free(token);
    if (parent) solaris_scope_release(parent);
}
static void expired(void *context, solaris_status_t status)
{
    solaris_socket_token_t *token = context; token->deadline = NULL;
    if (status == SOLARIS_OK) {
        settle(token, SOLARIS_ETIMEDOUT);
        solaris_scope_cancel(&token->scope);
    }
    solaris_scope_release(&token->scope);
}
static void acknowledged(void *context)
{
    solaris_socket_token_t *token = context;
    uv_mutex_lock(&token->mutex);
    if (!token->settled) {
        token->settled = 1;
        if (!solaris_executor_accepting(token->scope.owner) ||
            token->scope.generation != solaris_executor_generation(token->scope.owner)) token->result = SOLARIS_ECANCELLED;
        else if (token->options.deadline_ns && solaris_executor_now_ns(token->scope.owner) >= token->options.deadline_ns)
            token->result = SOLARIS_ETIMEDOUT;
        else token->result = token->host_status;
    }
    uv_mutex_unlock(&token->mutex);
    solaris_scope_cancel(&token->scope);
    solaris_scope_release(&token->scope); /* Accepted host work / reserved ACK node. */
}
solaris_status_t solaris_socket_policy_complete(solaris_socket_token_t *token, solaris_status_t status)
{
    if (!token) return SOLARIS_EINVAL;
    uv_mutex_lock(&token->mutex);
    solaris_status_t rc = token->acknowledged ? SOLARIS_ECLOSED : SOLARIS_OK;
    if (rc == SOLARIS_OK) {
        token->acknowledged = 1; token->host_status = status;
        rc = solaris_executor_defer(token->scope.owner, &token->ack);
        assert(rc == SOLARIS_OK);
    }
    uv_mutex_unlock(&token->mutex);
    return rc;
}
solaris_status_t solaris_socket_preparation_cancel(solaris_socket_token_t *token)
{
    if (!token) return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(token->scope.owner)) return SOLARIS_ETHREAD;
    uv_mutex_lock(&token->mutex); int settled = token->settled; uv_mutex_unlock(&token->mutex);
    if (settled) return SOLARIS_ECLOSED;
    settle(token, SOLARIS_ECANCELLED);
    solaris_scope_cancel(&token->scope);
    return SOLARIS_OK;
}
solaris_status_t solaris_socket_preparation_start(const solaris_socket_preparation_options_t *options,
    solaris_io_done_fn done, void *context, solaris_socket_token_t **out)
{
    if (!out) return SOLARIS_EINVAL;
    *out = NULL;
    if (!options || !options->owner || !done || !options->policy.start || !options->policy.cancel ||
        ((options->policy.retain == NULL) != (options->policy.release == NULL)) ||
        (options->family != SOLARIS_ADDRESS_IPV4 && options->family != SOLARIS_ADDRESS_IPV6) ||
        (options->kind != SOLARIS_SOCKET_POLICY_TCP && options->kind != SOLARIS_SOCKET_POLICY_UDP)) return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(options->owner)) return SOLARIS_ETHREAD;
    if (options->parent_scope && options->parent_scope->owner != options->owner) return SOLARIS_EINVAL;
    if (options->parent_scope && (options->parent_scope->cancelled || options->parent_scope->finishing ||
        !options->parent_scope->references)) return SOLARIS_ECLOSED;
    if (!solaris_executor_accepting(options->owner)) return SOLARIS_ECLOSED;
    uint64_t now = solaris_executor_now_ns(options->owner);
    if (options->deadline_ns && options->deadline_ns <= now) return SOLARIS_ETIMEDOUT;
    uintptr_t duplicate = 0u;
    solaris_status_t rc = duplicate_socket(options, &duplicate);
    if (rc != SOLARIS_OK) return rc;
    solaris_socket_token_t *token = solaris_memory_allocate(solaris_executor_budget(options->owner), sizeof(*token));
    if (!token) {
#ifndef _WIN32
        (void)close((int)duplicate);
#endif
        return SOLARIS_ENOMEM;
    }
    memset(token, 0, sizeof(*token)); token->options = *options; token->duplicate = duplicate; token->owns_duplicate = 1;
    token->done = done; token->context = context;
    token->ack = (solaris_deferred_t){.run = acknowledged, .context = token};
    if (uv_mutex_init(&token->mutex) != 0) { close_duplicate(token); solaris_memory_free(token); return SOLARIS_ENOMEM; }
    rc = solaris_scope_init(&token->scope, options->owner, cancelled, finished, token);
    if (rc != SOLARIS_OK) { uv_mutex_destroy(&token->mutex); close_duplicate(token); solaris_memory_free(token); return rc; }
    if (options->parent_scope) solaris_scope_retain(options->parent_scope);
    if (options->deadline_ns) {
        now = solaris_executor_now_ns(options->owner);
        if (options->deadline_ns <= now) {
            settle(token, SOLARIS_ETIMEDOUT); solaris_scope_cancel(&token->scope); return SOLARIS_ETIMEDOUT;
        }
        uint64_t delta = options->deadline_ns - now;
        uint64_t delay_ms = delta / UINT64_C(1000000) + (delta % UINT64_C(1000000) != 0u);
        solaris_scope_retain(&token->scope);
        rc = solaris_deadline_start(options->owner, delay_ms, expired, token, &token->deadline);
        if (rc != SOLARIS_OK) {
            solaris_scope_release(&token->scope); solaris_scope_cancel(&token->scope); return rc;
        }
    }
    if (token->options.policy.retain) { token->options.policy.retain(token->options.policy.context); token->retained = 1; }
    if (!solaris_executor_accepting(options->owner) || (options->parent_scope && options->parent_scope->cancelled) ||
        (options->deadline_ns && solaris_executor_now_ns(options->owner) >= options->deadline_ns)) {
        rc = !solaris_executor_accepting(options->owner) || (options->parent_scope && options->parent_scope->cancelled) ?
            SOLARIS_ECLOSED : SOLARIS_ETIMEDOUT;
        settle(token, rc); solaris_scope_cancel(&token->scope); return rc;
    }
    solaris_scope_retain(&token->scope); /* Host may ACK synchronously. */
    rc = token->options.policy.start(token->options.policy.context, token, duplicate, options->family, options->kind);
    if (rc != SOLARIS_OK) {
        settle(token, rc);
        uv_mutex_lock(&token->mutex); int acked = token->acknowledged; uv_mutex_unlock(&token->mutex);
        solaris_scope_cancel(&token->scope);
        if (!acked) solaris_scope_release(&token->scope);
        return rc;
    }
    token->accepted = 1; *out = token;
    if (!solaris_executor_accepting(options->owner)) {
        settle(token, SOLARIS_ECANCELLED); solaris_scope_cancel(&token->scope); notify_cancel(token);
    } else if (options->deadline_ns && solaris_executor_now_ns(options->owner) >= options->deadline_ns) {
        settle(token, SOLARIS_ETIMEDOUT); solaris_scope_cancel(&token->scope); notify_cancel(token);
    } else if (token->scope.cancelled) notify_cancel(token);
    return SOLARIS_OK;
}
