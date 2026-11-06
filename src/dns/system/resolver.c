#include "dns/system/resolver.h"
#include "runtime/executor/uv.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

struct solaris_resolve {
    solaris_scope_t scope;
    solaris_deferred_t result;
    uv_getaddrinfo_t native;
    solaris_deadline_t *deadline;
    solaris_address_t target;
    solaris_address_t addresses[SOLARIS_RESOLVER_MAX_ADDRESSES];
    size_t count;
    solaris_resolve_fn callback;
    void *context;
    solaris_status_t status;
    int accepted, pending, settled;
};

static void publish(solaris_resolve_t *request, solaris_status_t status);

static void deliver(void *context)
{
    solaris_resolve_t *request = context;
    request->callback(request->context, request->status,
                       request->status == SOLARIS_OK ? request->addresses : NULL,
                       request->status == SOLARIS_OK ? request->count : 0u);
    solaris_scope_release(&request->scope);
}

static void cancel(void *context)
{
    solaris_resolve_t *request = context;
    if (request->accepted && !request->settled) publish(request, SOLARIS_ECANCELLED);
    if (request->pending) (void)uv_cancel((uv_req_t *)&request->native);
    if (request->deadline != NULL) solaris_deadline_cancel(request->deadline);
}

static void destroy(void *context) { solaris_memory_free(context); }

static void publish(solaris_resolve_t *request, solaris_status_t status)
{
    if (request->settled) return;
    request->settled = 1;
    request->status = status;
    solaris_scope_retain(&request->scope);
    const solaris_status_t rc = solaris_executor_defer(request->scope.owner, &request->result);
    assert(rc == SOLARIS_OK); (void)rc;
    solaris_scope_cancel(&request->scope);
}

static void deadline(void *context, solaris_status_t status)
{
    solaris_resolve_t *request = context;
    request->deadline = NULL;
    if (status == SOLARIS_OK && !request->settled) publish(request, SOLARIS_ETIMEDOUT);
    solaris_scope_release(&request->scope);
}

static void resolved(uv_getaddrinfo_t *native, int status, struct addrinfo *addresses)
{
    solaris_resolve_t *request = native->data;
    request->pending = 0;
    if (!request->settled && request->accepted) {
        if (status == 0) {
            for (struct addrinfo *a = addresses; a != NULL && request->count < SOLARIS_RESOLVER_MAX_ADDRESSES; a = a->ai_next) {
                solaris_address_t address;
                if (solaris_address_from_sockaddr(a->ai_addr, &address) != SOLARIS_OK) continue;
                address.port = request->target.port;
                int duplicate = 0;
                for (size_t i = 0; i < request->count; i++) {
                    if (solaris_address_equal(&request->addresses[i], &address)) duplicate = 1;
                }
                if (!duplicate) request->addresses[request->count++] = address;
            }
        }
        publish(request, status == UV_ECANCELED ? SOLARIS_ECANCELLED :
                status == 0 && request->count != 0u ? SOLARIS_OK : SOLARIS_EIO);
    }
    if (addresses != NULL) uv_freeaddrinfo(addresses);
    solaris_scope_release(&request->scope);
}

solaris_status_t solaris_resolve_start(solaris_executor_t *executor,
                                       const solaris_address_t *target, uint64_t timeout_ms,
                                       solaris_resolve_fn callback, void *context,
                                       solaris_resolve_t **out)
{
    if (out == NULL) return SOLARIS_EINVAL;
    *out = NULL;
    if (executor == NULL || target == NULL || callback == NULL) return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(executor)) return SOLARIS_ETHREAD;
    if (target->family != SOLARIS_ADDRESS_DOMAIN && target->family != SOLARIS_ADDRESS_IPV4 &&
        target->family != SOLARIS_ADDRESS_IPV6) return SOLARIS_EINVAL;
    if (target->family == SOLARIS_ADDRESS_DOMAIN &&
        (target->host[0] == '\0' || memchr(target->host, '\0', sizeof(target->host)) == NULL)) return SOLARIS_EINVAL;
    solaris_resolve_t *request = solaris_memory_allocate(solaris_executor_budget(executor), sizeof(*request));
    if (request == NULL) return SOLARIS_ENOMEM;
    memset(request, 0, sizeof(*request));
    solaris_status_t rc = solaris_scope_init(&request->scope, executor, cancel, destroy, request);
    if (rc != SOLARIS_OK) { solaris_memory_free(request); return rc; }
    request->target = *target;
    request->callback = callback;
    request->context = context;
    request->result.run = deliver;
    request->result.context = request;
    request->native.data = request;
    if (target->family != SOLARIS_ADDRESS_DOMAIN) {
        request->addresses[0] = *target; request->count = 1u; request->accepted = 1;
        publish(request, SOLARIS_OK);
        *out = request;
        return SOLARIS_OK;
    }
    if (timeout_ms != 0u) {
        solaris_scope_retain(&request->scope);
        rc = solaris_deadline_start(executor, timeout_ms, deadline, request, &request->deadline);
        if (rc != SOLARIS_OK) {
            solaris_scope_release(&request->scope); solaris_scope_cancel(&request->scope); return rc;
        }
    }
    char port[6]; (void)snprintf(port, sizeof(port), "%u", (unsigned)target->port);
    struct addrinfo hints; memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    solaris_scope_retain(&request->scope);
    int native_rc = uv_getaddrinfo(solaris_executor_loop(executor), &request->native,
                                   resolved, target->host, port, &hints);
    if (native_rc != 0) {
        solaris_scope_release(&request->scope); solaris_scope_cancel(&request->scope);
        return native_rc == UV_ENOMEM ? SOLARIS_ENOMEM : SOLARIS_EIO;
    }
    request->pending = 1; request->accepted = 1;
    *out = request;
    return SOLARIS_OK;
}

void solaris_resolve_cancel(solaris_resolve_t *request)
{
    if (request != NULL) solaris_scope_cancel(&request->scope);
}
