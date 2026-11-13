#ifndef SOLARIS_SOCKET_PREPARATION_H
#define SOLARIS_SOCKET_PREPARATION_H

#include "contracts/runtime/socket_policy.h"
#include "contracts/io/channel.h"
#include "runtime/executor/executor.h"

typedef struct solaris_socket_preparation_options {
    solaris_executor_t *owner;
    /* Optional live scope on this owner, retained after token scope creation
     * through all cleanup, including rejected host/deadline setup paths. */
    solaris_scope_t *parent_scope;
    solaris_socket_policy_t policy;
    uintptr_t handle;
    uint32_t family, kind;
    /* Absolute monotonic deadline, never reset by a queued phase. Zero means
     * the parent owns the deadline. Already expired requests are rejected. */
    uint64_t deadline_ns;
} solaris_socket_preparation_options_t;

/* Owner-only. Copies options, validates/duplicates the socket, reserves the
 * ACK node, and creates scope/deadline before invoking host start. Rejection
 * sets *out=NULL and has no done callback. Rejected scoped setup may still
 * drain asynchronously: parent_scope is its resource-lifetime barrier.
 * Acceptance promises one deferred done after host ACK and deadline cleanup,
 * including cancel/timeout/stop.
 * The core closes only its duplicate; original ownership/flags never change.
 * The returned token is owner-owned until done returns, and cannot outlive its
 * executor. The host borrows it until complete; no request is reusable.
 * POSIX uses a real CLOEXEC duplicate. Windows currently returns ENOTSUP. */
solaris_status_t solaris_socket_preparation_start(const solaris_socket_preparation_options_t *options,
    solaris_io_done_fn done, void *context, solaris_socket_token_t **out);
/* Fixes ECANCELLED before requesting host cancellation. Deadline/stop use the
 * same drain path. Cancellation does not close the duplicate or finish done
 * before accepted host work ACKs; even a logically failed request pins scope.
 * A received ACK may still lose to owner cancellation before ACK processing. */
solaris_status_t solaris_socket_preparation_cancel(solaris_socket_token_t *token);

#endif
