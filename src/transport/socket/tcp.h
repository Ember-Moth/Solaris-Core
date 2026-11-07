#ifndef SOLARIS_TCP_LISTENER_H
#define SOLARIS_TCP_LISTENER_H

#include "transport/socket/socket.h"

typedef struct solaris_tcp_listener solaris_tcp_listener_t;
/* Runs on owner after accept. On success fills the stream callbacks/context;
 * on_open, on_data and on_close must be non-null on success. The stream
 * opens later exactly once with reading initially disabled. The
 * supplied stream may be stored only on success. Rejection has no callbacks.
 * The listener owns no accepted streams after this selection returns. */
typedef solaris_status_t (*solaris_tcp_accept_fn)(void *context,
    const solaris_address_t *peer, const solaris_address_t *local,
    solaris_stream_t *stream, solaris_stream_callbacks_t *callbacks, void **stream_context);
solaris_status_t solaris_tcp_listener_open(solaris_executor_t *owner,
    const solaris_address_t *bind, const solaris_dialer_options_t *stream_options,
    solaris_tcp_accept_fn accept, void (*on_close)(void *context, solaris_status_t status),
    void *context, solaris_tcp_listener_t **out, solaris_address_t *bound);
/* The optional same-owner parent is retained through complete destruction,
 * including cleanup after a rejected open. Rejection still has no on_close. */
solaris_status_t solaris_tcp_listener_open_scoped(solaris_executor_t *owner,
    solaris_scope_t *parent, const solaris_address_t *bind,
    const solaris_dialer_options_t *stream_options, solaris_tcp_accept_fn accept,
    void (*on_close)(void *context, solaris_status_t status), void *context,
    solaris_tcp_listener_t **out, solaris_address_t *bound);
void solaris_tcp_listener_close(solaris_tcp_listener_t *listener);

#endif
