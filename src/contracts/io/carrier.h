#ifndef SOLARIS_TRANSPORT_H
#define SOLARIS_TRANSPORT_H

#include "contracts/io/channel.h"
#include "transport/socket/socket.h"

/* A carrier factory has no knowledge of the proxy protocol using it. The
 * factory and its context are borrowed for open. A factory must copy/retain
 * any settings it needs later before open returns.
 * Like I/O, rejection returns a null output and schedules no callbacks.
 * When options.parent_scope is supplied, factories with asynchronous cleanup
 * must honor its same-owner fence even after a rejected open. Accepted on_close
 * alone does not establish that a rejected factory's native resources drained. */
typedef struct solaris_stream_factory {
    void *context;
    solaris_status_t (*open)(void *context, solaris_executor_t *owner,
        const solaris_dialer_options_t *options, const solaris_address_t *peer,
        const solaris_stream_callbacks_t *callbacks, void *callback_context,
        solaris_stream_t **out);
} solaris_stream_factory_t;

/* A null factory selects the standard physical dialer. Wrappers can supply
 * another carrier without changing the engine or any protocol adapter. */
solaris_status_t solaris_carrier_open(const solaris_stream_factory_t *factory,
    solaris_executor_t *owner, const solaris_dialer_options_t *options,
    const solaris_address_t *peer, const solaris_stream_callbacks_t *callbacks,
    void *context, solaris_stream_t **out);

#endif
