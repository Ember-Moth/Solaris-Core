#ifndef SOLARIS_TCP_RELAY_H
#define SOLARIS_TCP_RELAY_H
#include "contracts/flow/plan.h"
#include "runtime/executor/executor.h"
typedef struct solaris_tcp_relay solaris_tcp_relay_t;
typedef struct solaris_tcp_relay_options {
    solaris_executor_t *owner;
    solaris_address_t destination;
    size_t pending_byte_limit;
    void *context;
    void (*on_close)(void *context, solaris_status_t status);
    /* Optional, delivered once when outbound open settles, before close.
     * The inbound may defer reads/writes until its protocol reply drains.
     * Reentrant relay close is permitted. */
    void (*on_connect)(void *context, solaris_status_t status);
} solaris_tcp_relay_options_t;
/* Owner-only. On success consumes/clears plan and installs the callbacks for
 * an accepted, initially paused inbound stream. That stream must then deliver
 * deferred on_open and final on_close even if creation/activation fails.
 * Every buffer is bounded by pending_byte_limit, reads pause until its writes
 * complete. on_close waits for both channels and all accepted completions. */
solaris_status_t solaris_tcp_relay_prepare(const solaris_tcp_relay_options_t *options,
    solaris_dial_plan_t *plan, solaris_stream_callbacks_t *callbacks, void **context,
    solaris_tcp_relay_t **out);
void solaris_tcp_relay_close(solaris_tcp_relay_t *relay);
#endif
