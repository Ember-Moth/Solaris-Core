#ifndef SOLARIS_TUN_STACK_H
#define SOLARIS_TUN_STACK_H

#include "contracts/io/channel.h"
#include "runtime/executor/executor.h"

typedef struct solaris_tun_stack solaris_tun_stack_t;
/* All methods and callbacks are owner-only. Packets are bare IP, borrowed
 * until return. emit must copy before returning if it queues a packet.
 * EAGAIN is bounded output congestion; TCP retransmission remains in stack. */
typedef solaris_status_t (*solaris_tun_emit_fn)(void *context, const uint8_t *packet, size_t length);
/* Called for an established client. On success install callbacks/context for
 * a new stream; on_open is deferred and on_close is its release barrier.
 * Accepted streams start with reading disabled. Rejection has no callbacks. */
typedef solaris_status_t (*solaris_tun_accept_fn)(void *context,
    const solaris_address_t *source, const solaris_address_t *destination,
    solaris_stream_callbacks_t *callbacks, void **stream_context);

typedef struct solaris_tun_stack_options {
    solaris_executor_t *owner;
    void *context;
    solaris_tun_emit_fn emit;
    solaris_tun_accept_fn accept;
    void (*on_close)(void *context, solaris_status_t status);
    /* Addresses assigned to the TUN interface by the host. System needs a
     * distinct adjacent peer address routed back to TUN in each family.
     * Family zero disables that family. No routes are changed here. */
    solaris_address_t address4, peer4, address6, peer6;
    size_t mtu, flow_limit, pending_byte_limit;
    uint64_t idle_timeout_ms;
    /* Apple's includeAllNetworks prevents system TCP reinjection. */
    int include_all_networks;
} solaris_tun_stack_options_t;

typedef struct solaris_tun_stack_ops {
    solaris_status_t (*input)(void *state, const uint8_t *packet, size_t length);
    void (*close)(void *state);
} solaris_tun_stack_ops_t;
struct solaris_tun_stack { const solaris_tun_stack_ops_t *ops; void *state; };
/* Constructors perform explicit activation on owner. Rejection sets *out=NULL
 * and has no on_close. Successful close and executor cancellation close all
 * child streams before stack on_close. Handles expire at their close callback. */
solaris_status_t solaris_tun_system_create(const solaris_tun_stack_options_t *options,
                                          solaris_tun_stack_t **out);
solaris_status_t solaris_tun_lwip_create(const solaris_tun_stack_options_t *options,
                                        solaris_tun_stack_t **out);
#endif
