#ifndef SOLARIS_SYSTEM_STACK_INTERNAL_H
#define SOLARIS_SYSTEM_STACK_INTERNAL_H
#include "contracts/inbound/tun_stack.h"
#include "transport/socket/tcp.h"

/* Private dependency seam for a host listener service and loopback fixtures.
 * listen follows solaris_tcp_listener_open ownership and deferred callbacks.
 * A returned listener is closed by solaris_tcp_listener_close. Context remains
 * borrowed through the stack's final close callback. NULL uses native sockets. */
typedef struct solaris_tun_system_services {
    void *context;
    solaris_status_t (*listen)(void *context, solaris_executor_t *owner,
        const solaris_address_t *bind, const solaris_dialer_options_t *options,
        solaris_tcp_accept_fn accept, void (*on_close)(void *, solaris_status_t),
        void *listener_context, solaris_tcp_listener_t **out, solaris_address_t *bound);
} solaris_tun_system_services_t;
solaris_status_t solaris_tun_system_create_with_services(const solaris_tun_stack_options_t *options,
    const solaris_tun_system_services_t *services, solaris_tun_stack_t **out);
#endif
