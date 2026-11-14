#ifndef SOLARIS_DNS_LISTENER_H
#define SOLARIS_DNS_LISTENER_H

#include "contracts/dns/service.h"
#include "contracts/io/channel.h"

typedef struct solaris_dns_listener solaris_dns_listener_t;

/* The manager supplies an admission lease for each accepted TCP connection
 * or UDP request. For UDP the lease also keeps the physical slot alive. */
typedef struct solaris_dns_listener_lease {
    void *context;
    void (*retain)(void *context);
    void (*release)(void *context);
} solaris_dns_listener_lease_t;

typedef struct solaris_dns_listener_sender {
    void *context;
    solaris_status_t (*send)(void *context, const solaris_address_t *peer,
                             const solaris_slice_t *data, solaris_io_done_fn done, void *user);
} solaris_dns_listener_sender_t;

/* All calls run on parent_scope's owner. Creation retains the service binding
 * and parent; only an accepted create produces on_close, after complete drain. */
solaris_status_t solaris_dns_listener_create(solaris_scope_t *parent_scope, solaris_dns_binding_t *binding,
    const solaris_dns_lookup_view_t *view, void (*on_close)(void *), void *context,
    solaris_dns_listener_t **out);
/* Reject new admission while existing TCP connections and UDP requests finish.
 * close forces cancellation of those operations, including after retire. */
void solaris_dns_listener_retire(solaris_dns_listener_t *listener);
void solaris_dns_listener_close(solaris_dns_listener_t *listener);

solaris_status_t solaris_dns_listener_accept(solaris_dns_listener_t *listener, solaris_stream_t *stream,
    solaris_stream_callbacks_t *callbacks, void **stream_context, const solaris_dns_listener_lease_t *lease);
solaris_status_t solaris_dns_listener_packet(solaris_dns_listener_t *listener,
    const solaris_dns_listener_sender_t *sender, const solaris_address_t *peer, const solaris_buffer_t *packet,
    const solaris_dns_listener_lease_t *lease);

#endif
