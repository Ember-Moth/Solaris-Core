#ifndef SOLARIS_DNS_EXCHANGE_H
#define SOLARIS_DNS_EXCHANGE_H
#include "contracts/dns/wire.h"
#include "transport/socket/socket.h"
#include "transport/tls/tls.h"

enum { SOLARIS_DNS_TRANSPORT_UDP = 1, SOLARIS_DNS_TRANSPORT_TCP = 2, SOLARIS_DNS_TRANSPORT_TLS = 3 };
typedef struct solaris_dns_exchange solaris_dns_exchange_t;
typedef struct solaris_dns_exchange_options {
    solaris_address_t upstream; /* numeric, nonzero port; never OS resolution */
    uint32_t transport;
    uint64_t deadline_ns; /* absolute requesting-owner monotonic deadline */
    solaris_dns_lookup_view_t view;
    solaris_dialer_options_t dialer;
    solaris_dns_wire_limits_t wire_limits;
    /* TLS transport only. Trust is retained and identity is copied on accepted
     * start. Identity is independent of the numeric connect address. DoT offers
     * only "dot"; empty selection is allowed unless explicitly required. */
    solaris_tls_context_t *tls_trust;
    const char *tls_identity;
    int tls_require_alpn;
    /* Same-owner cleanup fence, including rejected start after scope creation. */
    solaris_scope_t *parent_scope;
} solaris_dns_exchange_options_t;
typedef struct solaris_dns_exchange_result {
    solaris_status_t status;
    const solaris_dns_wire_t *response; /* borrowed until done returns; may retain */
    solaris_dns_lookup_view_t view;
    solaris_address_t upstream;
    uint32_t transport, tcp_fallback;
    uint8_t selected_alpn[3]; /* binary "dot", or length zero */
    size_t selected_alpn_length;
    uint64_t started_ns, completed_ns, duration_ns;
    uint64_t bytes_read, bytes_written, discarded_packets, discarded_frames;
} solaris_dns_exchange_result_t;
typedef void (*solaris_dns_exchange_fn)(void *context, solaris_dns_exchange_t *exchange,
    const solaris_dns_exchange_result_t *result);

void solaris_dns_exchange_options_init(solaris_dns_exchange_options_t *options);
/* Owner-only. Query is retained on acceptance, never consumed. Options are
 * copied; host policy/lookup contexts outlive done. Every accepted exchange
 * completes once, deferred, only after native socket/write/timer cleanup.
 * Rejection returns out=NULL without a callback. Done's handle expires on
 * return. Cancel can revoke success until done starts; stop also revokes it.
 *
 * Each exchange has its own connection; this is not a connection pool. UDP
 * validates source endpoint + ID + complete question, ignoring unrelated or
 * malformed packets. A matching TC response retries via TCP to the same peer,
 * under the original deadline, only after UDP cleanup. TCP supports split and
 * coalesced length frames and discards unrelated complete replies. A malformed
 * length is terminal; TC over TCP/DoT is an error, not full success. DoT retains
 * the same deadline through connect/handshake/query and never falls back to
 * plaintext. TLS fields on UDP/TCP are invalid; a TLS-disabled build rejects
 * TLS transport with ENOTSUP before opening a socket.
 * All sockets use the supplied protect/bind policy and numeric upstream. The
 * dialer is forced to require explicit lookup, so no OS fallback is possible.
 * Limits and I/O buffers are bounded by the engine budget. No DNS answer or
 * transport retry policy beyond UDP TC -> TCP is implemented here. */
solaris_status_t solaris_dns_exchange_start(solaris_executor_t *owner,
    const solaris_dns_wire_t *query, const solaris_dns_exchange_options_t *options,
    solaris_dns_exchange_fn done, void *context, solaris_dns_exchange_t **out);
solaris_status_t solaris_dns_exchange_cancel(solaris_dns_exchange_t *exchange);
#endif
