#ifndef SOLARIS_PROXY_INBOUND_H
#define SOLARIS_PROXY_INBOUND_H
#include "contracts/flow/plan.h"
#include "contracts/policy/route.h"
#include "runtime/executor/executor.h"

typedef struct solaris_proxy_inbound solaris_proxy_inbound_t;
typedef struct solaris_tracker solaris_tracker_t;
typedef struct solaris_proxy_context {
    void *context;
    void (*retain)(void *context);
    void (*release)(void *context);
    uint64_t config_revision, selection_revision;
} solaris_proxy_context_t;
enum { SOLARIS_INBOUND_HTTP = 1, SOLARIS_INBOUND_SOCKS5 = 2, SOLARIS_INBOUND_MIXED = 3 };
enum { SOLARIS_INBOUND_TCP = 6, SOLARIS_INBOUND_UDP = 17 };
typedef struct solaris_inbound_request {
    uint32_t protocol, network;
    uint64_t inbound_id, connection_id;
    solaris_address_t source, destination;
    /* Authenticated user name, borrowed to callback return; never password. */
    const uint8_t *username;
    size_t username_length;
} solaris_inbound_request_t;
typedef struct solaris_proxy_inbound_snapshot {
    solaris_address_t bound;
    uint64_t accepted, rejected, authentication_failed, protocol_failed, udp_dropped;
    size_t connections;
    uint32_t closing, retired;
} solaris_proxy_inbound_snapshot_t;
typedef struct solaris_proxy_inbound_options {
    solaris_executor_t *owner;
    /* Optional same-owner construction/drain fence. Retained after scope
     * admission through final cleanup, including rejected creation rollback. */
    solaris_scope_t *parent_scope;
    /* Borrowed engine-wide tracker, outliving every admitted connection. */
    solaris_tracker_t *tracker;
    uint32_t protocol;
    solaris_address_t listen;
    uint64_t inbound_id;
    size_t connection_limit, header_limit, pending_byte_limit, pending_packet_limit, udp_mapping_limit;
    /* idle applies to TCP proxy streams and UDP associations, not an idle
     * SOCKS5 UDP control TCP connection. Control EOF/close/stop still revokes it. */
    uint64_t handshake_timeout_ms, idle_timeout_ms;
    int udp;
    void *context;
    /* Optional pair: each accepted TCP connection pins its immutable runtime
     * generation. The inbound container itself does not retain context. */
    void (*retain)(void *context);
    void (*release)(void *context);
    /* NULL permits unauthenticated clients. Otherwise authentication is
     * mandatory: HTTP Basic or SOCKS5 username/password, without downgrade.
     * Runs synchronously on owner. Borrowed credential bytes expire on return.
     * Returning OK accepts; any other status rejects. */
    solaris_status_t (*authenticate)(void *context, const uint8_t *username, size_t username_length,
                                     const uint8_t *password, size_t password_length);
    /* Return an owned, pinned plan on success; no network I/O in this hook. */
    solaris_status_t (*select)(void *context, solaris_executor_t *owner, const solaris_inbound_request_t *request,
                               solaris_dial_plan_t *out);
    /* Preferred asynchronous-routing template hook. No network I/O here.
     * Success returns one OWNED context reference; caller releases that
     * temporary reference after route_start/association admission pins it.
     * TCP uses this inbound's captured context; for a new UDP association the
     * provider may acquire the current logical inbound/auth-compatible view.
     * Existing UDP associations do not call this hook again. */
    solaris_status_t (*route)(void *context, solaris_executor_t *owner, const solaris_inbound_request_t *request,
                              solaris_route_options_t *out);
    void (*on_close)(void *context, const solaris_proxy_inbound_snapshot_t *snapshot, solaris_status_t status);
} solaris_proxy_inbound_options_t;
void solaris_proxy_inbound_options_init(solaris_proxy_inbound_options_t *options);
/* Owner-only activation. listen is numeric and port zero requests an actual
 * ephemeral port. Rejection leaves out=NULL and has no user callbacks.
 * Success on_close waits for listeners, connections, UDP and all I/O. */
solaris_status_t solaris_proxy_inbound_create(const solaris_proxy_inbound_options_t *options,
                                              solaris_proxy_inbound_t **out);
/* Detached generations own protocol/connection state but do not bind a TCP
 * socket. A stable external listener may dispatch to the current generation. */
solaris_status_t solaris_proxy_inbound_detached_create(const solaris_proxy_inbound_options_t *options,
                                                       solaris_proxy_inbound_t **out);
/* Owner-only accepted-stream handoff. Rejection stores no stream and promises
 * no stream callbacks. On success native open/data/close are delivered to the
 * returned callbacks; native open must be deferred and initially paused. */
solaris_status_t solaris_proxy_inbound_accept(solaris_proxy_inbound_t *inbound, const solaris_address_t *peer,
                                              const solaris_address_t *local, solaris_stream_t *stream,
                                              solaris_stream_callbacks_t *callbacks, void **stream_context);
/* Per-accept runtime+control capture. Success retains it for the TCP lifetime;
 * rejection owns nothing. Routing uses capture.context, authentication still
 * uses the immutable inbound options.context. NULL preserves the normal API. */
solaris_status_t solaris_proxy_inbound_accept_with_context(solaris_proxy_inbound_t *inbound,
                                                           const solaris_address_t *peer,
                                                           const solaris_address_t *local, solaris_stream_t *stream,
                                                           solaris_stream_callbacks_t *callbacks, void **stream_context,
                                                           const solaris_proxy_context_t *capture);
/* Stop new TCP admission and close an owned listener, then naturally drain
 * accepted connections/associations. Does not cancel existing work. Final
 * on_close is the complete resource barrier and expires the handle. */
solaris_status_t solaris_proxy_inbound_retire(solaris_proxy_inbound_t *inbound);
solaris_status_t solaris_proxy_inbound_snapshot(solaris_proxy_inbound_t *inbound,
                                                solaris_proxy_inbound_snapshot_t *out);
solaris_status_t solaris_proxy_inbound_close(solaris_proxy_inbound_t *inbound);
#endif
