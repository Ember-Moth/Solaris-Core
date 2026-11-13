#ifndef SOLARIS_UDP_ASSOCIATION_H
#define SOLARIS_UDP_ASSOCIATION_H

#include "contracts/io/outbound.h"
#include "contracts/flow/plan.h"
#include "contracts/policy/route.h"
#include "dns/system/resolver.h"

typedef struct solaris_udp_dispatcher solaris_udp_dispatcher_t;
typedef struct solaris_tracker solaris_tracker_t;
typedef struct solaris_udp_key {
    uint64_t inbound_id, inbound_generation, client_id;
    solaris_address_t source;
} solaris_udp_key_t;

/* References are thread-safe. send runs on the association owner, borrows its
 * arguments and must return without blocking. A foreign inbound owner needs
 * its own bounded message bridge. The endpoint stays fixed for this key. */
typedef struct solaris_udp_reply_endpoint {
    void *context;
    uint64_t generation;
    void (*retain)(void *context);
    void (*release)(void *context);
    solaris_status_t (*send)(void *context, uint64_t generation, const solaris_udp_key_t *key,
                             const solaris_address_t *peer, const solaris_buffer_t *payload);
} solaris_udp_reply_endpoint_t;

/* select returns one owned lease, without network I/O. It fixes the effective
 * outbound for the association; it must stay usable until release on owner.
 * Failure returns no lease. Selection changes affect new associations only. */
typedef solaris_dial_plan_t solaris_udp_plan_t;

enum { SOLARIS_UDP_ASSOCIATION_LANES = 1, SOLARIS_UDP_DESTINATION_LANES = 2 };

typedef struct solaris_udp_snapshot {
    uint64_t id;
    uint32_t worker_id;
    uint32_t closing;
    uint32_t mapping_mode;
    size_t mappings, active_lanes;
    size_t pending_packets, pending_bytes;
    uint64_t accepted, sent, failed, received, reply_dropped, queue_rejections;
    /* A single shared lane's port; zero for destination-specific mappings or
     * transports that cannot report a local socket. This is not a NAT claim. */
    uint16_t ipv4_local_port, ipv6_local_port;
} solaris_udp_snapshot_t;

typedef struct solaris_udp_dispatcher_options {
    solaris_executor_t *const *workers;
    size_t worker_count;
    solaris_budget_t *budget;
    /* Borrowed engine-wide tracker; one record per first-valid-packet admission. */
    solaris_tracker_t *tracker;
    size_t association_limit, mapping_limit, pending_packet_limit, pending_byte_limit;
    uint64_t idle_timeout_ms, open_timeout_ms, dns_timeout_ms;
    void *context;
    solaris_status_t (*select)(void *context, solaris_executor_t *owner, const solaris_udp_key_t *key,
                               const solaris_address_t *first_target, solaris_udp_plan_t *out);
    void (*on_close)(void *context, const solaris_udp_key_t *key, const solaris_udp_snapshot_t *snapshot,
                     solaris_status_t status);
    /* Optional pair; defaults to the system resolver. Same asynchronous,
     * exactly-once and borrowed-result contract as solaris_resolve_start. */
    solaris_status_t (*resolve)(void *context, solaris_executor_t *owner, const solaris_address_t *target,
                                uint64_t timeout_ms, solaris_resolve_fn callback, void *user, void **request);
    void (*cancel_resolve)(void *context, void *request);
} solaris_udp_dispatcher_options_t;

/* One dispatcher belongs to one engine namespace. All methods below may be
 * called from any thread; each object's I/O and callbacks have a fixed owner.
 * Close/destroy dispatcher before destroying its borrowed executors. destroy
 * returns EBUSY until all packet/close callbacks and endpoint releases drain. */
solaris_status_t solaris_udp_dispatcher_create(const solaris_udp_dispatcher_options_t *options,
                                               solaris_udp_dispatcher_t **out);
solaris_status_t solaris_udp_dispatcher_set_workers(solaris_udp_dispatcher_t *dispatcher,
                                                    solaris_executor_t *const *workers, size_t count);
solaris_status_t solaris_udp_submit(solaris_udp_dispatcher_t *dispatcher, const solaris_udp_key_t *key,
                                    const solaris_address_t *target, const solaris_slice_t *payload,
                                    const solaris_udp_reply_endpoint_t *reply, solaris_io_done_fn done, void *context,
                                    uint64_t *association_id);
/* Owner-only admission with a captured immutable routing template. The route
 * owner must equal this key's selected owner. A new entry copies the template
 * and retains its context before returning; caller keeps its own reference.
 * That retain hook must not reenter this dispatcher (admission lock held).
 * The template's done/user are replaced by the association. Existing entries
 * only enqueue and ignore route (which may be NULL), preserving their plan.
 * Rejection retains nothing. The snapshot capture and this call form one
 * admission; deferred routing never reacquires a newer configuration. */
/* With route.dial_lookup, the captured routing context is held until final
 * association destruction, not just route completion. Every later numeric
 * destination lookup uses that hook/view, DIRECT_TARGET and the mapping's
 * absolute deadline; cancellation returns through the same hook. Returned
 * address order is authoritative. Terminal lookup cancellation/network/access/
 * closed errors close the association, while ordinary DNS failures retain the
 * existing per-admission retry window. Without the hook, legacy dispatcher
 * resolver behavior remains unchanged. */
solaris_status_t solaris_udp_submit_routed(solaris_udp_dispatcher_t *dispatcher, const solaris_udp_key_t *key,
                                           const solaris_address_t *target, const solaris_slice_t *payload,
                                           const solaris_udp_reply_endpoint_t *reply, solaris_io_done_fn done,
                                           void *context, uint64_t *association_id,
                                           const solaris_route_options_t *route);
solaris_status_t solaris_udp_submit_batch(solaris_udp_dispatcher_t *dispatcher, const solaris_udp_key_t *key,
                                          const solaris_datagram_message_t *messages, size_t count,
                                          const solaris_udp_reply_endpoint_t *reply, size_t *accepted);
solaris_status_t solaris_udp_association_snapshot(solaris_udp_dispatcher_t *dispatcher, const solaris_udp_key_t *key,
                                                  solaris_udp_snapshot_t *out);
/* id prevents an old close request from closing a replacement with this key.
 * Explicit close cancels the association: on_close reports ECANCELLED, as for
 * executor stop. A previously determined failure keeps its original status. */
solaris_status_t solaris_udp_association_close(solaris_udp_dispatcher_t *dispatcher, const solaris_udp_key_t *key,
                                               uint64_t id);
solaris_status_t solaris_udp_dispatcher_close(solaris_udp_dispatcher_t *dispatcher);
solaris_status_t solaris_udp_dispatcher_destroy(solaris_udp_dispatcher_t *dispatcher);

#endif
