#ifndef SOLARIS_PROXY_INBOUND_H
#define SOLARIS_PROXY_INBOUND_H
#include "contracts/flow/plan.h"
#include "runtime/executor/executor.h"

typedef struct solaris_proxy_inbound solaris_proxy_inbound_t;
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
    uint32_t closing;
} solaris_proxy_inbound_snapshot_t;
typedef struct solaris_proxy_inbound_options {
    solaris_executor_t *owner;
    uint32_t protocol;
    solaris_address_t listen;
    uint64_t inbound_id;
    size_t connection_limit, header_limit, pending_byte_limit, pending_packet_limit, udp_mapping_limit;
    uint64_t handshake_timeout_ms, idle_timeout_ms;
    int udp;
    void *context;
    /* NULL permits unauthenticated clients. Otherwise authentication is
     * mandatory: HTTP Basic or SOCKS5 username/password, without downgrade.
     * Runs synchronously on owner. Borrowed credential bytes expire on return.
     * Returning OK accepts; any other status rejects. */
    solaris_status_t (*authenticate)(void *context, const uint8_t *username, size_t username_length,
                                     const uint8_t *password, size_t password_length);
    /* Return an owned, pinned plan on success; no network I/O in this hook. */
    solaris_status_t (*select)(void *context, solaris_executor_t *owner, const solaris_inbound_request_t *request,
                               solaris_dial_plan_t *out);
    void (*on_close)(void *context, const solaris_proxy_inbound_snapshot_t *snapshot, solaris_status_t status);
} solaris_proxy_inbound_options_t;
void solaris_proxy_inbound_options_init(solaris_proxy_inbound_options_t *options);
/* Owner-only activation. listen is numeric and port zero requests an actual
 * ephemeral port. Rejection leaves out=NULL and has no user callbacks.
 * Success on_close waits for listeners, connections, UDP and all I/O. */
solaris_status_t solaris_proxy_inbound_create(const solaris_proxy_inbound_options_t *options,
                                              solaris_proxy_inbound_t **out);
solaris_status_t solaris_proxy_inbound_snapshot(solaris_proxy_inbound_t *inbound,
                                                solaris_proxy_inbound_snapshot_t *out);
solaris_status_t solaris_proxy_inbound_close(solaris_proxy_inbound_t *inbound);
#endif
