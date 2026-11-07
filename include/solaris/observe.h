#ifndef SOLARIS_OBSERVE_H
#define SOLARIS_OBSERVE_H
#include <solaris/engine.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct solaris_connection_list solaris_connection_list_t;
/* Engine-local identity; always use it with the engine that returned it. */
typedef struct solaris_connection_id {
  uint64_t generation, id;
} solaris_connection_id_t;
enum { SOLARIS_FLOW_STREAM = 1, SOLARIS_FLOW_DATAGRAM = 2 };
enum {
  SOLARIS_FLOW_USER = 0,
  SOLARIS_FLOW_PROBE = 1,
  SOLARIS_FLOW_PURPOSE_COUNT = 2
};
enum {
  SOLARIS_CONNECTION_OPENING = 0,
  SOLARIS_CONNECTION_OPEN = 1,
  SOLARIS_CONNECTION_CLOSING = 2,
  SOLARIS_CONNECTION_CLOSED = 3
};
/* Text is a numeric IP or original domain, without credentials or a URL.
 * An empty host and zero port mean the endpoint is not known yet. */
typedef struct solaris_endpoint {
  char host[256];
  uint16_t port;
} solaris_endpoint_t;
typedef struct solaris_connection_info {
  solaris_connection_id_t key;
  uint64_t config_revision, selection_revision, inbound_id, rule_index, node_id;
  uint32_t worker_id, kind, purpose, state;
  solaris_endpoint_t source, logical_target, dial_target, last_destination,
      last_peer;
  uint64_t created_ns, opened_ns, closed_ns;
  uint64_t bytes_read, bytes_written, packets_read, packets_written;
  uint64_t accepted_writes, write_failures, rejections;
  size_t pending_bytes, pending_requests, active_channels;
  solaris_status_t status;
} solaris_connection_info_t;
typedef struct solaris_logical_traffic {
  uint64_t created, opened, closed, active, open_failures;
  uint64_t bytes_read, bytes_written, packets_read, packets_written;
  uint64_t accepted_writes, write_failures, rejections;
} solaris_logical_traffic_t;
typedef struct solaris_physical_traffic {
  uint64_t stream_read, stream_written, datagram_read, datagram_written;
  uint64_t packets_read, packets_written;
  uint32_t saturated;
} solaris_physical_traffic_t;
typedef struct solaris_traffic_info {
  uint64_t sampled_ns;
  solaris_logical_traffic_t logical[SOLARIS_FLOW_PURPOSE_COUNT];
  /* Outbound socket payload, below TLS/protocol framing; excludes IP/TCP/UDP
   * headers. Shared protocol sessions prevent exact USER/PROBE attribution. */
  solaris_physical_traffic_t physical;
} solaris_traffic_info_t;
/* Thread-safe copies. Lists are immutable, bounded by the tracker active and
 * history limits, and remain valid after engine destruction. Live counters
 * aggregate workers observationally, without a simultaneous owner fence. */
SOLARIS_API solaris_status_t solaris_engine_get_connections(
    solaris_engine_t *engine, int include_closed,
    solaris_connection_list_t **out, solaris_error_t *error);
SOLARIS_API void
solaris_connection_list_retain(solaris_connection_list_t *list);
SOLARIS_API void
solaris_connection_list_release(solaris_connection_list_t *list);
SOLARIS_API size_t
solaris_connection_list_count(const solaris_connection_list_t *list);
SOLARIS_API solaris_status_t
solaris_connection_list_get(const solaris_connection_list_t *list, size_t index,
                            solaris_connection_info_t *out);
SOLARIS_API solaris_status_t solaris_engine_get_connection(
    solaris_engine_t *engine, const solaris_connection_id_t *id,
    solaris_connection_info_t *out, solaris_error_t *error);
SOLARIS_API solaris_status_t
solaris_engine_get_traffic(solaris_engine_t *engine,
                           solaris_traffic_info_t *out, solaris_error_t *error);
typedef void (*solaris_connections_close_callback_t)(
    void *context, solaris_status_t status, uint64_t matched,
    const solaris_error_t *error);
/* Asynchronous close captures currently admitted flows, including handshakes
 * and pending routes. Completion waits for that captured set to drain. New
 * admissions remain allowed. Cancellation after closing begins cannot reopen
     * flows, and still waits for their cleanup. A cancelled completion retains
     * the matched count of flows whose close was already requested. callback may
     * be NULL. A stale generation is EAGAIN; a missing/closed ID is ECLOSED. */
SOLARIS_API solaris_status_t solaris_engine_close_connection(
    solaris_engine_t *engine, const solaris_connection_id_t *id,
    solaris_connections_close_callback_t callback, void *context,
    uint64_t *operation_id, solaris_error_t *error);
SOLARIS_API solaris_status_t solaris_engine_close_connections(
    solaris_engine_t *engine, solaris_connections_close_callback_t callback,
    void *context, uint64_t *operation_id, solaris_error_t *error);
#ifdef __cplusplus
}
#endif
#endif
