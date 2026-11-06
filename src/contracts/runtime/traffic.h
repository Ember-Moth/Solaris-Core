#ifndef SOLARIS_TRAFFIC_COUNTER_H
#define SOLARIS_TRAFFIC_COUNTER_H
#include "contracts/io/buffer.h"

typedef struct solaris_traffic_counter solaris_traffic_counter_t;
enum { SOLARIS_TRAFFIC_STREAM = 1, SOLARIS_TRAFFIC_DATAGRAM = 2 };
typedef struct solaris_traffic_snapshot {
    uint64_t stream_read, stream_written, datagram_read, datagram_written;
    uint64_t packets_read, packets_written;
    uint32_t saturated;
} solaris_traffic_snapshot_t;
/* Physical socket payload bytes, counted once below TLS/protocol/session
 * transforms. IP/TCP/UDP headers are not included. Use one counter per worker
 * and aggregate snapshots; references and snapshots are thread-safe. */
solaris_status_t solaris_traffic_counter_create(solaris_budget_t *budget, solaris_traffic_counter_t **out);
void solaris_traffic_counter_retain(solaris_traffic_counter_t *counter);
void solaris_traffic_counter_release(solaris_traffic_counter_t *counter);
solaris_status_t solaris_traffic_counter_snapshot(solaris_traffic_counter_t *counter, solaris_traffic_snapshot_t *out);
void solaris_traffic_record_read(solaris_traffic_counter_t *counter, int kind, uint64_t bytes);
void solaris_traffic_record_write(solaris_traffic_counter_t *counter, int kind, uint64_t bytes);
#endif
