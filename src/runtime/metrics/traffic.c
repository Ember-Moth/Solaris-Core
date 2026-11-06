#include "contracts/runtime/traffic.h"
#include <stdatomic.h>

struct solaris_traffic_counter {
    atomic_uint references, saturated;
    atomic_uint_fast64_t stream_read, stream_written, datagram_read, datagram_written, packets_read, packets_written;
};
solaris_status_t solaris_traffic_counter_create(solaris_budget_t *budget, solaris_traffic_counter_t **out)
{
    if (out == NULL) return SOLARIS_EINVAL;
    *out = NULL; if (budget == NULL) return SOLARIS_EINVAL;
    solaris_traffic_counter_t *counter = solaris_memory_allocate(budget, sizeof(*counter));
    if (counter == NULL) return SOLARIS_ENOMEM;
    atomic_init(&counter->references, 1u); atomic_init(&counter->saturated, 0u);
    atomic_init(&counter->stream_read, 0u); atomic_init(&counter->stream_written, 0u);
    atomic_init(&counter->datagram_read, 0u); atomic_init(&counter->datagram_written, 0u);
    atomic_init(&counter->packets_read, 0u); atomic_init(&counter->packets_written, 0u);
    *out = counter; return SOLARIS_OK;
}
void solaris_traffic_counter_retain(solaris_traffic_counter_t *counter)
{ if (counter != NULL) (void)atomic_fetch_add_explicit(&counter->references, 1u, memory_order_relaxed); }
void solaris_traffic_counter_release(solaris_traffic_counter_t *counter)
{ if (counter != NULL && atomic_fetch_sub_explicit(&counter->references, 1u, memory_order_acq_rel) == 1u) solaris_memory_free(counter); }
static void add(solaris_traffic_counter_t *counter, atomic_uint_fast64_t *field, uint64_t bytes)
{
    uint_fast64_t old = atomic_load_explicit(field, memory_order_relaxed);
    for (;;) {
        uint_fast64_t next = bytes > UINT64_MAX - old ? UINT64_MAX : old + bytes;
        if (atomic_compare_exchange_weak_explicit(field, &old, next, memory_order_relaxed, memory_order_relaxed)) {
            if (bytes > UINT64_MAX - old) atomic_store_explicit(&counter->saturated, 1u, memory_order_relaxed);
            return;
        }
    }
}
void solaris_traffic_record_read(solaris_traffic_counter_t *counter, int kind, uint64_t bytes)
{
    if (counter == NULL) return;
    if (kind == SOLARIS_TRAFFIC_STREAM) add(counter, &counter->stream_read, bytes);
    else if (kind == SOLARIS_TRAFFIC_DATAGRAM) { add(counter, &counter->datagram_read, bytes); add(counter, &counter->packets_read, 1u); }
}
void solaris_traffic_record_write(solaris_traffic_counter_t *counter, int kind, uint64_t bytes)
{
    if (counter == NULL) return;
    if (kind == SOLARIS_TRAFFIC_STREAM) add(counter, &counter->stream_written, bytes);
    else if (kind == SOLARIS_TRAFFIC_DATAGRAM) { add(counter, &counter->datagram_written, bytes); add(counter, &counter->packets_written, 1u); }
}
solaris_status_t solaris_traffic_counter_snapshot(solaris_traffic_counter_t *counter, solaris_traffic_snapshot_t *out)
{
    if (counter == NULL || out == NULL) return SOLARIS_EINVAL;
    out->stream_read = atomic_load_explicit(&counter->stream_read, memory_order_relaxed);
    out->stream_written = atomic_load_explicit(&counter->stream_written, memory_order_relaxed);
    out->datagram_read = atomic_load_explicit(&counter->datagram_read, memory_order_relaxed);
    out->datagram_written = atomic_load_explicit(&counter->datagram_written, memory_order_relaxed);
    out->packets_read = atomic_load_explicit(&counter->packets_read, memory_order_relaxed);
    out->packets_written = atomic_load_explicit(&counter->packets_written, memory_order_relaxed);
    out->saturated = atomic_load_explicit(&counter->saturated, memory_order_relaxed); return SOLARIS_OK;
}
