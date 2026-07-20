#ifndef APROXY_MEMORY_H
#define APROXY_MEMORY_H

#include <stddef.h>
#include <stdint.h>

#include "aproxy/error.h"

#define APROXY_MIB_BYTES (1024u * 1024u)
#define APROXY_IOS_PROCESS_LIMIT_BYTES (50u * APROXY_MIB_BYTES)
#define APROXY_DEFAULT_PROCESS_MEMORY_LIMIT_BYTES \
    (40u * APROXY_MIB_BYTES)
#define APROXY_DEFAULT_DYNAMIC_MEMORY_LIMIT_BYTES \
    (24u * APROXY_MIB_BYTES)

typedef struct aproxy_memory_stats {
    size_t dynamic_current_bytes;
    size_t dynamic_peak_bytes;
    size_t dynamic_limit_bytes;
    uint64_t rejected_reservations;
} aproxy_memory_stats_t;

/* A zero dynamic limit disables only the central allocation budget. */
void aproxy_memory_set_dynamic_limit(size_t limit_bytes);
int aproxy_memory_try_reserve(size_t bytes);
void aproxy_memory_release(size_t bytes);
void aproxy_memory_get_stats(aproxy_memory_stats_t *stats);

/* Linux reports RSS; Apple reports phys_footprint, which tracks jetsam usage. */
int aproxy_process_memory_bytes(size_t *bytes);

#endif
