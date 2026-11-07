#ifndef SOLARIS_CONFIG_PUBLICATION_H
#define SOLARIS_CONFIG_PUBLICATION_H
#include "contracts/io/buffer.h"
typedef struct solaris_publication solaris_publication_t;
typedef struct solaris_snapshot_ref {
    void *context;
    void (*retain)(void *context);
    void (*release)(void *context);
    uint64_t revision;
} solaris_snapshot_ref_t;
/* Referents are immutable and retain/release are thread-safe. retain must not
 * call back into this publication; release runs outside the publication lock.
 * Owner resources must schedule their retirement onto their own executor. */
solaris_status_t solaris_publication_create(solaris_budget_t *budget, solaris_publication_t **out);
/* Atomic load-and-retain. Caller releases the returned lease. Empty views have
 * NULL context and retain/release, but preserve the publication revision. */
solaris_status_t solaris_publication_acquire(solaris_publication_t *publication, solaris_snapshot_ref_t *out);
/* next stays caller-owned; on success publication obtains a separate reference.
 * next.revision must be expected+1. Empty tombstones also advance the revision,
 * preventing stale candidates from becoming valid after stop/restart. */
solaris_status_t solaris_publication_publish(solaris_publication_t *publication, uint64_t expected,
    const solaris_snapshot_ref_t *next, uint64_t *actual);
void solaris_snapshot_ref_release(solaris_snapshot_ref_t *reference);
/* Exclusive teardown after all concurrent publication callers have stopped.
 * Previously acquired snapshot leases remain valid independently. */
void solaris_publication_destroy(solaris_publication_t *publication);
#endif
