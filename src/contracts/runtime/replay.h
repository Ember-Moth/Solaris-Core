#ifndef SOLARIS_REPLAY_H
#define SOLARIS_REPLAY_H

#include "contracts/io/buffer.h"

typedef struct solaris_replay_store solaris_replay_store_t;
/* Thread-safe, bounded exact set. Tokens are caller-domain-separated hashes.
 * A full set rejects insertion; live entries are never evicted. Lifetime zero
 * remembers tokens for the store lifetime. The clock/context outlive the set.
 * Owners share one store across workers and configuration reloads. */
solaris_status_t solaris_replay_create(solaris_budget_t *budget, size_t capacity,
    uint64_t lifetime_ns, uint64_t (*now_ns)(void *), void *context,
    solaris_replay_store_t **out);
void solaris_replay_retain(solaris_replay_store_t *store);
void solaris_replay_release(solaris_replay_store_t *store);
int solaris_replay_is_persistent(const solaris_replay_store_t *store);
/* EACCESS: replay; EBUSY: capacity exhausted. Insertion is atomic. */
solaris_status_t solaris_replay_insert(solaris_replay_store_t *store, const uint8_t token[32]);

#endif
