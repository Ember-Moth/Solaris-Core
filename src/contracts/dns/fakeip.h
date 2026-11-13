#ifndef SOLARIS_DNS_FAKEIP_H
#define SOLARIS_DNS_FAKEIP_H

#include "contracts/io/address.h"
#include "contracts/io/buffer.h"
#include "runtime/executor/executor.h"

typedef struct solaris_fakeip_store solaris_fakeip_store_t;
typedef struct solaris_fakeip_lease solaris_fakeip_lease_t;
/* A contiguous allocatable range, not a subnet: the caller excludes interface,
 * gateway and other reserved addresses. count=0 disables this family. */
typedef struct solaris_fakeip_range {
    solaris_address_t first;
    uint32_t count;
} solaris_fakeip_range_t;
typedef struct solaris_fakeip_options {
    solaris_executor_t *owner;
    solaris_budget_t *budget;
    solaris_fakeip_range_t ipv4, ipv6;
    uint32_t entry_limit; /* Combined families, 1..65536. */
    uint64_t quarantine_ms, pool_epoch;
} solaris_fakeip_options_t;
typedef struct solaris_fakeip_manifest {
    uint64_t pool_epoch, seal_id, latest_seal_id;
    int clean;
} solaris_fakeip_manifest_t;

/* Mutable store operations are owner-only. No timer, file I/O or automatic
 * executor scope is created. The service stops/drains this store before its
 * owner quiesces, and destroys it BEFORE the owner executor becomes invalid.
 * A stopped store survives same-engine stop/start on the same executor. */
solaris_status_t solaris_fakeip_create(const solaris_fakeip_options_t *options,
                                     solaris_fakeip_store_t **out);
/* The first start needs either a validated import or explicit host assurance
 * that this numeric range does not overlap any still-usable previous pool.
 * Every start requires the host's durable dirty marker to be acknowledged.
 * These arguments are host attestations, not independently verifiable facts. */
solaris_status_t solaris_fakeip_start(solaris_fakeip_store_t *store,
                                    int host_fresh_pool, int host_dirty_recorded);
/* Stop closes admission without blocking; outstanding leases remain readable.
 * The caller drains DNS outputs and leases before attempting seal/destroy. */
solaris_status_t solaris_fakeip_stop(solaris_fakeip_store_t *store);
/* Destroy rejects a running store or outstanding leases with EBUSY. */
solaris_status_t solaris_fakeip_destroy(solaris_fakeip_store_t *store);

/* ASCII DNS names: case-fold and strip one trailing dot, validate label and
 * total lengths. IDNA conversion belongs to the caller; non-ASCII is rejected.
 * acquire creates only when absent; reverse never creates. Numeric ports are
 * ignored by reverse. Unknown/out-of-range synthetic addresses fail EACCESS.
 * Mappings remain stable until explicit collection or allocation pressure. */
solaris_status_t solaris_fakeip_acquire(solaris_fakeip_store_t *store,
                                      const char *name, uint32_t family,
                                      solaris_fakeip_lease_t **out);
solaris_status_t solaris_fakeip_reverse(solaris_fakeip_store_t *store,
                                      const solaris_address_t *address,
                                      solaris_fakeip_lease_t **out);
/* Call before an answer may become externally visible, including cached hits.
 * Failure means the caller must not publish that answer. TTL is milliseconds. */
solaris_status_t solaris_fakeip_mark_visible(solaris_fakeip_store_t *store,
                                           const solaris_fakeip_lease_t *lease,
                                           uint64_t ttl_ms);
/* Cross-owner safe retain/release and immutable access. Keep a live reference
 * while accessing name/address. Final release only decrements an atomic pin;
 * it never touches owner-only state, schedules work, or accesses the entry
 * again after that decrement. collect/stop/seal observe releases on owner.
 * Quarantine begins conservatively at that observation or TTL expiry, later
 * of the two. No caller may retain a reference it has already released. */
void solaris_fakeip_lease_retain(const solaris_fakeip_lease_t *lease);
void solaris_fakeip_lease_release(const solaris_fakeip_lease_t *lease);
const char *solaris_fakeip_lease_name(const solaris_fakeip_lease_t *lease);
const solaris_address_t *solaris_fakeip_lease_address(const solaris_fakeip_lease_t *lease);
uint64_t solaris_fakeip_lease_epoch(const solaris_fakeip_lease_t *lease);
solaris_status_t solaris_fakeip_collect(solaris_fakeip_store_t *store, size_t *reclaimed);

/* Caller first drains all DNS outputs that may still expose an answer. Seal
 * requires stopped state and zero pins, and a strictly increasing seal ID.
 * The owned immutable, bounded, versioned buffer contains reservations and
 * remaining durations, not process-local clocks or file paths. Its checksum
 * detects corruption; it cannot establish authenticity or freshness.
 * Import requires a never-used, empty, stopped store. Host must independently
 * obtain its latest committed clean manifest: epoch/seal/latest must match.
 * Import never replaces existing state, even after collect has emptied it.
 * Remaining durations restart conservatively; no wall clock is consulted. */
solaris_status_t solaris_fakeip_seal(solaris_fakeip_store_t *store, uint64_t seal_id,
                                   solaris_buffer_t **out);
solaris_status_t solaris_fakeip_import(solaris_fakeip_store_t *store,
                                     const void *bytes, size_t length,
                                     const solaris_fakeip_manifest_t *manifest);

#endif
