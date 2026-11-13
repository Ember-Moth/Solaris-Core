#ifndef SOLARIS_DNS_CACHE_H
#define SOLARIS_DNS_CACHE_H

#include "contracts/dns/lookup.h"
#include "contracts/dns/wire.h"

typedef struct solaris_dns_cache solaris_dns_cache_t;
/* Owned value key, also suitable for future inflight coalescing. No pointers.
 * ID and QNAME case are deliberately excluded; question bytes are ASCII-folded
 * only within labels. All other listed query semantics remain independent. */
typedef struct solaris_dns_cache_key {
    solaris_dns_lookup_view_t view;
    uint64_t policy_id, upstream_id;
    solaris_dns_question_t question;
    uint16_t query_flags, udp_size, edns_flags;
    uint8_t edns_present, edns_version;
} solaris_dns_cache_key_t;
solaris_status_t solaris_dns_cache_key_make(const solaris_dns_lookup_view_t *view,
    uint64_t policy_id, uint64_t upstream_id, const solaris_dns_wire_t *query,
    solaris_dns_cache_key_t *out);
int solaris_dns_cache_key_equal(const solaris_dns_cache_key_t *a, const solaris_dns_cache_key_t *b);

typedef struct solaris_dns_cache_options {
    solaris_executor_t *owner;
    solaris_budget_t *budget;
    size_t entry_limit, byte_limit;
    uint32_t record_limit, cname_depth;
    uint64_t stale_window_ms; /* Zero explicitly disables stale retention. */
} solaris_dns_cache_options_t;
enum { SOLARIS_DNS_CACHE_POSITIVE = 1, SOLARIS_DNS_CACHE_NXDOMAIN = 2, SOLARIS_DNS_CACHE_NODATA = 3 };
enum {
    SOLARIS_DNS_CACHE_STORED = 0, SOLARIS_DNS_CACHE_SKIP_TRUNCATED,
    SOLARIS_DNS_CACHE_SKIP_RCODE, SOLARIS_DNS_CACHE_SKIP_ZERO_TTL,
    SOLARIS_DNS_CACHE_SKIP_RDATA, SOLARIS_DNS_CACHE_SKIP_EDNS,
    SOLARIS_DNS_CACHE_SKIP_AUTHENTICATED, SOLARIS_DNS_CACHE_SKIP_NO_ANSWER,
    SOLARIS_DNS_CACHE_SKIP_CHAIN, SOLARIS_DNS_CACHE_SKIP_LIMIT
};
typedef struct solaris_dns_cache_put_result { uint32_t stored, reason, kind, ttl_seconds; } solaris_dns_cache_put_result_t;
typedef struct solaris_dns_cache_hit {
    solaris_buffer_t *wire; /* Owned, independent of entry/flush/cache lifetime. */
    uint32_t found, kind, stale, needs_refresh;
} solaris_dns_cache_hit_t;
typedef struct solaris_dns_cache_stats {
    size_t entries, charged_bytes;
    uint64_t hits, misses, stale_hits, evictions, skipped;
} solaris_dns_cache_stats_t;
enum { SOLARIS_DNS_CACHE_FLUSH_NETWORK = 1, SOLARIS_DNS_CACHE_FLUSH_RESOLVER = 2 };

void solaris_dns_cache_options_init(solaris_dns_cache_options_t *options);
/* All cache operations are service-owner only; key helpers are pure. Defaults:
 * 4096 entries, 8 MiB conservative retained charge, 256 RRs, 32 CNAME links,
 * 300 seconds stale window. Zero size/count limits select these defaults.
 * Hard maxima: 65536 entries, 1 GiB charge, 4096 RRs, 128 links, one day stale.
 * Charge includes entry, body, parsed RR storage and conservative fixed wire /
 * allocator overhead; the engine budget additionally bounds actual allocations.
 * The input wire must use the engine's bounded budget. Successful put retains
 * it; lookup allocates a distinct output on options.budget. No I/O, timers,
 * refresh tasks, or executor scope. Destroy before the owner becomes invalid. */
solaris_status_t solaris_dns_cache_create(const solaris_dns_cache_options_t *options,
    solaris_dns_cache_t **out);
solaris_status_t solaris_dns_cache_destroy(solaris_dns_cache_t *cache);
/* Transport authenticates source peer before calling put. ID/question and key
 * pairing are checked here. Noncacheable replies return OK/stored=0/reason;
 * such decisions MUST NOT fail the original successful exchange. Allocation
 * failure leaves previous cache contents intact and does not consume response.
 * A complete noncacheable new reply removes an older entry for the same key;
 * truncated replies and error RCODEs retain it for explicit stale policy.
 * First version excludes opaque RDATA, EDNS options, and AD=1 replies: the
 * current safe typed builder cannot preserve fresh AD, so it is never silently
 * removed on a fresh hit. Core performs no DNSSEC validation. CNAME chains must
 * be unique/acyclic/bounded; NXDOMAIN/NODATA require one covering authority SOA.
 * Negative lifetime uses min(SOA TTL, MINIMUM), capped by retained RR/CNAME TTLs.
 * Query EDNS options return ENOTSUP from key_make; callers bypass cache/coalescing. */
solaris_status_t solaris_dns_cache_put(solaris_dns_cache_t *cache,
    const solaris_dns_cache_key_t *key, const solaris_dns_wire_t *query,
    const solaris_dns_wire_t *response, solaris_dns_cache_put_result_t *out);
/* A miss is OK/found=0/wire=NULL. Each hit rebuilds current question/ID and a
 * bare per-hop OPT, never upstream options. Fresh TTLs age in whole seconds;
 * stale TTLs are 1 and AD is clear. needs_refresh only requests service-owned
 * work; it never schedules any. The service decides whether stale is allowed.
 * Replies are complete wire messages; transport applies its own UDP limit. */
solaris_status_t solaris_dns_cache_get(solaris_dns_cache_t *cache,
    const solaris_dns_cache_key_t *key, const solaris_dns_wire_t *query,
    int allow_stale, solaris_dns_cache_hit_t *out);
/* fields=0 flushes everything. Otherwise all selected revisions must match;
 * network-only flush invalidates that network across all roles/resolvers. */
solaris_status_t solaris_dns_cache_flush(solaris_dns_cache_t *cache, uint32_t fields,
    uint64_t network_revision, uint64_t resolver_revision, size_t *removed);
solaris_status_t solaris_dns_cache_snapshot(solaris_dns_cache_t *cache,
    solaris_dns_cache_stats_t *out);

#endif
