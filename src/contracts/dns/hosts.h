#ifndef SOLARIS_DNS_HOSTS_H
#define SOLARIS_DNS_HOSTS_H

#include "contracts/io/address.h"
#include "contracts/io/buffer.h"

#define SOLARIS_HOSTS_MAX_ADDRESSES 16u
#define SOLARIS_HOSTS_DEFAULT_ENTRIES 4096u
#define SOLARIS_HOSTS_DEFAULT_NODES 65536u
#define SOLARIS_HOSTS_DEFAULT_ALIAS_DEPTH 32u
enum { SOLARIS_HOSTS_ADDRESSES = 1, SOLARIS_HOSTS_ALIAS = 2 };
enum { SOLARIS_HOSTS_CONFIG = 1, SOLARIS_HOSTS_SYSTEM = 2, SOLARIS_HOSTS_DEFAULT = 3 };
enum {
    SOLARIS_HOSTS_INVALID_INPUT = 1, SOLARIS_HOSTS_INVALID_NAME,
    SOLARIS_HOSTS_INVALID_ADDRESS, SOLARIS_HOSTS_LIMIT, SOLARIS_HOSTS_DUPLICATE,
    SOLARIS_HOSTS_ALIAS_CYCLE, SOLARIS_HOSTS_ALIAS_DEPTH, SOLARIS_HOSTS_MEMORY
};
typedef struct solaris_hosts_entry {
    const char *name;
    uint32_t kind;
    const solaris_address_t *addresses;
    size_t address_count;
    const char *alias;
} solaris_hosts_entry_t;
typedef struct solaris_hosts_options {
    /* Zero fields use defaults. entries includes both inputs and localhost.
     * Hard maxima: entries 65536, nodes 1048576, alias depth 128, addresses 16.
     * address_total includes supplied addresses and localhost (default 65536). */
    uint32_t entries, nodes, alias_depth, addresses_per_entry, address_total;
} solaris_hosts_options_t;
typedef struct solaris_hosts_diagnostic {
    solaris_status_t status;
    uint32_t reason, source;
    size_t entry_index; /* Index in the indicated input; SIZE_MAX if global. */
    char message[128]; /* Static explanation, never copied input contents. */
} solaris_hosts_diagnostic_t;
typedef struct solaris_hosts solaris_hosts_t;
typedef struct solaris_hosts_result {
    uint32_t matched, source, kind, alias_hops;
    size_t entry_index, address_count;
    char first_alias[254], terminal_name[254];
    solaris_address_t addresses[SOLARIS_HOSTS_MAX_ADDRESSES];
} solaris_hosts_result_t;

void solaris_hosts_options_init(solaris_hosts_options_t *options);
/* Pure bounded construction, safe on a preparation worker. Copies every input;
 * success publishes one immutable owned snapshot, failure leaves *out=NULL.
 * No filesystem, resolver, system-host discovery, LAN discovery, or I/O.
 * Default localhost is exactly 127.0.0.1; explicit config may replace it.
 * Config is a reverse-label trie: exact branch, then whole-label '*', then
 * leading '.' (one or more labels). '+.' inserts both base and suffix forms.
 * '*' may occupy ANY whole label. System names must be exact, no patterns.
 * Case is ASCII-folded; one trailing dot is stripped; labels <=63, name <=253.
 * Non-ASCII/control/space bytes and partial wildcards are rejected. IDNA and
 * configuration value conversion belong to the caller. IPv4-mapped IPv6 is unmapped.
 * Duplicate normalized patterns, including overlapping '+.' expansions, are
 * errors rather than insertion-order overrides. Address order/duplicates stay.
 * Alias edges resolve within their own layer; the config graph includes the
 * built-in localhost. External terminal aliases are retained without I/O.
 * Cycles/depth limits are checked AFTER all inserts, independent of input order. */
solaris_status_t solaris_hosts_build(solaris_budget_t *budget,
    const solaris_hosts_entry_t *config, size_t config_count,
    const solaris_hosts_entry_t *system, size_t system_count,
    const solaris_hosts_options_t *options, solaris_hosts_t **out,
    solaris_hosts_diagnostic_t *diagnostic);
void solaris_hosts_retain(const solaris_hosts_t *hosts);
void solaris_hosts_release(const solaris_hosts_t *hosts);
/* Concurrent read-only copy-out. family=0 selects both, otherwise 4 or 6.
 * Initial config miss searches system; a config match never falls through to
 * system because of its value, alias target, or requested family. No network.
 * A miss is OK/matched=0. A matching address record with no selected family is
 * OK/matched=1/kind=ADDRESSES/count=0. External alias is kind=ALIAS/count=0 and
 * terminal_name supplies the next DNS query. first_alias preserves immediate
 * CNAME semantics even when the chain resolves to addresses. source/index refer
 * to the first match, not the terminal target. No DNS TTL/RCODE is invented. */
solaris_status_t solaris_hosts_lookup(const solaris_hosts_t *hosts, const char *name,
    uint32_t family, solaris_hosts_result_t *out);

#endif
