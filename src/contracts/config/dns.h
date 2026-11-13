#ifndef SOLARIS_CONFIG_DNS_H
#define SOLARIS_CONFIG_DNS_H
#include <solaris/config.h>
#include "contracts/dns/service.h"

/* Immutable offline image. Roles are indexed by lookup role minus one.
 * Upstream IDs are qualified by the runtime resolver revision, not global
 * identities. Host entries retain original configured layers for composition
 * with an explicit host network snapshot during preparation. */
typedef struct solaris_config_dns {
    uint32_t enabled, ipv6, ipv6_wait_ms, use_hosts, use_system_hosts;
    const solaris_hosts_entry_t *hosts;
    size_t host_count;
    const solaris_hosts_t *validated_hosts;
    const solaris_dns_upstream_t *upstreams[SOLARIS_DNS_ROLE_COUNT];
    size_t upstream_count[SOLARIS_DNS_ROLE_COUNT];
    uint64_t upstream_set_id[SOLARIS_DNS_ROLE_COUNT];
} solaris_config_dns_t;

/* NULL means neither dns nor hosts was supplied: retain the M2 system path.
 * Borrowed while the caller holds its config reference. */
const solaris_config_dns_t *solaris_config_dns(const solaris_config_t *config);
#endif
