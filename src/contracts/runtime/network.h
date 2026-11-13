#ifndef SOLARIS_RUNTIME_NETWORK_H
#define SOLARIS_RUNTIME_NETWORK_H

#include <solaris/platform.h>
#include "contracts/dns/hosts.h"

/* Immutable borrowed views. The caller must hold a snapshot reference while
 * copying/using them; these getters never acquire or publish an engine view.
 * A channel may copy policy hooks, then use their own paired retention. */
const solaris_socket_policy_t *solaris_network_snapshot_policy(const solaris_network_snapshot_t *snapshot);
const solaris_address_t *solaris_network_snapshot_dns_servers(const solaris_network_snapshot_t *snapshot, size_t *count);
/* Contiguous pure system entries for later composition with config hosts.
 * No default localhost, config layer or alias entries are synthesized. */
const solaris_hosts_entry_t *solaris_network_snapshot_system_hosts(const solaris_network_snapshot_t *snapshot, size_t *count);

#endif
