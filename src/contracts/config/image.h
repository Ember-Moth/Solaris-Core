#ifndef SOLARIS_CONFIG_IMAGE_H
#define SOLARIS_CONFIG_IMAGE_H
#include <solaris/config.h>
#include "contracts/module/config.h"
#include "contracts/policy/route.h"

typedef struct solaris_config_node {
    uint64_t id;
    const char *name, *type;
    uint32_t udp_enabled;
    /* Immutable normalized module-only fields; name/type/udp were consumed by
     * the common compiler. Default trust is injected by prepare, never by
     * silently turning verification off or exposing an internal YAML key. */
    const solaris_config_view_t *fields;
    const char *trust_file;
    uint32_t line, column;
} solaris_config_node_t;
typedef struct solaris_config_group {
    uint64_t id;
    const char *name;
    const uint64_t *members;
    size_t member_count;
    uint64_t selected_id;
} solaris_config_group_t;
typedef struct solaris_config_auth { const char *username, *password; } solaris_config_auth_t;
typedef struct solaris_config_listener {
    uint64_t id;
    const char *name;
    /* Values equal SOLARIS_INBOUND_HTTP/SOCKS5/MIXED, without depending on the
     * optional proxy adapter's headers. Top-level YAML port zero omits its
     * listener; explicit listeners[] require a nonzero fixed port in M2. */
    uint32_t protocol, udp;
    solaris_address_t listen;
    const solaris_config_auth_t *auth;
    size_t auth_count;
} solaris_config_listener_t;
/* Borrowed accessors require the caller to hold a config reference. IDs are
 * stable name-derived identities (collisions rejected), always qualified by
 * runtime config revision in public control and observation operations. */
const solaris_config_node_t *solaris_config_nodes(const solaris_config_t *config, size_t *count);
const solaris_config_group_t *solaris_config_groups(const solaris_config_t *config, size_t *count);
const solaris_route_rule_t *solaris_config_rules(const solaris_config_t *config, size_t *count);
const solaris_config_listener_t *solaris_config_listeners(const solaris_config_t *config, size_t *count);
uint64_t solaris_config_direct_target(const solaris_config_t *config);
uint64_t solaris_config_global_target(const solaris_config_t *config);
const char *solaris_config_base_directory(const solaris_config_t *config);
const char *solaris_config_source_name(const solaris_config_t *config);
#endif
