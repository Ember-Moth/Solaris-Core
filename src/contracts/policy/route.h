#ifndef SOLARIS_ROUTE_H
#define SOLARIS_ROUTE_H
#include <solaris/config.h>
#include "contracts/flow/plan.h"
#include "dns/system/resolver.h"

enum { SOLARIS_ROUTE_DOMAIN = 1, SOLARIS_ROUTE_DOMAIN_SUFFIX, SOLARIS_ROUTE_DOMAIN_KEYWORD,
       SOLARIS_ROUTE_IP_CIDR, SOLARIS_ROUTE_IP_CIDR6, SOLARIS_ROUTE_SRC_IP_CIDR,
       SOLARIS_ROUTE_SRC_PORT, SOLARIS_ROUTE_DST_PORT, SOLARIS_ROUTE_NETWORK, SOLARIS_ROUTE_MATCH };
enum { SOLARIS_NETWORK_TCP = 6, SOLARIS_NETWORK_UDP = 17 };
typedef struct solaris_route_rule {
    uint32_t kind, no_resolve, network, prefix_length;
    uint16_t port_first, port_last;
    uint64_t target_id;
    char domain[256];
    solaris_address_t address;
    uint32_t line, column;
} solaris_route_rule_t;
typedef struct solaris_flow_metadata {
    solaris_address_t source, destination, resolved;
    uint32_t network, resolved_valid;
    uint64_t inbound_id, connection_id, config_revision, selection_revision;
} solaris_flow_metadata_t;
typedef struct solaris_route_result {
    solaris_dial_plan_t plan;
    solaris_flow_metadata_t metadata;
    /* Original destination unless the selected adapter requests local numeric
     * resolution reuse; never overwrite metadata.destination. */
    solaris_address_t dial_target;
    /* UINT64_MAX means mode selection or the legitimate DIRECT fallback. */
    uint64_t rule_index;
    uint32_t effective_capabilities;
} solaris_route_result_t;
typedef struct solaris_route_job solaris_route_job_t;
typedef struct solaris_route_options {
    solaris_executor_t *owner;
    solaris_flow_metadata_t metadata;
    solaris_mode_t mode;
    const solaris_route_rule_t *rules;
    size_t rule_count;
    uint64_t direct_target, global_target, timeout_ms;
    void *context;
    /* Context pins immutable config AND control views for the full job. These
     * optional functions must be provided as a pair, and run on owner. */
    void (*retain)(void *context);
    void (*release)(void *context);
    /* No network I/O. Acquire one owned leaf plan plus its effective (module x
     * configuration x host) capabilities. On rejection returns no lease. */
    solaris_status_t (*acquire)(void *context, solaris_executor_t *owner, uint64_t target_id,
        solaris_dial_plan_t *plan, uint32_t *effective_capabilities);
    /* Same as solaris_resolve_start: acceptance promises a deferred exactly-
     * once callback, including cancellation; rejection has no callback. The
     * request expires when that callback returns. cancel never omits it. */
    solaris_status_t (*resolve)(void *context, solaris_executor_t *owner, const solaris_address_t *target,
        uint64_t timeout_ms, solaris_resolve_fn callback, void *user, void **request);
    void (*cancel_resolve)(void *context, void *request);
    /* Deferred, exactly once after accepted start, including cancel. result is
     * borrowed; move its owned plan with result_take_plan during this callback.
     * Unclaimed plans are released after callback. Job expires on return. */
    void (*done)(void *user, solaris_status_t status, solaris_route_result_t *result);
    void *user;
} solaris_route_options_t;
/* Pure matcher compiler. target is resolved by the configuration name graph.
 * kind/value/no_resolve never contain the policy target field. */
solaris_status_t solaris_route_rule_compile(const char *kind, const char *value, int no_resolve,
    uint64_t target, solaris_route_rule_t *out, solaris_error_t *error);
/* Job creation, cancellation and result transfer run on options.owner. */
solaris_status_t solaris_route_start(const solaris_route_options_t *options, solaris_route_job_t **out);
void solaris_route_cancel(solaris_route_job_t *job);
solaris_status_t solaris_route_result_take_plan(solaris_route_result_t *result, solaris_dial_plan_t *out);
#endif
