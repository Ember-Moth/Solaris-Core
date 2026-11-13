#include "policy/route/internal.h"
#include "contracts/dns/lookup.h"
#include <assert.h>
#include <string.h>

struct solaris_route_job {
    solaris_scope_t scope;
    solaris_route_options_t options;
    solaris_route_result_t result;
    solaris_deferred_t deferred;
    solaris_deadline_t *deadline;
    void *resolver;
    uint64_t due_ns;
    size_t index;
    char domain[256];
    solaris_status_t status;
    int accepted, retained, settled, attempted, resolving, delivering;
};
static void run(void *context);
static void settle(solaris_route_job_t *job, solaris_status_t status)
{
    if (job->settled) return;
    if (!solaris_dns_lookup_terminal(status) && solaris_executor_now_ns(job->scope.owner) >= job->due_ns)
        status = SOLARIS_ETIMEDOUT;
    job->status = status; job->settled = 1;
    solaris_scope_cancel(&job->scope);
}
static void cancel_scope(void *context)
{
    solaris_route_job_t *job = context;
    if (!job->settled) { job->settled = 1; job->status = SOLARIS_ECANCELLED; }
    if (job->deadline) solaris_deadline_cancel(job->deadline);
    if (job->resolver) job->options.cancel_resolve(job->options.context, job->resolver);
}
static void release_plan(solaris_dial_plan_t *plan)
{
    solaris_status_t rc = solaris_dial_plan_release(plan); assert(rc == SOLARIS_OK); (void)rc;
}
static void destroy(void *context)
{
    solaris_route_job_t *job = context;
    assert(!job->deadline && !job->resolving && !job->resolver && !job->deferred.queued);
    /* A successful selection is not handed to its caller until this barrier.
     * Explicit cancel or stop can revoke it after the matcher settled. */
    if (job->status == SOLARIS_OK && (!solaris_executor_accepting(job->scope.owner) ||
        solaris_executor_generation(job->scope.owner) != job->scope.generation)) job->status = SOLARIS_ECANCELLED;
    if (job->status != SOLARIS_OK) release_plan(&job->result.plan);
    job->delivering = 1;
    if (job->accepted) job->options.done(job->options.user, job->status, &job->result);
    release_plan(&job->result.plan);
    if (job->retained) job->options.release(job->options.context);
    solaris_memory_free(job);
}
static void schedule(solaris_route_job_t *job)
{
    if (job->deferred.queued || job->settled) return;
    solaris_scope_retain(&job->scope);
    solaris_status_t rc = solaris_executor_defer(job->scope.owner, &job->deferred);
    assert(rc == SOLARIS_OK); (void)rc;
}
static void deadline(void *context, solaris_status_t status)
{
    solaris_route_job_t *job = context; job->deadline = NULL;
    if (status == SOLARIS_OK) settle(job, SOLARIS_ETIMEDOUT);
    solaris_scope_release(&job->scope);
}
static solaris_status_t system_resolve(void *context, solaris_executor_t *owner, const solaris_address_t *target,
    uint64_t timeout_ms, solaris_resolve_fn callback, void *user, void **request)
{
    (void)context;
    solaris_resolve_t *resolver = NULL;
    solaris_status_t rc = solaris_resolve_start(owner, target, timeout_ms, callback, user, &resolver);
    *request = resolver; return rc;
}
static void system_cancel(void *context, void *request) { (void)context; solaris_resolve_cancel(request); }
static int numeric(const solaris_address_t *address)
{ return address->family == SOLARIS_ADDRESS_IPV4 || address->family == SOLARIS_ADDRESS_IPV6; }
static solaris_address_t unmap(const solaris_address_t *address)
{
    solaris_address_t result = *address;
    static const uint8_t prefix[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255};
    if (result.family == SOLARIS_ADDRESS_IPV6 && !memcmp(result.ip, prefix, sizeof(prefix))) {
        uint8_t ip[4]; memcpy(ip, result.ip + 12, sizeof(ip));
        memset(result.ip, 0, sizeof(result.ip)); memcpy(result.ip, ip, sizeof(ip));
        result.family = SOLARIS_ADDRESS_IPV4; result.scope_id = 0;
    }
    return result;
}
static void resolved(void *context, solaris_status_t status, const solaris_address_t *addresses, size_t count)
{
    solaris_route_job_t *job = context; job->resolver = NULL; job->resolving = 0;
    if (!job->settled) {
        if (solaris_dns_lookup_terminal(status)) settle(job, status);
        else if (solaris_executor_now_ns(job->scope.owner) >= job->due_ns) settle(job, SOLARIS_ETIMEDOUT);
        else {
            /* The resolver's ordered first usable address is the route address,
             * not an any-address match whose chosen dial target could differ. */
            if (status == SOLARIS_OK && addresses && count <= SOLARIS_RESOLVER_MAX_ADDRESSES) {
                for (size_t i = 0; i < count; ++i) if (numeric(&addresses[i])) {
                    job->result.metadata.resolved = unmap(&addresses[i]);
                    job->result.metadata.resolved.port = job->result.metadata.destination.port;
                    job->result.metadata.resolved_valid = 1; break;
                }
            }
            schedule(job);
        }
    }
    solaris_scope_release(&job->scope);
}
static void resolve_target(solaris_route_job_t *job)
{
    job->attempted = 1; job->resolving = 1;
    uint64_t now = solaris_executor_now_ns(job->scope.owner);
    if (now >= job->due_ns) { job->resolving = 0; settle(job, SOLARIS_ETIMEDOUT); return; }
    uint64_t remaining = (job->due_ns - now - 1) / UINT64_C(1000000) + 1;
    solaris_scope_retain(&job->scope);
    solaris_status_t rc = job->options.resolve(job->options.context, job->scope.owner,
        &job->result.metadata.destination, remaining, resolved, job, &job->resolver);
    if (rc != SOLARIS_OK) {
        job->resolving = 0; job->resolver = NULL; solaris_scope_release(&job->scope);
        /* A rejected resolver call is still the one permitted resolution
         * attempt; later non-IP rules can make a valid routing decision. */
        if (!job->settled) {
            if (solaris_dns_lookup_terminal(rc)) settle(job, rc);
            else schedule(job);
        }
    } else if (job->settled && job->resolver) job->options.cancel_resolve(job->options.context, job->resolver);
}
static int cidr_match(const solaris_route_rule_t *rule, const solaris_address_t *address)
{
    solaris_address_t normalized = unmap(address);
    if (normalized.family != rule->address.family) return 0;
    unsigned bytes = rule->prefix_length / 8, bits = rule->prefix_length % 8;
    if (bytes && memcmp(normalized.ip, rule->address.ip, bytes)) return 0;
    return !bits || !((normalized.ip[bytes] ^ rule->address.ip[bytes]) & (255u << (8 - bits)));
}
static int valid_rule(const solaris_route_rule_t *rule)
{
    if (!rule->target_id || rule->no_resolve > 1 || rule->kind < SOLARIS_ROUTE_DOMAIN || rule->kind > SOLARIS_ROUTE_FINAL)
        return 0;
    if (rule->kind <= SOLARIS_ROUTE_DOMAIN_KEYWORD)
        return !rule->no_resolve && rule->domain[0] && memchr(rule->domain, 0, sizeof(rule->domain));
    if (rule->kind <= SOLARIS_ROUTE_SRC_IP_CIDR) {
        if (!numeric(&rule->address) || rule->prefix_length > (rule->address.family == SOLARIS_ADDRESS_IPV4 ? 32u : 128u)) return 0;
        return (rule->kind != SOLARIS_ROUTE_IP_CIDR || rule->address.family == SOLARIS_ADDRESS_IPV4) &&
               (rule->kind != SOLARIS_ROUTE_IP_CIDR6 || rule->address.family == SOLARIS_ADDRESS_IPV6);
    }
    if (rule->no_resolve) return 0;
    if (rule->kind == SOLARIS_ROUTE_NETWORK) return rule->network == SOLARIS_NETWORK_TCP || rule->network == SOLARIS_NETWORK_UDP;
    if (rule->kind == SOLARIS_ROUTE_SRC_PORT || rule->kind == SOLARIS_ROUTE_DST_PORT) return rule->port_first <= rule->port_last;
    return 1;
}
static int matches(const solaris_route_job_t *job, const solaris_route_rule_t *rule)
{
    const solaris_flow_metadata_t *metadata = &job->result.metadata;
    switch (rule->kind) {
    case SOLARIS_ROUTE_DOMAIN: return job->domain[0] && !strcmp(job->domain, rule->domain);
    case SOLARIS_ROUTE_DOMAIN_SUFFIX: {
        size_t domain = strlen(job->domain), suffix = strlen(rule->domain);
        return domain >= suffix && !memcmp(job->domain + domain - suffix, rule->domain, suffix) &&
            (domain == suffix || job->domain[domain - suffix - 1] == '.');
    }
    case SOLARIS_ROUTE_DOMAIN_KEYWORD: return job->domain[0] && strstr(job->domain, rule->domain);
    case SOLARIS_ROUTE_IP_CIDR: case SOLARIS_ROUTE_IP_CIDR6:
        if (numeric(&metadata->destination)) return cidr_match(rule, &metadata->destination);
        return metadata->resolved_valid && cidr_match(rule, &metadata->resolved);
    case SOLARIS_ROUTE_SRC_IP_CIDR: return cidr_match(rule, &metadata->source);
    case SOLARIS_ROUTE_SRC_PORT: return metadata->source.port >= rule->port_first && metadata->source.port <= rule->port_last;
    case SOLARIS_ROUTE_DST_PORT: return metadata->destination.port >= rule->port_first && metadata->destination.port <= rule->port_last;
    case SOLARIS_ROUTE_NETWORK: return metadata->network == rule->network;
    case SOLARIS_ROUTE_FINAL: return 1;
    default: return 0;
    }
}
static solaris_status_t acquire(solaris_route_job_t *job, uint64_t target, uint64_t rule_index, int *skip_udp)
{
    solaris_dial_plan_t plan = {0}; uint32_t capabilities = 0;
    solaris_status_t rc = job->options.acquire(job->options.context, job->scope.owner, target, &plan, &capabilities);
    if (rc != SOLARIS_OK || job->settled) { release_plan(&plan); return rc; }
    if (!plan.outbound || !plan.release || !plan.node_id || plan.outbound->owner != job->scope.owner) {
        release_plan(&plan); return SOLARIS_EINVAL;
    }
    uint32_t required = job->result.metadata.network == SOLARIS_NETWORK_TCP ? SOLARIS_OUTBOUND_STREAM : SOLARIS_OUTBOUND_DATAGRAM;
    if (!(capabilities & required)) {
        release_plan(&plan);
        if (skip_udp && required == SOLARIS_OUTBOUND_DATAGRAM) *skip_udp = 1;
        return SOLARIS_ENOTSUP;
    }
    job->result.plan = plan; job->result.rule_index = rule_index; job->result.effective_capabilities = capabilities;
    job->result.dial_target = job->result.metadata.destination;
    if ((capabilities & SOLARIS_OUTBOUND_LOCAL_RESOLUTION) && job->result.metadata.resolved_valid &&
        job->result.metadata.destination.family == SOLARIS_ADDRESS_DOMAIN)
        job->result.dial_target = job->result.metadata.resolved;
    settle(job, SOLARIS_OK); return SOLARIS_OK;
}
static void run(void *context)
{
    solaris_route_job_t *job = context;
    if (job->settled) goto done;
    if (solaris_executor_now_ns(job->scope.owner) >= job->due_ns) { settle(job, SOLARIS_ETIMEDOUT); goto done; }
    if (job->options.mode != SOLARIS_MODE_RULE) {
        solaris_status_t rc = acquire(job, job->options.mode == SOLARIS_MODE_DIRECT ? job->options.direct_target : job->options.global_target,
            UINT64_MAX, NULL);
        if (rc != SOLARIS_OK && !job->settled) settle(job, rc);
        goto done;
    }
    for (unsigned work = 0; work < 64 && !job->settled && !job->resolving; ++work) {
        if (job->index == job->options.rule_count) {
            solaris_status_t rc = acquire(job, job->options.direct_target, UINT64_MAX, NULL);
            if (rc != SOLARIS_OK && !job->settled) settle(job, rc);
            break;
        }
        const solaris_route_rule_t *rule = &job->options.rules[job->index];
        if (!valid_rule(rule)) { settle(job, SOLARIS_EINVAL); break; }
        if ((rule->kind == SOLARIS_ROUTE_IP_CIDR || rule->kind == SOLARIS_ROUTE_IP_CIDR6) && !rule->no_resolve &&
            !job->attempted && job->result.metadata.destination.family == SOLARIS_ADDRESS_DOMAIN) {
            resolve_target(job); break;
        }
        uint64_t index = (uint64_t)job->index++;
        if (matches(job, rule)) {
            int skip = 0;
            solaris_status_t rc = acquire(job, rule->target_id, index, &skip);
            if (rc != SOLARIS_OK && (!skip || rule->kind == SOLARIS_ROUTE_FINAL) && !job->settled) settle(job, rc);
        }
    }
    if (!job->settled && !job->resolving) schedule(job);
done:
    solaris_scope_release(&job->scope);
}
solaris_status_t solaris_route_start(const solaris_route_options_t *options, solaris_route_job_t **out)
{
    if (!out) return SOLARIS_EINVAL;
    *out = NULL;
    if (!options || !options->owner || !options->acquire || !options->done ||
        options->mode < SOLARIS_MODE_RULE || options->mode > SOLARIS_MODE_DIRECT ||
        (options->rule_count && !options->rules) || !options->direct_target ||
        (options->mode == SOLARIS_MODE_GLOBAL && !options->global_target) || !options->timeout_ms ||
        options->timeout_ms > UINT64_MAX / UINT64_C(1000000) ||
        ((options->retain == NULL) != (options->release == NULL)) ||
        ((options->resolve == NULL) != (options->cancel_resolve == NULL)) ||
        (options->metadata.network != SOLARIS_NETWORK_TCP && options->metadata.network != SOLARIS_NETWORK_UDP) ||
        !options->metadata.destination.port || options->metadata.resolved_valid > 1 ||
        (options->metadata.resolved_valid && !numeric(&options->metadata.resolved)) ||
        (!numeric(&options->metadata.source) && options->metadata.source.family != 0)) return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(options->owner)) return SOLARIS_ETHREAD;
    char domain[256] = {0};
    const solaris_address_t *target = &options->metadata.destination;
    if (target->family == SOLARIS_ADDRESS_DOMAIN) {
        const char *end = memchr(target->host, 0, sizeof(target->host));
        if (!end || solaris_route_normalize_domain(target->host, (size_t)(end - target->host), 0, 0, domain) != SOLARIS_OK)
            return SOLARIS_EINVAL;
    } else if (!numeric(target)) return SOLARIS_EINVAL;
    uint64_t now = solaris_executor_now_ns(options->owner), duration = options->timeout_ms * UINT64_C(1000000);
    if (now > UINT64_MAX - duration) return SOLARIS_EOVERFLOW;
    solaris_route_job_t *job = solaris_memory_allocate(solaris_executor_budget(options->owner), sizeof(*job));
    if (!job) return SOLARIS_ENOMEM;
    memset(job, 0, sizeof(*job)); job->options = *options; job->result.metadata = options->metadata;
    job->result.dial_target = options->metadata.destination; job->result.rule_index = UINT64_MAX;
    if (job->result.metadata.resolved_valid) {
        job->result.metadata.resolved = unmap(&job->result.metadata.resolved);
        job->result.metadata.resolved.port = target->port;
    }
    memcpy(job->domain, domain, sizeof(domain)); job->attempted = options->metadata.resolved_valid || numeric(target);
    job->due_ns = now + duration; job->status = SOLARIS_ECANCELLED;
    job->deferred = (solaris_deferred_t){.run = run, .context = job};
    if (!job->options.resolve) { job->options.resolve = system_resolve; job->options.cancel_resolve = system_cancel; }
    solaris_status_t rc = solaris_scope_init(&job->scope, options->owner, cancel_scope, destroy, job);
    if (rc != SOLARIS_OK) { solaris_memory_free(job); return rc; }
    solaris_scope_retain(&job->scope);
    rc = solaris_deadline_start(options->owner, options->timeout_ms, deadline, job, &job->deadline);
    if (rc != SOLARIS_OK) { solaris_scope_release(&job->scope); settle(job, rc); return rc; }
    if (job->options.retain) { job->options.retain(job->options.context); job->retained = 1; }
    job->accepted = 1; *out = job; schedule(job); return SOLARIS_OK;
}
void solaris_route_cancel(solaris_route_job_t *job)
{
    if (!job || !solaris_executor_is_owner(job->scope.owner) || job->delivering) return;
    if (job->settled && job->status == SOLARIS_OK) job->status = SOLARIS_ECANCELLED;
    else settle(job, SOLARIS_ECANCELLED);
}
solaris_status_t solaris_route_result_take_plan(solaris_route_result_t *result, solaris_dial_plan_t *out)
{
    if (!out || !result || out == &result->plan) return SOLARIS_EINVAL;
    memset(out, 0, sizeof(*out));
    if (!result->plan.outbound) return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(result->plan.outbound->owner)) return SOLARIS_ETHREAD;
    *out = result->plan; memset(&result->plan, 0, sizeof(result->plan)); return SOLARIS_OK;
}
