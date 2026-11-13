#include "contracts/runtime/network.h"
#include "api/common/error.h"
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <uv.h>

struct solaris_network_snapshot {
    atomic_size_t references;
    solaris_network_snapshot_info_t info;
    solaris_socket_policy_t policy;
    solaris_address_t *servers, *addresses;
    solaris_hosts_entry_t *hosts;
    char (*names)[254];
    int policy_retained;
};

solaris_status_t solaris_platform_get_capabilities(solaris_platform_capabilities_t *out)
{
    if (!out) return SOLARIS_EINVAL;
    memset(out, 0, sizeof(*out));
#ifdef _WIN32
    out->async_socket_policy_status = SOLARIS_ENOTSUP;
#else
    out->async_socket_policy_status = SOLARIS_OK;
#endif
    out->dns_server_limit = SOLARIS_NETWORK_MAX_DNS_SERVERS;
    out->system_host_limit = SOLARIS_NETWORK_MAX_SYSTEM_HOSTS;
    out->addresses_per_host_limit = SOLARIS_NETWORK_MAX_HOST_ADDRESSES;
    out->total_host_address_limit = SOLARIS_NETWORK_MAX_TOTAL_HOST_ADDRESSES;
    return SOLARIS_OK;
}
void solaris_network_options_init(solaris_network_options_t *options)
{
    if (!options) return;
    memset(options, 0, sizeof(*options)); options->memory_limit_bytes = SOLARIS_NETWORK_DEFAULT_MEMORY_LIMIT_BYTES;
}
static int numeric_address(const char *text, uint16_t port, int allow_scope, solaris_address_t *out)
{
    if (!text) return 0;
    size_t n = 0; while (n < 64u && text[n]) ++n;
    if (!n || n == 64u) return 0;
    char numeric[64]; memcpy(numeric, text, n + 1u);
    uint32_t scope = 0;
    char *zone = strchr(numeric, '%');
    if (zone) {
        if (!allow_scope || !zone[1]) return 0;
        *zone++ = 0;
        for (const char *p = zone; *p; ++p) {
            if (*p < '0' || *p > '9' || scope > (UINT32_MAX - (uint32_t)(*p - '0')) / 10u) return 0;
            scope = scope * 10u + (uint32_t)(*p - '0');
        }
        if (!scope) return 0;
    }
    if (solaris_address_parse(numeric, port, out) != SOLARIS_OK ||
        (out->family != SOLARIS_ADDRESS_IPV4 && out->family != SOLARIS_ADDRESS_IPV6) ||
        (zone && out->family != SOLARIS_ADDRESS_IPV6)) return 0;
    out->scope_id = scope;
    if (!allow_scope && out->family == SOLARIS_ADDRESS_IPV6) {
        static const uint8_t mapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255};
        if (memcmp(out->ip, mapped, sizeof(mapped)) == 0) {
            memmove(out->ip, out->ip + 12u, 4u); memset(out->ip + 4u, 0, 12u); out->family = SOLARIS_ADDRESS_IPV4;
        }
    }
    return 1;
}
static int normalized_name(const char *input, char out[254])
{
    if (!input) return 0;
    size_t n = 0; while (n < 255u && input[n]) ++n;
    if (!n || n == 255u) return 0;
    if (input[n - 1u] == '.') --n;
    if (!n || n > 253u) return 0;
    for (size_t i = 0; i < n; ++i) {
        unsigned char c = (unsigned char)input[i];
        out[i] = (char)(c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c);
    }
    out[n] = 0; return 1; /* The shared hosts builder validates labels. */
}
void solaris_network_snapshot_retain(solaris_network_snapshot_t *snapshot)
{ if (snapshot) atomic_fetch_add_explicit(&snapshot->references, 1u, memory_order_relaxed); }
void solaris_network_snapshot_release(solaris_network_snapshot_t *snapshot)
{
    if (!snapshot || atomic_fetch_sub_explicit(&snapshot->references, 1u, memory_order_acq_rel) != 1u) return;
    solaris_memory_free(snapshot->servers); solaris_memory_free(snapshot->addresses);
    solaris_memory_free(snapshot->hosts); solaris_memory_free(snapshot->names);
    if (snapshot->policy_retained) snapshot->policy.release(snapshot->policy.context);
    solaris_memory_free(snapshot);
}
solaris_status_t solaris_network_snapshot_create(const solaris_network_options_t *options,
    solaris_network_snapshot_t **out, solaris_error_t *error)
{
    if (!out) return solaris_error_set(error, SOLARIS_EINVAL, 0, "missing network snapshot output");
    *out = NULL;
    if (!options || !options->revision || !options->network_revision || !options->resolver_revision ||
        options->ipv4_available > 1u || options->ipv6_available > 1u || options->strict_dns > 1u ||
        (options->dns_server_count && !options->dns_servers) || (options->system_host_count && !options->system_hosts))
        return solaris_error_set(error, SOLARIS_EINVAL, 0, "invalid network revisions, flags or input arrays");
    if (options->dns_server_count > SOLARIS_NETWORK_MAX_DNS_SERVERS || options->system_host_count > SOLARIS_NETWORK_MAX_SYSTEM_HOSTS ||
        options->memory_limit_bytes > SOLARIS_NETWORK_MAX_MEMORY_LIMIT_BYTES)
        return solaris_error_set(error, SOLARIS_EOVERFLOW, 0, "network snapshot limit exceeded");
    const solaris_socket_policy_t *policy = &options->socket_policy;
    int has_policy = policy->context || policy->start || policy->cancel || policy->retain || policy->release;
    if (has_policy && (!policy->start || !policy->cancel || ((policy->retain == NULL) != (policy->release == NULL)) ||
        (policy->context && !policy->retain)))
        return solaris_error_set(error, SOLARIS_EINVAL, 0, "socket policy requires complete lifetime and cancellation hooks");
    solaris_platform_capabilities_t capabilities; (void)solaris_platform_get_capabilities(&capabilities);
    if (has_policy && capabilities.async_socket_policy_status != SOLARIS_OK)
        return solaris_error_set(error, SOLARIS_ENOTSUP, 0, "asynchronous socket policy is unavailable on this platform");
    size_t address_count = 0;
    for (size_t i = 0; i < options->system_host_count; ++i) {
        const solaris_network_host_input_t *host = &options->system_hosts[i];
        if (!host->addresses || !host->address_count)
            return solaris_error_set(error, SOLARIS_EINVAL, 0, "system hosts requires a nonempty address list");
        if (host->address_count > SOLARIS_NETWORK_MAX_HOST_ADDRESSES ||
            host->address_count > SOLARIS_NETWORK_MAX_TOTAL_HOST_ADDRESSES - address_count)
            return solaris_error_set(error, SOLARIS_EOVERFLOW, 0, "system hosts address limit exceeded");
        address_count += host->address_count;
    }
    solaris_budget_t *budget = NULL;
    solaris_status_t rc = solaris_budget_create(options->memory_limit_bytes ? options->memory_limit_bytes :
        SOLARIS_NETWORK_DEFAULT_MEMORY_LIMIT_BYTES, NULL, &budget);
    if (rc != SOLARIS_OK) return solaris_error_set(error, rc, 0, "network snapshot budget allocation failed");
    solaris_network_snapshot_t *snapshot = solaris_memory_allocate(budget, sizeof(*snapshot));
    if (!snapshot) { solaris_budget_release(budget); return solaris_error_set(error, SOLARIS_ENOMEM, 0, "network snapshot allocation failed"); }
    memset(snapshot, 0, sizeof(*snapshot)); atomic_init(&snapshot->references, 1u);
    snapshot->info = (solaris_network_snapshot_info_t){options->revision, options->network_revision,
        options->resolver_revision, options->network_id, options->ipv4_available, options->ipv6_available,
        options->strict_dns, (uint32_t)has_policy, options->dns_server_count, options->system_host_count, address_count};
    snapshot->policy = *policy;
    const char *message = "network snapshot allocation failed";
    rc = SOLARIS_ENOMEM;
    if (options->dns_server_count) {
        snapshot->servers = solaris_memory_allocate(budget, options->dns_server_count * sizeof(*snapshot->servers));
        if (!snapshot->servers) goto fail;
        for (size_t i = 0; i < options->dns_server_count; ++i)
            if (!numeric_address(options->dns_servers[i].address, options->dns_servers[i].port ? options->dns_servers[i].port : 53u, 1,
                                 &snapshot->servers[i])) {
                rc = SOLARIS_EINVAL; message = "invalid numeric system DNS endpoint"; goto fail;
            }
    }
    if (options->system_host_count) {
        snapshot->hosts = solaris_memory_allocate(budget, options->system_host_count * sizeof(*snapshot->hosts));
        snapshot->names = solaris_memory_allocate(budget, options->system_host_count * sizeof(*snapshot->names));
        snapshot->addresses = solaris_memory_allocate(budget, address_count * sizeof(*snapshot->addresses));
        if (!snapshot->hosts || !snapshot->names || !snapshot->addresses) goto fail;
        size_t offset = 0;
        for (size_t i = 0; i < options->system_host_count; ++i) {
            const solaris_network_host_input_t *host = &options->system_hosts[i];
            if (!normalized_name(host->name, snapshot->names[i])) {
                rc = SOLARIS_EINVAL; message = "invalid system hosts name"; goto fail;
            }
            snapshot->hosts[i] = (solaris_hosts_entry_t){snapshot->names[i], SOLARIS_HOSTS_ADDRESSES,
                snapshot->addresses + offset, host->address_count, NULL};
            for (size_t j = 0; j < host->address_count; ++j)
                if (!numeric_address(host->addresses[j], 0u, 0, &snapshot->addresses[offset + j])) {
                    rc = SOLARIS_EINVAL; message = "invalid numeric system hosts address"; goto fail;
                }
            offset += host->address_count;
        }
        solaris_hosts_options_t limits; solaris_hosts_options_init(&limits);
        limits.entries = SOLARIS_NETWORK_MAX_SYSTEM_HOSTS + 1u;
        limits.address_total = SOLARIS_NETWORK_MAX_TOTAL_HOST_ADDRESSES + 1u;
        solaris_hosts_t *validated = NULL; solaris_hosts_diagnostic_t diagnostic;
        rc = solaris_hosts_build(budget, NULL, 0u, snapshot->hosts, options->system_host_count, &limits, &validated, &diagnostic);
        if (rc != SOLARIS_OK) {
            solaris_error_set(error, rc, 0, diagnostic.message);
            solaris_network_snapshot_release(snapshot); solaris_budget_release(budget); return rc;
        }
        /* Its default config localhost is validation-only, never system data. */
        solaris_hosts_release(validated);
    }
    if (has_policy && policy->retain) { policy->retain(policy->context); snapshot->policy_retained = 1; }
    solaris_budget_release(budget); *out = snapshot;
    return solaris_error_set(error, SOLARIS_OK, 0, NULL);
fail:
    solaris_network_snapshot_release(snapshot); solaris_budget_release(budget);
    return solaris_error_set(error, rc, 0, message);
}
static solaris_status_t endpoint_info(const solaris_address_t *address, solaris_network_endpoint_info_t *out)
{
    out->family = address->family; out->scope_id = address->scope_id; out->port = address->port;
    if (uv_inet_ntop(address->family == SOLARIS_ADDRESS_IPV4 ? AF_INET : AF_INET6, address->ip, out->address, sizeof(out->address)) != 0)
        return SOLARIS_EINVAL;
    if (address->scope_id) {
        size_t n = strlen(out->address);
        int written = snprintf(out->address + n, sizeof(out->address) - n, "%%%u", address->scope_id);
        if (written < 0 || (size_t)written >= sizeof(out->address) - n) return SOLARIS_EOVERFLOW;
    }
    return SOLARIS_OK;
}
solaris_status_t solaris_network_snapshot_get_info(const solaris_network_snapshot_t *snapshot, solaris_network_snapshot_info_t *out)
{
    if (!out) return SOLARIS_EINVAL;
    memset(out, 0, sizeof(*out)); if (!snapshot) return SOLARIS_EINVAL;
    *out = snapshot->info; return SOLARIS_OK;
}
solaris_status_t solaris_network_snapshot_get_dns_server(const solaris_network_snapshot_t *snapshot,
    size_t index, solaris_network_endpoint_info_t *out)
{
    if (!out) return SOLARIS_EINVAL;
    memset(out, 0, sizeof(*out)); if (!snapshot || index >= snapshot->info.dns_server_count) return SOLARIS_EINVAL;
    return endpoint_info(&snapshot->servers[index], out);
}
solaris_status_t solaris_network_snapshot_get_host(const solaris_network_snapshot_t *snapshot, size_t index, solaris_network_host_info_t *out)
{
    if (!out) return SOLARIS_EINVAL;
    memset(out, 0, sizeof(*out)); if (!snapshot || index >= snapshot->info.system_host_count) return SOLARIS_EINVAL;
    memcpy(out->name, snapshot->names[index], strlen(snapshot->names[index]) + 1u);
    out->address_count = snapshot->hosts[index].address_count; return SOLARIS_OK;
}
solaris_status_t solaris_network_snapshot_get_host_address(const solaris_network_snapshot_t *snapshot,
    size_t host_index, size_t address_index, solaris_network_endpoint_info_t *out)
{
    if (!out) return SOLARIS_EINVAL;
    memset(out, 0, sizeof(*out));
    if (!snapshot || host_index >= snapshot->info.system_host_count || address_index >= snapshot->hosts[host_index].address_count)
        return SOLARIS_EINVAL;
    return endpoint_info(&snapshot->hosts[host_index].addresses[address_index], out);
}
const solaris_socket_policy_t *solaris_network_snapshot_policy(const solaris_network_snapshot_t *snapshot)
{ return snapshot ? &snapshot->policy : NULL; }
const solaris_address_t *solaris_network_snapshot_dns_servers(const solaris_network_snapshot_t *snapshot, size_t *count)
{ if (count) *count = snapshot ? snapshot->info.dns_server_count : 0u; return snapshot ? snapshot->servers : NULL; }
const solaris_hosts_entry_t *solaris_network_snapshot_system_hosts(const solaris_network_snapshot_t *snapshot, size_t *count)
{ if (count) *count = snapshot ? snapshot->info.system_host_count : 0u; return snapshot ? snapshot->hosts : NULL; }
