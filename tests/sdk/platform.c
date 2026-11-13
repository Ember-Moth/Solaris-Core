#include <solaris/platform.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef __cplusplus
#include <thread>
#endif

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)
typedef struct policy_state { unsigned int references, retains, releases, starts, cancels; } policy_state_t;
static void retained(void *context)
{ policy_state_t *state = (policy_state_t *)context; CHECK(state->references++ != 0u); state->retains++; }
static void released(void *context)
{ policy_state_t *state = (policy_state_t *)context; CHECK(state->references-- != 0u); state->releases++; }
static solaris_status_t policy_start(void *context, solaris_socket_token_t *token,
    uintptr_t handle, uint32_t family, uint32_t kind)
{
    policy_state_t *state = (policy_state_t *)context;
    (void)token; (void)handle; (void)family; (void)kind;
    if (state) state->starts++;
    CHECK(0); return SOLARIS_EIO;
}
static void policy_cancel(void *context, solaris_socket_token_t *token)
{ policy_state_t *state = (policy_state_t *)context; (void)token; if (state) state->cancels++; CHECK(0); }
static char *owned_string(const char *text)
{
    size_t n = strlen(text) + 1u; char *copy = (char *)malloc(n); CHECK(copy != NULL); memcpy(copy, text, n); return copy;
}
static void options_init(solaris_network_options_t *options)
{
    solaris_network_options_init(options);
    CHECK(options->memory_limit_bytes == SOLARIS_NETWORK_DEFAULT_MEMORY_LIMIT_BYTES);
    options->revision = 11u; options->network_revision = 4u; options->resolver_revision = 7u;
    options->network_id = UINT64_C(0x1122334455667788);
    options->ipv4_available = 1u; options->ipv6_available = 1u; options->strict_dns = 1u;
}
static void invalid(solaris_network_options_t *options, solaris_status_t expected)
{
    solaris_network_snapshot_t *snapshot = NULL; solaris_error_t error;
    memset(&error, 0xa5, sizeof(error));
    CHECK(solaris_network_snapshot_create(options, &snapshot, &error) == expected && snapshot == NULL && error.code == expected);
    CHECK(error.system_code == 0 && error.message[0] && strstr(error.message, "credential-fixture") == NULL);
}
static void copied_inputs(void)
{
    solaris_network_options_t options; options_init(&options);
    solaris_network_server_input_t *servers = (solaris_network_server_input_t *)calloc(2u, sizeof(*servers));
    solaris_network_host_input_t *hosts = (solaris_network_host_input_t *)calloc(2u, sizeof(*hosts));
    const char **addresses = (const char **)calloc(3u, sizeof(*addresses)); CHECK(servers && hosts && addresses);
    servers[0].address = owned_string("127.0.0.53"); servers[0].port = 0u;
    servers[1].address = owned_string("fe80::1%0007"); servers[1].port = 5353u;
    addresses[0] = owned_string("::ffff:127.0.0.2"); addresses[1] = owned_string("::1"); addresses[2] = owned_string("::1");
    hosts[0].name = owned_string("MiXeD.Example."); hosts[0].addresses = addresses; hosts[0].address_count = 2u;
    hosts[1].name = owned_string("LOCALHOST"); hosts[1].addresses = addresses + 2u; hosts[1].address_count = 1u;
    options.dns_servers = servers; options.dns_server_count = 2u; options.system_hosts = hosts; options.system_host_count = 2u;
    solaris_network_snapshot_t *snapshot = NULL; solaris_error_t error;
    CHECK(solaris_network_snapshot_create(&options, &snapshot, &error) == SOLARIS_OK && snapshot && error.code == SOLARIS_OK);
    for (size_t i = 0; i < 2u; ++i) { free((void *)servers[i].address); free((void *)hosts[i].name); }
    for (size_t i = 0; i < 3u; ++i) free((void *)addresses[i]);
    free(addresses); free(servers); free(hosts); memset(&options, 0xa5, sizeof(options));
    solaris_network_snapshot_retain(snapshot); solaris_network_snapshot_release(snapshot);
    solaris_network_snapshot_info_t info; CHECK(solaris_network_snapshot_get_info(snapshot, &info) == SOLARIS_OK);
    CHECK(info.revision == 11u && info.network_revision == 4u && info.resolver_revision == 7u && info.network_id == UINT64_C(0x1122334455667788));
    CHECK(info.ipv4_available && info.ipv6_available && info.strict_dns && !info.socket_policy_configured);
    CHECK(info.dns_server_count == 2u && info.system_host_count == 2u && info.system_host_address_count == 3u);
    solaris_network_endpoint_info_t endpoint;
    CHECK(solaris_network_snapshot_get_dns_server(snapshot, 0u, &endpoint) == SOLARIS_OK);
    CHECK(endpoint.family == SOLARIS_SOCKET_FAMILY_IPV4 && endpoint.scope_id == 0u && endpoint.port == 53u && !strcmp(endpoint.address, "127.0.0.53"));
    CHECK(solaris_network_snapshot_get_dns_server(snapshot, 1u, &endpoint) == SOLARIS_OK);
    CHECK(endpoint.family == SOLARIS_SOCKET_FAMILY_IPV6 && endpoint.scope_id == 7u && endpoint.port == 5353u && !strcmp(endpoint.address, "fe80::1%7"));
    solaris_network_host_info_t host;
    CHECK(solaris_network_snapshot_get_host(snapshot, 0u, &host) == SOLARIS_OK && !strcmp(host.name, "mixed.example") && host.address_count == 2u);
    CHECK(solaris_network_snapshot_get_host_address(snapshot, 0u, 0u, &endpoint) == SOLARIS_OK);
    CHECK(endpoint.family == SOLARIS_SOCKET_FAMILY_IPV4 && !strcmp(endpoint.address, "127.0.0.2") && !endpoint.port && !endpoint.scope_id);
    CHECK(solaris_network_snapshot_get_host(snapshot, 1u, &host) == SOLARIS_OK && !strcmp(host.name, "localhost") && host.address_count == 1u);
    CHECK(solaris_network_snapshot_get_host_address(snapshot, 1u, 0u, &endpoint) == SOLARIS_OK && !strcmp(endpoint.address, "::1"));
    CHECK(solaris_network_snapshot_get_host_address(snapshot, 1u, 1u, &endpoint) == SOLARIS_EINVAL && endpoint.address[0] == 0);
    CHECK(solaris_network_snapshot_get_dns_server(snapshot, 2u, &endpoint) == SOLARIS_EINVAL);
    CHECK(solaris_network_snapshot_get_host(snapshot, 2u, &host) == SOLARIS_EINVAL);
    solaris_network_snapshot_release(snapshot);
    CHECK(info.system_host_count == 2u && info.network_revision == 4u); /* Copy-out is independent. */
}
static void revisions_and_empty(void)
{
    solaris_network_options_t options; options_init(&options);
    options.network_id = 0u; options.ipv4_available = options.ipv6_available = 0u;
    solaris_network_snapshot_t *first = NULL, *second = NULL;
    CHECK(solaris_network_snapshot_create(&options, &first, NULL) == SOLARIS_OK);
    options.revision++; options.resolver_revision++;
    CHECK(solaris_network_snapshot_create(&options, &second, NULL) == SOLARIS_OK);
    solaris_network_snapshot_info_t info;
    CHECK(solaris_network_snapshot_get_info(second, &info) == SOLARIS_OK && info.revision == 12u && info.network_revision == 4u && info.resolver_revision == 8u);
    CHECK(!info.system_host_count && !info.system_host_address_count && !info.dns_server_count && !info.network_id);
    CHECK(!info.ipv4_available && !info.ipv6_available && info.strict_dns);
    solaris_network_host_info_t host; CHECK(solaris_network_snapshot_get_host(second, 0u, &host) == SOLARIS_EINVAL);
    CHECK(solaris_network_snapshot_get_info(first, &info) == SOLARIS_OK && info.revision == 11u && info.resolver_revision == 7u);
    solaris_network_snapshot_release(first); solaris_network_snapshot_release(second);
    options_init(&options); options.revision = 0u; invalid(&options, SOLARIS_EINVAL);
    options_init(&options); options.network_revision = 0u; invalid(&options, SOLARIS_EINVAL);
    options_init(&options); options.resolver_revision = 0u; invalid(&options, SOLARIS_EINVAL);
    options_init(&options); options.strict_dns = 2u; invalid(&options, SOLARIS_EINVAL);
    options_init(&options); options.ipv4_available = 2u; invalid(&options, SOLARIS_EINVAL);
    options_init(&options); options.ipv6_available = 2u; invalid(&options, SOLARIS_EINVAL);
}
static void bounds_and_diagnostics(void)
{
    solaris_network_options_t options; options_init(&options);
    solaris_network_server_input_t server = {"https://user:credential-fixture@resolver.example", 53u};
    options.dns_servers = &server; options.dns_server_count = 1u; invalid(&options, SOLARIS_EINVAL);
    const char *invalid_servers[] = {"resolver.example", "[::1]", "fe80::1%en0", "fe80::1%0", "fe80::1%4294967296", "127.0.0.1%7", ""};
    for (size_t i = 0; i < sizeof(invalid_servers) / sizeof(invalid_servers[0]); ++i) {
        server.address = invalid_servers[i]; invalid(&options, SOLARIS_EINVAL);
    }
    server.address = "127.0.0.53"; options.dns_server_count = SOLARIS_NETWORK_MAX_DNS_SERVERS + 1u;
    invalid(&options, SOLARIS_EOVERFLOW);
    options_init(&options); options.dns_server_count = 1u; invalid(&options, SOLARIS_EINVAL);
    options_init(&options); options.system_host_count = 1u; invalid(&options, SOLARIS_EINVAL);
    const char *addresses[16]; for (size_t i = 0; i < 16u; ++i) addresses[i] = "127.0.0.1";
    solaris_network_host_input_t hosts[2] = {{"credential-fixture bad", addresses, 1u}, {"host.example", addresses, 1u}};
    options_init(&options); options.system_hosts = hosts; options.system_host_count = 1u; invalid(&options, SOLARIS_EINVAL);
    hosts[0].name = "*.example"; invalid(&options, SOLARIS_EINVAL);
    hosts[0].name = "HOST.EXAMPLE."; options.system_host_count = 2u; invalid(&options, SOLARIS_EINVAL);
    options.system_host_count = 1u; hosts[0].address_count = 0u; invalid(&options, SOLARIS_EINVAL);
    hosts[0].address_count = 17u; invalid(&options, SOLARIS_EOVERFLOW);
    hosts[0].address_count = 1u; addresses[0] = "fe80::1%7"; invalid(&options, SOLARIS_EINVAL); addresses[0] = "127.0.0.1";
    options.system_host_count = SOLARIS_NETWORK_MAX_SYSTEM_HOSTS + 1u; invalid(&options, SOLARIS_EOVERFLOW);
    size_t count = SOLARIS_NETWORK_MAX_TOTAL_HOST_ADDRESSES / 16u + 1u;
    solaris_network_host_input_t *many = (solaris_network_host_input_t *)calloc(count, sizeof(*many)); CHECK(many != NULL);
    for (size_t i = 0; i < count; ++i) { many[i].name = "host.example"; many[i].addresses = addresses; many[i].address_count = 16u; }
    options.system_hosts = many; options.system_host_count = count; invalid(&options, SOLARIS_EOVERFLOW); free(many);
    options_init(&options); options.memory_limit_bytes = SOLARIS_NETWORK_MAX_MEMORY_LIMIT_BYTES + 1u; invalid(&options, SOLARIS_EOVERFLOW);
    options_init(&options); options.memory_limit_bytes = 1u; invalid(&options, SOLARIS_ENOMEM);
}
static void policy_lifetime(void)
{
    solaris_platform_capabilities_t capabilities; memset(&capabilities, 0xa5, sizeof(capabilities));
    CHECK(solaris_platform_get_capabilities(&capabilities) == SOLARIS_OK);
    CHECK(capabilities.dns_server_limit == 16u && capabilities.system_host_limit == 4096u &&
        capabilities.addresses_per_host_limit == 16u && capabilities.total_host_address_limit == 16384u);
#ifdef _WIN32
    CHECK(capabilities.async_socket_policy_status == SOLARIS_ENOTSUP);
#else
    CHECK(capabilities.async_socket_policy_status == SOLARIS_OK);
#endif
    solaris_network_options_t options; options_init(&options);
    policy_state_t state = {1u, 0u, 0u, 0u, 0u};
    options.socket_policy.context = &state; options.socket_policy.start = policy_start;
    invalid(&options, SOLARIS_EINVAL);
    options.socket_policy.cancel = policy_cancel; invalid(&options, SOLARIS_EINVAL);
    options.socket_policy.retain = retained; invalid(&options, SOLARIS_EINVAL);
    options.socket_policy.release = released;
    solaris_network_snapshot_t *snapshot = NULL; solaris_error_t error;
    if (capabilities.async_socket_policy_status == SOLARIS_ENOTSUP) {
        invalid(&options, SOLARIS_ENOTSUP); CHECK(state.references == 1u && !state.retains && !state.releases);
    } else {
        options.memory_limit_bytes = 1u; invalid(&options, SOLARIS_ENOMEM); CHECK(state.references == 1u && !state.retains);
        options.memory_limit_bytes = 0u;
        CHECK(solaris_network_snapshot_create(&options, &snapshot, &error) == SOLARIS_OK);
        CHECK(state.references == 2u && state.retains == 1u && !state.starts && !state.cancels);
        released(&state); /* Caller reference; snapshot is now the sole owner. */
        solaris_network_snapshot_retain(snapshot); solaris_network_snapshot_release(snapshot);
        CHECK(state.references == 1u && state.retains == 1u && state.releases == 1u);
        solaris_network_snapshot_info_t info; CHECK(solaris_network_snapshot_get_info(snapshot, &info) == SOLARIS_OK && info.socket_policy_configured);
        solaris_network_snapshot_release(snapshot); CHECK(!state.references && state.releases == 2u && !state.starts && !state.cancels);
    }
    options_init(&options); options.socket_policy.start = policy_start; options.socket_policy.cancel = policy_cancel;
    if (capabilities.async_socket_policy_status == SOLARIS_OK) {
        CHECK(solaris_network_snapshot_create(&options, &snapshot, NULL) == SOLARIS_OK); solaris_network_snapshot_release(snapshot);
    } else invalid(&options, SOLARIS_ENOTSUP);
}
#ifdef __cplusplus
static void concurrent_readers(void)
{
    solaris_network_options_t options; options_init(&options);
    solaris_network_server_input_t server = {"127.0.0.53", 53u};
    const char *addresses[] = {"127.0.0.2", "::1"};
    solaris_network_host_input_t host = {"parallel.example", addresses, 2u};
    options.dns_servers = &server; options.dns_server_count = 1u;
    options.system_hosts = &host; options.system_host_count = 1u;
    solaris_network_snapshot_t *snapshot = NULL;
    CHECK(solaris_network_snapshot_create(&options, &snapshot, NULL) == SOLARIS_OK);
    std::thread readers[4];
    for (size_t i = 0; i < 4u; ++i) {
        solaris_network_snapshot_retain(snapshot);
        readers[i] = std::thread([snapshot]() {
            for (unsigned int j = 0; j < 1000u; ++j) {
                solaris_network_snapshot_retain(snapshot);
                solaris_network_snapshot_info_t info; solaris_network_endpoint_info_t endpoint; solaris_network_host_info_t entry;
                CHECK(solaris_network_snapshot_get_info(snapshot, &info) == SOLARIS_OK && info.revision == 11u);
                CHECK(solaris_network_snapshot_get_dns_server(snapshot, 0u, &endpoint) == SOLARIS_OK && endpoint.port == 53u);
                CHECK(solaris_network_snapshot_get_host(snapshot, 0u, &entry) == SOLARIS_OK && !strcmp(entry.name, "parallel.example"));
                CHECK(solaris_network_snapshot_get_host_address(snapshot, 0u, 1u, &endpoint) == SOLARIS_OK && !strcmp(endpoint.address, "::1"));
                solaris_network_snapshot_release(snapshot);
            }
            solaris_network_snapshot_release(snapshot);
        });
    }
    solaris_network_snapshot_release(snapshot); /* Last free may run on a reader. */
    for (size_t i = 0; i < 4u; ++i) readers[i].join();
}
#endif
int main(void)
{
    copied_inputs(); revisions_and_empty(); bounds_and_diagnostics(); policy_lifetime();
#ifdef __cplusplus
    concurrent_readers();
#endif
    solaris_network_snapshot_info_t info; solaris_network_endpoint_info_t endpoint; solaris_network_host_info_t host;
    CHECK(solaris_network_snapshot_get_info(NULL, &info) == SOLARIS_EINVAL);
    CHECK(solaris_network_snapshot_get_dns_server(NULL, 0u, &endpoint) == SOLARIS_EINVAL);
    CHECK(solaris_network_snapshot_get_host(NULL, 0u, &host) == SOLARIS_EINVAL);
    CHECK(solaris_network_snapshot_get_host_address(NULL, 0u, 0u, &endpoint) == SOLARIS_EINVAL);
    CHECK(solaris_network_snapshot_get_info(NULL, NULL) == SOLARIS_EINVAL);
    CHECK(solaris_platform_get_capabilities(NULL) == SOLARIS_EINVAL);
    CHECK(solaris_socket_policy_complete(NULL, SOLARIS_OK) == SOLARIS_EINVAL);
    solaris_network_snapshot_retain(NULL); solaris_network_snapshot_release(NULL); solaris_network_options_init(NULL);
    puts("platform SDK: owned network snapshots, separate revisions, numeric endpoints/system hosts, limits and policy lifetime passed");
    return 0;
}
