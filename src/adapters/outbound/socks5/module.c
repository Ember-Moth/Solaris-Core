#include "adapters/outbound/socks5/internal.h"
#include "config/outbound/dialer.h"
#include "contracts/module/module.h"
#include <string.h>

enum { SOCKS5_CAPABILITIES = SOLARIS_OUTBOUND_STREAM | SOLARIS_OUTBOUND_STREAM_DOMAIN | SOLARIS_OUTBOUND_HALF_CLOSE |
    SOLARIS_OUTBOUND_DATAGRAM | SOLARIS_OUTBOUND_DATAGRAM_MULTI | SOLARIS_OUTBOUND_DATAGRAM_DOMAIN };
typedef struct socks5_config {
    solaris_address_t server;
    solaris_dialer_config_t dialer;
    solaris_socks5_credentials_t credentials;
} socks5_config_t;
typedef struct socks5_outbound {
    solaris_outbound_t outbound;
    solaris_address_t server;
    solaris_dialer_options_t dialer;
    solaris_stream_factory_t carrier;
    solaris_socks5_credentials_t credentials;
    int retired;
} socks5_outbound_t;
static uint32_t capabilities(void *state) { return ((socks5_outbound_t *)state)->retired ? 0u : SOCKS5_CAPABILITIES; }
static solaris_status_t open_stream(void *state, const solaris_address_t *target,
    const solaris_stream_callbacks_t *callbacks, void *context, solaris_stream_t **out)
{
    socks5_outbound_t *node = state; if (node->retired) return SOLARIS_ECLOSED;
    return solaris_socks5_stream_open(node->outbound.owner, &node->carrier, &node->dialer, &node->server,
        &node->credentials, 1u, target, NULL, callbacks, context, out);
}
static solaris_status_t open_datagram(void *state, uint32_t family,
    const solaris_datagram_callbacks_t *callbacks, void *context, solaris_datagram_t **out)
{
    socks5_outbound_t *node = state; if (node->retired) return SOLARIS_ECLOSED;
    if (family != SOLARIS_ADDRESS_IPV4 && family != SOLARIS_ADDRESS_IPV6 && family != SOLARIS_ADDRESS_DOMAIN) return SOLARIS_EINVAL;
    return solaris_socks5_udp_open(node->outbound.owner, &node->carrier, &node->dialer, &node->server,
        &node->credentials, callbacks, context, out);
}
static void retire(void *state) { ((socks5_outbound_t *)state)->retired = 1; }
static const solaris_outbound_ops_t operations = {capabilities, open_stream, open_datagram, retire};
static solaris_status_t compile(const solaris_config_view_t *view, solaris_budget_t *budget, void **out, solaris_error_t *error)
{
    static const char *const fields[] = {"server", "port", "username", "password", SOLARIS_DIALER_CONFIG_FIELDS};
    solaris_status_t rc = solaris_config_check_fields(view, fields, sizeof(fields) / sizeof(fields[0]), error);
    if (rc != SOLARIS_OK) return rc;
    socks5_config_t *config = solaris_memory_allocate(budget, sizeof(*config)); if (config == NULL) return SOLARIS_ENOMEM;
    memset(config, 0, sizeof(*config)); *out = config;
    char server[256]; uint64_t port;
    rc = solaris_config_string(view, "server", 1, server, sizeof(server), error); if (rc != SOLARIS_OK) return rc;
    if (solaris_config_get(view, "port") == NULL) return solaris_config_error(view, "port", "required field is missing", error);
    rc = solaris_config_uint(view, "port", 1080u, 1u, 65535u, &port, error); if (rc != SOLARIS_OK) return rc;
    if (solaris_address_parse(server, (uint16_t)port, &config->server) != SOLARIS_OK) return solaris_config_error(view, "server", "invalid address", error);
    rc = solaris_config_string(view, "username", 0, (char *)config->credentials.username, sizeof(config->credentials.username), error);
    if (rc != SOLARIS_OK) return rc;
    rc = solaris_config_string(view, "password", 0, (char *)config->credentials.password, sizeof(config->credentials.password), error);
    if (rc != SOLARIS_OK) return rc;
    config->credentials.username_length = (uint8_t)strlen((const char *)config->credentials.username);
    config->credentials.password_length = (uint8_t)strlen((const char *)config->credentials.password);
    if ((config->credentials.username_length == 0u) != (config->credentials.password_length == 0u))
        return solaris_config_error(view, config->credentials.username_length == 0u ? "username" : "password", "username and password must both be provided", error);
    return solaris_dialer_config_compile(view, &config->dialer, error);
}
static void free_config(void *state)
{ if (state != NULL) { solaris_socks5_clear(state, sizeof(socks5_config_t)); solaris_memory_free(state); } }
static solaris_status_t create(const void *compiled, const solaris_module_services_t *services,
    void **state, solaris_outbound_t **out, solaris_error_t *error)
{
    (void)error; const socks5_config_t *config = compiled;
    socks5_outbound_t *node = solaris_memory_allocate(solaris_executor_budget(services->owner), sizeof(*node)); if (node == NULL) return SOLARIS_ENOMEM;
    memset(node, 0, sizeof(*node)); *state = node;
    solaris_status_t rc = solaris_dialer_config_apply(&config->dialer, &services->dialer, &node->dialer); if (rc != SOLARIS_OK) return rc;
    node->dialer.lookup_view.role = SOLARIS_DNS_PROXY_SERVER;
    node->server = config->server; node->credentials = config->credentials; node->carrier = services->carrier;
    node->outbound = (solaris_outbound_t){&operations, node, services->owner}; *out = &node->outbound; return SOLARIS_OK;
}
static void destroy(void *state) { solaris_socks5_clear(state, sizeof(socks5_outbound_t)); solaris_memory_free(state); }
const solaris_outbound_module_t solaris_socks5_module = {
    "socks5", NULL, 0u, NULL, 0u, SOCKS5_CAPABILITIES, compile, free_config, create, retire, destroy
};
