#include "config/outbound/proxy.h"
#include <string.h>

solaris_status_t solaris_proxy_config_compile(const solaris_config_view_t *view,
    solaris_budget_t *budget, solaris_proxy_config_t *config, solaris_error_t *error)
{
    memset(config, 0, sizeof(*config));
    char server[256]; uint64_t port;
    solaris_status_t rc = solaris_config_string(view, "server", 1, server, sizeof(server), error);
    if (rc != SOLARIS_OK) return rc;
    if (solaris_config_get(view, "port") == NULL) return solaris_config_error(view, "port", "required", error);
    rc = solaris_config_uint(view, "port", 443u, 1u, 65535u, &port, error);
    if (rc != SOLARIS_OK) return rc;
    rc = solaris_address_parse(server, (uint16_t)port, &config->server);
    if (rc != SOLARIS_OK) return solaris_config_error(view, "server", "invalid address", error);
    rc = solaris_dialer_config_compile(view, &config->dialer, error);
    if (rc != SOLARIS_OK) return rc;
    const solaris_config_view_t *tls = solaris_config_get(view, "tls");
    if (tls != NULL && tls->kind != SOLARIS_CONFIG_BOOL) return solaris_config_error(view, "tls", "expected boolean", error);
    int enabled = tls != NULL && tls->value.boolean;
    const solaris_config_view_t *pem = solaris_config_get(view, "ca-pem");
    if (!enabled) {
        if (pem != NULL || solaris_config_get(view, "servername") != NULL)
            return solaris_config_error(view, "tls", "TLS settings require tls: true", error);
        return SOLARIS_OK;
    }
    if (pem == NULL || pem->kind != SOLARIS_CONFIG_STRING || pem->value.string.data == NULL)
        return solaris_config_error(view, "ca-pem", "explicit PEM trust anchors required", error);
    rc = solaris_config_string(view, "servername", 0, config->identity, sizeof(config->identity), error);
    if (rc != SOLARIS_OK) return rc;
    if (config->identity[0] == '\0') memcpy(config->identity, server, strlen(server) + 1u);
    solaris_address_t identity;
    if (strlen(config->identity) > 253u || solaris_address_parse(config->identity, 443u, &identity) != SOLARIS_OK)
        return solaris_config_error(view, "servername", "invalid certificate identity", error);
    rc = solaris_tls_context_create(budget, pem->value.string.data, pem->value.string.length, &config->tls);
    if (rc == SOLARIS_EINVAL) return solaris_config_error(view, "ca-pem", "invalid or oversized trust bundle", error);
    return rc;
}
void solaris_proxy_config_clear(solaris_proxy_config_t *config)
{ solaris_tls_context_release(config->tls); config->tls = NULL; }
solaris_status_t solaris_proxy_transport_init(const solaris_proxy_config_t *config,
    const solaris_module_services_t *services, solaris_proxy_transport_t *transport)
{
    memset(transport, 0, sizeof(*transport));
    solaris_status_t rc = solaris_dialer_config_apply(&config->dialer, &services->dialer, &transport->dialer);
    if (rc != SOLARIS_OK) return rc;
    transport->server = config->server; transport->carrier = services->carrier;
    memcpy(transport->identity, config->identity, sizeof(transport->identity));
    transport->tls = config->tls;
    transport->tls_minimum_version = config->tls_minimum_version == 0u ? SOLARIS_TLS_1_2 : config->tls_minimum_version;
    if (transport->tls != NULL) solaris_tls_context_retain(transport->tls);
    return SOLARIS_OK;
}
void solaris_proxy_transport_clear(solaris_proxy_transport_t *transport)
{ solaris_tls_context_release(transport->tls); transport->tls = NULL; }
solaris_status_t solaris_proxy_transport_open(void *context, solaris_executor_t *owner,
    const solaris_dialer_options_t *options, const solaris_address_t *peer,
    const solaris_stream_callbacks_t *callbacks, void *callback_context, solaris_stream_t **out)
{
    solaris_proxy_transport_t *transport = context;
    if (transport->tls != NULL)
        return solaris_tls_open(owner, transport->tls, transport->identity, transport->tls_minimum_version, &transport->carrier,
            options, peer, callbacks, callback_context, out);
    return solaris_carrier_open(&transport->carrier, owner, options, peer, callbacks, callback_context, out);
}
