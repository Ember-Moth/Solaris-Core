#include "adapters/outbound/shadowsocks/internal.h"
#include "config/outbound/proxy.h"
#include "codec/address/socks.h"
#include "transport/datagram/uot.h"
#include "contracts/io/plugin.h"
#include <openssl/crypto.h>
#include <string.h>

enum { SS_CAPS = SOLARIS_OUTBOUND_STREAM | SOLARIS_OUTBOUND_STREAM_DOMAIN | SOLARIS_OUTBOUND_HALF_CLOSE |
    SOLARIS_OUTBOUND_DATAGRAM | SOLARIS_OUTBOUND_DATAGRAM_DOMAIN | SOLARIS_OUTBOUND_DATAGRAM_MULTI };
typedef struct ss_config {
    solaris_proxy_config_t proxy; solaris_ss_key_t key; int uot;
    char plugin[65], plugin_options[1025];
} ss_config_t;
typedef struct ss_outbound {
    solaris_outbound_t outbound;
    solaris_proxy_transport_t transport;
    solaris_ss_parameters_t parameters;
    solaris_stream_plugin_binding_t plugin;
    int retired, uot;
} ss_outbound_t;
static uint32_t capabilities(void *state)
{
    ss_outbound_t *ss = state;
    if (ss->retired) return 0u;
    return ss->plugin.carrier.open != NULL && !ss->uot ? SS_CAPS &
        ~(SOLARIS_OUTBOUND_DATAGRAM | SOLARIS_OUTBOUND_DATAGRAM_DOMAIN | SOLARIS_OUTBOUND_DATAGRAM_MULTI) : SS_CAPS;
}
static solaris_status_t open_carrier(void *state, solaris_executor_t *owner,
    const solaris_dialer_options_t *options, const solaris_address_t *destination,
    const solaris_stream_callbacks_t *callbacks, void *context, solaris_stream_t **out)
{
    ss_outbound_t *ss = state;
    solaris_ss_parameters_t parameters = ss->parameters; parameters.destination = *destination;
    solaris_stream_factory_t carrier = {.context = &ss->transport, .open = solaris_proxy_transport_open};
    return solaris_filter_open(owner, &carrier, options, &ss->transport.server,
        &solaris_ss_stream_codec, &parameters, callbacks, context, out);
}
static solaris_status_t open_stream(void *state, const solaris_address_t *destination,
    const solaris_stream_callbacks_t *callbacks, void *context, solaris_stream_t **out)
{
    ss_outbound_t *ss = state;
    if (ss->retired) return SOLARIS_ECLOSED;
    uint8_t address[260]; size_t length;
    solaris_status_t rc = solaris_socks_address_write(destination, address, sizeof(address), &length);
    if (rc != SOLARIS_OK) return rc;
    return open_carrier(ss, ss->outbound.owner, &ss->transport.dialer, destination, callbacks, context, out);
}
static solaris_status_t open_datagram(void *state, uint32_t family,
    const solaris_datagram_callbacks_t *callbacks, void *context, solaris_datagram_t **out)
{
    ss_outbound_t *ss = state;
    if (ss->retired) return SOLARIS_ECLOSED;
    if (family != SOLARIS_ADDRESS_IPV4 && family != SOLARIS_ADDRESS_IPV6 && family != SOLARIS_ADDRESS_DOMAIN) return SOLARIS_EINVAL;
    if (ss->plugin.carrier.open != NULL && !ss->uot) return SOLARIS_ENOTSUP;
    if (ss->uot) {
        solaris_stream_factory_t carrier = {.context = ss, .open = open_carrier};
        return solaris_uot_open(ss->outbound.owner, &carrier, &ss->transport.dialer, callbacks, context, out);
    }
    return solaris_ss_udp_open(ss->outbound.owner, &ss->transport.dialer, &ss->transport.server,
        &ss->parameters, callbacks, context, out);
}
static void retire(void *state)
{
    ss_outbound_t *ss = state;
    if (ss->retired) return;
    ss->retired = 1;
    if (ss->plugin.retire != NULL) ss->plugin.retire(ss->plugin.state);
}
static const solaris_outbound_ops_t ops = {capabilities, open_stream, open_datagram, retire};
static solaris_status_t compile(const solaris_config_view_t *view, solaris_budget_t *budget, void **out, solaris_error_t *error)
{
    static const char *const fields[] = {SOLARIS_PROXY_CONFIG_FIELDS, "cipher", "password", "udp-over-tcp", "plugin", "plugin-opts"};
    solaris_status_t rc = solaris_config_check_fields(view, fields, sizeof(fields) / sizeof(fields[0]), error);
    if (rc != SOLARIS_OK) return rc;
    char cipher[64], password[1025];
    rc = solaris_config_string(view, "cipher", 1, cipher, sizeof(cipher), error);
    if (rc != SOLARIS_OK) return rc;
    rc = solaris_config_string(view, "password", 1, password, sizeof(password), error);
    if (rc != SOLARIS_OK) return rc;
    ss_config_t *config = solaris_memory_allocate(budget, sizeof(*config));
    if (config == NULL) { OPENSSL_cleanse(password, sizeof(password)); return SOLARIS_ENOMEM; }
    memset(config, 0, sizeof(*config)); *out = config;
    const solaris_config_view_t *uot = solaris_config_get(view, "udp-over-tcp");
    if (uot != NULL && uot->kind != SOLARIS_CONFIG_BOOL) {
        OPENSSL_cleanse(password, sizeof(password));
        return solaris_config_error(view, "udp-over-tcp", "expected boolean (UoT v2)", error);
    }
    config->uot = uot != NULL && uot->value.boolean;
    rc = solaris_ss_key_parse(cipher, password, &config->key); OPENSSL_cleanse(password, sizeof(password));
    if (rc != SOLARIS_OK) return solaris_config_error(view, rc == SOLARIS_ENOTSUP ? "cipher" : "password",
        rc == SOLARIS_ENOTSUP ? "unsupported Shadowsocks cipher" : "invalid key: 2022 requires exact-length base64 PSKs; identity chains require AES and at most 8 identity keys", error);
    rc = solaris_config_string(view, "plugin", 0, config->plugin, sizeof(config->plugin), error);
    if (rc != SOLARIS_OK) return rc;
    rc = solaris_config_string(view, "plugin-opts", 0, config->plugin_options, sizeof(config->plugin_options), error);
    if (rc != SOLARIS_OK) return rc;
    if (solaris_config_get(view, "plugin-opts") != NULL && config->plugin[0] == '\0')
        return solaris_config_error(view, "plugin-opts", "plugin options require a plugin name", error);
    rc = solaris_proxy_config_compile(view, budget, &config->proxy, error);
    if (rc == SOLARIS_OK && config->proxy.tls != NULL)
        return solaris_config_error(view, "tls", "native Shadowsocks does not use TLS", error);
    return rc;
}
static void free_config(void *state)
{
    ss_config_t *config = state; if (config == NULL) return; solaris_proxy_config_clear(&config->proxy);
    OPENSSL_cleanse(config, sizeof(*config)); solaris_memory_free(config);
}
static solaris_status_t create(const void *compiled, const solaris_module_services_t *services,
    void **state, solaris_outbound_t **out, solaris_error_t *error)
{
    const ss_config_t *config = compiled;
    if (config->plugin[0] != '\0' && (services->stream_plugin == NULL || services->stream_plugin->create == NULL)) return SOLARIS_ENOTSUP;
    if (!config->key.modern && !solaris_replay_is_persistent(services->replay)) return SOLARIS_EINVAL;
    ss_outbound_t *ss = solaris_memory_allocate(solaris_executor_budget(services->owner), sizeof(*ss));
    if (ss == NULL) return SOLARIS_ENOMEM;
    memset(ss, 0, sizeof(*ss)); *state = ss;
    solaris_status_t rc = solaris_proxy_transport_init(&config->proxy, services, &ss->transport);
    if (rc != SOLARIS_OK) return rc;
    if (config->plugin[0] != '\0') {
        solaris_stream_plugin_request_t request = {
            .name = config->plugin, .options = config->plugin_options, .owner = services->owner,
            .scope = services->scope, .server = ss->transport.server, .upstream = ss->transport.carrier
        };
        rc = services->stream_plugin->create(services->stream_plugin->context, &request, &ss->plugin, error);
        if (rc != SOLARIS_OK) return rc;
        if (ss->plugin.carrier.open == NULL || ss->plugin.retire == NULL || ss->plugin.destroy == NULL) return SOLARIS_EINVAL;
        ss->transport.carrier = ss->plugin.carrier;
    }
    ss->parameters.key = config->key; ss->parameters.replay = services->replay; ss->parameters.source = services->crypto;
    ss->uot = config->uot;
    solaris_replay_retain(ss->parameters.replay);
    ss->outbound = (solaris_outbound_t){&ops, ss, services->owner}; *out = &ss->outbound; return SOLARIS_OK;
}
static void destroy(void *state)
{
    ss_outbound_t *ss = state; solaris_proxy_transport_clear(&ss->transport); solaris_replay_release(ss->parameters.replay);
    if (ss->plugin.destroy != NULL) ss->plugin.destroy(ss->plugin.state);
    OPENSSL_cleanse(&ss->parameters.key, sizeof(ss->parameters.key)); solaris_memory_free(ss);
}
static const char *const aliases[] = {"ss"};
const solaris_outbound_module_t solaris_shadowsocks_module = {
    "shadowsocks", aliases, 1u, NULL, 0u, SS_CAPS, compile, free_config, create, retire, destroy
};
