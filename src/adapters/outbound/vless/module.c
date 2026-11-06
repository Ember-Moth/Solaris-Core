#include "contracts/module/module.h"
#include "config/outbound/proxy.h"
#include "adapters/outbound/vless/internal.h"
#include "adapters/outbound/vless/encryption/client.h"
#include "adapters/outbound/vless/vision/codec.h"
#include "adapters/outbound/vless/datagram.h"
#include <string.h>

enum { VLESS_CAPS = SOLARIS_OUTBOUND_STREAM | SOLARIS_OUTBOUND_STREAM_DOMAIN | SOLARIS_OUTBOUND_HALF_CLOSE |
    SOLARIS_OUTBOUND_DATAGRAM | SOLARIS_OUTBOUND_DATAGRAM_MULTI | SOLARIS_OUTBOUND_DATAGRAM_DOMAIN };
typedef struct vless_config {
    solaris_proxy_config_t proxy;
    solaris_vless_encryption_config_t encryption;
    uint8_t uuid[16];
    int vision, allow_udp443;
} vless_config_t;
typedef struct vless_outbound {
    solaris_outbound_t outbound;
    solaris_proxy_transport_t transport;
    solaris_vless_encryption_client_t *encryption;
    uint8_t uuid[16];
    solaris_crypto_source_t crypto;
    int vision, allow_udp443;
    int retired;
} vless_outbound_t;
static int nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static int parse_uuid(const char *text, uint8_t out[16])
{
    size_t length = strlen(text), pos = 0u;
    if (length != 32u && length != 36u) return 0;
    for (size_t i = 0u; i < 16u; ++i) {
        if (length == 36u && (i == 4u || i == 6u || i == 8u || i == 10u)) {
            if (text[pos++] != '-') return 0;
        }
        int a = nibble(text[pos++]), b = nibble(text[pos++]);
        if (a < 0 || b < 0) return 0;
        out[i] = (uint8_t)((a << 4) | b);
    }
    return pos == length;
}
static uint32_t capabilities(void *state) { return ((vless_outbound_t *)state)->retired ? 0u : VLESS_CAPS; }
static solaris_status_t open_carrier(void *context, solaris_executor_t *owner,
    const solaris_dialer_options_t *options, const solaris_address_t *peer,
    const solaris_stream_callbacks_t *callbacks, void *callback_context, solaris_stream_t **out)
{
    vless_outbound_t *vless = context;
    if (vless->encryption == NULL)
        return solaris_proxy_transport_open(&vless->transport, owner, options, peer, callbacks, callback_context, out);
    solaris_stream_factory_t factory = {.context = &vless->transport, .open = solaris_proxy_transport_open};
    return solaris_filter_open(owner, &factory, options, peer, &solaris_vless_encryption_codec,
        vless->encryption, callbacks, callback_context, out);
}
static solaris_status_t open_stream(void *state, const solaris_address_t *destination,
    const solaris_stream_callbacks_t *callbacks, void *context, solaris_stream_t **out)
{
    vless_outbound_t *vless = state;
    if (vless->retired) return SOLARIS_ECLOSED;
    if (destination->port == 0u || destination->scope_id != 0u ||
        (destination->family != SOLARIS_ADDRESS_IPV4 && destination->family != SOLARIS_ADDRESS_IPV6 &&
         destination->family != SOLARIS_ADDRESS_DOMAIN)) return SOLARIS_EINVAL;
    if (destination->family == SOLARIS_ADDRESS_DOMAIN &&
        (memchr(destination->host, '\0', sizeof(destination->host)) == NULL || destination->host[0] == '\0')) return SOLARIS_EINVAL;
    solaris_vless_parameters_t parameters = {.destination = *destination, .command = 1u}; memcpy(parameters.uuid, vless->uuid, 16u);
    solaris_stream_factory_t factory = {.context = vless, .open = open_carrier};
    if (vless->vision) {
        parameters.vision = 1u;
        solaris_vless_vision_parameters_t vision = {.request = parameters, .crypto = vless->crypto};
        return solaris_filter_open(vless->outbound.owner, &factory, &vless->transport.dialer, &vless->transport.server,
            &solaris_vless_vision_codec, &vision, callbacks, context, out);
    }
    return solaris_filter_open(vless->outbound.owner, &factory, &vless->transport.dialer, &vless->transport.server,
        &solaris_vless_stream_codec, &parameters, callbacks, context, out);
}
static solaris_status_t open_mux(void *context, solaris_executor_t *owner,
    const solaris_dialer_options_t *options, const solaris_address_t *peer,
    const solaris_stream_callbacks_t *callbacks, void *callback_context, solaris_stream_t **out)
{
    (void)peer; vless_outbound_t *vless = context;
    solaris_vless_parameters_t parameters = {.command = 3u}; memcpy(parameters.uuid, vless->uuid, 16u);
    solaris_stream_factory_t factory = {.context = vless, .open = open_carrier};
    if (vless->vision) {
        parameters.vision = 1u;
        solaris_vless_vision_parameters_t vision = {.request = parameters, .crypto = vless->crypto};
        return solaris_filter_open(owner, &factory, options, &vless->transport.server,
            &solaris_vless_vision_codec, &vision, callbacks, callback_context, out);
    }
    return solaris_filter_open(owner, &factory, options, &vless->transport.server,
        &solaris_vless_stream_codec, &parameters, callbacks, callback_context, out);
}
static solaris_status_t open_datagram(void *state, uint32_t family,
    const solaris_datagram_callbacks_t *callbacks, void *context, solaris_datagram_t **out)
{
    vless_outbound_t *vless = state;
    if (vless->retired) return SOLARIS_ECLOSED;
    if (family != SOLARIS_ADDRESS_IPV4 && family != SOLARIS_ADDRESS_IPV6 && family != SOLARIS_ADDRESS_DOMAIN)
        return SOLARIS_EINVAL;
    solaris_stream_factory_t factory = {.context = vless, .open = open_mux};
    int reject_udp443 = vless->vision && !vless->allow_udp443;
    return solaris_datagram_stream_open(vless->outbound.owner, &factory, &vless->transport.dialer,
        &vless->transport.server, &solaris_vless_xudp_codec, &reject_udp443, callbacks, context, out);
}
static void retire(void *state) { ((vless_outbound_t *)state)->retired = 1; }
static const solaris_outbound_ops_t outbound_ops = {capabilities, open_stream, open_datagram, retire};
static solaris_status_t compile(const solaris_config_view_t *view, solaris_budget_t *budget, void **out, solaris_error_t *error)
{
    static const char *const fields[] = {SOLARIS_PROXY_CONFIG_FIELDS, "uuid", "encryption", "flow"};
    solaris_status_t rc = solaris_config_check_fields(view, fields, sizeof(fields) / sizeof(fields[0]), error);
    if (rc != SOLARIS_OK) return rc;
    char uuid[37];
    rc = solaris_config_string(view, "uuid", 1, uuid, sizeof(uuid), error);
    if (rc != SOLARIS_OK) return rc;
    vless_config_t *config = solaris_memory_allocate(budget, sizeof(*config));
    if (config == NULL) return SOLARIS_ENOMEM;
    memset(config, 0, sizeof(*config)); *out = config;
    if (!parse_uuid(uuid, config->uuid)) return solaris_config_error(view, "uuid", "expected hexadecimal UUID", error);
    if (solaris_config_get(view, "encryption") != NULL) {
        char encryption[SOLARIS_VLESS_ENCRYPTION_TEXT];
        rc = solaris_config_string(view, "encryption", 1, encryption, sizeof(encryption), error);
        if (rc != SOLARIS_OK) return rc;
        rc = solaris_vless_encryption_config_parse(encryption, &config->encryption);
        if (rc != SOLARIS_OK) return solaris_config_error(view, "encryption", "invalid or unsupported VLESS encryption parameters", error);
    }
    char flow[32] = {0}; const solaris_config_view_t *flow_value = solaris_config_get(view, "flow");
    if (flow_value == NULL || flow_value->kind != SOLARIS_CONFIG_STRING || flow_value->value.string.data == NULL ||
        flow_value->value.string.length != 0u) rc = solaris_config_string(view, "flow", 0, flow, sizeof(flow), error);
    if (rc != SOLARIS_OK) return rc;
    if (flow[0] != '\0') {
        config->vision = 1;
        if (strcmp(flow, "xtls-rprx-vision-udp443") == 0) config->allow_udp443 = 1;
        else if (strcmp(flow, "xtls-rprx-vision") != 0) return solaris_config_error(view, "flow", "unsupported VLESS flow", error);
    }
    rc = solaris_proxy_config_compile(view, budget, &config->proxy, error);
    if (rc != SOLARIS_OK) return rc;
    if (config->vision && config->encryption.key_count == 0u) {
        if (config->proxy.tls == NULL) return solaris_config_error(view, "flow", "Vision requires TLS or VLESS encryption", error);
        config->proxy.tls_minimum_version = SOLARIS_TLS_1_3;
    }
    return SOLARIS_OK;
}
static void free_config(void *state)
{ vless_config_t *config = state; if (config == NULL) return; solaris_proxy_config_clear(&config->proxy); solaris_memory_free(config); }
static uint64_t now_ns(void *context) { return solaris_executor_now_ns(context); }
static solaris_status_t create(const void *compiled, const solaris_module_services_t *services,
    void **state, solaris_outbound_t **out, solaris_error_t *error)
{
    (void)error;
    const vless_config_t *config = compiled;
    vless_outbound_t *vless = solaris_memory_allocate(solaris_executor_budget(services->owner), sizeof(*vless));
    if (vless == NULL) return SOLARIS_ENOMEM;
    memset(vless, 0, sizeof(*vless)); *state = vless;
    solaris_status_t rc = solaris_proxy_transport_init(&config->proxy, services, &vless->transport);
    if (rc != SOLARIS_OK) return rc;
    if (config->encryption.key_count != 0u) {
        rc = solaris_vless_encryption_client_create(&config->encryption, solaris_executor_budget(services->owner),
            &services->crypto, services->owner, now_ns, &vless->encryption);
        if (rc != SOLARIS_OK) return rc;
    }
    memcpy(vless->uuid, config->uuid, 16u);
    vless->vision = config->vision; vless->allow_udp443 = config->allow_udp443; vless->crypto = services->crypto;
    vless->outbound = (solaris_outbound_t){&outbound_ops, vless, services->owner};
    *out = &vless->outbound; return SOLARIS_OK;
}
static void destroy(void *state)
{
    vless_outbound_t *vless = state; solaris_proxy_transport_clear(&vless->transport);
    solaris_vless_encryption_client_release(vless->encryption); solaris_memory_free(vless);
}
const solaris_outbound_module_t solaris_vless_module = {
    "vless", NULL, 0u, NULL, 0u, VLESS_CAPS, compile, free_config, create, retire, destroy
};
