#include "adapters/outbound/anytls/internal.h"
#include "config/outbound/proxy.h"
#include "codec/address/socks.h"
#include "transport/datagram/uot.h"
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <string.h>

enum { ANYTLS_CAPS = SOLARIS_OUTBOUND_STREAM | SOLARIS_OUTBOUND_STREAM_DOMAIN |
    SOLARIS_OUTBOUND_DATAGRAM | SOLARIS_OUTBOUND_DATAGRAM_DOMAIN | SOLARIS_OUTBOUND_DATAGRAM_MULTI };
typedef struct anytls_config {
    solaris_proxy_config_t proxy;
    uint8_t password_hash[32];
    uint64_t idle_ms, idle_check_ms, min_idle, sessions;
} anytls_config_t;
typedef struct anytls_outbound {
    solaris_outbound_t outbound;
    solaris_scope_t *scope;
    solaris_proxy_transport_t transport;
    solaris_anytls_parameters_t parameters;
    solaris_session_pool_t *pool;
    int retired;
} anytls_outbound_t;
static uint32_t capabilities(void *state) { return ((anytls_outbound_t *)state)->retired ? 0u : ANYTLS_CAPS; }
static solaris_status_t open_carrier(void *state, solaris_executor_t *owner,
    const solaris_dialer_options_t *options, const solaris_address_t *peer,
    const solaris_stream_callbacks_t *callbacks, void *context, solaris_stream_t **out)
{
    (void)owner; anytls_outbound_t *a = state;
    return solaris_session_pool_open(a->pool, options, peer, callbacks, context, out);
}
static solaris_status_t open_stream(void *state, const solaris_address_t *peer,
    const solaris_stream_callbacks_t *callbacks, void *context, solaris_stream_t **out)
{
    anytls_outbound_t *a = state;
    if (a->retired) return SOLARIS_ECLOSED;
    uint8_t wire[260]; size_t size;
    solaris_status_t rc = solaris_socks_address_write(peer, wire, sizeof(wire), &size);
    if (rc != SOLARIS_OK) return rc;
    return solaris_session_pool_open(a->pool, NULL, peer, callbacks, context, out);
}
static solaris_status_t open_datagram(void *state, uint32_t family,
    const solaris_datagram_callbacks_t *callbacks, void *context, solaris_datagram_t **out)
{
    anytls_outbound_t *a = state;
    if (a->retired) return SOLARIS_ECLOSED;
    if (family != SOLARIS_ADDRESS_IPV4 && family != SOLARIS_ADDRESS_IPV6 && family != SOLARIS_ADDRESS_DOMAIN) return SOLARIS_EINVAL;
    solaris_stream_factory_t factory = {.context = a, .open = open_carrier};
    return solaris_uot_open(a->outbound.owner, &factory, &a->transport.dialer, callbacks, context, out);
}
static void retire(void *state)
{
    anytls_outbound_t *a = state; a->retired = 1;
    if (a->pool != NULL) solaris_session_pool_retire(a->pool);
}
static const solaris_outbound_ops_t operations = {capabilities, open_stream, open_datagram, retire};
static solaris_status_t compile(const solaris_config_view_t *view, solaris_budget_t *budget, void **out, solaris_error_t *error)
{
    static const char *const fields[] = {SOLARIS_PROXY_CONFIG_FIELDS, "password", "idle-session-timeout-ms", "idle-session-check-interval-ms", "min-idle-session", "session-limit"};
    solaris_status_t rc = solaris_config_check_fields(view, fields, sizeof(fields) / sizeof(fields[0]), error);
    if (rc != SOLARIS_OK) return rc;
    char password[1025]; rc = solaris_config_string(view, "password", 1, password, sizeof(password), error);
    if (rc != SOLARIS_OK) return rc;
    anytls_config_t *config = solaris_memory_allocate(budget, sizeof(*config));
    if (config == NULL) { OPENSSL_cleanse(password, sizeof(password)); return SOLARIS_ENOMEM; }
    memset(config, 0, sizeof(*config)); *out = config;
    SHA256((const uint8_t *)password, strlen(password), config->password_hash); OPENSSL_cleanse(password, sizeof(password));
    rc = solaris_config_uint(view, "idle-session-timeout-ms", 60000u, 1u, 3600000u, &config->idle_ms, error);
    if (rc == SOLARIS_OK) rc = solaris_config_uint(view, "idle-session-check-interval-ms", 30000u, 1u, 3600000u, &config->idle_check_ms, error);
    if (rc == SOLARIS_OK) rc = solaris_config_uint(view, "session-limit", 64u, 1u, 1024u, &config->sessions, error);
    if (rc == SOLARIS_OK) rc = solaris_config_uint(view, "min-idle-session", 0u, 0u, config->sessions, &config->min_idle, error);
    if (rc == SOLARIS_OK) rc = solaris_proxy_config_compile(view, budget, &config->proxy, error);
    if (rc == SOLARIS_OK && config->proxy.tls == NULL) return solaris_config_error(view, "tls", "AnyTLS requires TLS with CA and identity validation", error);
    return rc;
}
static void free_config(void *state)
{
    anytls_config_t *config = state; if (config == NULL) return;
    solaris_proxy_config_clear(&config->proxy); OPENSSL_cleanse(config->password_hash, sizeof(config->password_hash)); solaris_memory_free(config);
}
static void pool_closed(void *context)
{ anytls_outbound_t *a = context; a->pool = NULL; solaris_scope_release(a->scope); }
static solaris_status_t create(const void *compiled, const solaris_module_services_t *services,
    void **state, solaris_outbound_t **out, solaris_error_t *error)
{
    (void)error; const anytls_config_t *config = compiled;
    anytls_outbound_t *a = solaris_memory_allocate(solaris_executor_budget(services->owner), sizeof(*a));
    if (a == NULL) return SOLARIS_ENOMEM;
    memset(a, 0, sizeof(*a)); *state = a; a->scope = services->scope;
    solaris_status_t rc = solaris_proxy_transport_init(&config->proxy, services, &a->transport); if (rc != SOLARIS_OK) return rc;
    memcpy(a->parameters.password_hash, config->password_hash, 32u); a->parameters.crypto = services->crypto; a->parameters.diagnostic = services->diagnostic;
    rc = solaris_anytls_policy_default(&a->parameters.policy); if (rc != SOLARIS_OK) return rc;
    solaris_session_pool_options_t options = {
        .carrier = {.context = &a->transport, .open = solaris_proxy_transport_open}, .peer = a->transport.server,
        .dialer = a->transport.dialer, .codec = &solaris_anytls_session_codec, .parameters = &a->parameters,
        .session_limit = (size_t)config->sessions, .streams_per_session = 1u, .idle_timeout_ms = config->idle_ms,
        .idle_check_interval_ms = config->idle_check_ms, .min_idle_sessions = (size_t)config->min_idle,
        .ack_timeout_fails_session = 1,
        .on_close = pool_closed, .context = a
    };
    rc = solaris_session_pool_create(services->owner, &options, &a->pool); if (rc != SOLARIS_OK) return rc;
    solaris_scope_retain(a->scope);
    a->outbound = (solaris_outbound_t){&operations, a, services->owner}; *out = &a->outbound; return SOLARIS_OK;
}
static void destroy(void *state)
{
    anytls_outbound_t *a = state; solaris_proxy_transport_clear(&a->transport);
    OPENSSL_cleanse(a->parameters.password_hash, sizeof(a->parameters.password_hash)); solaris_memory_free(a);
}
const solaris_outbound_module_t solaris_anytls_module = {"anytls", NULL, 0u, NULL, 0u, ANYTLS_CAPS, compile, free_config, create, retire, destroy};
