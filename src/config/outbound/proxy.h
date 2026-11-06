#ifndef SOLARIS_PROXY_CONFIG_H
#define SOLARIS_PROXY_CONFIG_H

#include "config/outbound/dialer.h"
#include "contracts/module/module.h"
#include "transport/tls/tls.h"

#define SOLARIS_PROXY_CONFIG_FIELDS "server", "port", "tls", "servername", "ca-pem", SOLARIS_DIALER_CONFIG_FIELDS
typedef struct solaris_proxy_config {
    solaris_address_t server;
    solaris_dialer_config_t dialer;
    solaris_tls_context_t *tls;
    uint16_t tls_minimum_version;
    char identity[256];
} solaris_proxy_config_t;

typedef struct solaris_proxy_transport {
    solaris_address_t server;
    solaris_dialer_options_t dialer;
    solaris_stream_factory_t carrier;
    solaris_tls_context_t *tls;
    uint16_t tls_minimum_version;
    char identity[256];
} solaris_proxy_transport_t;

solaris_status_t solaris_proxy_config_compile(const solaris_config_view_t *view,
    solaris_budget_t *budget, solaris_proxy_config_t *config, solaris_error_t *error);
void solaris_proxy_config_clear(solaris_proxy_config_t *config);
solaris_status_t solaris_proxy_transport_init(const solaris_proxy_config_t *config,
    const solaris_module_services_t *services, solaris_proxy_transport_t *transport);
void solaris_proxy_transport_clear(solaris_proxy_transport_t *transport);
solaris_status_t solaris_proxy_transport_open(void *context, solaris_executor_t *owner,
    const solaris_dialer_options_t *options, const solaris_address_t *peer,
    const solaris_stream_callbacks_t *callbacks, void *callback_context, solaris_stream_t **out);

#endif
