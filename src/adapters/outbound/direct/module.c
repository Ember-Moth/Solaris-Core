#include "adapters/outbound/direct/internal.h"
#include "contracts/module/module.h"
#include "config/outbound/dialer.h"
#include <string.h>

static uint32_t capabilities(void *state)
{
    return ((solaris_direct_outbound_t *)state)->retired ? 0u :
        SOLARIS_OUTBOUND_STREAM | SOLARIS_OUTBOUND_DATAGRAM | SOLARIS_OUTBOUND_STREAM_DOMAIN |
        SOLARIS_OUTBOUND_DATAGRAM_MULTI | SOLARIS_OUTBOUND_HALF_CLOSE | SOLARIS_OUTBOUND_LOCAL_RESOLUTION;
}

static solaris_status_t stream(void *state, const solaris_address_t *destination,
                                const solaris_stream_callbacks_t *callbacks, void *context,
                                solaris_stream_t **out)
{
    solaris_direct_outbound_t *direct = state;
    if (direct->retired) return SOLARIS_ECLOSED;
    return solaris_dialer_open_stream(direct->outbound.owner, &direct->options, destination, callbacks, context, out);
}

static solaris_status_t datagram(void *state, uint32_t family,
                                  const solaris_datagram_callbacks_t *callbacks,
                                  void *context, solaris_datagram_t **out)
{
    solaris_direct_outbound_t *direct = state;
    if (direct->retired) return SOLARIS_ECLOSED;
    return solaris_dialer_open_datagram(direct->outbound.owner, &direct->options, family, callbacks, context, out);
}

static void retire(void *state) { ((solaris_direct_outbound_t *)state)->retired = 1; }
static const solaris_outbound_ops_t operations = {capabilities, stream, datagram, retire};

solaris_status_t solaris_direct_outbound_init(solaris_direct_outbound_t *direct,
                                              solaris_executor_t *executor,
                                              const solaris_dialer_options_t *options)
{
    if (direct == NULL || executor == NULL) return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(executor)) return SOLARIS_ETHREAD;
    memset(direct, 0, sizeof(*direct));
    solaris_status_t rc = solaris_dialer_options_normalize(options, &direct->options);
    if (rc != SOLARIS_OK) return rc;
    direct->outbound.ops = &operations; direct->outbound.state = direct; direct->outbound.owner = executor;
    return SOLARIS_OK;
}

static solaris_status_t compile_config(const solaris_config_view_t *view, solaris_budget_t *budget,
                                        void **out, solaris_error_t *error)
{
    static const char *const fields[] = {SOLARIS_DIALER_CONFIG_FIELDS};
    solaris_status_t rc = solaris_config_check_fields(view, fields, sizeof(fields) / sizeof(fields[0]), error);
    if (rc != SOLARIS_OK) return rc;
    solaris_dialer_config_t compiled;
    rc = solaris_dialer_config_compile(view, &compiled, error);
    if (rc != SOLARIS_OK) return rc;
    solaris_dialer_config_t *config = solaris_memory_allocate(budget, sizeof(*config));
    if (config == NULL) return SOLARIS_ENOMEM;
    *config = compiled; *out = config;
    return SOLARIS_OK;
}
static solaris_status_t create_instance(const void *config, const solaris_module_services_t *services,
                                         void **state, solaris_outbound_t **out, solaris_error_t *error)
{
    (void)error;
    solaris_dialer_options_t options;
    solaris_status_t rc = solaris_dialer_config_apply(config, &services->dialer, &options);
    if (rc != SOLARIS_OK) return rc;
    solaris_direct_outbound_t *direct = solaris_memory_allocate(solaris_executor_budget(services->owner), sizeof(*direct));
    if (direct == NULL) return SOLARIS_ENOMEM;
    rc = solaris_direct_outbound_init(direct, services->owner, &options);
    if (rc != SOLARIS_OK) { solaris_memory_free(direct); return rc; }
    *state = direct; *out = &direct->outbound;
    return SOLARIS_OK;
}
const solaris_outbound_module_t solaris_direct_module = {
    .name = "direct",
    .capabilities = SOLARIS_OUTBOUND_STREAM | SOLARIS_OUTBOUND_DATAGRAM | SOLARIS_OUTBOUND_STREAM_DOMAIN |
                    SOLARIS_OUTBOUND_DATAGRAM_MULTI | SOLARIS_OUTBOUND_HALF_CLOSE | SOLARIS_OUTBOUND_LOCAL_RESOLUTION,
    .compile = compile_config, .free_config = solaris_memory_free,
    .create = create_instance, .retire = retire, .destroy = solaris_memory_free
};
