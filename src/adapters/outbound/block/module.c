#include "adapters/outbound/block/internal.h"
#include "contracts/module/module.h"
#include "runtime/executor/executor.h"
#include <string.h>

static uint32_t capabilities(void *state)
{
    return ((solaris_block_outbound_t *)state)->retired ? 0u :
        SOLARIS_OUTBOUND_STREAM | SOLARIS_OUTBOUND_DATAGRAM |
        SOLARIS_OUTBOUND_STREAM_DOMAIN | SOLARIS_OUTBOUND_DATAGRAM_DOMAIN;
}

static solaris_status_t stream(void *state, const solaris_address_t *destination,
                                const solaris_stream_callbacks_t *callbacks, void *context,
                                solaris_stream_t **out)
{
    (void)destination; (void)callbacks; (void)context; (void)out;
    return ((solaris_block_outbound_t *)state)->retired ? SOLARIS_ECLOSED : SOLARIS_EACCESS;
}
static solaris_status_t datagram(void *state, uint32_t family,
                                  const solaris_datagram_callbacks_t *callbacks,
                                  void *context, solaris_datagram_t **out)
{
    (void)family; (void)callbacks; (void)context; (void)out;
    return ((solaris_block_outbound_t *)state)->retired ? SOLARIS_ECLOSED : SOLARIS_EACCESS;
}
static void retire(void *state) { ((solaris_block_outbound_t *)state)->retired = 1; }
static const solaris_outbound_ops_t operations = {capabilities, stream, datagram, retire};

solaris_status_t solaris_block_outbound_init(solaris_block_outbound_t *block, solaris_executor_t *executor)
{
    if (block == NULL || executor == NULL) return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(executor)) return SOLARIS_ETHREAD;
    memset(block, 0, sizeof(*block));
    block->outbound.ops = &operations; block->outbound.state = block; block->outbound.owner = executor;
    return SOLARIS_OK;
}

static solaris_status_t compile_config(const solaris_config_view_t *view, solaris_budget_t *budget,
                                        void **out, solaris_error_t *error)
{
    (void)budget; (void)out;
    return solaris_config_check_fields(view, NULL, 0u, error);
}
static solaris_status_t create_instance(const void *config, const solaris_module_services_t *services,
                                         void **state, solaris_outbound_t **out, solaris_error_t *error)
{
    (void)config; (void)error;
    solaris_block_outbound_t *block = solaris_memory_allocate(solaris_executor_budget(services->owner), sizeof(*block));
    if (block == NULL) return SOLARIS_ENOMEM;
    solaris_status_t rc = solaris_block_outbound_init(block, services->owner);
    if (rc != SOLARIS_OK) { solaris_memory_free(block); return rc; }
    *state = block; *out = &block->outbound;
    return SOLARIS_OK;
}
static const char *const aliases[] = {"reject"};
const solaris_outbound_module_t solaris_block_module = {
    .name = "block", .aliases = aliases, .alias_count = 1u,
    .capabilities = SOLARIS_OUTBOUND_STREAM | SOLARIS_OUTBOUND_DATAGRAM |
                    SOLARIS_OUTBOUND_STREAM_DOMAIN | SOLARIS_OUTBOUND_DATAGRAM_DOMAIN,
    .compile = compile_config, .free_config = solaris_memory_free,
    .create = create_instance, .retire = retire, .destroy = solaris_memory_free
};
