#include "contracts/io/outbound.h"
#include "runtime/executor/executor.h"

solaris_status_t solaris_outbound_capabilities(solaris_outbound_t *outbound, uint32_t *capabilities)
{
    if (outbound == NULL || capabilities == NULL) return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(outbound->owner)) return SOLARIS_ETHREAD;
    *capabilities = outbound->ops->capabilities(outbound->state);
    return SOLARIS_OK;
}

solaris_status_t solaris_outbound_open_stream(solaris_outbound_t *outbound,
                                              const solaris_address_t *destination,
                                              const solaris_stream_callbacks_t *callbacks,
                                              void *context, solaris_stream_t **out)
{
    if (out == NULL) return SOLARIS_EINVAL;
    *out = NULL;
    if (outbound == NULL || destination == NULL || callbacks == NULL) return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(outbound->owner)) return SOLARIS_ETHREAD;
    return outbound->ops->open_stream(outbound->state, destination, callbacks, context, out);
}

solaris_status_t solaris_outbound_open_datagram(solaris_outbound_t *outbound, uint32_t family,
                                                const solaris_datagram_callbacks_t *callbacks,
                                                void *context, solaris_datagram_t **out)
{
    if (out == NULL) return SOLARIS_EINVAL;
    *out = NULL;
    if (outbound == NULL || callbacks == NULL) return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(outbound->owner)) return SOLARIS_ETHREAD;
    return outbound->ops->open_datagram(outbound->state, family, callbacks, context, out);
}

solaris_status_t solaris_outbound_retire(solaris_outbound_t *outbound)
{
    if (outbound == NULL) return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(outbound->owner)) return SOLARIS_ETHREAD;
    outbound->ops->retire(outbound->state);
    return SOLARIS_OK;
}
