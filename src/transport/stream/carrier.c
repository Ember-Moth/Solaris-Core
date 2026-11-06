#include "contracts/io/carrier.h"

solaris_status_t solaris_carrier_open(const solaris_stream_factory_t *factory,
    solaris_executor_t *owner, const solaris_dialer_options_t *options,
    const solaris_address_t *peer, const solaris_stream_callbacks_t *callbacks,
    void *context, solaris_stream_t **out)
{
    if (out == NULL) return SOLARIS_EINVAL;
    *out = NULL;
    if (owner == NULL || peer == NULL || callbacks == NULL ||
        callbacks->on_open == NULL || callbacks->on_data == NULL || callbacks->on_close == NULL)
        return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(owner)) return SOLARIS_ETHREAD;
    if (factory == NULL || factory->open == NULL)
        return solaris_dialer_open_stream(owner, options, peer, callbacks, context, out);
    return factory->open(factory->context, owner, options, peer, callbacks, context, out);
}
