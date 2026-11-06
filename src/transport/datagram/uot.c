#include "transport/datagram/uot.h"
#include "codec/uot/codec.h"
#include <string.h>

solaris_status_t solaris_uot_open(solaris_executor_t *owner, const solaris_stream_factory_t *factory,
    const solaris_dialer_options_t *options, const solaris_datagram_callbacks_t *callbacks,
    void *context, solaris_datagram_t **out)
{
    if (out == NULL) return SOLARIS_EINVAL;
    *out = NULL;
    /* UoT's magic peer is proxy metadata, never a physical DNS destination. */
    if (factory == NULL || factory->open == NULL) return SOLARIS_EINVAL;
    solaris_address_t peer = {.family = SOLARIS_ADDRESS_DOMAIN};
    memcpy(peer.host, SOLARIS_UOT_V2_ADDRESS, sizeof(SOLARIS_UOT_V2_ADDRESS));
    return solaris_datagram_stream_open(owner, factory, options, &peer,
        &solaris_uot_v2_codec, NULL, callbacks, context, out);
}
