#ifndef SOLARIS_TRANSPORT_UOT_H
#define SOLARIS_TRANSPORT_UOT_H
#include "transport/datagram/stream.h"

solaris_status_t solaris_uot_open(solaris_executor_t *owner, const solaris_stream_factory_t *factory,
    const solaris_dialer_options_t *options, const solaris_datagram_callbacks_t *callbacks,
    void *context, solaris_datagram_t **out);
#endif
