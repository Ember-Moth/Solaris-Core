#ifndef SOLARIS_DIRECT_OUTBOUND_H
#define SOLARIS_DIRECT_OUTBOUND_H

#include "contracts/io/outbound.h"
#include "transport/socket/socket.h"

/* Adapter-private storage; generic construction goes through the registry. */
typedef struct solaris_direct_outbound {
    solaris_outbound_t outbound;
    solaris_dialer_options_t options;
    int retired;
} solaris_direct_outbound_t;

solaris_status_t solaris_direct_outbound_init(solaris_direct_outbound_t *direct,
                                              solaris_executor_t *executor,
                                              const solaris_dialer_options_t *options);

#endif
