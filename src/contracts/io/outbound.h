#ifndef SOLARIS_OUTBOUND_H
#define SOLARIS_OUTBOUND_H

#include "contracts/io/channel.h"

enum {
    SOLARIS_OUTBOUND_STREAM = 1u << 0,
    SOLARIS_OUTBOUND_DATAGRAM = 1u << 1,
    SOLARIS_OUTBOUND_STREAM_DOMAIN = 1u << 2,
    SOLARIS_OUTBOUND_DATAGRAM_MULTI = 1u << 3,
    SOLARIS_OUTBOUND_HALF_CLOSE = 1u << 4,
    SOLARIS_OUTBOUND_DATAGRAM_DOMAIN = 1u << 5,
    /* Reuse a numeric route resolution for actual dialing while preserving
     * the original destination in metadata. Remote-domain adapters omit it. */
    SOLARIS_OUTBOUND_LOCAL_RESOLUTION = 1u << 6
};

typedef struct solaris_outbound_ops {
    uint32_t (*capabilities)(void *state);
    solaris_status_t (*open_stream)(void *state, const solaris_address_t *destination,
                                    const solaris_stream_callbacks_t *callbacks,
                                    void *context, solaris_stream_t **out);
    solaris_status_t (*open_datagram)(void *state, uint32_t family,
                                      const solaris_datagram_callbacks_t *callbacks,
                                      void *context, solaris_datagram_t **out);
    /* Stops new admission. Already returned channels retain independent scope
     * lifetimes; engine stop is the operation that cancels all active I/O. */
    void (*retire)(void *state);
} solaris_outbound_ops_t;

typedef struct solaris_outbound {
    const solaris_outbound_ops_t *ops;
    void *state;
    solaris_executor_t *owner;
} solaris_outbound_t;

solaris_status_t solaris_outbound_capabilities(solaris_outbound_t *outbound, uint32_t *capabilities);
solaris_status_t solaris_outbound_open_stream(solaris_outbound_t *outbound,
                                              const solaris_address_t *destination,
                                              const solaris_stream_callbacks_t *callbacks,
                                              void *context, solaris_stream_t **out);
solaris_status_t solaris_outbound_open_datagram(solaris_outbound_t *outbound, uint32_t family,
                                                const solaris_datagram_callbacks_t *callbacks,
                                                void *context, solaris_datagram_t **out);
solaris_status_t solaris_outbound_retire(solaris_outbound_t *outbound);

#endif
