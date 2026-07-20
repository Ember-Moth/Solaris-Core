#include "aproxy/protocol.h"

#include <stdlib.h>

int aproxy_protocol_start(aproxy_protocol_t *protocol)
{
    if (protocol == NULL || protocol->vtable == NULL ||
        protocol->vtable->start == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    return protocol->vtable->start(protocol->impl);
}

int aproxy_protocol_open_stream(aproxy_protocol_t *protocol,
                                const aproxy_addr_t *destination,
                                aproxy_stream_data_cb on_data,
                                aproxy_stream_event_cb on_open,
                                aproxy_stream_event_cb on_close,
                                void *user_data,
                                aproxy_stream_t **out)
{
    if (protocol == NULL || protocol->vtable == NULL ||
        protocol->vtable->open_stream == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    return protocol->vtable->open_stream(protocol->impl, destination, on_data,
                                         on_open, on_close, user_data, out);
}

void aproxy_protocol_close(aproxy_protocol_t *protocol)
{
    if (protocol != NULL && protocol->vtable != NULL &&
        protocol->vtable->close != NULL) {
        protocol->vtable->close(protocol->impl);
    }
}

void aproxy_protocol_free(aproxy_protocol_t *protocol)
{
    if (protocol == NULL) {
        return;
    }
    if (protocol->vtable != NULL && protocol->vtable->free != NULL) {
        protocol->vtable->free(protocol->impl);
    }
    free(protocol);
}
