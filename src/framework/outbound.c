#include "aproxy/outbound.h"

#include <stdlib.h>

int aproxy_outbound_connect(aproxy_outbound_t *outbound)
{
    if (outbound == NULL || outbound->vtable == NULL ||
        outbound->vtable->connect == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    return outbound->vtable->connect(outbound->impl);
}

int aproxy_outbound_open_stream(aproxy_outbound_t *outbound,
                                const aproxy_addr_t *destination,
                                aproxy_stream_data_cb on_data,
                                aproxy_stream_event_cb on_open,
                                aproxy_stream_event_cb on_close,
                                void *user_data,
                                aproxy_stream_t **out)
{
    if (outbound == NULL || outbound->vtable == NULL ||
        outbound->vtable->open_stream == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    return outbound->vtable->open_stream(outbound->impl, destination, on_data,
                                         on_open, on_close, user_data, out);
}

int aproxy_outbound_open_packet(aproxy_outbound_t *outbound,
                                const aproxy_addr_t *initial_destination,
                                aproxy_packet_flow_data_cb on_data,
                                aproxy_packet_flow_event_cb on_open,
                                aproxy_packet_flow_event_cb on_close,
                                void *user_data,
                                aproxy_packet_flow_t **out)
{
    if (outbound == NULL || outbound->vtable == NULL ||
        outbound->vtable->open_packet == NULL) {
        return APROXY_ERR_UNSUPPORTED;
    }
    return outbound->vtable->open_packet(
        outbound->impl, initial_destination, on_data, on_open, on_close,
        user_data, out);
}

void aproxy_outbound_close(aproxy_outbound_t *outbound)
{
    if (outbound != NULL && outbound->vtable != NULL &&
        outbound->vtable->close != NULL) {
        outbound->vtable->close(outbound->impl);
    }
}

void aproxy_outbound_free(aproxy_outbound_t *outbound)
{
    if (outbound == NULL) {
        return;
    }
    if (outbound->vtable != NULL && outbound->vtable->free != NULL) {
        outbound->vtable->free(outbound->impl);
    }
    free(outbound);
}
