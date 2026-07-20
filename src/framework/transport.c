#include "aproxy/transport.h"

#include <stdlib.h>

int aproxy_transport_connect(aproxy_transport_t *transport)
{
    if (transport == NULL || transport->vtable == NULL ||
        transport->vtable->connect == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    return transport->vtable->connect(transport->impl);
}

int aproxy_transport_write(aproxy_transport_t *transport,
                           const uint8_t *data,
                           size_t len)
{
    if (transport == NULL || transport->vtable == NULL ||
        transport->vtable->write == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    return transport->vtable->write(transport->impl, data, len);
}

void aproxy_transport_close(aproxy_transport_t *transport)
{
    if (transport != NULL && transport->vtable != NULL &&
        transport->vtable->close != NULL) {
        transport->vtable->close(transport->impl);
    }
}

void aproxy_transport_free(aproxy_transport_t *transport)
{
    if (transport == NULL) {
        return;
    }
    if (transport->vtable != NULL && transport->vtable->free != NULL) {
        transport->vtable->free(transport->impl);
    }
    free(transport);
}
