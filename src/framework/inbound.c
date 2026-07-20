#include "aproxy/inbound.h"

#include <stdlib.h>

int aproxy_inbound_start(aproxy_inbound_t *inbound)
{
    if (inbound == NULL || inbound->vtable == NULL ||
        inbound->vtable->start == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    return inbound->vtable->start(inbound->impl);
}

void aproxy_inbound_stop(aproxy_inbound_t *inbound)
{
    if (inbound != NULL && inbound->vtable != NULL &&
        inbound->vtable->stop != NULL) {
        inbound->vtable->stop(inbound->impl);
    }
}

void aproxy_inbound_free(aproxy_inbound_t *inbound)
{
    if (inbound == NULL) {
        return;
    }
    if (inbound->vtable != NULL && inbound->vtable->free != NULL) {
        inbound->vtable->free(inbound->impl);
    }
    free(inbound);
}
