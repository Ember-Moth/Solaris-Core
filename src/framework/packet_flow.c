#include "packet_flow_internal.h"

#include <stdlib.h>

int aproxy_packet_flow_new(const aproxy_packet_flow_vtable_t *vtable,
                           void *impl,
                           aproxy_packet_flow_t **out)
{
    if (vtable == NULL || out == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    aproxy_packet_flow_t *flow =
        (aproxy_packet_flow_t *)calloc(1u, sizeof(*flow));
    if (flow == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    flow->vtable = vtable;
    flow->impl = impl;
    *out = flow;
    return APROXY_OK;
}

int aproxy_packet_flow_send(aproxy_packet_flow_t *flow,
                            const aproxy_addr_t *destination,
                            const uint8_t *data,
                            size_t len)
{
    if (flow == NULL || flow->vtable == NULL ||
        flow->vtable->send == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    return flow->vtable->send(flow->impl, destination, data, len);
}

int aproxy_packet_flow_send_batch(
    aproxy_packet_flow_t *flow,
    const aproxy_packet_flow_datagram_t *datagrams,
    size_t count,
    size_t *accepted)
{
    if (accepted != NULL) {
        *accepted = 0u;
    }
    if (flow == NULL || flow->vtable == NULL || datagrams == NULL ||
        count == 0u || accepted == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    if (flow->vtable->send_batch != NULL) {
        const int rc = flow->vtable->send_batch(
            flow->impl, datagrams, count, accepted);
        if (*accepted > count) {
            *accepted = 0u;
            return APROXY_ERR_INVALID_FRAME;
        }
        return rc;
    }
    if (flow->vtable->send == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    for (size_t i = 0u; i < count; i++) {
        const aproxy_packet_flow_datagram_t *datagram = &datagrams[i];
        const int rc = flow->vtable->send(
            flow->impl, datagram->destination, datagram->data, datagram->len);
        if (rc != APROXY_OK) {
            return rc;
        }
        *accepted = i + 1u;
    }
    return APROXY_OK;
}

int aproxy_packet_flow_supports_batch(const aproxy_packet_flow_t *flow)
{
    return flow != NULL && flow->vtable != NULL &&
           flow->vtable->send_batch != NULL;
}

int aproxy_packet_flow_close(aproxy_packet_flow_t *flow)
{
    if (flow == NULL || flow->vtable == NULL ||
        flow->vtable->close == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    return flow->vtable->close(flow->impl);
}

uint32_t aproxy_packet_flow_id(const aproxy_packet_flow_t *flow)
{
    if (flow == NULL || flow->vtable == NULL ||
        flow->vtable->id == NULL) {
        return 0u;
    }
    return flow->vtable->id(flow->impl);
}

void *aproxy_packet_flow_native(const aproxy_packet_flow_t *flow)
{
    if (flow == NULL || flow->vtable == NULL ||
        flow->vtable->native == NULL) {
        return NULL;
    }
    return flow->vtable->native(flow->impl);
}

void aproxy_packet_flow_free(aproxy_packet_flow_t *flow)
{
    if (flow == NULL) {
        return;
    }
    if (flow->vtable != NULL && flow->vtable->free != NULL) {
        flow->vtable->free(flow->impl);
    }
    free(flow);
}
