#include "aproxy/block_outbound.h"

#include <stdlib.h>
#include <string.h>

#include "aproxy/error.h"

typedef struct block_outbound_impl {
    char *tag;
} block_outbound_impl_t;

static char *copy_string(const char *value)
{
    const size_t len = strlen(value);
    char *copy = (char *)malloc(len + 1u);
    if (copy != NULL) {
        memcpy(copy, value, len + 1u);
    }
    return copy;
}

static int block_connect(void *impl)
{
    return impl == NULL ? APROXY_ERR_INVALID_ARGUMENT : APROXY_OK;
}

static int block_open_stream(void *impl,
                             const aproxy_addr_t *destination,
                             aproxy_stream_data_cb on_data,
                             aproxy_stream_event_cb on_open,
                             aproxy_stream_event_cb on_close,
                             void *user_data,
                             aproxy_stream_t **out)
{
    (void)destination;
    (void)on_data;
    (void)on_open;
    (void)on_close;
    (void)user_data;
    if (impl == NULL || out == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    *out = NULL;
    return APROXY_ERR_UNSUPPORTED;
}

static int block_open_packet(void *impl,
                             const aproxy_addr_t *initial_destination,
                             aproxy_packet_flow_data_cb on_data,
                             aproxy_packet_flow_event_cb on_open,
                             aproxy_packet_flow_event_cb on_close,
                             void *user_data,
                             aproxy_packet_flow_t **out)
{
    (void)initial_destination;
    (void)on_data;
    (void)on_open;
    (void)on_close;
    (void)user_data;
    if (impl == NULL || out == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    *out = NULL;
    return APROXY_ERR_UNSUPPORTED;
}

static void block_close(void *impl)
{
    (void)impl;
}

static void block_free(void *impl)
{
    block_outbound_impl_t *block = (block_outbound_impl_t *)impl;
    if (block == NULL) {
        return;
    }
    free(block->tag);
    free(block);
}

static const aproxy_outbound_vtable_t block_vtable = {
    .connect = block_connect,
    .open_stream = block_open_stream,
    .open_packet = block_open_packet,
    .close = block_close,
    .free = block_free,
};

int aproxy_block_outbound_new(const char *tag, aproxy_outbound_t **out)
{
    if (out == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    *out = NULL;
    block_outbound_impl_t *impl =
        (block_outbound_impl_t *)calloc(1u, sizeof(*impl));
    aproxy_outbound_t *outbound =
        (aproxy_outbound_t *)calloc(1u, sizeof(*outbound));
    if (impl == NULL || outbound == NULL) {
        free(impl);
        free(outbound);
        return APROXY_ERR_NO_MEMORY;
    }
    impl->tag = copy_string(tag != NULL ? tag : "block");
    if (impl->tag == NULL) {
        free(outbound);
        block_free(impl);
        return APROXY_ERR_NO_MEMORY;
    }
    outbound->tag = impl->tag;
    outbound->vtable = &block_vtable;
    outbound->impl = impl;
    outbound->udp_transport = APROXY_OUTBOUND_UDP_PACKET;
    *out = outbound;
    return APROXY_OK;
}
