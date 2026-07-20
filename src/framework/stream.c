#include "stream_internal.h"

#include <stdlib.h>

int aproxy_stream_new(const aproxy_stream_vtable_t *vtable,
                      void *impl,
                      aproxy_stream_t **out)
{
    if (vtable == NULL || out == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    aproxy_stream_t *stream = (aproxy_stream_t *)calloc(1u, sizeof(*stream));
    if (stream == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    stream->vtable = vtable;
    stream->impl = impl;
    *out = stream;
    return APROXY_OK;
}

void aproxy_stream_free(aproxy_stream_t *stream)
{
    if (stream == NULL) {
        return;
    }
    if (stream->vtable != NULL && stream->vtable->free != NULL) {
        stream->vtable->free(stream->impl);
    }
    free(stream);
}

int aproxy_stream_write(aproxy_stream_t *stream,
                        const uint8_t *data,
                        size_t len)
{
    if (stream == NULL || stream->vtable == NULL ||
        stream->vtable->write == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    return stream->vtable->write(stream->impl, data, len);
}

int aproxy_stream_close(aproxy_stream_t *stream)
{
    if (stream == NULL || stream->vtable == NULL ||
        stream->vtable->close == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    return stream->vtable->close(stream->impl);
}

uint32_t aproxy_stream_id(const aproxy_stream_t *stream)
{
    if (stream == NULL || stream->vtable == NULL ||
        stream->vtable->id == NULL) {
        return 0u;
    }
    return stream->vtable->id(stream->impl);
}

void *aproxy_stream_native(const aproxy_stream_t *stream)
{
    if (stream == NULL || stream->vtable == NULL ||
        stream->vtable->native == NULL) {
        return NULL;
    }
    return stream->vtable->native(stream->impl);
}
