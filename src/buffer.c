#include "aproxy/buffer.h"
#include "aproxy/memory.h"

#include <stdlib.h>
#include <string.h>

void aproxy_buffer_init(aproxy_buffer_t *buffer)
{
    if (buffer == NULL) {
        return;
    }
    buffer->data = NULL;
    buffer->len = 0u;
    buffer->cap = 0u;
}

void aproxy_buffer_free(aproxy_buffer_t *buffer)
{
    if (buffer == NULL) {
        return;
    }
    free(buffer->data);
    aproxy_memory_release(buffer->cap);
    aproxy_buffer_init(buffer);
}

int aproxy_buffer_reserve(aproxy_buffer_t *buffer, size_t capacity)
{
    if (buffer == NULL) {
        return ANYTLS_ERR_INVALID_ARGUMENT;
    }
    if (capacity <= buffer->cap) {
        return ANYTLS_OK;
    }

    size_t next = buffer->cap == 0u ? 256u : buffer->cap;
    while (next < capacity) {
        if (next > (SIZE_MAX / 2u)) {
            next = capacity;
            break;
        }
        next *= 2u;
    }

    /* Account for realloc's worst case: the old and new blocks coexist. */
    if (aproxy_memory_try_reserve(next) != APROXY_OK) {
        return ANYTLS_ERR_NO_MEMORY;
    }
    uint8_t *data = (uint8_t *)realloc(buffer->data, next);
    if (data == NULL) {
        aproxy_memory_release(next);
        return ANYTLS_ERR_NO_MEMORY;
    }
    aproxy_memory_release(buffer->cap);
    buffer->data = data;
    buffer->cap = next;
    return ANYTLS_OK;
}

int aproxy_buffer_append(aproxy_buffer_t *buffer,
                         const uint8_t *data,
                         size_t len)
{
    if (buffer == NULL || (data == NULL && len > 0u)) {
        return ANYTLS_ERR_INVALID_ARGUMENT;
    }
    if (len > SIZE_MAX - buffer->len) {
        return ANYTLS_ERR_FRAME_TOO_LARGE;
    }
    const int rc = aproxy_buffer_reserve(buffer, buffer->len + len);
    if (rc != ANYTLS_OK) {
        return rc;
    }
    if (len > 0u) {
        memcpy(buffer->data + buffer->len, data, len);
        buffer->len += len;
    }
    return ANYTLS_OK;
}

int aproxy_buffer_append_zero(aproxy_buffer_t *buffer, size_t len)
{
    if (buffer == NULL) {
        return ANYTLS_ERR_INVALID_ARGUMENT;
    }
    if (len > SIZE_MAX - buffer->len) {
        return ANYTLS_ERR_FRAME_TOO_LARGE;
    }
    const int rc = aproxy_buffer_reserve(buffer, buffer->len + len);
    if (rc != ANYTLS_OK) {
        return rc;
    }
    memset(buffer->data + buffer->len, 0, len);
    buffer->len += len;
    return ANYTLS_OK;
}

void aproxy_buffer_consume(aproxy_buffer_t *buffer, size_t len)
{
    if (buffer == NULL || len == 0u) {
        return;
    }
    if (len >= buffer->len) {
        buffer->len = 0u;
        return;
    }
    memmove(buffer->data, buffer->data + len, buffer->len - len);
    buffer->len -= len;
}

void aproxy_buffer_clear(aproxy_buffer_t *buffer)
{
    if (buffer != NULL) {
        buffer->len = 0u;
    }
}
