#include "aproxy/ring.h"
#include "aproxy/memory.h"

#include <stdlib.h>
#include <string.h>

void aproxy_ring_init(aproxy_ring_t *ring)
{
    if (ring == NULL) {
        return;
    }
    ring->data = NULL;
    ring->cap = 0u;
    ring->head = 0u;
    ring->len = 0u;
}

void aproxy_ring_free(aproxy_ring_t *ring)
{
    if (ring == NULL) {
        return;
    }
    free(ring->data);
    aproxy_memory_release(ring->cap);
    aproxy_ring_init(ring);
}

static size_t ring_tail(const aproxy_ring_t *ring)
{
    return (ring->head + ring->len) & (ring->cap - 1u);
}

int aproxy_ring_reserve(aproxy_ring_t *ring, size_t capacity)
{
    if (ring == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    if (capacity <= ring->cap) {
        return APROXY_OK;
    }

    size_t next = ring->cap == 0u ? 1024u : ring->cap;
    while (next < capacity) {
        if (next > (SIZE_MAX / 2u)) {
            return APROXY_ERR_NO_MEMORY;
        }
        next *= 2u;
    }

    if (aproxy_memory_try_reserve(next) != APROXY_OK) {
        return APROXY_ERR_NO_MEMORY;
    }
    uint8_t *data = (uint8_t *)malloc(next);
    if (data == NULL) {
        aproxy_memory_release(next);
        return APROXY_ERR_NO_MEMORY;
    }
    if (ring->len > 0u) {
        (void)aproxy_ring_peek(ring, 0u, data, ring->len);
    }
    free(ring->data);
    aproxy_memory_release(ring->cap);
    ring->data = data;
    ring->cap = next;
    ring->head = 0u;
    return APROXY_OK;
}

size_t aproxy_ring_size(const aproxy_ring_t *ring)
{
    return ring == NULL ? 0u : ring->len;
}

size_t aproxy_ring_capacity(const aproxy_ring_t *ring)
{
    return ring == NULL ? 0u : ring->cap;
}

size_t aproxy_ring_writable(const aproxy_ring_t *ring)
{
    if (ring == NULL || ring->cap < ring->len) {
        return 0u;
    }
    return ring->cap - ring->len;
}

int aproxy_ring_write(aproxy_ring_t *ring, const uint8_t *data, size_t len)
{
    if (ring == NULL || (data == NULL && len > 0u)) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    if (len > SIZE_MAX - ring->len) {
        return APROXY_ERR_FRAME_TOO_LARGE;
    }
    int rc = aproxy_ring_reserve(ring, ring->len + len);
    if (rc != APROXY_OK) {
        return rc;
    }
    if (len == 0u) {
        return APROXY_OK;
    }

    aproxy_span_t spans[2];
    size_t count = aproxy_ring_write_spans(ring, spans);
    size_t copied = 0u;
    for (size_t i = 0u; i < count && copied < len; i++) {
        const size_t chunk = spans[i].len < len - copied
                                 ? spans[i].len
                                 : len - copied;
        memcpy(spans[i].data, data + copied, chunk);
        copied += chunk;
    }
    ring->len += copied;
    return copied == len ? APROXY_OK : APROXY_ERR_BUFFER_TOO_SMALL;
}

size_t aproxy_ring_read(aproxy_ring_t *ring, uint8_t *out, size_t len)
{
    if (ring == NULL || (out == NULL && len > 0u)) {
        return 0u;
    }
    const size_t n = aproxy_ring_peek(ring, 0u, out, len);
    aproxy_ring_consume(ring, n);
    return n;
}

int aproxy_ring_peek_byte(const aproxy_ring_t *ring, size_t offset, uint8_t *out)
{
    if (ring == NULL || out == NULL || offset >= ring->len ||
        ring->cap == 0u) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    *out = ring->data[(ring->head + offset) & (ring->cap - 1u)];
    return APROXY_OK;
}

size_t aproxy_ring_peek(const aproxy_ring_t *ring,
                        size_t offset,
                        uint8_t *out,
                        size_t len)
{
    if (ring == NULL || (out == NULL && len > 0u) || offset >= ring->len ||
        ring->cap == 0u) {
        return 0u;
    }
    size_t available = ring->len - offset;
    if (len > available) {
        len = available;
    }
    size_t pos = (ring->head + offset) & (ring->cap - 1u);
    size_t copied = 0u;
    while (copied < len) {
        size_t chunk = ring->cap - pos;
        if (chunk > len - copied) {
            chunk = len - copied;
        }
        memcpy(out + copied, ring->data + pos, chunk);
        copied += chunk;
        pos = 0u;
    }
    return copied;
}

void aproxy_ring_consume(aproxy_ring_t *ring, size_t len)
{
    if (ring == NULL || ring->len == 0u || ring->cap == 0u) {
        return;
    }
    if (len >= ring->len) {
        ring->head = 0u;
        ring->len = 0u;
        return;
    }
    ring->head = (ring->head + len) & (ring->cap - 1u);
    ring->len -= len;
}

void aproxy_ring_clear(aproxy_ring_t *ring)
{
    if (ring == NULL) {
        return;
    }
    ring->head = 0u;
    ring->len = 0u;
}

size_t aproxy_ring_read_spans(const aproxy_ring_t *ring,
                              aproxy_const_span_t spans[2])
{
    return aproxy_ring_read_spans_at(ring, 0u,
                                     ring == NULL ? 0u : ring->len, spans);
}

size_t aproxy_ring_read_spans_at(const aproxy_ring_t *ring,
                                 size_t offset,
                                 size_t len,
                                 aproxy_const_span_t spans[2])
{
    if (ring == NULL || spans == NULL || offset >= ring->len || len == 0u ||
        ring->cap == 0u) {
        return 0u;
    }
    if (len > ring->len - offset) {
        len = ring->len - offset;
    }
    const size_t start = (ring->head + offset) & (ring->cap - 1u);
    const size_t first = ring->cap - start < len ? ring->cap - start : len;
    spans[0].data = ring->data + start;
    spans[0].len = first;
    if (first == len) {
        return 1u;
    }
    spans[1].data = ring->data;
    spans[1].len = len - first;
    return 2u;
}

size_t aproxy_ring_write_spans(aproxy_ring_t *ring, aproxy_span_t spans[2])
{
    if (ring == NULL || spans == NULL || ring->cap == 0u ||
        ring->len == ring->cap) {
        return 0u;
    }
    const size_t tail = ring_tail(ring);
    const size_t writable = ring->cap - ring->len;
    const size_t first = ring->head <= tail
                             ? ring->cap - tail
                             : ring->head - tail;
    spans[0].data = ring->data + tail;
    spans[0].len = first < writable ? first : writable;
    if (spans[0].len == writable) {
        return 1u;
    }
    spans[1].data = ring->data;
    spans[1].len = writable - spans[0].len;
    return 2u;
}

int aproxy_ring_commit_write(aproxy_ring_t *ring, size_t len)
{
    if (ring == NULL || len > aproxy_ring_writable(ring)) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    ring->len += len;
    return APROXY_OK;
}
