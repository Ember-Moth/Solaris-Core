#ifndef APROXY_RING_H
#define APROXY_RING_H

#include <stddef.h>
#include <stdint.h>

#include "aproxy/error.h"

typedef struct aproxy_span {
    uint8_t *data;
    size_t len;
} aproxy_span_t;

typedef struct aproxy_const_span {
    const uint8_t *data;
    size_t len;
} aproxy_const_span_t;

typedef struct aproxy_ring {
    uint8_t *data;
    size_t cap;
    size_t head;
    size_t len;
} aproxy_ring_t;

void aproxy_ring_init(aproxy_ring_t *ring);
void aproxy_ring_free(aproxy_ring_t *ring);
int aproxy_ring_reserve(aproxy_ring_t *ring, size_t capacity);
size_t aproxy_ring_size(const aproxy_ring_t *ring);
size_t aproxy_ring_capacity(const aproxy_ring_t *ring);
size_t aproxy_ring_writable(const aproxy_ring_t *ring);

int aproxy_ring_write(aproxy_ring_t *ring, const uint8_t *data, size_t len);
size_t aproxy_ring_read(aproxy_ring_t *ring, uint8_t *out, size_t len);
int aproxy_ring_peek_byte(const aproxy_ring_t *ring, size_t offset, uint8_t *out);
size_t aproxy_ring_peek(const aproxy_ring_t *ring,
                        size_t offset,
                        uint8_t *out,
                        size_t len);
void aproxy_ring_consume(aproxy_ring_t *ring, size_t len);
void aproxy_ring_clear(aproxy_ring_t *ring);

size_t aproxy_ring_read_spans(const aproxy_ring_t *ring,
                              aproxy_const_span_t spans[2]);

size_t aproxy_ring_read_spans_at(const aproxy_ring_t *ring,
                                 size_t offset,
                                 size_t len,
                                 aproxy_const_span_t spans[2]);

size_t aproxy_ring_write_spans(aproxy_ring_t *ring, aproxy_span_t spans[2]);

/* Commit bytes filled through aproxy_ring_write_spans(). */
int aproxy_ring_commit_write(aproxy_ring_t *ring, size_t len);

#endif
