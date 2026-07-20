#ifndef APROXY_BUFPOOL_H
#define APROXY_BUFPOOL_H

#include <stddef.h>
#include <stdint.h>

#include "aproxy/error.h"

typedef struct aproxy_bufpool_node {
    struct aproxy_bufpool_node *next;
} aproxy_bufpool_node_t;

typedef struct aproxy_bufpool {
    size_t chunk_size;
    size_t max_free;
    size_t free_count;
    aproxy_bufpool_node_t *free_list;
} aproxy_bufpool_t;

void aproxy_bufpool_init(aproxy_bufpool_t *pool,
                         size_t chunk_size,
                         size_t max_free);

void aproxy_bufpool_destroy(aproxy_bufpool_t *pool);

/* Releases cached chunks while keeping the pool reusable. */
void aproxy_bufpool_trim(aproxy_bufpool_t *pool);

uint8_t *aproxy_bufpool_acquire(aproxy_bufpool_t *pool,
                                size_t min_capacity,
                                size_t *capacity);

void aproxy_bufpool_release(aproxy_bufpool_t *pool,
                            uint8_t *data,
                            size_t capacity);

#endif
