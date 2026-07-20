#include "aproxy/bufpool.h"
#include "aproxy/memory.h"

#include <stdlib.h>

void aproxy_bufpool_init(aproxy_bufpool_t *pool,
                         size_t chunk_size,
                         size_t max_free)
{
    if (pool == NULL) {
        return;
    }
    if (chunk_size < sizeof(aproxy_bufpool_node_t)) {
        chunk_size = sizeof(aproxy_bufpool_node_t);
    }
    pool->chunk_size = chunk_size;
    pool->max_free = max_free;
    pool->free_count = 0u;
    pool->free_list = NULL;
}

void aproxy_bufpool_trim(aproxy_bufpool_t *pool)
{
    if (pool == NULL) {
        return;
    }
    aproxy_bufpool_node_t *node = pool->free_list;
    while (node != NULL) {
        aproxy_bufpool_node_t *next = node->next;
        free(node);
        aproxy_memory_release(pool->chunk_size);
        node = next;
    }
    pool->free_list = NULL;
    pool->free_count = 0u;
}

void aproxy_bufpool_destroy(aproxy_bufpool_t *pool)
{
    aproxy_bufpool_trim(pool);
}

uint8_t *aproxy_bufpool_acquire(aproxy_bufpool_t *pool,
                                size_t min_capacity,
                                size_t *capacity)
{
    if (capacity != NULL) {
        *capacity = 0u;
    }
    if (pool == NULL) {
        if (aproxy_memory_try_reserve(min_capacity) != APROXY_OK) {
            return NULL;
        }
        uint8_t *direct = (uint8_t *)malloc(min_capacity);
        if (direct == NULL) {
            aproxy_memory_release(min_capacity);
        }
        if (capacity != NULL && direct != NULL) {
            *capacity = min_capacity;
        }
        return direct;
    }
    if (min_capacity <= pool->chunk_size && pool->free_list != NULL) {
        aproxy_bufpool_node_t *node = pool->free_list;
        pool->free_list = node->next;
        pool->free_count--;
        if (capacity != NULL) {
            *capacity = pool->chunk_size;
        }
        return (uint8_t *)node;
    }

    const size_t alloc_size =
        min_capacity > pool->chunk_size ? min_capacity : pool->chunk_size;
    if (aproxy_memory_try_reserve(alloc_size) != APROXY_OK) {
        return NULL;
    }
    uint8_t *data = (uint8_t *)malloc(alloc_size);
    if (data == NULL) {
        aproxy_memory_release(alloc_size);
    }
    if (capacity != NULL && data != NULL) {
        *capacity = alloc_size;
    }
    return data;
}

void aproxy_bufpool_release(aproxy_bufpool_t *pool,
                            uint8_t *data,
                            size_t capacity)
{
    if (data == NULL) {
        return;
    }
    if (pool == NULL || capacity != pool->chunk_size ||
        pool->free_count >= pool->max_free) {
        free(data);
        aproxy_memory_release(capacity);
        return;
    }
    aproxy_bufpool_node_t *node = (aproxy_bufpool_node_t *)data;
    node->next = pool->free_list;
    pool->free_list = node;
    pool->free_count++;
}
