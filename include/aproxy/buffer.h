#ifndef APROXY_BUFFER_H
#define APROXY_BUFFER_H

#include <stddef.h>
#include <stdint.h>

#include "aproxy/error.h"

typedef struct aproxy_buffer {
    uint8_t *data;
    size_t len;
    size_t cap;
} aproxy_buffer_t;

void aproxy_buffer_init(aproxy_buffer_t *buffer);
void aproxy_buffer_free(aproxy_buffer_t *buffer);
int aproxy_buffer_reserve(aproxy_buffer_t *buffer, size_t capacity);
int aproxy_buffer_append(aproxy_buffer_t *buffer,
                         const uint8_t *data,
                         size_t len);
int aproxy_buffer_append_zero(aproxy_buffer_t *buffer, size_t len);
void aproxy_buffer_consume(aproxy_buffer_t *buffer, size_t len);
void aproxy_buffer_clear(aproxy_buffer_t *buffer);

#endif
