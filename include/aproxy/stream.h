#ifndef APROXY_STREAM_H
#define APROXY_STREAM_H

#include <stddef.h>
#include <stdint.h>

#include "aproxy/error.h"

typedef struct aproxy_stream aproxy_stream_t;

typedef void (*aproxy_stream_data_cb)(aproxy_stream_t *stream,
                                      const uint8_t *data,
                                      size_t len,
                                      void *user_data);

typedef void (*aproxy_stream_event_cb)(aproxy_stream_t *stream,
                                       int status,
                                       void *user_data);

int aproxy_stream_write(aproxy_stream_t *stream,
                        const uint8_t *data,
                        size_t len);

int aproxy_stream_close(aproxy_stream_t *stream);

uint32_t aproxy_stream_id(const aproxy_stream_t *stream);

void *aproxy_stream_native(const aproxy_stream_t *stream);

void aproxy_stream_free(aproxy_stream_t *stream);

#endif
