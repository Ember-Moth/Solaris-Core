#ifndef ANYTLS_BUFFER_H
#define ANYTLS_BUFFER_H

#include "aproxy/buffer.h"

typedef aproxy_buffer_t anytls_buffer_t;

#define anytls_buffer_init aproxy_buffer_init
#define anytls_buffer_free aproxy_buffer_free
#define anytls_buffer_reserve aproxy_buffer_reserve
#define anytls_buffer_append aproxy_buffer_append
#define anytls_buffer_append_zero aproxy_buffer_append_zero
#define anytls_buffer_consume aproxy_buffer_consume
#define anytls_buffer_clear aproxy_buffer_clear

#endif
