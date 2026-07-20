#ifndef APROXY_XHTTP_REQUEST_H
#define APROXY_XHTTP_REQUEST_H

#include <nghttp2/nghttp2.h>

#include "aproxy/xhttp.h"

typedef enum xhttp_request_kind {
    XHTTP_REQUEST_DOWNLOAD = 0,
    XHTTP_REQUEST_STREAM_UPLOAD,
    XHTTP_REQUEST_STREAM_ONE,
    XHTTP_REQUEST_PACKET_UPLOAD,
} xhttp_request_kind_t;

#define XHTTP_REQUEST_INLINE_HEADERS 32u

typedef struct xhttp_header_arena_chunk xhttp_header_arena_chunk_t;

typedef struct xhttp_request_headers {
    nghttp2_nv *fields;
    size_t count;
    size_t capacity;
    xhttp_header_arena_chunk_t *arena;
    nghttp2_nv inline_fields[XHTTP_REQUEST_INLINE_HEADERS];
} xhttp_request_headers_t;

void xhttp_request_headers_init(xhttp_request_headers_t *headers);
void xhttp_request_headers_free(xhttp_request_headers_t *headers);

int xhttp_request_headers_build(const aproxy_xhttp_config_t *config,
                                xhttp_request_kind_t kind,
                                const char *session_id,
                                const char *sequence,
                                const uint8_t *payload,
                                size_t payload_len,
                                xhttp_request_headers_t *headers);

const char *xhttp_request_header_find(
    const xhttp_request_headers_t *headers,
    const char *name);

#endif
