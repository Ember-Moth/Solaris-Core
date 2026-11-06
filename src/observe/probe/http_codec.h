#ifndef SOLARIS_HTTP_PROBE_CODEC_H
#define SOLARIS_HTTP_PROBE_CODEC_H
#include "contracts/io/channel.h"

#define SOLARIS_HTTP_PROBE_HEADER_LIMIT 16384u
typedef struct solaris_http_probe_target {
    solaris_address_t address;
    char identity[256];
    int tls;
} solaris_http_probe_target_t;
solaris_status_t solaris_http_probe_request(solaris_budget_t *budget, const char *url,
    solaris_http_probe_target_t *target, solaris_buffer_t **request);
/* Exact, complete CRLF-delimited header block, without response body. */
solaris_status_t solaris_http_probe_response(const uint8_t *header, size_t length, uint16_t *status);
#endif
