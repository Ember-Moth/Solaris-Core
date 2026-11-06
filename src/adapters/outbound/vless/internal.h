#ifndef SOLARIS_VLESS_INTERNAL_H
#define SOLARIS_VLESS_INTERNAL_H

#include "transport/stream/filter.h"

typedef struct solaris_vless_parameters { solaris_address_t destination; uint8_t uuid[16], command, vision; } solaris_vless_parameters_t;

solaris_status_t solaris_vless_request(const solaris_vless_parameters_t *parameters,
    solaris_budget_t *budget, solaris_buffer_t **out);
solaris_status_t solaris_vless_response(const uint8_t *wire, size_t size, size_t *consumed);

extern const solaris_stream_codec_ops_t solaris_vless_stream_codec;

#endif
