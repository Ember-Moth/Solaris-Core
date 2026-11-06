#ifndef SOLARIS_VLESS_VISION_CODEC_H
#define SOLARIS_VLESS_VISION_CODEC_H

#include "adapters/outbound/vless/internal.h"
#include "contracts/runtime/crypto.h"

typedef struct solaris_vless_vision_parameters {
    solaris_vless_parameters_t request;
    solaris_crypto_source_t crypto;
} solaris_vless_vision_parameters_t;
extern const solaris_stream_codec_ops_t solaris_vless_vision_codec;

#endif
