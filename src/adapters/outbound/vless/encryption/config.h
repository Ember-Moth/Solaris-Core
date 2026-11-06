#ifndef SOLARIS_VLESS_ENCRYPTION_CONFIG_H
#define SOLARIS_VLESS_ENCRYPTION_CONFIG_H

#include "contracts/module/config.h"
#include <stdint.h>

#define SOLARIS_VLESS_ENCRYPTION_KEYS 8u
#define SOLARIS_VLESS_ENCRYPTION_PADDING 31u
#define SOLARIS_VLESS_ENCRYPTION_TEXT 16384u
typedef struct solaris_vless_encryption_range {
    uint32_t probability, minimum, maximum;
} solaris_vless_encryption_range_t;
typedef struct solaris_vless_encryption_key {
    uint8_t bytes[1184];
    size_t length;
} solaris_vless_encryption_key_t;
typedef struct solaris_vless_encryption_config {
    solaris_vless_encryption_key_t keys[SOLARIS_VLESS_ENCRYPTION_KEYS];
    solaris_vless_encryption_range_t padding[SOLARIS_VLESS_ENCRYPTION_PADDING];
    size_t key_count, padding_count;
    uint32_t mode; /* native=0, xorpub=1, random=2 */
    int resume, chacha;
} solaris_vless_encryption_config_t;

/* Missing encryption is equivalent to none. Explicit strings must match the
 * pinned Xray grammar; bounded resource limits are part of this implementation. */
solaris_status_t solaris_vless_encryption_config_parse(const char *text,
    solaris_vless_encryption_config_t *out);

#endif
