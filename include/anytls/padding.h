#ifndef ANYTLS_PADDING_H
#define ANYTLS_PADDING_H

#include <stddef.h>
#include <stdint.h>

#include "anytls/error.h"

#define ANYTLS_PADDING_CHECK_MARK (-1)
#define ANYTLS_PADDING_MAX_RANGES_PER_PACKET 64u

extern const uint8_t anytls_default_padding_scheme[];
extern const size_t anytls_default_padding_scheme_len;

typedef struct anytls_padding_factory anytls_padding_factory_t;
typedef struct anytls_padding_store anytls_padding_store_t;

int anytls_padding_factory_new(const uint8_t *raw,
                               size_t raw_len,
                               anytls_padding_factory_t **out);

void anytls_padding_factory_free(anytls_padding_factory_t *factory);

uint32_t anytls_padding_stop(const anytls_padding_factory_t *factory);

const char *anytls_padding_md5_hex(const anytls_padding_factory_t *factory);

const uint8_t *anytls_padding_raw(const anytls_padding_factory_t *factory,
                                  size_t *len);

int anytls_padding_generate_record_payload_sizes(
    const anytls_padding_factory_t *factory,
    uint32_t packet,
    int *out_sizes,
    size_t out_capacity,
    size_t *out_count);

int anytls_padding_auth_length(const anytls_padding_factory_t *factory,
                               uint16_t *out_len);

int anytls_padding_store_new_default(anytls_padding_store_t **out);

void anytls_padding_store_free(anytls_padding_store_t *store);

const anytls_padding_factory_t *anytls_padding_store_get(
    const anytls_padding_store_t *store);

int anytls_padding_store_update(anytls_padding_store_t *store,
                                const uint8_t *raw,
                                size_t raw_len);

#endif
