#ifndef APROXY_TLS_H
#define APROXY_TLS_H

#include <stddef.h>
#include <stdint.h>

#include "aproxy/error.h"

typedef struct aproxy_tls_context aproxy_tls_context_t;

typedef struct aproxy_ech_config {
    /* Borrowed serialized ECHConfigList bytes. */
    const uint8_t *config_list;
    size_t config_list_len;
    int grease;
    int required;
} aproxy_ech_config_t;

int aproxy_ech_config_list_decode_base64(const char *encoded,
                                         uint8_t **out,
                                         size_t *out_len);

int aproxy_ech_config_list_validate(const uint8_t *config_list,
                                    size_t config_list_len);

/* The context is immutable after creation and may be shared by connections. */
int aproxy_tls_context_new(int insecure_skip_verify,
                           aproxy_tls_context_t **out);

void aproxy_tls_context_retain(aproxy_tls_context_t *context);

/* Releases one reference. Active TLS clients retain their own reference. */
void aproxy_tls_context_free(aproxy_tls_context_t *context);

#endif
