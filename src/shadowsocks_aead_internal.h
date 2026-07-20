#ifndef SHADOWSOCKS_AEAD_INTERNAL_H
#define SHADOWSOCKS_AEAD_INTERNAL_H

#include <openssl/aead.h>

#include "shadowsocks/aead.h"

const EVP_AEAD *shadowsocks_aead_evp(shadowsocks_aead_method_t method);

int shadowsocks_aead_derive_subkey(shadowsocks_aead_method_t method,
                                   const uint8_t *key,
                                   size_t key_len,
                                   const uint8_t *salt,
                                   uint8_t *out_subkey);

int shadowsocks_aead_init_ctx(shadowsocks_aead_method_t method,
                              const uint8_t *subkey,
                              EVP_AEAD_CTX *ctx,
                              const EVP_AEAD **out_aead);

int shadowsocks_2022_session_key(shadowsocks_aead_method_t method,
                                 const uint8_t *key,
                                 size_t key_len,
                                 const uint8_t *salt,
                                 size_t salt_len,
                                 uint8_t *out_key);

#endif
