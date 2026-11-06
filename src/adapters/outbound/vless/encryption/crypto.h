#ifndef SOLARIS_VLESS_ENCRYPTION_CRYPTO_H
#define SOLARIS_VLESS_ENCRYPTION_CRYPTO_H

#include "contracts/runtime/crypto.h"
#include <openssl/aead.h>
#include <openssl/aes.h>

typedef struct solaris_vless_encryption_aead {
    EVP_AEAD_CTX context;
    uint8_t nonce[12];
} solaris_vless_encryption_aead_t;
typedef struct solaris_vless_encryption_ctr {
    AES_KEY key;
    uint8_t iv[16], block[16];
    unsigned int offset;
} solaris_vless_encryption_ctr_t;
typedef struct solaris_vless_encryption_mask {
    uint8_t header[5];
    size_t header_size, remaining;
} solaris_vless_encryption_mask_t;
solaris_status_t solaris_vless_encryption_random(const solaris_crypto_source_t *source, uint8_t *out, size_t size);
solaris_status_t solaris_vless_encryption_uniform(const solaris_crypto_source_t *source, uint32_t bound, uint32_t *out);
void solaris_vless_encryption_derive(const void *context, size_t context_size, const void *key, size_t key_size, uint8_t out[32]);
void solaris_vless_encryption_hash(const void *data, size_t size, uint8_t out[32]);
solaris_status_t solaris_vless_encryption_aead_init(solaris_vless_encryption_aead_t *out, int chacha,
    const void *context, size_t context_size, const void *key, size_t key_size);
/* A NULL nonce increments the internal big-endian nonce, committing only on
 * success. Explicit nonces leave the running counter unchanged. */
solaris_status_t solaris_vless_encryption_seal(solaris_vless_encryption_aead_t *aead, const uint8_t *nonce,
    const uint8_t *plain, size_t size, const uint8_t *aad, size_t aad_size, uint8_t *out);
solaris_status_t solaris_vless_encryption_unseal(solaris_vless_encryption_aead_t *aead, const uint8_t *nonce,
    const uint8_t *wire, size_t size, const uint8_t *aad, size_t aad_size, uint8_t *out);
void solaris_vless_encryption_aead_clear(solaris_vless_encryption_aead_t *aead);
int solaris_vless_encryption_nonce_max(const solaris_vless_encryption_aead_t *aead);
void solaris_vless_encryption_ctr_init(solaris_vless_encryption_ctr_t *ctr, const void *key, size_t key_size, const uint8_t iv[16]);
void solaris_vless_encryption_ctr_apply(solaris_vless_encryption_ctr_t *ctr, const uint8_t *in, uint8_t *out, size_t size);
/* Record helpers preserve the counter and header mask when input is partial or
 * authentication fails. The caller allocates plaintext before opening a record. */
solaris_status_t solaris_vless_encryption_record_size(const solaris_vless_encryption_ctr_t *ctr, int masked,
    const uint8_t *wire, size_t size, size_t *cipher_size);
solaris_status_t solaris_vless_encryption_record_seal(solaris_vless_encryption_aead_t *aead,
    solaris_vless_encryption_ctr_t *ctr, int masked, int chacha, const uint8_t united[96],
    const uint8_t *plain, size_t size, uint8_t *out);
solaris_status_t solaris_vless_encryption_record_open(solaris_vless_encryption_aead_t *aead,
    solaris_vless_encryption_ctr_t *ctr, int masked, int chacha, const uint8_t united[96],
    const uint8_t *wire, size_t size, uint8_t *out);
/* Random appearance preserves header CTR after bypassing the AEAD layer.
 * Input may split any header or body; rejected input commits no mask state. */
solaris_status_t solaris_vless_encryption_mask_stream(solaris_vless_encryption_ctr_t *ctr,
    solaris_vless_encryption_mask_t *mask, int encrypt, const uint8_t *input, size_t size, uint8_t *out);

#endif
