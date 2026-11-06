#include "adapters/outbound/vless/encryption/crypto.h"
#include "blake3.h"
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <string.h>

solaris_status_t solaris_vless_encryption_random(const solaris_crypto_source_t *source, uint8_t *out, size_t size)
{ return source->random != NULL ? source->random(source->context, out, size) : RAND_bytes(out, size) ? SOLARIS_OK : SOLARIS_EIO; }
solaris_status_t solaris_vless_encryption_uniform(const solaris_crypto_source_t *source, uint32_t bound, uint32_t *out)
{
    if (bound == 0u) return SOLARIS_EINVAL;
    uint32_t threshold = (0u - bound) % bound;
    for (unsigned int attempt = 0u; attempt < 16u; ++attempt) {
        uint8_t bytes[4]; solaris_status_t rc = solaris_vless_encryption_random(source, bytes, sizeof(bytes));
        if (rc != SOLARIS_OK) return rc;
        uint32_t n = ((uint32_t)bytes[0] << 24u) | ((uint32_t)bytes[1] << 16u) | ((uint32_t)bytes[2] << 8u) | bytes[3];
        if (n >= threshold) { *out = n % bound; return SOLARIS_OK; }
    }
    return SOLARIS_EIO;
}
void solaris_vless_encryption_derive(const void *context, size_t context_size, const void *key, size_t key_size, uint8_t out[32])
{
    blake3_hasher hash; blake3_hasher_init_derive_key_raw(&hash, context, context_size);
    blake3_hasher_update(&hash, key, key_size); blake3_hasher_finalize(&hash, out, 32u); OPENSSL_cleanse(&hash, sizeof(hash));
}
void solaris_vless_encryption_hash(const void *data, size_t size, uint8_t out[32])
{
    blake3_hasher hash; blake3_hasher_init(&hash); blake3_hasher_update(&hash, data, size);
    blake3_hasher_finalize(&hash, out, 32u); OPENSSL_cleanse(&hash, sizeof(hash));
}
solaris_status_t solaris_vless_encryption_aead_init(solaris_vless_encryption_aead_t *out, int chacha,
    const void *context, size_t context_size, const void *key, size_t key_size)
{
    uint8_t derived[32]; solaris_vless_encryption_derive(context, context_size, key, key_size, derived);
    solaris_vless_encryption_aead_t next = {0};
    int ok = EVP_AEAD_CTX_init(&next.context, chacha ? EVP_aead_chacha20_poly1305() : EVP_aead_aes_256_gcm(), derived, 32u, 16u, NULL);
    OPENSSL_cleanse(derived, sizeof(derived));
    if (!ok) { EVP_AEAD_CTX_cleanup(&next.context); return SOLARIS_EIO; }
    EVP_AEAD_CTX_cleanup(&out->context); *out = next; OPENSSL_cleanse(&next, sizeof(next)); return SOLARIS_OK;
}
static void increment(uint8_t nonce[12])
{ for (size_t i = 12u; i > 0u; --i) if (++nonce[i - 1u] != 0u) break; }
solaris_status_t solaris_vless_encryption_seal(solaris_vless_encryption_aead_t *aead, const uint8_t *nonce,
    const uint8_t *plain, size_t size, const uint8_t *aad, size_t aad_size, uint8_t *out)
{
    uint8_t next[12]; memcpy(next, aead->nonce, sizeof(next));
    if (nonce == NULL) increment(next); else memcpy(next, nonce, sizeof(next));
    size_t written = 0u;
    if (size > SIZE_MAX - 16u || !EVP_AEAD_CTX_seal(&aead->context, out, &written, size + 16u, next, 12u, plain, size, aad, aad_size) ||
        written != size + 16u) return SOLARIS_EIO;
    if (nonce == NULL) memcpy(aead->nonce, next, sizeof(next));
    return SOLARIS_OK;
}
solaris_status_t solaris_vless_encryption_unseal(solaris_vless_encryption_aead_t *aead, const uint8_t *nonce,
    const uint8_t *wire, size_t size, const uint8_t *aad, size_t aad_size, uint8_t *out)
{
    if (size < 16u) return SOLARIS_EIO;
    uint8_t next[12]; memcpy(next, aead->nonce, sizeof(next));
    if (nonce == NULL) increment(next); else memcpy(next, nonce, sizeof(next));
    size_t written = 0u;
    if (!EVP_AEAD_CTX_open(&aead->context, out, &written, size - 16u, next, 12u, wire, size, aad, aad_size) ||
        written != size - 16u) return SOLARIS_EACCESS;
    if (nonce == NULL) memcpy(aead->nonce, next, sizeof(next));
    return SOLARIS_OK;
}
void solaris_vless_encryption_aead_clear(solaris_vless_encryption_aead_t *aead)
{ EVP_AEAD_CTX_cleanup(&aead->context); OPENSSL_cleanse(aead, sizeof(*aead)); }
int solaris_vless_encryption_nonce_max(const solaris_vless_encryption_aead_t *aead)
{ for (size_t i = 0u; i < 12u; ++i) if (aead->nonce[i] != 255u) return 0; return 1; }
void solaris_vless_encryption_ctr_init(solaris_vless_encryption_ctr_t *ctr, const void *key, size_t key_size, const uint8_t iv[16])
{
    uint8_t derived[32]; solaris_vless_encryption_derive("VLESS", 5u, key, key_size, derived);
    memset(ctr, 0, sizeof(*ctr)); (void)AES_set_encrypt_key(derived, 256u, &ctr->key); memcpy(ctr->iv, iv, 16u);
    OPENSSL_cleanse(derived, sizeof(derived));
}
void solaris_vless_encryption_ctr_apply(solaris_vless_encryption_ctr_t *ctr, const uint8_t *in, uint8_t *out, size_t size)
{ AES_ctr128_encrypt(in, out, size, &ctr->key, ctr->iv, ctr->block, &ctr->offset); }
static void record_header(const solaris_vless_encryption_ctr_t *ctr, int masked, const uint8_t *wire,
    uint8_t header[5], solaris_vless_encryption_ctr_t *next)
{
    *next = *ctr;
    if (masked) solaris_vless_encryption_ctr_apply(next, wire, header, 5u);
    else memcpy(header, wire, 5u);
}
solaris_status_t solaris_vless_encryption_record_size(const solaris_vless_encryption_ctr_t *ctr, int masked,
    const uint8_t *wire, size_t size, size_t *cipher_size)
{
    *cipher_size = 0u; if (size < 5u) return SOLARIS_EAGAIN;
    uint8_t header[5]; solaris_vless_encryption_ctr_t next; record_header(ctr, masked, wire, header, &next);
    size_t length = ((size_t)header[3] << 8u) | header[4];
    if (header[0] != 23u || header[1] != 3u || header[2] != 3u || length < 17u || length > 16640u) return SOLARIS_EIO;
    *cipher_size = length; return size < length + 5u ? SOLARIS_EAGAIN : SOLARIS_OK;
}
solaris_status_t solaris_vless_encryption_record_seal(solaris_vless_encryption_aead_t *aead,
    solaris_vless_encryption_ctr_t *ctr, int masked, int chacha, const uint8_t united[96],
    const uint8_t *plain, size_t size, uint8_t *out)
{
    if (size == 0u || size > 8192u) return SOLARIS_EMSGSIZE;
    out[0] = 23u; out[1] = out[2] = 3u; out[3] = (uint8_t)((size + 16u) >> 8u); out[4] = (uint8_t)(size + 16u);
    int rekey = solaris_vless_encryption_nonce_max(aead);
    solaris_status_t rc = solaris_vless_encryption_seal(aead, NULL, plain, size, out, 5u, out + 5u);
    if (rc == SOLARIS_OK && rekey) rc = solaris_vless_encryption_aead_init(aead, chacha, out, size + 21u, united, 96u);
    if (rc == SOLARIS_OK && masked) solaris_vless_encryption_ctr_apply(ctr, out, out, 5u);
    return rc;
}
solaris_status_t solaris_vless_encryption_record_open(solaris_vless_encryption_aead_t *aead,
    solaris_vless_encryption_ctr_t *ctr, int masked, int chacha, const uint8_t united[96],
    const uint8_t *wire, size_t size, uint8_t *out)
{
    size_t length; solaris_status_t rc = solaris_vless_encryption_record_size(ctr, masked, wire, size, &length);
    if (rc != SOLARIS_OK) return rc;
    uint8_t header[5]; solaris_vless_encryption_ctr_t next; record_header(ctr, masked, wire, header, &next);
    int rekey = solaris_vless_encryption_nonce_max(aead);
    rc = solaris_vless_encryption_unseal(aead, NULL, wire + 5u, length, header, 5u, out);
    if (rc == SOLARIS_OK && rekey) {
        uint8_t context[16645]; memcpy(context, header, 5u); memcpy(context + 5u, wire + 5u, length);
        rc = solaris_vless_encryption_aead_init(aead, chacha, context, length + 5u, united, 96u);
    }
    if (rc == SOLARIS_OK) *ctr = next;
    return rc;
}
solaris_status_t solaris_vless_encryption_mask_stream(solaris_vless_encryption_ctr_t *ctr,
    solaris_vless_encryption_mask_t *mask, int encrypt, const uint8_t *input, size_t size, uint8_t *out)
{
    solaris_vless_encryption_ctr_t next = *ctr; solaris_vless_encryption_mask_t frame = *mask;
    size_t offset = 0u;
    while (offset < size) {
        size_t count = size - offset;
        if (frame.remaining != 0u) {
            if (count > frame.remaining) count = frame.remaining;
            memcpy(out + offset, input + offset, count); frame.remaining -= count;
        } else {
            if (count > 5u - frame.header_size) count = 5u - frame.header_size;
            if (encrypt) memcpy(frame.header + frame.header_size, input + offset, count);
            solaris_vless_encryption_ctr_apply(&next, input + offset, out + offset, count);
            if (!encrypt) memcpy(frame.header + frame.header_size, out + offset, count);
            frame.header_size += count;
            if (frame.header_size == 5u) {
                size_t length = ((size_t)frame.header[3] << 8u) | frame.header[4];
                if (frame.header[0] != 23u || frame.header[1] != 3u || frame.header[2] != 3u || length < 17u || length > 16640u)
                    return SOLARIS_EIO;
                frame.header_size = 0u; frame.remaining = length;
            }
        }
        offset += count;
    }
    *ctr = next; *mask = frame; return SOLARIS_OK;
}
