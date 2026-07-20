#include "shadowsocks/aead.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/aead.h>
#include <openssl/aes.h>
#include <openssl/base64.h>
#include <openssl/digest.h>
#include <openssl/hkdf.h>
#include <openssl/md5.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "blake3.h"
#include "byteorder.h"
#include "shadowsocks_aead_internal.h"

static const char ss_subkey_info[] = "ss-subkey";
static const char ss_2022_session_key_context[] =
    "shadowsocks 2022 session subkey";
static const char ss_2022_identity_key_context[] =
    "shadowsocks 2022 identity subkey";

#define SS_2022_HEADER_TYPE_CLIENT 0u
#define SS_2022_HEADER_TYPE_SERVER 1u
#define SS_2022_MAX_PADDING_LEN 900u
#define SS_2022_TIMESTAMP_WINDOW 30

static void put_u64(uint8_t *out, uint64_t v)
{
    anytls_put_u32_be(out, (uint32_t)(v >> 32u));
    anytls_put_u32_be(out + 4u, (uint32_t)v);
}

static uint64_t get_u64(const uint8_t *in)
{
    return ((uint64_t)anytls_get_u32_be(in) << 32u) |
           (uint64_t)anytls_get_u32_be(in + 4u);
}

static int timestamp_is_fresh(uint64_t epoch)
{
    const time_t now = time(NULL);
    if (now == (time_t)-1) {
        return 0;
    }
    const int64_t diff = (int64_t)now - (int64_t)epoch;
    return diff >= -SS_2022_TIMESTAMP_WINDOW &&
           diff <= SS_2022_TIMESTAMP_WINDOW;
}

static int random_padding(size_t payload_len,
                          uint16_t port,
                          uint16_t *out_padding_len)
{
    if (out_padding_len == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    *out_padding_len = 0u;
    if (port != 53u || payload_len >= SS_2022_MAX_PADDING_LEN) {
        return APROXY_OK;
    }
    const uint16_t limit = (uint16_t)(SS_2022_MAX_PADDING_LEN -
                                     payload_len);
    uint8_t rnd[2];
    if (RAND_bytes(rnd, sizeof(rnd)) != 1) {
        return APROXY_ERR_CRYPTO;
    }
    const uint16_t value = anytls_get_u16_be(rnd);
    *out_padding_len = (uint16_t)(value % limit + 1u);
    return APROXY_OK;
}

static int aes_crypt_block(const uint8_t *key,
                           size_t key_len,
                           uint8_t block[16],
                           int encrypt)
{
    AES_KEY aes;
    const unsigned bits = (unsigned)(key_len * 8u);
    if (encrypt) {
        if (AES_set_encrypt_key(key, bits, &aes) != 0) {
            return APROXY_ERR_CRYPTO;
        }
        AES_encrypt(block, block, &aes);
    } else {
        if (AES_set_decrypt_key(key, bits, &aes) != 0) {
            return APROXY_ERR_CRYPTO;
        }
        AES_decrypt(block, block, &aes);
    }
    return APROXY_OK;
}

static int method_is_2022_chacha(shadowsocks_aead_method_t method)
{
    return method == SHADOWSOCKS_AEAD_2022_BLAKE3_CHACHA20_POLY1305;
}

static void secure_zero(void *data, size_t len)
{
    volatile uint8_t *p = (volatile uint8_t *)data;
    while (len-- > 0u) {
        *p++ = 0u;
    }
}

static int buffers_overlap(const uint8_t *a,
                           size_t a_len,
                           const uint8_t *b,
                           size_t b_len)
{
    if (a == NULL || b == NULL || a_len == 0u || b_len == 0u) {
        return 0;
    }
    const uintptr_t a_start = (uintptr_t)a;
    const uintptr_t b_start = (uintptr_t)b;
    if (a_len > UINTPTR_MAX - a_start || b_len > UINTPTR_MAX - b_start) {
        return 1;
    }
    return a_start < b_start + b_len && b_start < a_start + a_len;
}

static int normalize_2022_psk(shadowsocks_aead_method_t method,
                              const char *encoded,
                              size_t encoded_len,
                              uint8_t *out)
{
    const size_t key_len = shadowsocks_aead_key_len(method);
    size_t decoded_capacity = 0u;
    if (encoded == NULL || encoded_len == 0u || out == NULL ||
        key_len == 0u || !EVP_DecodedLength(&decoded_capacity, encoded_len)) {
        return APROXY_ERR_PARSE;
    }
    uint8_t *decoded =
        (uint8_t *)malloc(decoded_capacity == 0u ? 1u : decoded_capacity);
    if (decoded == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    size_t decoded_len = 0u;
    const int ok = EVP_DecodeBase64(decoded, &decoded_len, decoded_capacity,
                                    (const uint8_t *)encoded, encoded_len);
    int rc = APROXY_OK;
    if (!ok) {
        rc = APROXY_ERR_PARSE;
    } else if (decoded_len < key_len) {
        rc = APROXY_ERR_INVALID_ARGUMENT;
    } else if (decoded_len == key_len) {
        memcpy(out, decoded, key_len);
    } else {
        uint8_t digest[SHA256_DIGEST_LENGTH];
        SHA256(decoded, decoded_len, digest);
        memcpy(out, digest, key_len);
        secure_zero(digest, sizeof(digest));
    }
    secure_zero(decoded, decoded_capacity);
    free(decoded);
    return rc;
}

static const EVP_AEAD *shadowsocks_2022_udp_aead(
    shadowsocks_aead_method_t method)
{
    if (method_is_2022_chacha(method)) {
        return EVP_aead_xchacha20_poly1305();
    }
    return shadowsocks_aead_evp(method);
}

int shadowsocks_aead_method_from_name(const char *name,
                                      shadowsocks_aead_method_t *out)
{
    if (name == NULL || out == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    if (strcmp(name, "aes-128-gcm") == 0) {
        *out = SHADOWSOCKS_AEAD_AES_128_GCM;
        return APROXY_OK;
    }
    if (strcmp(name, "aes-192-gcm") == 0) {
        *out = SHADOWSOCKS_AEAD_AES_192_GCM;
        return APROXY_OK;
    }
    if (strcmp(name, "aes-256-gcm") == 0) {
        *out = SHADOWSOCKS_AEAD_AES_256_GCM;
        return APROXY_OK;
    }
    if (strcmp(name, "chacha20-ietf-poly1305") == 0) {
        *out = SHADOWSOCKS_AEAD_CHACHA20_IETF_POLY1305;
        return APROXY_OK;
    }
    if (strcmp(name, "xchacha20-ietf-poly1305") == 0) {
        *out = SHADOWSOCKS_AEAD_XCHACHA20_IETF_POLY1305;
        return APROXY_OK;
    }
    if (strcmp(name, "2022-blake3-aes-128-gcm") == 0) {
        *out = SHADOWSOCKS_AEAD_2022_BLAKE3_AES_128_GCM;
        return APROXY_OK;
    }
    if (strcmp(name, "2022-blake3-aes-256-gcm") == 0) {
        *out = SHADOWSOCKS_AEAD_2022_BLAKE3_AES_256_GCM;
        return APROXY_OK;
    }
    if (strcmp(name, "2022-blake3-chacha20-poly1305") == 0) {
        *out = SHADOWSOCKS_AEAD_2022_BLAKE3_CHACHA20_POLY1305;
        return APROXY_OK;
    }
    return APROXY_ERR_UNSUPPORTED;
}

size_t shadowsocks_aead_key_len(shadowsocks_aead_method_t method)
{
    switch (method) {
    case SHADOWSOCKS_AEAD_AES_128_GCM:
    case SHADOWSOCKS_AEAD_2022_BLAKE3_AES_128_GCM:
        return 16u;
    case SHADOWSOCKS_AEAD_AES_192_GCM:
        return 24u;
    case SHADOWSOCKS_AEAD_AES_256_GCM:
    case SHADOWSOCKS_AEAD_CHACHA20_IETF_POLY1305:
    case SHADOWSOCKS_AEAD_XCHACHA20_IETF_POLY1305:
    case SHADOWSOCKS_AEAD_2022_BLAKE3_AES_256_GCM:
    case SHADOWSOCKS_AEAD_2022_BLAKE3_CHACHA20_POLY1305:
        return 32u;
    default:
        return 0u;
    }
}

const EVP_AEAD *shadowsocks_aead_evp(shadowsocks_aead_method_t method)
{
    switch (method) {
    case SHADOWSOCKS_AEAD_AES_128_GCM:
    case SHADOWSOCKS_AEAD_2022_BLAKE3_AES_128_GCM:
        return EVP_aead_aes_128_gcm();
    case SHADOWSOCKS_AEAD_AES_192_GCM:
        return EVP_aead_aes_192_gcm();
    case SHADOWSOCKS_AEAD_AES_256_GCM:
    case SHADOWSOCKS_AEAD_2022_BLAKE3_AES_256_GCM:
        return EVP_aead_aes_256_gcm();
    case SHADOWSOCKS_AEAD_CHACHA20_IETF_POLY1305:
    case SHADOWSOCKS_AEAD_2022_BLAKE3_CHACHA20_POLY1305:
        return EVP_aead_chacha20_poly1305();
    case SHADOWSOCKS_AEAD_XCHACHA20_IETF_POLY1305:
        return EVP_aead_xchacha20_poly1305();
    default:
        return NULL;
    }
}

int shadowsocks_aead_method_is_2022(shadowsocks_aead_method_t method)
{
    return method == SHADOWSOCKS_AEAD_2022_BLAKE3_AES_128_GCM ||
           method == SHADOWSOCKS_AEAD_2022_BLAKE3_AES_256_GCM ||
           method == SHADOWSOCKS_AEAD_2022_BLAKE3_CHACHA20_POLY1305;
}

int shadowsocks_aead_key_from_password(shadowsocks_aead_method_t method,
                                       const char *password,
                                       uint8_t *out_key,
                                       size_t out_capacity,
                                       size_t *out_len)
{
    if (password == NULL || out_key == NULL || out_len == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    if (shadowsocks_aead_method_is_2022(method)) {
        return APROXY_ERR_UNSUPPORTED;
    }
    const size_t key_len = shadowsocks_aead_key_len(method);
    if (key_len == 0u) {
        return APROXY_ERR_UNSUPPORTED;
    }
    *out_len = key_len;
    if (out_capacity < key_len) {
        return APROXY_ERR_BUFFER_TOO_SMALL;
    }

    const uint8_t *password_bytes = (const uint8_t *)password;
    const size_t password_len = strlen(password);
    uint8_t digest[MD5_DIGEST_LENGTH];
    uint8_t previous[MD5_DIGEST_LENGTH];
    size_t previous_len = 0u;
    size_t produced = 0u;
    while (produced < key_len) {
        MD5_CTX md5;
        if (!MD5_Init(&md5)) {
            return APROXY_ERR_CRYPTO;
        }
        if (previous_len > 0u && !MD5_Update(&md5, previous,
                                             previous_len)) {
            return APROXY_ERR_CRYPTO;
        }
        if (!MD5_Update(&md5, password_bytes, password_len) ||
            !MD5_Final(digest, &md5)) {
            return APROXY_ERR_CRYPTO;
        }
        const size_t take = key_len - produced < sizeof(digest)
                                ? key_len - produced
                                : sizeof(digest);
        memcpy(out_key + produced, digest, take);
        memcpy(previous, digest, sizeof(digest));
        previous_len = sizeof(digest);
        produced += take;
    }
    return APROXY_OK;
}

int shadowsocks_2022_key_from_password(shadowsocks_aead_method_t method,
                                       const char *password,
                                       uint8_t *out_key,
                                       size_t out_capacity,
                                       size_t *out_len)
{
    if (password == NULL || out_key == NULL || out_len == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    if (!shadowsocks_aead_method_is_2022(method)) {
        return APROXY_ERR_UNSUPPORTED;
    }
    const size_t key_len = shadowsocks_aead_key_len(method);
    *out_len = key_len;
    if (out_capacity < key_len) {
        return APROXY_ERR_BUFFER_TOO_SMALL;
    }
    if (strchr(password, ':') != NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    return normalize_2022_psk(method, password, strlen(password), out_key);
}

int shadowsocks_2022_psk_list_parse(shadowsocks_aead_method_t method,
                                    const char *password,
                                    shadowsocks_2022_psk_list_t *out)
{
    if (password == NULL || out == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    memset(out, 0, sizeof(*out));
    if (!shadowsocks_aead_method_is_2022(method)) {
        return APROXY_ERR_UNSUPPORTED;
    }

    const size_t key_len = shadowsocks_aead_key_len(method);
    size_t count = 1u;
    for (const char *p = password; *p != '\0'; p++) {
        if (*p == ':') {
            count++;
        }
    }
    if (password[0] == '\0' || count > SIZE_MAX / key_len ||
        (method_is_2022_chacha(method) && count != 1u)) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }

    uint8_t *keys = (uint8_t *)calloc(count, key_len);
    if (keys == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    const char *start = password;
    int rc = APROXY_OK;
    for (size_t i = 0u; i < count; i++) {
        const char *end = strchr(start, ':');
        const size_t token_len = end == NULL ? strlen(start)
                                             : (size_t)(end - start);
        rc = normalize_2022_psk(method, start, token_len,
                                keys + i * key_len);
        if (rc != APROXY_OK) {
            secure_zero(keys, count * key_len);
            free(keys);
            return rc;
        }
        start = end == NULL ? start + token_len : end + 1u;
    }
    out->keys = keys;
    out->count = count;
    out->key_len = key_len;
    return APROXY_OK;
}

void shadowsocks_2022_psk_list_free(shadowsocks_2022_psk_list_t *list)
{
    if (list == NULL) {
        return;
    }
    if (list->keys != NULL && list->key_len > 0u &&
        list->count <= SIZE_MAX / list->key_len) {
        secure_zero(list->keys, list->count * list->key_len);
    }
    free(list->keys);
    memset(list, 0, sizeof(*list));
}

const uint8_t *shadowsocks_2022_psk_at(
    const shadowsocks_2022_psk_list_t *list,
    size_t index)
{
    if (list == NULL || list->keys == NULL || index >= list->count ||
        list->key_len == 0u) {
        return NULL;
    }
    return list->keys + index * list->key_len;
}

int shadowsocks_2022_tcp_eih_write(
    shadowsocks_aead_method_t method,
    const shadowsocks_2022_psk_list_t *psks,
    const uint8_t *salt,
    size_t salt_len,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len)
{
    if (!shadowsocks_aead_method_is_2022(method) || psks == NULL ||
        psks->keys == NULL || psks->count == 0u || salt == NULL ||
        out_len == NULL || psks->key_len != shadowsocks_aead_key_len(method) ||
        salt_len != psks->key_len) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    if (method_is_2022_chacha(method) && psks->count > 1u) {
        return APROXY_ERR_UNSUPPORTED;
    }
    if (psks->count - 1u > SIZE_MAX / 16u) {
        return APROXY_ERR_FRAME_TOO_LARGE;
    }
    const size_t need = (psks->count - 1u) * 16u;
    *out_len = need;
    if (need == 0u) {
        return APROXY_OK;
    }
    if (out == NULL || out_capacity < need) {
        return APROXY_ERR_BUFFER_TOO_SMALL;
    }

    for (size_t i = 0u; i + 1u < psks->count; i++) {
        const uint8_t *identity_psk = shadowsocks_2022_psk_at(psks, i);
        const uint8_t *next_psk = shadowsocks_2022_psk_at(psks, i + 1u);
        uint8_t identity_key[SHADOWSOCKS_AEAD_MAX_KEY_LEN];
        blake3_hasher hasher;
        blake3_hasher_init_derive_key(&hasher,
                                      ss_2022_identity_key_context);
        blake3_hasher_update(&hasher, identity_psk, psks->key_len);
        blake3_hasher_update(&hasher, salt, salt_len);
        blake3_hasher_finalize(&hasher, identity_key, psks->key_len);

        blake3_hasher_init(&hasher);
        blake3_hasher_update(&hasher, next_psk, psks->key_len);
        blake3_hasher_finalize(&hasher, out + i * 16u, 16u);
        const int rc = aes_crypt_block(identity_key, psks->key_len,
                                       out + i * 16u, 1);
        secure_zero(identity_key, sizeof(identity_key));
        if (rc != APROXY_OK) {
            return rc;
        }
    }
    return APROXY_OK;
}

int shadowsocks_aead_derive_subkey(shadowsocks_aead_method_t method,
                                   const uint8_t *key,
                                   size_t key_len,
                                   const uint8_t *salt,
                                   uint8_t *out_subkey)
{
    const size_t expected = shadowsocks_aead_key_len(method);
    if (expected == 0u || key == NULL || salt == NULL ||
        out_subkey == NULL || key_len != expected) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    return HKDF(out_subkey, expected, EVP_sha1(), key, key_len, salt,
                expected, (const uint8_t *)ss_subkey_info,
                sizeof(ss_subkey_info) - 1u)
               ? APROXY_OK
               : APROXY_ERR_CRYPTO;
}

int shadowsocks_2022_session_key(shadowsocks_aead_method_t method,
                                 const uint8_t *key,
                                 size_t key_len,
                                 const uint8_t *salt,
                                 size_t salt_len,
                                 uint8_t *out_key)
{
    const size_t expected = shadowsocks_aead_key_len(method);
    if (!shadowsocks_aead_method_is_2022(method) || key == NULL ||
        salt == NULL || out_key == NULL || key_len != expected ||
        salt_len == 0u || salt_len > SHADOWSOCKS_AEAD_MAX_SALT_LEN) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }

    blake3_hasher hasher;
    blake3_hasher_init_derive_key(&hasher, ss_2022_session_key_context);
    blake3_hasher_update(&hasher, key, key_len);
    blake3_hasher_update(&hasher, salt, salt_len);
    blake3_hasher_finalize(&hasher, out_key, expected);
    return APROXY_OK;
}

int shadowsocks_aead_init_ctx(shadowsocks_aead_method_t method,
                              const uint8_t *subkey,
                              EVP_AEAD_CTX *ctx,
                              const EVP_AEAD **out_aead)
{
    const EVP_AEAD *aead = shadowsocks_aead_evp(method);
    const size_t key_len = shadowsocks_aead_key_len(method);
    if (aead == NULL || subkey == NULL || ctx == NULL ||
        out_aead == NULL || EVP_AEAD_key_length(aead) != key_len) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    EVP_AEAD_CTX_zero(ctx);
    if (!EVP_AEAD_CTX_init(ctx, aead, subkey, key_len,
                           EVP_AEAD_DEFAULT_TAG_LENGTH, NULL)) {
        return APROXY_ERR_CRYPTO;
    }
    *out_aead = aead;
    return APROXY_OK;
}

int shadowsocks_aead_udp_seal(shadowsocks_aead_method_t method,
                              const uint8_t *key,
                              size_t key_len,
                              const uint8_t *salt,
                              const aproxy_addr_t *destination,
                              const uint8_t *payload,
                              size_t payload_len,
                              uint8_t *out,
                              size_t out_capacity,
                              size_t *out_len)
{
    if (key == NULL || destination == NULL ||
        (payload == NULL && payload_len > 0u) || out == NULL ||
        out_len == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    const size_t salt_len = shadowsocks_aead_key_len(method);
    const EVP_AEAD *aead = shadowsocks_aead_evp(method);
    if (salt_len == 0u || aead == NULL || key_len != salt_len ||
        shadowsocks_aead_method_is_2022(method)) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }

    size_t addr_len = 0u;
    int rc = aproxy_addr_encode_socksaddr(destination, NULL, 0u,
                                          &addr_len);
    if (rc != APROXY_ERR_BUFFER_TOO_SMALL) {
        return rc;
    }
    const size_t plaintext_len = addr_len + payload_len;
    const size_t need = salt_len + plaintext_len + EVP_AEAD_max_overhead(aead);
    *out_len = need;
    if (out_capacity < need) {
        return APROXY_ERR_BUFFER_TOO_SMALL;
    }

    uint8_t *plaintext = out + salt_len;
    if (payload_len > 0u) {
        memmove(plaintext + addr_len, payload, payload_len);
    }

    if (salt != NULL) {
        memcpy(out, salt, salt_len);
    } else if (RAND_bytes(out, salt_len) != 1) {
        return APROXY_ERR_CRYPTO;
    }
    uint8_t subkey[SHADOWSOCKS_AEAD_MAX_KEY_LEN];
    rc = shadowsocks_aead_derive_subkey(method, key, key_len, out, subkey);
    if (rc != APROXY_OK) {
        return rc;
    }

    rc = aproxy_addr_encode_socksaddr(destination, plaintext, addr_len,
                                      &addr_len);
    if (rc != APROXY_OK) {
        return rc;
    }

    EVP_AEAD_CTX ctx;
    const EVP_AEAD *ctx_aead = NULL;
    rc = shadowsocks_aead_init_ctx(method, subkey, &ctx, &ctx_aead);
    if (rc != APROXY_OK) {
        return rc;
    }
    uint8_t nonce[EVP_AEAD_MAX_NONCE_LENGTH] = {0};
    size_t sealed_len = 0u;
    const int ok = EVP_AEAD_CTX_seal(
        &ctx, out + salt_len, &sealed_len, out_capacity - salt_len,
        nonce, EVP_AEAD_nonce_length(ctx_aead), plaintext, plaintext_len,
        NULL, 0u);
    EVP_AEAD_CTX_cleanup(&ctx);
    if (!ok) {
        return APROXY_ERR_CRYPTO;
    }
    *out_len = salt_len + sealed_len;
    return APROXY_OK;
}

int shadowsocks_aead_udp_open(shadowsocks_aead_method_t method,
                              const uint8_t *key,
                              size_t key_len,
                              const uint8_t *packet,
                              size_t packet_len,
                              aproxy_addr_t *source,
                              uint8_t *payload_out,
                              size_t payload_capacity,
                              size_t *payload_len)
{
    if (key == NULL || packet == NULL || source == NULL ||
        payload_out == NULL || payload_len == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    const size_t salt_len = shadowsocks_aead_key_len(method);
    const EVP_AEAD *aead = shadowsocks_aead_evp(method);
    if (salt_len == 0u || aead == NULL || key_len != salt_len ||
        shadowsocks_aead_method_is_2022(method) ||
        packet_len < salt_len + EVP_AEAD_max_overhead(aead)) {
        return APROXY_ERR_INVALID_FRAME;
    }

    uint8_t subkey[SHADOWSOCKS_AEAD_MAX_KEY_LEN];
    int rc = shadowsocks_aead_derive_subkey(method, key, key_len, packet,
                                            subkey);
    if (rc != APROXY_OK) {
        return rc;
    }

    const size_t ciphertext_len = packet_len - salt_len;
    const uint8_t *ciphertext = packet + salt_len;
    const int use_output_buffer = payload_capacity >= ciphertext_len &&
                                  !buffers_overlap(payload_out,
                                                   ciphertext_len,
                                                   ciphertext,
                                                   ciphertext_len);
    uint8_t *plaintext = use_output_buffer
                             ? payload_out
                             : (uint8_t *)malloc(ciphertext_len == 0u
                                                    ? 1u
                                                    : ciphertext_len);
    if (plaintext == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }

    EVP_AEAD_CTX ctx;
    const EVP_AEAD *ctx_aead = NULL;
    rc = shadowsocks_aead_init_ctx(method, subkey, &ctx, &ctx_aead);
    if (rc != APROXY_OK) {
        if (!use_output_buffer) {
            free(plaintext);
        }
        return rc;
    }
    uint8_t nonce[EVP_AEAD_MAX_NONCE_LENGTH] = {0};
    size_t plaintext_len = 0u;
    const int ok = EVP_AEAD_CTX_open(
        &ctx, plaintext, &plaintext_len, ciphertext_len, nonce,
        EVP_AEAD_nonce_length(ctx_aead), ciphertext, ciphertext_len,
        NULL, 0u);
    EVP_AEAD_CTX_cleanup(&ctx);
    if (!ok) {
        if (!use_output_buffer) {
            free(plaintext);
        }
        return APROXY_ERR_CRYPTO;
    }

    size_t consumed = 0u;
    rc = aproxy_addr_decode_socksaddr(plaintext, plaintext_len, source,
                                      &consumed);
    if (rc != APROXY_OK) {
        if (!use_output_buffer) {
            free(plaintext);
        }
        return rc;
    }
    const size_t body_len = plaintext_len - consumed;
    *payload_len = body_len;
    if (payload_capacity < body_len) {
        if (!use_output_buffer) {
            free(plaintext);
        }
        return APROXY_ERR_BUFFER_TOO_SMALL;
    }
    if (body_len > 0u) {
        memmove(payload_out, plaintext + consumed, body_len);
    }
    if (!use_output_buffer) {
        free(plaintext);
    }
    return APROXY_OK;
}

int shadowsocks_2022_udp_session_new(shadowsocks_aead_method_t method,
                                     const uint8_t *key,
                                     size_t key_len,
                                     uint64_t *session_id,
                                     uint64_t *packet_id,
                                     uint8_t *session_key,
                                     size_t session_key_capacity)
{
    if (!shadowsocks_aead_method_is_2022(method) || key == NULL ||
        session_id == NULL || packet_id == NULL || key_len !=
        shadowsocks_aead_key_len(method)) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }

    uint8_t session_id_bytes[8];
    if (RAND_bytes(session_id_bytes, sizeof(session_id_bytes)) != 1) {
        return APROXY_ERR_CRYPTO;
    }
    *session_id = get_u64(session_id_bytes);
    *packet_id = 0u;

    if (method_is_2022_chacha(method)) {
        if (session_key != NULL && session_key_capacity >= key_len) {
            memset(session_key, 0, key_len);
        }
        return APROXY_OK;
    }

    if (session_key == NULL || session_key_capacity < key_len) {
        return APROXY_ERR_BUFFER_TOO_SMALL;
    }
    return shadowsocks_2022_session_key(method, key, key_len,
                                        session_id_bytes,
                                        sizeof(session_id_bytes),
                                        session_key);
}

int shadowsocks_2022_udp_seal(shadowsocks_aead_method_t method,
                              const uint8_t *key,
                              size_t key_len,
                              uint64_t session_id,
                              uint64_t packet_id,
                              const uint8_t *session_key,
                              const aproxy_addr_t *destination,
                              const uint8_t *payload,
                              size_t payload_len,
                              uint8_t *out,
                              size_t out_capacity,
                              size_t *out_len)
{
    shadowsocks_2022_psk_list_t psks = {
        .keys = (uint8_t *)key,
        .count = key == NULL ? 0u : 1u,
        .key_len = key_len,
    };
    return shadowsocks_2022_udp_seal_multi(
        method, &psks, session_id, packet_id, session_key, destination,
        payload, payload_len, out, out_capacity, out_len);
}

static int write_udp_eih(const shadowsocks_2022_psk_list_t *psks,
                         const uint8_t packet_header[16],
                         uint8_t *out)
{
    for (size_t i = 0u; i + 1u < psks->count; i++) {
        const uint8_t *identity_psk = shadowsocks_2022_psk_at(psks, i);
        const uint8_t *next_psk = shadowsocks_2022_psk_at(psks, i + 1u);
        blake3_hasher hasher;
        uint8_t *identity = out + i * 16u;
        blake3_hasher_init(&hasher);
        blake3_hasher_update(&hasher, next_psk, psks->key_len);
        blake3_hasher_finalize(&hasher, identity, 16u);
        for (size_t j = 0u; j < 16u; j++) {
            identity[j] ^= packet_header[j];
        }
        const int rc = aes_crypt_block(identity_psk, psks->key_len,
                                       identity, 1);
        if (rc != APROXY_OK) {
            return rc;
        }
    }
    return APROXY_OK;
}

int shadowsocks_2022_udp_seal_multi(
    shadowsocks_aead_method_t method,
    const shadowsocks_2022_psk_list_t *psks,
    uint64_t session_id,
    uint64_t packet_id,
    const uint8_t *session_key,
    const aproxy_addr_t *destination,
    const uint8_t *payload,
    size_t payload_len,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len)
{
    if (!shadowsocks_aead_method_is_2022(method) || psks == NULL ||
        psks->keys == NULL || psks->count == 0u ||
        destination == NULL || (payload == NULL && payload_len > 0u) ||
        out == NULL || out_len == NULL ||
        psks->key_len != shadowsocks_aead_key_len(method)) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    const int chacha = method_is_2022_chacha(method);
    if ((chacha && psks->count != 1u) || (!chacha && session_key == NULL)) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    const uint8_t *first_key = shadowsocks_2022_psk_at(psks, 0u);
    const uint8_t *last_key = shadowsocks_2022_psk_at(psks,
                                                      psks->count - 1u);
    const size_t key_len = psks->key_len;

    size_t addr_len = 0u;
    int rc = aproxy_addr_encode_socksaddr(destination, NULL, 0u,
                                          &addr_len);
    if (rc != APROXY_ERR_BUFFER_TOO_SMALL) {
        return rc;
    }
    uint16_t padding_len = 0u;
    rc = random_padding(payload_len, destination->port, &padding_len);
    if (rc != APROXY_OK) {
        return rc;
    }
    const size_t plaintext_tail_len = 1u + 8u + 2u + padding_len +
                                      addr_len + payload_len;
    if (psks->count - 1u > SIZE_MAX / 16u) {
        return APROXY_ERR_FRAME_TOO_LARGE;
    }
    const size_t identity_len = chacha ? 0u : (psks->count - 1u) * 16u;
    const size_t packet_header_len = 16u + identity_len;
    if (plaintext_tail_len > SIZE_MAX - packet_header_len) {
        return APROXY_ERR_FRAME_TOO_LARGE;
    }
    const size_t plaintext_len = packet_header_len + plaintext_tail_len;
    const EVP_AEAD *aead = shadowsocks_2022_udp_aead(method);
    if (aead == NULL) {
        return APROXY_ERR_UNSUPPORTED;
    }
    const size_t prefix_len = chacha ? SHADOWSOCKS_2022_PACKET_NONCE_LEN
                                     : 0u;
    const size_t need = prefix_len + plaintext_len +
                        EVP_AEAD_max_overhead(aead);
    *out_len = need;
    if (out_capacity < need) {
        return APROXY_ERR_BUFFER_TOO_SMALL;
    }

    size_t pos = 0u;
    if (chacha) {
        if (RAND_bytes(out, SHADOWSOCKS_2022_PACKET_NONCE_LEN) != 1) {
            return APROXY_ERR_CRYPTO;
        }
        pos = SHADOWSOCKS_2022_PACKET_NONCE_LEN;
    }
    uint8_t *plain = out + pos;
    put_u64(plain, session_id);
    put_u64(plain + 8u, packet_id);
    if (!chacha && identity_len > 0u) {
        rc = write_udp_eih(psks, plain, plain + 16u);
        if (rc != APROXY_OK) {
            return rc;
        }
    }
    size_t plain_pos = packet_header_len;
    plain[plain_pos++] = SS_2022_HEADER_TYPE_CLIENT;
    put_u64(plain + plain_pos, (uint64_t)time(NULL));
    plain_pos += 8u;
    anytls_put_u16_be(plain + plain_pos, padding_len);
    plain_pos += 2u;
    if (padding_len > 0u) {
        if (RAND_bytes(plain + plain_pos, padding_len) != 1) {
            return APROXY_ERR_CRYPTO;
        }
        plain_pos += padding_len;
    }
    rc = aproxy_addr_encode_socksaddr(destination, plain + plain_pos,
                                      addr_len, &addr_len);
    if (rc != APROXY_OK) {
        return rc;
    }
    plain_pos += addr_len;
    if (payload_len > 0u) {
        memcpy(plain + plain_pos, payload, payload_len);
    }

    EVP_AEAD_CTX ctx;
    const uint8_t *aead_key = chacha ? last_key : session_key;
    EVP_AEAD_CTX_zero(&ctx);
    if (!EVP_AEAD_CTX_init(&ctx, aead, aead_key, key_len,
                           EVP_AEAD_DEFAULT_TAG_LENGTH, NULL)) {
        return APROXY_ERR_CRYPTO;
    }
    uint8_t nonce_buf[SHADOWSOCKS_2022_PACKET_NONCE_LEN];
    if (!chacha) {
        memcpy(nonce_buf, plain + 4u, 12u);
    }
    const uint8_t *nonce = chacha ? out : nonce_buf;
    const size_t nonce_len = EVP_AEAD_nonce_length(aead);
    uint8_t *seal_out = chacha ? plain : plain + packet_header_len;
    const uint8_t *seal_in = seal_out;
    const size_t seal_in_len = chacha ? plaintext_len : plaintext_tail_len;
    const size_t seal_max_out = chacha ? out_capacity - pos
                                       : out_capacity - packet_header_len;
    size_t sealed_len = 0u;
    const int ok = EVP_AEAD_CTX_seal(&ctx, seal_out, &sealed_len,
                                     seal_max_out, nonce, nonce_len,
                                     seal_in, seal_in_len, NULL, 0u);
    EVP_AEAD_CTX_cleanup(&ctx);
    if (!ok || sealed_len != seal_in_len + EVP_AEAD_max_overhead(aead)) {
        return APROXY_ERR_CRYPTO;
    }
    if (!chacha) {
        rc = aes_crypt_block(first_key, key_len, out, 1);
        if (rc != APROXY_OK) {
            return rc;
        }
    }
    *out_len = chacha ? pos + sealed_len : packet_header_len + sealed_len;
    return APROXY_OK;
}

static int parse_2022_udp_payload(const uint8_t *plaintext,
                                  size_t plaintext_len,
                                  size_t pos,
                                  uint64_t expected_client_session_id,
                                  aproxy_addr_t *source,
                                  uint8_t *payload_out,
                                  size_t payload_capacity,
                                  size_t *payload_len)
{
    if (plaintext_len - pos < 1u + 8u + 8u + 2u) {
        return APROXY_ERR_INVALID_FRAME;
    }
    if (plaintext[pos++] != SS_2022_HEADER_TYPE_SERVER) {
        return APROXY_ERR_INVALID_FRAME;
    }
    const uint64_t epoch = get_u64(plaintext + pos);
    pos += 8u;
    if (!timestamp_is_fresh(epoch)) {
        return APROXY_ERR_INVALID_FRAME;
    }
    const uint64_t client_session_id = get_u64(plaintext + pos);
    pos += 8u;
    if (expected_client_session_id != 0u &&
        client_session_id != expected_client_session_id) {
        return APROXY_ERR_INVALID_FRAME;
    }
    const uint16_t padding_len = anytls_get_u16_be(plaintext + pos);
    pos += 2u;
    if (plaintext_len - pos < padding_len) {
        return APROXY_ERR_INVALID_FRAME;
    }
    pos += padding_len;

    size_t consumed = 0u;
    int rc = aproxy_addr_decode_socksaddr(plaintext + pos,
                                          plaintext_len - pos, source,
                                          &consumed);
    if (rc != APROXY_OK) {
        return rc;
    }
    pos += consumed;
    const size_t body_len = plaintext_len - pos;
    *payload_len = body_len;
    if (payload_capacity < body_len) {
        return APROXY_ERR_BUFFER_TOO_SMALL;
    }
    if (body_len > 0u) {
        memmove(payload_out, plaintext + pos, body_len);
    }
    return APROXY_OK;
}

int shadowsocks_2022_udp_open_ex(
    shadowsocks_aead_method_t method,
    const uint8_t *key,
    size_t key_len,
    const uint8_t *packet,
    size_t packet_len,
    uint64_t expected_client_session_id,
    uint64_t *remote_session_id,
    uint64_t *remote_packet_id,
    uint8_t *remote_session_key,
    size_t remote_session_key_capacity,
    aproxy_addr_t *source,
    uint8_t *payload_out,
    size_t payload_capacity,
    size_t *payload_len)
{
    if (!shadowsocks_aead_method_is_2022(method) || key == NULL ||
        packet == NULL || remote_session_id == NULL ||
        remote_packet_id == NULL || source == NULL || payload_out == NULL ||
        payload_len == NULL ||
        key_len != shadowsocks_aead_key_len(method)) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }

    const int chacha = method_is_2022_chacha(method);
    const EVP_AEAD *aead = shadowsocks_2022_udp_aead(method);
    if (aead == NULL) {
        return APROXY_ERR_UNSUPPORTED;
    }
    const size_t tag_len = EVP_AEAD_max_overhead(aead);
    const size_t prefix_len = chacha ? SHADOWSOCKS_2022_PACKET_NONCE_LEN
                                     : 16u;
    if (packet_len < prefix_len + tag_len) {
        return APROXY_ERR_INVALID_FRAME;
    }

    uint8_t packet_header[16];
    uint8_t candidate_remote_key[SHADOWSOCKS_AEAD_MAX_KEY_LEN];
    const uint8_t *nonce = packet;
    const uint8_t *ciphertext = NULL;
    size_t ciphertext_len = 0u;
    const uint8_t *aead_key = key;
    size_t parse_pos = 16u;
    uint64_t parsed_remote_session_id = 0u;
    uint64_t parsed_remote_packet_id = 0u;

    if (chacha) {
        nonce = packet;
        ciphertext = packet + SHADOWSOCKS_2022_PACKET_NONCE_LEN;
        ciphertext_len = packet_len - SHADOWSOCKS_2022_PACKET_NONCE_LEN;
    } else {
        memcpy(packet_header, packet, sizeof(packet_header));
        int rc = aes_crypt_block(key, key_len, packet_header, 0);
        if (rc != APROXY_OK) {
            return rc;
        }
        parsed_remote_session_id = get_u64(packet_header);
        parsed_remote_packet_id = get_u64(packet_header + 8u);
        if (remote_session_key == NULL ||
            remote_session_key_capacity < key_len) {
            return APROXY_ERR_BUFFER_TOO_SMALL;
        }
        if (*remote_session_id == parsed_remote_session_id) {
            memcpy(candidate_remote_key, remote_session_key, key_len);
        } else {
            rc = shadowsocks_2022_session_key(method, key, key_len,
                                              packet_header, 8u,
                                              candidate_remote_key);
            if (rc != APROXY_OK) {
                return rc;
            }
        }
        nonce = packet_header + 4u;
        ciphertext = packet + 16u;
        ciphertext_len = packet_len - 16u;
        aead_key = candidate_remote_key;
        parse_pos = 0u;
    }

    const int use_output_buffer = payload_capacity >= ciphertext_len &&
                                  !buffers_overlap(payload_out,
                                                   ciphertext_len,
                                                   ciphertext,
                                                   ciphertext_len);
    uint8_t *plaintext = use_output_buffer
                             ? payload_out
                             : (uint8_t *)malloc(ciphertext_len == 0u
                                                    ? 1u
                                                    : ciphertext_len);
    if (plaintext == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }

    EVP_AEAD_CTX ctx;
    EVP_AEAD_CTX_zero(&ctx);
    if (!EVP_AEAD_CTX_init(&ctx, aead, aead_key, key_len,
                           EVP_AEAD_DEFAULT_TAG_LENGTH, NULL)) {
        if (!use_output_buffer) {
            free(plaintext);
        }
        return APROXY_ERR_CRYPTO;
    }
    size_t plaintext_len = 0u;
    const int ok = EVP_AEAD_CTX_open(
        &ctx, plaintext, &plaintext_len, ciphertext_len, nonce,
        EVP_AEAD_nonce_length(aead), ciphertext, ciphertext_len, NULL, 0u);
    EVP_AEAD_CTX_cleanup(&ctx);
    if (!ok) {
        if (!use_output_buffer) {
            free(plaintext);
        }
        return APROXY_ERR_CRYPTO;
    }

    if (chacha) {
        if (plaintext_len < 16u) {
            if (!use_output_buffer) {
                free(plaintext);
            }
            return APROXY_ERR_INVALID_FRAME;
        }
        parsed_remote_session_id = get_u64(plaintext);
        parsed_remote_packet_id = get_u64(plaintext + 8u);
        parse_pos = 16u;
    }

    int rc = parse_2022_udp_payload(
        plaintext, plaintext_len, parse_pos, expected_client_session_id,
        source, payload_out, payload_capacity, payload_len);
    if (rc == APROXY_OK) {
        *remote_session_id = parsed_remote_session_id;
        *remote_packet_id = parsed_remote_packet_id;
        if (!chacha) {
            memcpy(remote_session_key, candidate_remote_key, key_len);
        }
    }
    if (!use_output_buffer) {
        free(plaintext);
    }
    return rc;
}

int shadowsocks_2022_udp_open(shadowsocks_aead_method_t method,
                              const uint8_t *key,
                              size_t key_len,
                              const uint8_t *packet,
                              size_t packet_len,
                              uint64_t expected_client_session_id,
                              uint64_t *remote_session_id,
                              uint8_t *remote_session_key,
                              size_t remote_session_key_capacity,
                              aproxy_addr_t *source,
                              uint8_t *payload_out,
                              size_t payload_capacity,
                              size_t *payload_len)
{
    uint64_t packet_id = 0u;
    return shadowsocks_2022_udp_open_ex(
        method, key, key_len, packet, packet_len,
        expected_client_session_id, remote_session_id, &packet_id,
        remote_session_key, remote_session_key_capacity, source,
        payload_out, payload_capacity, payload_len);
}

void shadowsocks_2022_replay_reset(
    shadowsocks_2022_replay_window_t *window)
{
    if (window != NULL) {
        memset(window, 0, sizeof(*window));
    }
}

int shadowsocks_2022_replay_check(
    const shadowsocks_2022_replay_window_t *window,
    uint64_t packet_id)
{
    if (window == NULL) {
        return 0;
    }
    if (packet_id > window->last) {
        return 1;
    }
    const uint64_t window_size =
        (SHADOWSOCKS_2022_REPLAY_BLOCKS - 1u) * 64u;
    if (window->last - packet_id > window_size) {
        return 0;
    }
    const size_t block =
        (size_t)((packet_id >> 6u) &
                 (SHADOWSOCKS_2022_REPLAY_BLOCKS - 1u));
    const unsigned bit = (unsigned)(packet_id & 63u);
    return ((window->blocks[block] >> bit) & 1u) == 0u;
}

void shadowsocks_2022_replay_add(
    shadowsocks_2022_replay_window_t *window,
    uint64_t packet_id)
{
    if (window == NULL) {
        return;
    }
    uint64_t block_index = packet_id >> 6u;
    if (packet_id > window->last) {
        uint64_t last_block = window->last >> 6u;
        uint64_t diff = block_index - last_block;
        if (diff > SHADOWSOCKS_2022_REPLAY_BLOCKS) {
            diff = SHADOWSOCKS_2022_REPLAY_BLOCKS;
        }
        for (uint64_t i = 0u; i < diff; i++) {
            last_block = (last_block + 1u) &
                         (SHADOWSOCKS_2022_REPLAY_BLOCKS - 1u);
            window->blocks[last_block] = 0u;
        }
        window->last = packet_id;
    }
    const size_t block =
        (size_t)(block_index & (SHADOWSOCKS_2022_REPLAY_BLOCKS - 1u));
    window->blocks[block] |= UINT64_C(1) << (packet_id & 63u);
}
