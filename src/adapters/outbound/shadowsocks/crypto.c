#include "adapters/outbound/shadowsocks/internal.h"
#include <openssl/base64.h>
#include <openssl/crypto.h>
#include <openssl/hkdf.h>
#include <openssl/md5.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/digest.h>
#include "blake3.h"
#include <string.h>
#include <time.h>

solaris_status_t solaris_ss_key_parse(const char *method, const char *password, solaris_ss_key_t *key)
{
    memset(key, 0, sizeof(*key));
    if (strcmp(method, "aes-128-gcm") == 0) key->length = 16u;
    else if (strcmp(method, "aes-256-gcm") == 0) key->length = 32u;
    else if (strcmp(method, "chacha20-ietf-poly1305") == 0) { key->length = 32u; key->chacha = 1; }
    else if (strcmp(method, "2022-blake3-aes-128-gcm") == 0) { key->length = 16u; key->modern = 1; }
    else if (strcmp(method, "2022-blake3-aes-256-gcm") == 0) { key->length = 32u; key->modern = 1; }
    else return SOLARIS_ENOTSUP;
    size_t length = strlen(password);
    if (length == 0u) return SOLARIS_EINVAL;
    if (key->modern) {
        uint8_t decoded[48]; size_t count = 0u;
        if (length != ((key->length + 2u) / 3u) * 4u ||
            !EVP_DecodeBase64(decoded, &count, sizeof(decoded), (const uint8_t *)password, length) || count != key->length) {
            OPENSSL_cleanse(decoded, sizeof(decoded)); return SOLARIS_EINVAL;
        }
        memcpy(key->bytes, decoded, count); OPENSSL_cleanse(decoded, sizeof(decoded));
    } else {
        uint8_t digest[16]; size_t pos = 0u;
        while (pos < key->length) {
            MD5_CTX md5; MD5_Init(&md5);
            if (pos != 0u) MD5_Update(&md5, digest, sizeof(digest));
            MD5_Update(&md5, password, length); MD5_Final(digest, &md5);
            memcpy(key->bytes + pos, digest, sizeof(digest)); pos += sizeof(digest);
            OPENSSL_cleanse(&md5, sizeof(md5));
        }
        OPENSSL_cleanse(digest, sizeof(digest));
    }
    return SOLARIS_OK;
}
solaris_status_t solaris_ss_random(const solaris_crypto_source_t *source, uint8_t *out, size_t size)
{ return source->random != NULL ? source->random(source->context, out, size) : RAND_bytes(out, size) ? SOLARIS_OK : SOLARIS_EIO; }
uint64_t solaris_ss_time(const solaris_crypto_source_t *source)
{ if (source->unix_seconds != NULL) return source->unix_seconds(source->context); time_t now = time(NULL); return now < 0 ? 0u : (uint64_t)now; }
int solaris_ss_time_valid(const solaris_crypto_source_t *source, uint64_t stamp)
{ uint64_t now = solaris_ss_time(source); return stamp > now ? stamp - now <= 30u : now - stamp <= 30u; }
solaris_status_t solaris_ss_aead(const solaris_ss_key_t *key, const uint8_t *salt, size_t size, EVP_AEAD_CTX *out)
{
    uint8_t subkey[32];
    if (key->modern) {
        blake3_hasher hasher; blake3_hasher_init_derive_key(&hasher, "shadowsocks 2022 session subkey");
        blake3_hasher_update(&hasher, key->bytes, key->length); blake3_hasher_update(&hasher, salt, size);
        blake3_hasher_finalize(&hasher, subkey, key->length); OPENSSL_cleanse(&hasher, sizeof(hasher));
    } else if (!HKDF(subkey, key->length, EVP_sha1(), key->bytes, key->length, salt, size,
                     (const uint8_t *)"ss-subkey", 9u)) return SOLARIS_EIO;
    const EVP_AEAD *algorithm = key->chacha ? EVP_aead_chacha20_poly1305() :
        key->length == 16u ? EVP_aead_aes_128_gcm() : EVP_aead_aes_256_gcm();
    int ok = EVP_AEAD_CTX_init(out, algorithm, subkey, key->length, 16u, NULL);
    OPENSSL_cleanse(subkey, sizeof(subkey)); return ok ? SOLARIS_OK : SOLARIS_EIO;
}
solaris_status_t solaris_ss_replay(const solaris_ss_parameters_t *parameters, const uint8_t *salt)
{
    /* The same namespace covers both directions and TCP/UDP: reflection and
     * cross-transport reuse of a key/salt pair must also be rejected. */
    SHA256_CTX hash; uint8_t token[32], algorithm = (uint8_t)parameters->key.chacha;
    SHA256_Init(&hash); SHA256_Update(&hash, "solaris ss salt", 15u);
    SHA256_Update(&hash, &algorithm, 1u); SHA256_Update(&hash, parameters->key.bytes, parameters->key.length);
    SHA256_Update(&hash, salt, parameters->key.length); SHA256_Final(token, &hash);
    return solaris_replay_insert(parameters->replay, token);
}
uint64_t solaris_ss_read64(const uint8_t *bytes)
{ uint64_t result = 0u; for (size_t i = 0u; i < 8u; ++i) result = (result << 8) | bytes[i]; return result; }
void solaris_ss_write64(uint8_t *bytes, uint64_t value)
{ for (size_t i = 0u; i < 8u; ++i) { bytes[7u - i] = (uint8_t)value; value >>= 8; } }
