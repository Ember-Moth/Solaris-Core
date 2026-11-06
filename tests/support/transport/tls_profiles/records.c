#include "profile.h"
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/sha2.h>
#include "blake3.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); ERR_print_errors_fp(stderr); abort(); } } while (0)
static void length16(uint8_t *out, size_t n) { out[0] = (uint8_t)(n >> 8); out[1] = (uint8_t)n; }
static void number64(uint8_t *out, uint64_t value) { for (unsigned i = 0u; i < 8u; ++i) out[i] = (uint8_t)(value >> (56u - 8u * i)); }
static HMAC_CTX *shadow_hmac(tls_test_profile_t *p, const char *direction)
{
    HMAC_CTX *h = HMAC_CTX_new(); CHECK(h && HMAC_Init_ex(h, p->password, (int)strlen(p->password), EVP_sha1(), NULL));
    CHECK(HMAC_Update(h, p->server_random, sizeof(p->server_random)));
    if (direction) CHECK(HMAC_Update(h, (const uint8_t *)direction, 1u));
    return h;
}
static void hmac_digest(HMAC_CTX *h, uint8_t digest[EVP_MAX_MD_SIZE])
{
    HMAC_CTX *copy = HMAC_CTX_new(); unsigned size;
    CHECK(copy && HMAC_CTX_copy_ex(copy, h) && HMAC_Final(copy, digest, &size) && size >= 4u); HMAC_CTX_free(copy);
}
static int shadow_check(HMAC_CTX *h, const uint8_t *record, size_t size, int update_tag)
{
    if (!h || size < 9u) return 0;
    HMAC_CTX *next = HMAC_CTX_new(); CHECK(next && HMAC_CTX_copy_ex(next, h) && HMAC_Update(next, record + 9u, size - 9u));
    uint8_t digest[EVP_MAX_MD_SIZE]; hmac_digest(next, digest);
    int ok = CRYPTO_memcmp(digest, record + 5u, 4u) == 0;
    if (ok) {
        if (update_tag) CHECK(HMAC_Update(next, record + 5u, 4u));
        CHECK(HMAC_CTX_copy_ex(h, next));
    }
    HMAC_CTX_free(next); return ok;
}
int tls_test_shadow_input(tls_test_profile_t *p, uint8_t *record, size_t *size, int application)
{
    if (record[0] == SSL3_RT_HANDSHAKE && *size >= 43u && record[5] == SSL3_MT_SERVER_HELLO) {
        memcpy(p->server_random, record + 11u, 32u);
        HMAC_CTX_free(p->shadow_handshake); p->shadow_handshake = shadow_hmac(p, NULL);
        SHA256_CTX hash; SHA256_Init(&hash); SHA256_Update(&hash, p->password, strlen(p->password));
        SHA256_Update(&hash, p->server_random, 32u); SHA256_Final(p->shadow_mask, &hash);
    }
    if (record[0] != SSL3_RT_APPLICATION_DATA) return application ? -1 : 0;
    if (application) {
        if (!p->shadow_read) p->shadow_read = shadow_hmac(p, "S");
        if (shadow_check(p->shadow_read, record, *size, 1)) {
            memmove(record, record + 9u, *size - 9u); *size -= 9u; return 1;
        }
    }
    if (!shadow_check(p->shadow_handshake, record, *size, 0)) return -1;
    p->authorized = 1;
    if (application) return 0; // Authenticated leftover camouflage records.
    memmove(record + 5u, record + 9u, *size - 9u); *size -= 4u; length16(record + 3u, *size - 5u);
    for (size_t i = 5u; i < *size; ++i) record[i] ^= p->shadow_mask[(i - 5u) % 32u];
    return 0;
}
size_t tls_test_shadow_output(tls_test_profile_t *p, const uint8_t *data, size_t size, uint8_t *record)
{
    if (!p->shadow_write) p->shadow_write = shadow_hmac(p, "C");
    record[0] = SSL3_RT_APPLICATION_DATA; record[1] = 3; record[2] = 3; length16(record + 3u, size + 4u);
    CHECK(HMAC_Update(p->shadow_write, data, size)); uint8_t digest[EVP_MAX_MD_SIZE]; hmac_digest(p->shadow_write, digest);
    memcpy(record + 5u, digest, 4u); memcpy(record + 9u, data, size); CHECK(HMAC_Update(p->shadow_write, digest, 4u)); return size + 9u;
}
static void restls_hash(tls_test_profile_t *p, int inbound, blake3_hasher *h)
{
    uint8_t counter[8]; number64(counter, inbound ? p->rx_counter : p->tx_counter);
    const char *direction = inbound ? "server-to-client" : "client-to-server";
    blake3_hasher_init_keyed(h, p->auth_key); blake3_hasher_update(h, p->server_random, 32u);
    blake3_hasher_update(h, direction, strlen(direction)); blake3_hasher_update(h, counter, sizeof(counter));
}
static size_t restls_header(SSL *ssl)
{ return SSL_version(ssl) == TLS1_2_VERSION && strstr(SSL_CIPHER_get_name(SSL_get_current_cipher(ssl)), "GCM") != NULL ? 13u : 5u; }
size_t tls_test_restls_output(tls_test_profile_t *p, SSL *ssl, const uint8_t *data, size_t size, uint8_t *record)
{
    size_t header = restls_header(ssl); record[0] = 23; record[1] = 3; record[2] = 3; length16(record + 3u, header - 5u + 12u + size);
    if (header == 13u) number64(record + 5u, p->tx_counter + 1u);
    uint8_t *payload = record + header; length16(payload + 8u, size); payload[10] = payload[11] = 0u; memcpy(payload + 12u, data, size);
    uint8_t digest[32]; blake3_hasher h; restls_hash(p, 0, &h); blake3_hasher_update(&h, data, size < 32u ? size : 32u); blake3_hasher_finalize(&h, digest, sizeof(digest));
    for (unsigned i = 0u; i < 4u; ++i) payload[8u + i] ^= digest[i];
    restls_hash(p, 0, &h);
    if (p->tx_counter == 0u) {
        const uint8_t *finished; size_t n; CHECK(SSL_get0_solaris_client_finished(ssl, &finished, &n) && n <= sizeof(p->finished));
        memcpy(p->finished, finished, n); p->finished_size = n;
        // Restls binds the last client flight. TLS 1.2 full handshakes send
        // Client Finished first; TLS 1.3 and TLS 1.2 resumption send it last.
        if (SSL_version(ssl) == TLS1_3_VERSION || SSL_session_reused(ssl)) blake3_hasher_update(&h, finished, n);
    }
    blake3_hasher_update(&h, record, header); blake3_hasher_update(&h, payload + 8u, 4u + size); blake3_hasher_finalize(&h, payload, 8u);
    p->tx_counter++; return header + 12u + size;
}
int tls_test_restls_input(tls_test_profile_t *p, SSL *ssl, uint8_t *record, size_t size, const uint8_t **out, size_t *out_size)
{
    (void)ssl; *out = NULL; *out_size = 0u; size_t header = p->server_gcm_counter ? 13u : 5u;
    if (record[0] != SSL3_RT_APPLICATION_DATA || size < header + 12u) return 0;
    uint8_t *payload = record + header; size_t available = size - header - 12u; uint8_t digest[32]; blake3_hasher h;
    restls_hash(p, 1, &h); blake3_hasher_update(&h, record, header); blake3_hasher_update(&h, payload + 8u, size - header - 8u); blake3_hasher_finalize(&h, digest, sizeof(digest));
    if (CRYPTO_memcmp(payload, digest, 8u) != 0) return 0;
    restls_hash(p, 1, &h); blake3_hasher_update(&h, payload + 12u, available < 32u ? available : 32u); blake3_hasher_finalize(&h, digest, sizeof(digest));
    for (unsigned i = 0u; i < 4u; ++i) payload[8u + i] ^= digest[i];
    size_t n = ((size_t)payload[8] << 8) | payload[9]; if (n > available || payload[10] != 0u || payload[11] != 0u) return -1;
    p->rx_counter++; *out = payload + 12u; *out_size = n; return 1;
}
