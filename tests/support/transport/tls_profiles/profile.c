#include "profile.h"
#include <openssl/aead.h>
#include <openssl/cipher.h>
#include <openssl/curve25519.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hkdf.h>
#include <openssl/mem.h>
#include <openssl/rand.h>
#include <openssl/sha2.h>
#include <openssl/x509.h>
#include "blake3.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); ERR_print_errors_fp(stderr); abort(); } } while (0)
static const char password[] = "solaris-tls-patch-password";
static unsigned u16(const uint8_t *p) { return ((unsigned)p[0] << 8) | p[1]; }
static unsigned hex_digit(char c)
{
    if (c >= '0' && c <= '9') return (unsigned)(c - '0');
    if (c >= 'a' && c <= 'f') return (unsigned)(c - 'a') + 10u;
    if (c >= 'A' && c <= 'F') return (unsigned)(c - 'A') + 10u;
    CHECK(0); return 0u;
}
static int jls_random(tls_test_profile_t *p, const uint8_t *wire, size_t size, uint8_t random[32], int decrypt)
{
    if (size < 38u || size > 65536u) return 0;
    uint8_t *auth = malloc(size); if (!auth) return 0; memcpy(auth, wire, size); memset(auth + 6u, 0, 32u);
    uint8_t key[32], nonce[32], plain[32]; SHA256_CTX hash;
    SHA256_Init(&hash); SHA256_Update(&hash, p->username, strlen(p->username)); SHA256_Update(&hash, auth, size); SHA256_Final(nonce, &hash);
    SHA256_Init(&hash); SHA256_Update(&hash, p->password, strlen(p->password)); SHA256_Update(&hash, auth, size); SHA256_Final(key, &hash); free(auth);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); int length = 0, final = 0, ok = 0;
    if (ctx && EVP_CipherInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL, !decrypt) &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(nonce), NULL) &&
        EVP_CipherInit_ex(ctx, NULL, NULL, key, nonce, !decrypt)) {
        if (decrypt) {
            ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, random + 16) &&
                EVP_CipherUpdate(ctx, plain, &length, random, 16) && EVP_CipherFinal_ex(ctx, plain + length, &final) && length + final == 16;
        } else {
            ok = EVP_CipherUpdate(ctx, plain, &length, random, 16) && EVP_CipherFinal_ex(ctx, plain + length, &final) && length + final == 16 &&
                EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, plain + 16);
            if (ok) memcpy(random, plain, 32);
        }
    }
    EVP_CIPHER_CTX_free(ctx); OPENSSL_cleanse(key, sizeof(key)); OPENSSL_cleanse(plain, sizeof(plain)); return ok;
}
static int forbidden_random(const uint8_t random[32])
{
    static const uint8_t retry_tail[8] = {0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c};
    return memcmp(random + 24, "DOWNGRD\0", 8) == 0 || memcmp(random + 24, "DOWNGRD\1", 8) == 0 || memcmp(random + 24, retry_tail, 8) == 0;
}
static int hello(SSL *ssl, const uint8_t *wire, size_t size, SSL_SOLARIS_CLIENT_HELLO_OUTPUT *out, void *context)
{
    tls_test_profile_t *p = context; p->hello_calls++;
    SSL_CLIENT_HELLO parsed; if (!SSL_parse_client_hello(ssl, &parsed, wire + 4, size - 4)) return 0;
    const uint8_t *ext; size_t length;
    if (SSL_early_callback_ctx_extension_get(&parsed, TLSEXT_TYPE_pre_shared_key, &ext, &length)) p->offered_psks++;
    if (p->kind == PROFILE_JLS) {
        for (unsigned tries = 0u; tries < 16u; ++tries) {
            if (!jls_random(p, wire, size, out->random, 0)) return 0;
            if (!forbidden_random(out->random)) return 1;
            if (!RAND_bytes(out->random, 16)) return 0;
        }
        return 0;
    }
    if (p->kind == PROFILE_REALITY) {
        uint8_t shared[32], plain[16] = {26, 10, 31, 0}, sealed[32];
        if (!SSL_solaris_client_hello_x25519_for_group(ssl, p->reality_group, p->server_key, shared)) return 0;
        int ok = HKDF(p->auth_key, 32, EVP_sha256(), shared, 32, wire + 6, 20, (const uint8_t *)"REALITY", 7);
        OPENSSL_cleanse(shared, sizeof(shared)); if (!ok) return 0;
        uint32_t now = p->bad_time ? 0u : (uint32_t)time(NULL);
        for (unsigned i = 0u; i < 4u; ++i) plain[4u + i] = (uint8_t)(now >> (24u - 8u * i));
        for (unsigned i = 0u; i < 8u; ++i) plain[8u + i] = (uint8_t)(p->bad_short ? 0u : i + 1u);
        uint8_t *aad = malloc(size); if (!aad) return 0; memcpy(aad, wire, size); memset(aad + 39u, 0, 32u);
        EVP_AEAD_CTX *aead = EVP_AEAD_CTX_new(EVP_aead_aes_256_gcm(), p->auth_key, 32, 16); size_t sealed_size = 0u;
        ok = aead && EVP_AEAD_CTX_seal(aead, sealed, &sealed_size, sizeof(sealed), wire + 26u, 12u, plain, sizeof(plain), aad, size) && sealed_size == 32u;
        if (ok) memcpy(out->session_id, sealed, 32u);
        EVP_AEAD_CTX_free(aead); free(aad); OPENSSL_cleanse(plain, sizeof(plain)); return ok;
    }
    if (p->kind == PROFILE_SHADOWTLS) {
        uint8_t *auth = malloc(size); if (!auth) return 0; memcpy(auth, wire, size); memset(auth + 39u + 28u, 0, 4u);
        uint8_t digest[EVP_MAX_MD_SIZE]; unsigned n;
        int ok = HMAC(EVP_sha1(), p->password, strlen(p->password), auth, size, digest, &n) != NULL;
        if (ok) memcpy(out->session_id + 28u, digest, 4u);
        free(auth); return ok;
    }
    if (p->kind == PROFILE_RESTLS12) {
        const uint16_t groups[] = {SSL_GROUP_X25519, SSL_GROUP_SECP256R1, SSL_GROUP_SECP384R1};
        const uint8_t *ticket = NULL; size_t ticket_size = 0u;
        (void)SSL_early_callback_ctx_extension_get(&parsed, TLSEXT_TYPE_session_ticket, &ticket, &ticket_size);
        const size_t offsets3[] = {0, 11, 22, 32}, offsets4[] = {0, 8, 16, 24, 32}; const size_t *offsets = ticket_size ? offsets4 : offsets3;
        for (unsigned i = 0; i < (ticket_size ? 4u : 3u); ++i) {
            const uint8_t *key = ticket; size_t n = ticket_size; uint8_t hash[32];
            if (i < 3u && !SSL_get0_solaris_eager_key_share(ssl, groups[i], &key, &n)) return 0;
            blake3_hasher h; blake3_hasher_init_keyed(&h, p->auth_key); blake3_hasher_update(&h, key, n); blake3_hasher_finalize(&h, hash, sizeof(hash));
            memcpy(out->session_id + offsets[i], hash, offsets[i + 1u] - offsets[i]);
        }
        return 1;
    }
    if (p->kind == PROFILE_RESTLS13) {
        blake3_hasher h; blake3_hasher_init_keyed(&h, p->auth_key);
        if (!SSL_early_callback_ctx_extension_get(&parsed, TLSEXT_TYPE_key_share, &ext, &length) || length < 2u) return 0;
        size_t offset = 2u;
        while (offset < length) {
            if (length - offset < 4u) return 0;
            size_t n = u16(ext + offset + 2u);
            if (n > length - offset - 4u) return 0;
            blake3_hasher_update(&h, ext + offset, 2u); blake3_hasher_update(&h, ext + offset + 4u, n); offset += 4u + n;
        }
        if (SSL_early_callback_ctx_extension_get(&parsed, TLSEXT_TYPE_pre_shared_key, &ext, &length)) {
            if (length < 2u || u16(ext) > length - 2u) return 0;
            size_t end = 2u + u16(ext); offset = 2u;
            while (offset < end) {
                if (end - offset < 2u) return 0;
                size_t n = u16(ext + offset); offset += 2u;
                if (n + 4u > end - offset) return 0;
                blake3_hasher_update(&h, ext + offset, n); offset += n + 4u;
            }
        }
        blake3_hasher_finalize(&h, out->session_id, 16u); return 1;
    }
    return 0;
}
static int peer(SSL *ssl, const uint8_t *wire, size_t size, void *context)
{
    tls_test_profile_t *p = context; p->peer_calls++;
    CHECK(SSL_get_solaris_peer_auth_result(ssl) == SSL_SOLARIS_AUTH_PENDING);
    uint8_t context_id[32] = {0}; CHECK(!SSL_set_solaris_peer_auth_callback(ssl, context_id, peer, context));
    if (size < 38u || p->reject_peer) return 0;
    uint8_t random[32]; memcpy(random, wire + 6u, 32u);
    return !forbidden_random(random) && jls_random(p, wire, size, random, 1);
}
static int record_probe(SSL *ssl, const uint8_t header[5], uint8_t *record, size_t size, void *context)
{
    (void)header; tls_test_profile_t *p = context; p->record_calls++;
    if (SSL_get_server_random(ssl, p->server_random, sizeof(p->server_random)) != 32u) return 0;
    uint8_t digest[32]; blake3_hasher h; blake3_hasher_init_keyed(&h, p->auth_key); blake3_hasher_update(&h, p->server_random, 32u); blake3_hasher_finalize(&h, digest, sizeof(digest));
    size_t offset = 0u;
    if (SSL_version(ssl) == TLS1_2_VERSION && strstr(SSL_CIPHER_get_name(SSL_get_current_cipher(ssl)), "GCM") != NULL && size >= 8u) {
        static const uint8_t zero[8] = {0}; if (memcmp(record, zero, 8u) == 0) offset = 8u;
    }
    p->server_gcm_counter = offset == 8u;
    size_t masked = size - offset; if (masked > 16u) masked = 16u;
    for (size_t i = 0u; i < masked; ++i) record[offset + i] ^= digest[i];
    return 1;
}
static enum ssl_verify_result_t reality_verify(SSL *ssl, uint8_t *alert)
{
    tls_test_profile_t *p = SSL_get_app_data(ssl); X509 *cert = SSL_get_peer_certificate(ssl); int ok = 0;
    if (cert) {
        EVP_PKEY *key = X509_get_pubkey(cert); uint8_t public_key[32]; size_t key_size = sizeof(public_key);
        const ASN1_BIT_STRING *signature; const X509_ALGOR *algorithm; X509_get0_signature(&signature, &algorithm, cert); (void)algorithm;
        if (key && EVP_PKEY_id(key) == EVP_PKEY_ED25519 && EVP_PKEY_get_raw_public_key(key, public_key, &key_size) && key_size == 32u && ASN1_STRING_length(signature) == 64) {
            uint8_t mac[64]; unsigned n;
            ok = HMAC(EVP_sha512(), p->auth_key, 32, public_key, 32, mac, &n) && n == 64u && CRYPTO_memcmp(mac, ASN1_STRING_get0_data(signature), 64u) == 0;
        }
        EVP_PKEY_free(key); X509_free(cert);
    }
    p->authorized = ok; if (!ok) *alert = SSL_AD_BAD_CERTIFICATE;
    return ok ? ssl_verify_ok : ssl_verify_invalid;
}
void tls_test_profile_init(tls_test_profile_t *p, const char *kind, const char *variant, const char *public_hex)
{
    memset(p, 0, sizeof(*p)); p->password = password; p->username = "user"; p->hostname = "localhost"; p->reality_group = SSL_GROUP_X25519;
    if (strcmp(kind, "ordinary") == 0) p->kind = PROFILE_ORDINARY;
    else if (strcmp(kind, "reality") == 0) p->kind = PROFILE_REALITY;
    else if (strcmp(kind, "shadowtls3") == 0) p->kind = PROFILE_SHADOWTLS;
    else if (strcmp(kind, "restls12") == 0) p->kind = PROFILE_RESTLS12;
    else if (strcmp(kind, "restls13") == 0) p->kind = PROFILE_RESTLS13;
    else { CHECK(strcmp(kind, "jls") == 0); p->kind = PROFILE_JLS; p->hostname = "jls.example"; }
    if (strcmp(variant, "wrong") == 0 || strcmp(variant, "fallback") == 0) p->password = "wrong-password";
    p->fallback = strcmp(variant, "fallback") == 0;
    if (strcmp(variant, "other") == 0) { p->username = "other"; p->password = "solaris-tls-patch-password-other"; p->other_user = 1; }
    p->generation = strcmp(variant, "generation2") == 0;
    p->bad_time = strcmp(variant, "expired") == 0; p->bad_short = strcmp(variant, "bad-short") == 0;
    p->reject_peer = strcmp(variant, "reject-peer") == 0;
    if (strcmp(variant, "name2") == 0) p->hostname = "other.example";
    if (strcmp(variant, "wrong-name") == 0) p->hostname = "invalid.example";
    if (strcmp(variant, "localname") == 0) p->hostname = "localhost";
    if (strcmp(variant, "hybrid") == 0) p->reality_group = SSL_GROUP_X25519_MLKEM768;
    if (p->kind == PROFILE_REALITY) {
        CHECK(strlen(public_hex) == 64u);
        for (unsigned i = 0u; i < 32u; ++i)
            p->server_key[i] = (uint8_t)((hex_digit(public_hex[2u * i]) << 4u) | hex_digit(public_hex[2u * i + 1u]));
        if (strcmp(variant, "wrong") == 0) { uint8_t secret[32]; memset(secret, 0x71, 32u); X25519_public_from_private(p->server_key, secret); }
    }
    if (p->kind == PROFILE_RESTLS12 || p->kind == PROFILE_RESTLS13) {
        blake3_hasher h; blake3_hasher_init_derive_key(&h, "restls-traffic-key"); blake3_hasher_update(&h, p->password, strlen(p->password)); blake3_hasher_finalize(&h, p->auth_key, 32u);
    }
}
void tls_test_profile_configure(tls_test_profile_t *p, SSL *ssl)
{
    SSL_set_app_data(ssl, p); CHECK(SSL_set_tlsext_host_name(ssl, p->hostname));
    CHECK(X509_VERIFY_PARAM_set1_host(SSL_get0_param(ssl), p->hostname, strlen(p->hostname)));
    uint16_t version = p->kind == PROFILE_RESTLS12 ? TLS1_2_VERSION : TLS1_3_VERSION;
    CHECK(SSL_set_min_proto_version(ssl, version) && SSL_set_max_proto_version(ssl, version));
    if (p->kind == PROFILE_ORDINARY) return;
    CHECK(SSL_set_solaris_client_hello_callback(ssl, p->kind == PROFILE_JLS ? SSL_SOLARIS_HELLO_RANDOM : SSL_SOLARIS_HELLO_SESSION_ID, hello, p));
    if (p->kind == PROFILE_JLS) {
        uint8_t context[32] = {0x4a, 0x4c, 0x53, 3}; context[4] = (uint8_t)p->other_user; context[5] = (uint8_t)p->generation;
        CHECK(SSL_set_solaris_peer_auth_callback(ssl, context, peer, p));
        CHECK(!SSL_set_solaris_record_auth_callback(ssl, 0u, record_probe, p));
    } else if (p->kind == PROFILE_REALITY) {
        CHECK(SSL_disable_solaris_resumption(ssl));
        uint16_t groups[] = {SSL_GROUP_X25519_MLKEM768, SSL_GROUP_X25519};
        CHECK(SSL_set1_group_ids(ssl, groups, 2u)); CHECK(SSL_set1_client_key_shares(ssl, groups, p->reality_group == SSL_GROUP_X25519 ? 2u : 1u));
        const uint16_t signatures[] = {SSL_SIGN_ED25519, SSL_SIGN_ECDSA_SECP256R1_SHA256, SSL_SIGN_RSA_PSS_RSAE_SHA256,
            SSL_SIGN_ECDSA_SECP384R1_SHA384, SSL_SIGN_RSA_PSS_RSAE_SHA384, SSL_SIGN_RSA_PSS_RSAE_SHA512};
        CHECK(SSL_set_verify_algorithm_prefs(ssl, signatures, sizeof(signatures) / sizeof(signatures[0])));
        SSL_set_custom_verify(ssl, SSL_VERIFY_PEER, reality_verify);
    } else if (p->kind == PROFILE_SHADOWTLS) {
        CHECK(SSL_disable_solaris_resumption(ssl));
    } else if (p->kind == PROFILE_RESTLS12 || p->kind == PROFILE_RESTLS13) {
        CHECK(SSL_set_solaris_record_auth_callback(ssl, p->fallback ? SSL_SOLARIS_RECORD_ALLOW_FALLBACK : 0u, record_probe, p));
        uint8_t context[32] = {0}; CHECK(!SSL_set_solaris_peer_auth_callback(ssl, context, peer, p));
        CHECK(SSL_enable_solaris_client_finished_capture(ssl));
        if (p->kind == PROFILE_RESTLS12) {
            const uint16_t groups[] = {SSL_GROUP_X25519, SSL_GROUP_SECP256R1, SSL_GROUP_SECP384R1};
            CHECK(SSL_set1_solaris_eager_key_shares(ssl, groups, 3u) && SSL_set1_group_ids(ssl, groups, 3u));
            CHECK(SSL_set_strict_cipher_list(ssl, "ECDHE-ECDSA-AES128-GCM-SHA256"));
        }
    }
}
int tls_test_profile_authenticated(tls_test_profile_t *p, SSL *ssl)
{
    if (p->kind == PROFILE_JLS) return SSL_get_solaris_peer_auth_result(ssl) == SSL_SOLARIS_AUTH_OK;
    if (p->kind == PROFILE_RESTLS12 || p->kind == PROFILE_RESTLS13) return SSL_get_solaris_record_auth_result(ssl) == SSL_SOLARIS_AUTH_OK;
    return p->kind == PROFILE_ORDINARY ? SSL_get_verify_result(ssl) == X509_V_OK : p->authorized;
}
void tls_test_profile_free(tls_test_profile_t *p)
{
    HMAC_CTX_free(p->shadow_handshake); HMAC_CTX_free(p->shadow_read); HMAC_CTX_free(p->shadow_write); SSL_SESSION_free(p->session);
    OPENSSL_cleanse(p, sizeof(*p));
}
