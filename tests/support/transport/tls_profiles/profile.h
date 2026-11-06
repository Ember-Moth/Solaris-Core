#ifndef SOLARIS_TEST_TLS_PROFILE_H
#define SOLARIS_TEST_TLS_PROFILE_H
#include <openssl/ssl.h>
#include <openssl/hmac.h>
#include <stddef.h>
#include <stdint.h>

enum { PROFILE_ORDINARY, PROFILE_REALITY, PROFILE_SHADOWTLS, PROFILE_RESTLS12, PROFILE_RESTLS13, PROFILE_JLS };
typedef struct tls_test_profile {
    int kind, authorized, fallback, other_user, generation, bad_time, bad_short, reject_peer, server_gcm_counter;
    uint16_t reality_group;
    const char *password, *username, *hostname;
    uint8_t server_key[32], auth_key[32], server_random[32], shadow_mask[32];
    uint8_t finished[4096];
    size_t finished_size;
    uint64_t tx_counter, rx_counter;
    HMAC_CTX *shadow_handshake, *shadow_read, *shadow_write;
    SSL_SESSION *session;
    unsigned hello_calls, peer_calls, record_calls, offered_psks;
} tls_test_profile_t;
void tls_test_profile_init(tls_test_profile_t *profile, const char *kind, const char *variant, const char *public_hex);
void tls_test_profile_configure(tls_test_profile_t *profile, SSL *ssl);
int tls_test_profile_authenticated(tls_test_profile_t *profile, SSL *ssl);
void tls_test_profile_free(tls_test_profile_t *profile);
int tls_test_shadow_input(tls_test_profile_t *profile, uint8_t *record, size_t *size, int application);
size_t tls_test_shadow_output(tls_test_profile_t *profile, const uint8_t *data, size_t size, uint8_t *record);
size_t tls_test_restls_output(tls_test_profile_t *profile, SSL *ssl, const uint8_t *data, size_t size, uint8_t *record);
int tls_test_restls_input(tls_test_profile_t *profile, SSL *ssl, uint8_t *record, size_t size, const uint8_t **out, size_t *out_size);
#endif
