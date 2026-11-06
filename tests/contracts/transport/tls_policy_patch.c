#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/hpke.h>
#include <openssl/mem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); ERR_print_errors_fp(stderr); abort(); } } while (0)
static int hello(SSL *ssl, const uint8_t *data, size_t size, SSL_SOLARIS_CLIENT_HELLO_OUTPUT *out, void *context)
{ (void)ssl; (void)data; (void)size; (void)out; (*(unsigned *)context)++; return 1; }
static int record(SSL *ssl, const uint8_t header[5], uint8_t *data, size_t size, void *context)
{ (void)ssl; (void)header; (void)data; (void)size; (*(unsigned *)context)++; return 1; }
static int peer(SSL *ssl, const uint8_t *data, size_t size, void *context)
{ (void)ssl; (void)data; (void)size; (*(unsigned *)context)++; return 1; }
static unsigned psk(SSL *ssl, const char *hint, char *identity, unsigned identity_size, uint8_t *secret, unsigned secret_size)
{ (void)ssl; (void)hint; (void)identity; (void)identity_size; (void)secret; (void)secret_size; CHECK(0); return 0; }
static void fail_before_wire(SSL *ssl, unsigned *calls)
{
    BIO *input = BIO_new(BIO_s_mem()), *output = BIO_new(BIO_s_mem()); CHECK(input && output); SSL_set_bio(ssl, input, output);
    int rc = SSL_do_handshake(ssl); CHECK(rc < 0 && SSL_get_error(ssl, rc) == SSL_ERROR_SSL);
    CHECK(*calls == 0u && BIO_ctrl_pending(output) == 0u);
    CHECK(SSL_get_solaris_peer_auth_result(ssl) != SSL_SOLARIS_AUTH_OK && SSL_get_solaris_record_auth_result(ssl) != SSL_SOLARIS_AUTH_OK);
    SSL_free(ssl); ERR_clear_error();
}
int main(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_method()), *dtls = SSL_CTX_new(DTLS_method()); CHECK(ctx && dtls);
    const uint16_t group = SSL_GROUP_X25519; uint8_t identity[32] = {0}; unsigned calls = 0u;
    CHECK(!SSL_set_solaris_client_hello_callback(NULL, 1u, hello, &calls));
    CHECK(!SSL_set_solaris_record_auth_callback(NULL, 0u, record, &calls));
    CHECK(!SSL_set_solaris_peer_auth_callback(NULL, identity, peer, &calls));
    CHECK(!SSL_set1_solaris_eager_key_shares(NULL, &group, 1u));
    CHECK(!SSL_enable_solaris_client_finished_capture(NULL) && !SSL_disable_solaris_resumption(NULL));
    const uint8_t *out = (const uint8_t *)1; size_t n = 3u;
    CHECK(!SSL_get0_solaris_client_finished(NULL, &out, &n) && !out && !n);
    out = (const uint8_t *)1; CHECK(!SSL_get0_solaris_client_finished(NULL, &out, NULL) && !out);
    n = 3u; CHECK(!SSL_get0_solaris_eager_key_share(NULL, group, NULL, &n) && !n);
    for (unsigned mode = 0u; mode < 2u; ++mode) {
        SSL *ssl = SSL_new(mode ? ctx : dtls); CHECK(ssl); SSL_set_connect_state(ssl);
        static const SSL_QUIC_METHOD quic = {0}; if (mode) CHECK(SSL_set_quic_method(ssl, &quic));
        CHECK(!SSL_set_solaris_client_hello_callback(ssl, 1u, hello, &calls));
        CHECK(!SSL_set_solaris_record_auth_callback(ssl, 0u, record, &calls));
        CHECK(!SSL_set_solaris_peer_auth_callback(ssl, identity, peer, &calls));
        CHECK(!SSL_set1_solaris_eager_key_shares(ssl, &group, 1u));
        CHECK(!SSL_enable_solaris_client_finished_capture(ssl) && !SSL_disable_solaris_resumption(ssl)); SSL_free(ssl);
    }
    EVP_HPKE_KEY key; EVP_HPKE_KEY_zero(&key); CHECK(EVP_HPKE_KEY_generate(&key, EVP_hpke_x25519_hkdf_sha256()));
    uint8_t *config, *list; size_t config_size, list_size;
    CHECK(SSL_marshal_ech_config(&config, &config_size, 1u, &key, "public.example", 64u));
    SSL_ECH_KEYS *keys = SSL_ECH_KEYS_new(); CHECK(keys && SSL_ECH_KEYS_add(keys, 1, config, config_size, &key));
    CHECK(SSL_ECH_KEYS_marshal_retry_configs(keys, &list, &list_size));
    for (unsigned mode = 0u; mode < 5u; ++mode) {
        SSL *ssl = SSL_new(ctx); CHECK(ssl); SSL_set_connect_state(ssl);
        uint16_t version = mode == 3u ? TLS1_2_VERSION : TLS1_3_VERSION;
        CHECK(SSL_set_min_proto_version(ssl, version) && SSL_set_max_proto_version(ssl, version));
        CHECK(SSL_set_tlsext_host_name(ssl, "private.example") && SSL_set1_ech_config_list(ssl, list, list_size));
        if (mode == 0u) CHECK(SSL_set_solaris_client_hello_callback(ssl, 1u, hello, &calls));
        if (mode == 1u) CHECK(SSL_set_solaris_record_auth_callback(ssl, 0u, record, &calls));
        if (mode == 2u) CHECK(SSL_enable_solaris_client_finished_capture(ssl));
        if (mode == 3u) CHECK(SSL_set1_solaris_eager_key_shares(ssl, &group, 1u) && SSL_set_solaris_client_hello_callback(ssl, 2u, hello, &calls));
        if (mode == 4u) CHECK(SSL_set_solaris_peer_auth_callback(ssl, identity, peer, &calls) && SSL_set_solaris_client_hello_callback(ssl, 1u, hello, &calls));
        fail_before_wire(ssl, &calls);
    }
    OPENSSL_free(config); OPENSSL_free(list); SSL_ECH_KEYS_free(keys); EVP_HPKE_KEY_cleanup(&key);
    SSL *ssl = SSL_new(ctx); CHECK(ssl); SSL_set_connect_state(ssl);
    CHECK(SSL_set1_solaris_eager_key_shares(ssl, &group, 1u));
    CHECK(!SSL_set_solaris_peer_auth_callback(ssl, identity, peer, &calls));
    CHECK(SSL_set_solaris_client_hello_callback(ssl, 2u, hello, &calls));
    CHECK(SSL_set_min_proto_version(ssl, TLS1_3_VERSION) && SSL_set_max_proto_version(ssl, TLS1_3_VERSION)); fail_before_wire(ssl, &calls);
    ssl = SSL_new(ctx); CHECK(ssl); SSL_set_connect_state(ssl); CHECK(SSL_disable_solaris_resumption(ssl));
    CHECK(SSL_set_min_proto_version(ssl, TLS1_3_VERSION) && SSL_set_max_proto_version(ssl, TLS1_3_VERSION));
    SSL_set_psk_client_callback(ssl, psk); fail_before_wire(ssl, &calls);
    SSL_CTX_free(ctx); SSL_CTX_free(dtls);
    puts("TLS patch policy: invalid arguments, DTLS/QUIC/ECH, incompatible eager/peer modes and external PSK rejected before wire output"); return 0;
}
