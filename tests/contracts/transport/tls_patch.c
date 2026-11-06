#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/curve25519.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); ERR_print_errors_fp(stderr); abort(); } } while (0)
typedef struct fixture { unsigned calls, psk; int reject, no_x25519; SSL_SESSION *session; } fixture_t;
static int new_session(SSL *ssl, SSL_SESSION *session)
{
    fixture_t *test = SSL_get_app_data(ssl);
    SSL_SESSION_free(test->session); SSL_SESSION_up_ref(session); test->session = session;
    return 0;
}
static unsigned u16(const uint8_t *p) { return ((unsigned)p[0] << 8) | p[1]; }
static int hello(SSL *ssl, const uint8_t *wire, size_t length,
    SSL_SOLARIS_CLIENT_HELLO_OUTPUT *output, void *arg)
{
    fixture_t *test = arg; test->calls++;
    CHECK(length >= 71u && wire[0] == SSL3_MT_CLIENT_HELLO && wire[38] == 32u);
    CHECK(!SSL_set_solaris_client_hello_callback(ssl, 3u, hello, arg));
    CHECK(memcmp(output->random, wire + 6, 32u) == 0 && memcmp(output->session_id, wire + 39, 32u) == 0);
    SSL_CLIENT_HELLO parsed;
    CHECK(SSL_parse_client_hello(ssl, &parsed, wire + 4, length - 4));
    const uint8_t *ext; size_t size;
    uint8_t private_key[32], public_key[32], ours[32], theirs[32], zero[32] = {0};
    memset(private_key, 0x49, sizeof(private_key)); X25519_public_from_private(public_key, private_key);
    CHECK(!SSL_solaris_client_hello_x25519(ssl, zero, ours) && memcmp(ours, zero, 32u) == 0);
    int derived = SSL_solaris_client_hello_x25519(ssl, public_key, ours);
    if (test->no_x25519) { CHECK(!derived && memcmp(ours, zero, 32u) == 0); return 0; }
    CHECK(derived && SSL_early_callback_ctx_extension_get(&parsed, TLSEXT_TYPE_key_share, &ext, &size));
    CHECK(size >= 2u && u16(ext) == size - 2u);
    size_t cursor = 2u; int found = 0;
    while (cursor < size) {
        CHECK(size - cursor >= 4u); unsigned group = u16(ext + cursor), bytes = u16(ext + cursor + 2u); cursor += 4u;
        CHECK(bytes <= size - cursor);
        if (group == SSL_GROUP_X25519) {
            CHECK(bytes == 32u && X25519(theirs, private_key, ext + cursor) && memcmp(ours, theirs, 32u) == 0); found = 1;
        }
        cursor += bytes;
    }
    CHECK(found);
    if (SSL_early_callback_ctx_extension_get(&parsed, TLSEXT_TYPE_pre_shared_key, &ext, &size)) {
        CHECK(size >= 4u); cursor = 2u + u16(ext); CHECK(cursor + 2u <= size && cursor + 2u + u16(ext + cursor) == size); cursor += 2u;
        while (cursor < size) {
            unsigned bytes = ext[cursor++]; CHECK(bytes != 0u && bytes <= size - cursor);
            for (unsigned i = 0u; i < bytes; ++i) CHECK(ext[cursor + i] == 0u);
            cursor += bytes;
        }
        test->psk++;
    }
    memset(output->random, 0xa3, 32u); memset(output->session_id, 0x54, 32u);
    OPENSSL_cleanse(ours, sizeof(ours)); OPENSSL_cleanse(theirs, sizeof(theirs));
    OPENSSL_cleanse(private_key, sizeof(private_key));
    return !test->reject;
}
static int step(SSL *ssl)
{
    int rc = SSL_do_handshake(ssl);
    if (rc == 1) return 1;
    int error = SSL_get_error(ssl, rc);
    return error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE ? 0 : -1;
}
enum { NORMAL, AUTH, REJECT, TLS12_AUTH, HRR, WRONG_NAME, UNTRUSTED, NO_X25519, TLS12_NORMAL, EARLY_DATA };
static SSL_SESSION *run(SSL_CTX *client_ctx, SSL_CTX *server_ctx, int mode, SSL_SESSION *resume)
{
    SSL *client = SSL_new(client_ctx), *server = SSL_new(server_ctx); CHECK(client && server);
    SSL_set_connect_state(client); SSL_set_accept_state(server);
    uint16_t version = mode == TLS12_AUTH || mode == TLS12_NORMAL ? TLS1_2_VERSION : TLS1_3_VERSION;
    CHECK(SSL_set_min_proto_version(client, version) && SSL_set_max_proto_version(client, version));
    CHECK(SSL_set_min_proto_version(server, version) && SSL_set_max_proto_version(server, version));
    const char *host = mode == WRONG_NAME ? "invalid.local" : "localhost";
    CHECK(X509_VERIFY_PARAM_set1_host(SSL_get0_param(client), host, strlen(host)));
    if (mode == UNTRUSTED) {
        X509_STORE *empty = X509_STORE_new(); CHECK(empty); CHECK(SSL_set1_verify_cert_store(client, empty)); X509_STORE_free(empty);
    }
    const uint16_t groups[] = {SSL_GROUP_X25519, SSL_GROUP_SECP256R1};
    uint16_t share = mode == NO_X25519 ? SSL_GROUP_SECP256R1 : SSL_GROUP_X25519;
    CHECK(SSL_set1_group_ids(client, groups, 2u) && SSL_set1_client_key_shares(client, &share, 1u));
    if (mode == HRR) { uint16_t curve = SSL_GROUP_SECP256R1; CHECK(SSL_set1_group_ids(server, &curve, 1u)); }
    if (mode == EARLY_DATA) SSL_set_early_data_enabled(client, 1);
    fixture_t test = {0}; test.reject = mode == REJECT; test.no_x25519 = mode == NO_X25519;
    SSL_set_app_data(client, &test);
    CHECK(!SSL_set_solaris_client_hello_callback(server, 3u, hello, &test));
    CHECK(!SSL_set_solaris_client_hello_callback(client, 4u, hello, &test));
    CHECK(!SSL_set_solaris_client_hello_callback(client, 0u, hello, &test));
    CHECK(!SSL_set_solaris_client_hello_callback(client, 3u, NULL, &test));
    if (mode != NORMAL && mode != TLS12_NORMAL) CHECK(SSL_set_solaris_client_hello_callback(client, 3u, hello, &test));
    if (resume) CHECK(SSL_set_session(client, resume));
    uint8_t secret[32], zero[32] = {0};
    memset(secret, 1, sizeof(secret)); CHECK(!SSL_solaris_client_hello_x25519(client, zero, secret) && memcmp(secret, zero, 32) == 0);
    BIO *left, *right; CHECK(BIO_new_bio_pair(&left, 1024, &right, 1024));
    SSL_set_bio(client, left, left); SSL_set_bio(server, right, right);
    int c = 0, s = 0;
    for (unsigned round = 0; round < 1000u && (c != 1 || s != 1); ++round) {
        c = step(client); if (c < 0) break;
        s = step(server); if (s < 0) break;
    }
    int expected = mode == NORMAL || mode == TLS12_NORMAL || mode == AUTH;
    SSL_SESSION *session = NULL;
    if (expected) {
        CHECK(c == 1 && s == 1);
        CHECK(SSL_get_verify_result(client) == X509_V_OK);
        CHECK(SSL_session_reused(client) == (resume != NULL));
        if (mode == AUTH) {
            CHECK(test.calls == 1u && test.psk == (resume != NULL));
            uint8_t random[32]; CHECK(SSL_get_client_random(server, random, 32u) == 32u);
            for (unsigned i = 0u; i < 32u; ++i) CHECK(random[i] == 0xa3);
        } else CHECK(test.calls == 0u);
        CHECK(SSL_write(server, "ticket", 6) == 6);
        char buffer[6]; CHECK(SSL_read(client, buffer, sizeof(buffer)) == 6 && memcmp(buffer, "ticket", 6) == 0);
        CHECK(SSL_write(client, "echo", 4) == 4 && SSL_read(server, buffer, sizeof(buffer)) == 4 && memcmp(buffer, "echo", 4) == 0);
        session = test.session; test.session = NULL; CHECK(session);
    } else CHECK(c < 0 || s < 0);
    CHECK(!SSL_set_solaris_client_hello_callback(client, 3u, hello, &test));
    memset(secret, 1, sizeof(secret)); CHECK(!SSL_solaris_client_hello_x25519(client, zero, secret) && memcmp(secret, zero, 32) == 0);
    SSL_SESSION_free(test.session); SSL_free(client); SSL_free(server); ERR_clear_error(); return session;
}
int main(int argc, char **argv)
{
    CHECK(argc == 3);
    SSL_CTX *client = SSL_CTX_new(TLS_method()), *server = SSL_CTX_new(TLS_method()); CHECK(client && server);
    CHECK(SSL_CTX_use_certificate_chain_file(server, argv[1]) && SSL_CTX_use_PrivateKey_file(server, argv[2], SSL_FILETYPE_PEM));
    CHECK(SSL_CTX_load_verify_locations(client, argv[1], NULL)); SSL_CTX_set_verify(client, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_session_cache_mode(client, SSL_SESS_CACHE_CLIENT);
    SSL_CTX_sess_set_new_cb(client, new_session);
    SSL_SESSION_free(run(client, server, NORMAL, NULL));
    SSL_SESSION_free(run(client, server, TLS12_NORMAL, NULL));
    SSL_SESSION *session = run(client, server, AUTH, NULL); CHECK(SSL_SESSION_is_resumable(session));
    SSL_SESSION_free(run(client, server, AUTH, session)); SSL_SESSION_free(session);
    for (int mode = REJECT; mode <= EARLY_DATA; ++mode) if (mode != TLS12_NORMAL) SSL_SESSION_free(run(client, server, mode, NULL));
    SSL_CTX_free(client); SSL_CTX_free(server);
    puts("ClientHello patch: transcript, PSK resumption, key share and rejection boundaries passed"); return 0;
}
