#include <openssl/ssl.h>
#include <openssl/curve25519.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); ERR_print_errors_fp(stderr); abort(); } } while (0)
#include "support/transport/tls_memory.h"

static const uint16_t curves[] = {SSL_GROUP_X25519, SSL_GROUP_SECP256R1, SSL_GROUP_SECP384R1};
typedef struct fixture {
    uint8_t public_keys[3][97];
    size_t public_lengths[3];
    unsigned calls, exchanges, shares;
    int tls12, missing;
    uint16_t selected;
    SSL_SESSION *session;
} fixture_t;
static unsigned u16(const uint8_t *p) { return ((unsigned)p[0] << 8) | p[1]; }
static int new_session(SSL *ssl, SSL_SESSION *session)
{ fixture_t *test = SSL_get_app_data(ssl); SSL_SESSION_free(test->session); SSL_SESSION_up_ref(session); test->session = session; return 0; }
static int hello(SSL *ssl, const uint8_t *wire, size_t length, SSL_SOLARIS_CLIENT_HELLO_OUTPUT *out, void *context)
{
    fixture_t *test = context; CHECK(++test->calls == 1u);
    CHECK(!SSL_set1_solaris_eager_key_shares(ssl, curves, 3u));
    const uint8_t *key = (const uint8_t *)1; size_t size = 999u;
    CHECK(!SSL_get0_solaris_eager_key_share(ssl, SSL_GROUP_SECP521R1, &key, &size) && !key && size == 0u);
    if (test->tls12) {
        for (unsigned i = 0u; i < 3u; ++i) {
            if (test->missing && i != 0u) {
                CHECK(!SSL_get0_solaris_eager_key_share(ssl, curves[i], &key, &size) && !key && size == 0u); continue;
            }
            CHECK(SSL_get0_solaris_eager_key_share(ssl, curves[i], &key, &size));
            CHECK(size == (i == 0u ? 32u : i == 1u ? 65u : 97u));
            memcpy(test->public_keys[i], key, size); test->public_lengths[i] = size;
        }
    } else {
        SSL_CLIENT_HELLO parsed; CHECK(SSL_parse_client_hello(ssl, &parsed, wire + 4, length - 4));
        const uint8_t *extension; size_t n;
        CHECK(SSL_early_callback_ctx_extension_get(&parsed, TLSEXT_TYPE_key_share, &extension, &n) && n >= 2u && u16(extension) == n - 2u);
        uint8_t peer_private[32], peer_public[32], actual[32], expected[32], zero[32] = {0};
        memset(peer_private, 0x37, sizeof(peer_private)); X25519_public_from_private(peer_public, peer_private);
        size_t offset = 2u;
        while (offset < n) {
            CHECK(n - offset >= 4u); uint16_t group = (uint16_t)u16(extension + offset); size_t bytes = u16(extension + offset + 2u); offset += 4u;
            CHECK(bytes <= n - offset);
            if (group == SSL_GROUP_X25519 || group == SSL_GROUP_X25519_MLKEM768) {
                CHECK(bytes == (group == SSL_GROUP_X25519 ? 32u : 1216u));
                CHECK(!SSL_solaris_client_hello_x25519_for_group(ssl, group, zero, actual) && memcmp(actual, zero, 32u) == 0);
                CHECK(SSL_solaris_client_hello_x25519_for_group(ssl, group, peer_public, actual));
                CHECK(X25519(expected, peer_private, extension + offset + bytes - 32u) && memcmp(actual, expected, 32u) == 0);
                memcpy(actual, peer_public, sizeof(actual));
                CHECK(SSL_solaris_client_hello_x25519_for_group(ssl, group, actual, actual) && memcmp(actual, expected, 32u) == 0);
                if (group == SSL_GROUP_X25519) CHECK(SSL_solaris_client_hello_x25519(ssl, peer_public, actual) && memcmp(actual, expected, 32u) == 0);
                test->shares++;
            }
            offset += bytes;
        }
        OPENSSL_cleanse(peer_private, sizeof(peer_private)); OPENSSL_cleanse(actual, sizeof(actual)); OPENSSL_cleanse(expected, sizeof(expected));
    }
    memset(out->session_id, 0x6d, 32u); return 1;
}
static void observe(tls_test_pair_t *pair, tls_test_wire_t *wire, uint8_t *data, size_t size)
{
    fixture_t *test = pair->context;
    if (!test->tls12 || wire->from_server || wire->protected_epoch || data[0] != SSL3_RT_HANDSHAKE || size < 10u || data[5] != SSL3_MT_CLIENT_KEY_EXCHANGE) return;
    CHECK(++test->exchanges == 1u);
    unsigned i = 0u; while (i < 3u && curves[i] != test->selected) i++; CHECK(i < 3u);
    CHECK(data[9] == test->public_lengths[i] && size == 10u + test->public_lengths[i]);
    CHECK(memcmp(data + 10u, test->public_keys[i], test->public_lengths[i]) == 0);
}
static SSL_SESSION *run(SSL_CTX *client_ctx, SSL_CTX *server_ctx, uint16_t version, uint16_t group, int missing, int mixed, SSL_SESSION *resume)
{
    tls_test_pair_t *pair = calloc(1u, sizeof(*pair)); CHECK(pair); tls_test_pair_init(pair, client_ctx, server_ctx);
    fixture_t test = {.tls12 = version == TLS1_2_VERSION, .missing = missing, .selected = group}; pair->context = &test; pair->record = observe;
    SSL_set_app_data(pair->client, &test);
    CHECK(SSL_set_min_proto_version(pair->client, version) && SSL_set_max_proto_version(pair->client, version));
    CHECK(SSL_set_min_proto_version(pair->server, version) && SSL_set_max_proto_version(pair->server, version));
    uint16_t invalid[] = {SSL_GROUP_SECP521R1}, duplicate[] = {SSL_GROUP_X25519, SSL_GROUP_X25519};
    CHECK(!SSL_set1_solaris_eager_key_shares(pair->server, curves, 3u));
    CHECK(!SSL_set1_solaris_eager_key_shares(pair->client, invalid, 1u));
    CHECK(!SSL_set1_solaris_eager_key_shares(pair->client, duplicate, 2u));
    CHECK(!SSL_set1_solaris_eager_key_shares(pair->client, curves, 0u));
    CHECK(!SSL_set1_solaris_eager_key_shares(pair->client, curves, 4u));
    CHECK(!SSL_set1_solaris_eager_key_shares(pair->client, NULL, 1u));
    if (test.tls12) {
        CHECK(SSL_set1_solaris_eager_key_shares(pair->client, curves, missing ? 1u : 3u));
        CHECK(SSL_set1_group_ids(pair->client, curves, 3u) && SSL_set1_group_ids(pair->server, &group, 1u));
        CHECK(SSL_set_strict_cipher_list(pair->client, "ECDHE-ECDSA-AES128-GCM-SHA256") && SSL_set_strict_cipher_list(pair->server, "ECDHE-ECDSA-AES128-GCM-SHA256"));
    } else {
        uint16_t groups[] = {SSL_GROUP_X25519_MLKEM768, SSL_GROUP_X25519};
        CHECK(SSL_set1_group_ids(pair->client, groups, 2u) && SSL_set1_group_ids(pair->server, &group, 1u));
        CHECK(SSL_set1_client_key_shares(pair->client, mixed ? groups : &group, mixed ? 2u : 1u));
    }
    const uint8_t *key = (const uint8_t *)1; size_t size = 100u;
    CHECK(!SSL_get0_solaris_eager_key_share(pair->client, group, &key, &size) && !key && !size);
    uint8_t zero[32] = {0}, output[32]; memset(output, 0x33, sizeof(output));
    CHECK(!SSL_solaris_client_hello_x25519_for_group(pair->client, group, zero, output) && memcmp(output, zero, 32u) == 0);
    CHECK(SSL_set_solaris_client_hello_callback(pair->client, SSL_SOLARIS_HELLO_SESSION_ID, hello, &test));
    if (resume) CHECK(SSL_set_session(pair->client, resume));
    CHECK(tls_test_handshake(pair) == !missing);
    CHECK(test.calls == 1u);
    if (!missing) {
        int expected_resume = resume != NULL && SSL_SESSION_has_ticket(resume);
        CHECK(SSL_get_verify_result(pair->client) == X509_V_OK && SSL_session_reused(pair->client) == expected_resume);
        if (test.tls12) CHECK(test.exchanges == !expected_resume);
        else CHECK(test.shares == (mixed ? 2u : 1u));
        tls_test_application(pair);
    }
    CHECK(!SSL_get0_solaris_eager_key_share(pair->client, group, &key, &size) && !key && !size);
    tls_test_pair_free(pair); free(pair); return test.session;
}
int main(int argc, char **argv)
{
    CHECK(argc == 3);
    SSL_CTX *client = SSL_CTX_new(TLS_method()), *server = SSL_CTX_new(TLS_method()); CHECK(client && server);
    CHECK(SSL_CTX_use_certificate_chain_file(server, argv[1]) && SSL_CTX_use_PrivateKey_file(server, argv[2], SSL_FILETYPE_PEM));
    CHECK(SSL_CTX_load_verify_locations(client, argv[1], NULL)); SSL_CTX_set_verify(client, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_session_cache_mode(client, SSL_SESS_CACHE_CLIENT); SSL_CTX_sess_set_new_cb(client, new_session);
    for (unsigned i = 0u; i < 3u; ++i) {
        SSL_SESSION *session = run(client, server, TLS1_2_VERSION, curves[i], 0, 0, NULL); CHECK(session && SSL_SESSION_is_resumable(session));
        SSL_SESSION_free(run(client, server, TLS1_2_VERSION, curves[i], 0, 0, session)); SSL_SESSION_free(session);
    }
    SSL_SESSION_free(run(client, server, TLS1_2_VERSION, SSL_GROUP_SECP256R1, 1, 0, NULL));
    SSL_CTX_set_options(server, SSL_OP_NO_TICKET);
    SSL_SESSION *legacy = run(client, server, TLS1_2_VERSION, SSL_GROUP_X25519, 0, 0, NULL);
    CHECK(legacy && !SSL_SESSION_has_ticket(legacy));
    SSL_SESSION_free(run(client, server, TLS1_2_VERSION, SSL_GROUP_X25519, 0, 0, legacy)); SSL_SESSION_free(legacy);
    SSL_CTX_clear_options(server, SSL_OP_NO_TICKET);
    SSL_SESSION_free(run(client, server, TLS1_3_VERSION, SSL_GROUP_X25519_MLKEM768, 0, 0, NULL));
    SSL_SESSION_free(run(client, server, TLS1_3_VERSION, SSL_GROUP_X25519_MLKEM768, 0, 1, NULL));
    SSL_CTX_free(client); SSL_CTX_free(server);
    puts("TLS key patch: eager X25519/P-256/P-384 reuse, TLS 1.2 tickets, missing-group rejection and hybrid derivation passed"); return 0;
}
