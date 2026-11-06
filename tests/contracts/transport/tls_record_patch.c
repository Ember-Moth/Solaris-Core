#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); ERR_print_errors_fp(stderr); abort(); } } while (0)
#include "support/transport/tls_memory.h"

enum { MASKED, FALLBACK, BAD_TAG, CALLBACK_REJECT, STRICT_ORIGINAL, CBC_REJECT };
typedef struct fixture { unsigned calls; int mode; } fixture_t;
static int probe(SSL *ssl, const uint8_t header[5], uint8_t *record, size_t size, void *context)
{
    fixture_t *test = context; CHECK(++test->calls == 1u && size >= 16u && header[1] == 3u);
    CHECK(SSL_get_solaris_record_auth_result(ssl) == SSL_SOLARIS_AUTH_PENDING);
    CHECK(!SSL_set_solaris_record_auth_callback(ssl, 0, probe, context));
    for (size_t i = 0; i < size; ++i) record[i] ^= (uint8_t)(0x57u + (i % 16u));
    return test->mode != CALLBACK_REJECT;
}
static void alter(tls_test_pair_t *pair, tls_test_wire_t *wire, uint8_t *record, size_t size)
{
    fixture_t *test = pair->context;
    if (!wire->from_server || wire->protected_records != 1u || record[0] == SSL3_RT_CHANGE_CIPHER_SPEC) return;
    if (test->mode == MASKED || test->mode == BAD_TAG) {
        for (size_t i = 5u; i < size; ++i) record[i] ^= (uint8_t)(0x57u + ((i - 5u) % 16u));
        if (test->mode == BAD_TAG) record[size - 1u] ^= 0x80u;
    }
}
static void run(SSL_CTX *client_ctx, SSL_CTX *server_ctx, unsigned version, unsigned cipher, int mode)
{
    tls_test_pair_t *pair = calloc(1u, sizeof(*pair)); CHECK(pair); tls_test_pair_init(pair, client_ctx, server_ctx);
    fixture_t test = {.mode = mode}; pair->context = &test; pair->record = alter;
    CHECK(SSL_set_min_proto_version(pair->client, version) && SSL_set_max_proto_version(pair->client, version));
    CHECK(SSL_set_min_proto_version(pair->server, version) && SSL_set_max_proto_version(pair->server, version));
    if (version == TLS1_3_VERSION) {
        uint16_t id = (uint16_t)(0x1301u + cipher);
        CHECK(SSL_set1_tls13_ciphers(pair->client, &id, NULL, 1u) && SSL_set1_tls13_ciphers(pair->server, &id, NULL, 1u));
    } else {
        const char *names[] = {"ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-ECDSA-AES256-GCM-SHA384", "ECDHE-ECDSA-CHACHA20-POLY1305", "ECDHE-ECDSA-AES128-SHA"};
        CHECK(SSL_set_strict_cipher_list(pair->client, names[cipher]) && SSL_set_strict_cipher_list(pair->server, names[cipher]));
    }
    CHECK(!SSL_set_solaris_record_auth_callback(pair->server, 0u, probe, &test));
    CHECK(!SSL_set_solaris_record_auth_callback(pair->client, 2u, probe, &test));
    CHECK(!SSL_set_solaris_record_auth_callback(pair->client, 0u, NULL, &test));
    CHECK(SSL_set_solaris_record_auth_callback(pair->client, mode == FALLBACK ? SSL_SOLARIS_RECORD_ALLOW_FALLBACK : 0u, probe, &test));
    CHECK(SSL_enable_solaris_client_finished_capture(pair->client) && !SSL_enable_solaris_client_finished_capture(pair->server));
    const uint8_t *finished = (const uint8_t *)1; size_t length = 99u;
    CHECK(!SSL_get0_solaris_client_finished(pair->client, &finished, &length) && !finished && length == 0u);
    int expected = mode == MASKED || mode == FALLBACK;
    CHECK(tls_test_handshake(pair) == expected);
    CHECK(test.calls == (mode == CBC_REJECT ? 0u : 1u));
    if (expected) {
        CHECK(SSL_get_verify_result(pair->client) == X509_V_OK);
        CHECK(SSL_get_solaris_record_auth_result(pair->client) == (mode == MASKED ? SSL_SOLARIS_AUTH_OK : SSL_SOLARIS_AUTH_REJECTED));
        CHECK(SSL_get0_solaris_client_finished(pair->client, &finished, &length) && length > 5u && length <= 4096u);
        size_t matches = 0u;
        for (size_t i = 0u; i + length <= pair->c2s.observed_size; ++i)
            if (memcmp(pair->c2s.observed + i, finished, length) == 0) matches++;
        CHECK(matches == 1u);
        size_t offset = 0u;
        while (offset < length) {
            CHECK(length - offset >= 5u);
            size_t record_size = 5u + ((size_t)finished[offset + 3u] << 8) + finished[offset + 4u];
            CHECK(record_size <= length - offset && finished[offset] == (version == TLS1_3_VERSION ? SSL3_RT_APPLICATION_DATA : SSL3_RT_HANDSHAKE));
            offset += record_size;
        }
        tls_test_application(pair);
        const uint8_t *again; size_t again_length;
        CHECK(SSL_get0_solaris_client_finished(pair->client, &again, &again_length) && again == finished && again_length == length);
    } else CHECK(SSL_get_solaris_record_auth_result(pair->client) == SSL_SOLARIS_AUTH_REJECTED);
    CHECK(!SSL_enable_solaris_client_finished_capture(pair->client));
    tls_test_pair_free(pair); free(pair);
}
int main(int argc, char **argv)
{
    CHECK(argc == 3);
    SSL_CTX *client = SSL_CTX_new(TLS_method()), *server = SSL_CTX_new(TLS_method()); CHECK(client && server);
    CHECK(SSL_CTX_use_certificate_chain_file(server, argv[1]) && SSL_CTX_use_PrivateKey_file(server, argv[2], SSL_FILETYPE_PEM));
    CHECK(SSL_CTX_load_verify_locations(client, argv[1], NULL)); SSL_CTX_set_verify(client, SSL_VERIFY_PEER, NULL);
    for (unsigned version = TLS1_2_VERSION; version <= TLS1_3_VERSION; ++version)
        for (unsigned cipher = 0u; cipher < 3u; ++cipher)
            for (int mode = MASKED; mode <= STRICT_ORIGINAL; ++mode) run(client, server, version, cipher, mode);
    run(client, server, TLS1_2_VERSION, 3u, CBC_REJECT);
    SSL_CTX_free(client); SSL_CTX_free(server);
    puts("TLS record patch: AEAD trial rollback, strict failure, CBC rejection, fragmented BIO and exact Finished ciphertext passed"); return 0;
}
