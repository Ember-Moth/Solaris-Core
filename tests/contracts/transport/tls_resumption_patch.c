#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); ERR_print_errors_fp(stderr); abort(); } } while (0)
#include "support/transport/tls_memory.h"

typedef struct fixture { SSL_SESSION *session; unsigned sessions, hellos; int disabled; } fixture_t;
static int new_session(SSL *ssl, SSL_SESSION *session)
{
    fixture_t *f = SSL_get_app_data(ssl); f->sessions++; SSL_SESSION_free(f->session); SSL_SESSION_up_ref(session); f->session = session; return 0;
}
static void message(int writing, int version, int type, const void *data, size_t size, SSL *ssl, void *context)
{
    (void)version; (void)context; fixture_t *f = SSL_get_app_data(ssl);
    if (!writing || type != SSL3_RT_HANDSHAKE || size < 4u || ((const uint8_t *)data)[0] != SSL3_MT_CLIENT_HELLO) return;
    f->hellos++; SSL_CLIENT_HELLO hello; CHECK(SSL_parse_client_hello(ssl, &hello, (const uint8_t *)data + 4u, size - 4u));
    if (f->disabled) {
        const uint8_t *ext; size_t length;
        CHECK(!SSL_early_callback_ctx_extension_get(&hello, TLSEXT_TYPE_session_ticket, &ext, &length));
        CHECK(!SSL_early_callback_ctx_extension_get(&hello, TLSEXT_TYPE_pre_shared_key, &ext, &length));
        CHECK(!SSL_early_callback_ctx_extension_get(&hello, TLSEXT_TYPE_psk_key_exchange_modes, &ext, &length));
    }
}
static SSL_SESSION *run(SSL_CTX *client, SSL_CTX *server, uint16_t version, SSL_SESSION *offered, int disabled, int early)
{
    tls_test_pair_t *pair = calloc(1u, sizeof(*pair)); CHECK(pair); tls_test_pair_init(pair, client, server);
    fixture_t f = {.disabled = disabled}; SSL_set_app_data(pair->client, &f);
    CHECK(SSL_set_min_proto_version(pair->client, version) && SSL_set_max_proto_version(pair->client, version));
    CHECK(SSL_set_min_proto_version(pair->server, version) && SSL_set_max_proto_version(pair->server, version));
    CHECK(!SSL_disable_solaris_resumption(pair->server));
    if (disabled) {
        CHECK(SSL_disable_solaris_resumption(pair->client));
        SSL_set_shed_handshake_config(pair->client, 1);
    }
    // Set a session after the policy: it must still be discarded at handshake.
    if (offered) CHECK(SSL_set_session(pair->client, offered));
    if (early) SSL_set_early_data_enabled(pair->client, 1);
    CHECK(tls_test_handshake(pair) == !early);
    if (!early) {
        CHECK(f.hellos == 1u && SSL_get_verify_result(pair->client) == X509_V_OK);
        CHECK(SSL_session_reused(pair->client) == (!disabled && offered != NULL));
        tls_test_application(pair);
        if (disabled) {
            CHECK(f.sessions == 0u && f.session == NULL && !SSL_SESSION_is_resumable(SSL_get_session(pair->client)));
        } else if (!offered) CHECK(f.sessions != 0u && f.session && SSL_SESSION_is_resumable(f.session));
        else if (f.session) CHECK(SSL_SESSION_is_resumable(f.session));
    } else CHECK(f.hellos == 0u && f.sessions == 0u);
    CHECK(!SSL_disable_solaris_resumption(pair->client));
    tls_test_pair_free(pair); free(pair); return f.session;
}
int main(int argc, char **argv)
{
    CHECK(argc == 3);
    SSL_CTX *client = SSL_CTX_new(TLS_method()), *server = SSL_CTX_new(TLS_method()); CHECK(client && server);
    CHECK(SSL_CTX_use_certificate_chain_file(server, argv[1]) && SSL_CTX_use_PrivateKey_file(server, argv[2], SSL_FILETYPE_PEM));
    CHECK(SSL_CTX_load_verify_locations(client, argv[1], NULL)); SSL_CTX_set_verify(client, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_session_cache_mode(client, SSL_SESS_CACHE_CLIENT); SSL_CTX_sess_set_new_cb(client, new_session); SSL_CTX_set_msg_callback(client, message);
    for (uint16_t version = TLS1_2_VERSION; version <= TLS1_3_VERSION; ++version) {
        SSL_SESSION *session = run(client, server, version, NULL, 0, 0); CHECK(session);
        SSL_SESSION_free(run(client, server, version, session, 1, 0)); CHECK(SSL_SESSION_is_resumable(session));
        SSL_SESSION_free(run(client, server, version, session, 0, 0));
        if (version == TLS1_3_VERSION) SSL_SESSION_free(run(client, server, version, session, 1, 1));
        SSL_SESSION_free(session);
    }
    SSL_CTX_free(client); SSL_CTX_free(server);
    puts("TLS resumption policy: no PSK/ticket advertisements, no cache callbacks, retained ordinary behavior and early-data rejection passed"); return 0;
}
