#include "support/runtime/files.h"
#include "support/transport/tls_profiles/profile.h"
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/x509.h>
#include <uv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <signal.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#endif

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); ERR_print_errors_fp(stderr); abort(); } } while (0)
static uv_os_sock_t connect_peer(unsigned port)
{
    uv_os_sock_t fd = socket(AF_INET, SOCK_STREAM, 0);
#ifdef _WIN32
    CHECK(fd != INVALID_SOCKET); DWORD timeout = 8000;
#else
    CHECK(fd >= 0); struct timeval timeout = {.tv_sec = 8};
#endif
    CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout)) == 0);
    CHECK(setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof(timeout)) == 0);
    struct sockaddr_in target; CHECK(uv_ip4_addr("127.0.0.1", (int)port, &target) == 0);
    CHECK(connect(fd, (const struct sockaddr *)&target, sizeof(target)) == 0); return fd;
}
static int write_all(uv_os_sock_t fd, const uint8_t *data, size_t size)
{
    while (size) { int n = (int)send(fd, (const char *)data, (int)size, 0); if (n <= 0) return 0; data += n; size -= (size_t)n; }
    return 1;
}
static int read_all(uv_os_sock_t fd, uint8_t *data, size_t size)
{
    while (size) { int n = (int)recv(fd, (char *)data, (int)size, 0); if (n <= 0) return 0; data += n; size -= (size_t)n; }
    return 1;
}
static int read_record(uv_os_sock_t fd, uint8_t record[32768], size_t *size)
{
    if (!read_all(fd, record, 5u)) return 0;
    *size = 5u + ((size_t)record[3] << 8) + record[4];
    return *size <= 32768u && read_all(fd, record + 5u, *size - 5u);
}
static int flush(SSL *ssl, uv_os_sock_t fd)
{
    uint8_t data[16384]; int n;
    while ((n = BIO_read(SSL_get_wbio(ssl), data, sizeof(data))) > 0) if (!write_all(fd, data, (size_t)n)) return 0;
    return 1;
}
static int feed(SSL *ssl, uv_os_sock_t fd, tls_test_profile_t *profile)
{
    uint8_t record[32768]; size_t size;
    if (!read_record(fd, record, &size)) return 0;
    if (profile->kind == PROFILE_SHADOWTLS && tls_test_shadow_input(profile, record, &size, 0) < 0) return 0;
    // Fragment delivery independently of the peer's TCP or TLS write boundaries.
    for (size_t offset = 0u; offset < size;) {
        size_t n = size - offset; if (n > 11u) n = 11u;
        if (BIO_write(SSL_get_rbio(ssl), record + offset, (int)n) != (int)n) return 0;
        offset += n;
    }
    return 1;
}
static int handshake(SSL *ssl, uv_os_sock_t fd, tls_test_profile_t *profile)
{
    for (unsigned i = 0u; i < 1000u; ++i) {
        int rc = SSL_do_handshake(ssl); int error = rc == 1 ? 0 : SSL_get_error(ssl, rc);
        if (!flush(ssl, fd)) return 0;
        if (rc == 1) return 1;
        if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) return 0;
        if (error == SSL_ERROR_WANT_READ && !feed(ssl, fd, profile)) return 0;
    }
    return 0;
}
static void encrypted_echo(SSL *ssl, uv_os_sock_t fd, tls_test_profile_t *profile, const uint8_t *payload, size_t size)
{
    CHECK(SSL_write(ssl, payload, (int)size) == (int)size && flush(ssl, fd));
    uint8_t received[256]; size_t total = 0u;
    for (unsigned i = 0u; i < 100u && total < size; ++i) {
        int n = SSL_read(ssl, received + total, (int)(sizeof(received) - total));
        if (n > 0) total += (size_t)n;
        else { int error = SSL_get_error(ssl, n); CHECK(error == SSL_ERROR_WANT_READ && feed(ssl, fd, profile)); }
        CHECK(flush(ssl, fd));
    }
    CHECK(total == size && memcmp(received, payload, size) == 0);
}
static void raw_echo(SSL *ssl, uv_os_sock_t fd, tls_test_profile_t *profile, const uint8_t *payload, size_t size)
{
    uint8_t record[32768]; size_t encoded = profile->kind == PROFILE_SHADOWTLS ? tls_test_shadow_output(profile, payload, size, record) : tls_test_restls_output(profile, ssl, payload, size, record);
    CHECK(write_all(fd, record, encoded));
    uint8_t received[256]; size_t total = 0u;
    for (unsigned i = 0u; i < 100u && total < size; ++i) {
        size_t count; CHECK(read_record(fd, record, &count));
        const uint8_t *data = NULL; size_t n = 0u; int decoded;
        if (profile->kind == PROFILE_SHADOWTLS) {
            decoded = tls_test_shadow_input(profile, record, &count, 1); data = record; n = count;
        } else {
            decoded = tls_test_restls_input(profile, ssl, record, count, &data, &n);
            if (decoded == 0) {
                // Authenticated camouflage TLS post-handshake records remain
                // TLS data; they are never returned as proxy application data.
                CHECK(BIO_write(SSL_get_rbio(ssl), record, (int)count) == (int)count);
                uint8_t ignored[32768]; int rc = SSL_read(ssl, ignored, sizeof(ignored));
                if (rc <= 0) { int error = SSL_get_error(ssl, rc); CHECK(error == SSL_ERROR_WANT_READ); }
                profile->rx_counter++; CHECK(flush(ssl, fd));
            }
        }
        CHECK(decoded >= 0);
        if (decoded == 1) { CHECK(total + n <= sizeof(received)); memcpy(received + total, data, n); total += n; }
    }
    CHECK(total == size && memcmp(received, payload, size) == 0);
}
static int new_session(SSL *ssl, SSL_SESSION *session)
{
    tls_test_profile_t *profile = SSL_get_app_data(ssl);
    SSL_SESSION_free(profile->session); SSL_SESSION_up_ref(session); profile->session = session; return 0;
}
static SSL_SESSION *load_session(SSL_CTX *ctx, const char *path)
{
    FILE *file = solaris_test_fopen(path, "rb"); CHECK(file);
    uint8_t bytes[16384]; size_t n = fread(bytes, 1u, sizeof(bytes), file); CHECK(n > 0u && n < sizeof(bytes) && feof(file)); fclose(file);
    return SSL_SESSION_from_bytes(bytes, n, ctx);
}
static void save_session(const SSL_SESSION *session, const char *path)
{
    uint8_t *bytes = NULL; size_t size;
    CHECK(session && SSL_SESSION_is_resumable(session) && SSL_SESSION_to_bytes(session, &bytes, &size));
    FILE *file = solaris_test_fopen(path, "wb"); CHECK(file && fwrite(bytes, 1u, size, file) == size); CHECK(fclose(file) == 0); OPENSSL_free(bytes);
}
int main(int argc, char **argv)
{
    CHECK(argc == 10);
#ifdef _WIN32
    WSADATA wsa; CHECK(WSAStartup(MAKEWORD(2, 2), &wsa) == 0);
#else
    (void)signal(SIGPIPE, SIG_IGN);
#endif
    tls_test_profile_t profile; tls_test_profile_init(&profile, argv[1], argv[2], argv[9]);
    SSL_CTX *ctx = SSL_CTX_new(TLS_method()); CHECK(ctx && SSL_CTX_load_verify_locations(ctx, argv[4], NULL));
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL); SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_CLIENT); SSL_CTX_sess_set_new_cb(ctx, new_session);
    // Upstream reverify requires a custom verifier. Exercise the alternate
    // profile's fresh authentication path without enabling it for PKIX modes.
    if (profile.kind == PROFILE_JLS) SSL_CTX_set_reverify_on_resume(ctx, 1);
    SSL *ssl = SSL_new(ctx); CHECK(ssl); SSL_set_connect_state(ssl); tls_test_profile_configure(&profile, ssl);
    if (strcmp(argv[2], "shedding") == 0) SSL_set_shed_handshake_config(ssl, 1);
    if (strcmp(argv[2], "tls12") == 0) CHECK(SSL_set_min_proto_version(ssl, TLS1_2_VERSION) && SSL_set_max_proto_version(ssl, TLS1_2_VERSION));
    if (strcmp(argv[2], "no-ed") == 0) {
        const uint16_t signatures[] = {SSL_SIGN_ECDSA_SECP256R1_SHA256, SSL_SIGN_RSA_PSS_RSAE_SHA256};
        CHECK(SSL_set_verify_algorithm_prefs(ssl, signatures, 2u));
    }
    if (strcmp(argv[5], "-") != 0) {
        SSL_SESSION *session = load_session(ctx, argv[5]);
        if (strcmp(argv[8], "bad-session") == 0) { CHECK(!session); SSL_free(ssl); SSL_CTX_free(ctx); tls_test_profile_free(&profile); puts("malformed session rejected"); return 0; }
        CHECK(session);
        if (strcmp(argv[2], "copy") == 0) {
            SSL_SESSION *copy = SSL_SESSION_copy_without_early_data(session); CHECK(copy); SSL_SESSION_free(session); session = copy;
        }
        CHECK(SSL_set_session(ssl, session)); SSL_SESSION_free(session);
    }
    BIO *input = BIO_new(BIO_s_mem()), *output = BIO_new(BIO_s_mem()); CHECK(input && output); BIO_set_mem_eof_return(input, -1); SSL_set_bio(ssl, input, output);
    uv_os_sock_t fd = connect_peer((unsigned)strtoul(argv[3], NULL, 10));
    int established = handshake(ssl, fd, &profile), authenticated = established && tls_test_profile_authenticated(&profile, ssl);
    if (strcmp(argv[8], "reject") == 0 || strcmp(argv[8], "fallback") == 0) {
        CHECK(!authenticated);
        if (strcmp(argv[2], "bad-finished") == 0 || strcmp(argv[2], "bad-algorithm") == 0) {
            CHECK(profile.peer_calls == 1u && SSL_get_solaris_peer_auth_result(ssl) == SSL_SOLARIS_AUTH_PENDING);
            CHECK(ERR_GET_REASON(ERR_peek_last_error()) == (strcmp(argv[2], "bad-finished") == 0 ? SSL_R_DIGEST_CHECK_FAILED : SSL_R_WRONG_SIGNATURE_TYPE));
        }
        if (strcmp(argv[8], "fallback") == 0) CHECK(established && SSL_get_solaris_record_auth_result(ssl) == SSL_SOLARIS_AUTH_REJECTED);
        puts("peer rejected before proxy payload");
    } else {
        CHECK(authenticated && SSL_session_reused(ssl) == (strcmp(argv[8], "resume") == 0));
        if (profile.kind == PROFILE_JLS) CHECK(profile.peer_calls == 1u && SSL_get_verify_result(ssl) != X509_V_OK);
        if (profile.kind == PROFILE_JLS && strcmp(argv[8], "full") == 0 && strcmp(argv[5], "-") != 0) CHECK(profile.offered_psks == 0u);
        for (unsigned round = 0u; round < 2u; ++round) {
            uint8_t payload[64]; size_t size = round == 0u ? 32u : 55u;
            for (size_t i = 0u; i < size; ++i) payload[i] = (uint8_t)(i * 19u + 37u + round);
            if (profile.kind == PROFILE_SHADOWTLS || profile.kind == PROFILE_RESTLS12 || profile.kind == PROFILE_RESTLS13) raw_echo(ssl, fd, &profile, payload, size);
            else encrypted_echo(ssl, fd, &profile, payload, size);
        }
        if (strcmp(argv[6], "-") != 0) save_session(profile.session, argv[6]);
        printf("profile=%s variant=%s resumed=%d hello=%u peer=%u record=%u psk=%u finished=%zu: authenticated bidirectional data passed\n",
            argv[1], argv[2], SSL_session_reused(ssl), profile.hello_calls, profile.peer_calls, profile.record_calls, profile.offered_psks, profile.finished_size);
        if (strcmp(argv[7], "clear") == 0) {
            CHECK(SSL_clear(ssl) && SSL_get_solaris_peer_auth_result(ssl) != SSL_SOLARIS_AUTH_OK);
            CHECK(SSL_do_handshake(ssl) < 0 && BIO_ctrl_pending(SSL_get_wbio(ssl)) == 0u);
        }
    }
#ifdef _WIN32
    closesocket(fd); WSACleanup();
#else
    close(fd);
#endif
    SSL_free(ssl); SSL_CTX_free(ctx); tls_test_profile_free(&profile); ERR_clear_error(); return 0;
}
