#ifndef SOLARIS_TEST_TLS_MEMORY_H
#define SOLARIS_TEST_TLS_MEMORY_H
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct tls_test_wire {
    BIO *output;
    uint8_t record[32768], observed[65536];
    size_t used, ready, position, observed_size;
    unsigned records, protected_records;
    int protected_epoch, from_server;
} tls_test_wire_t;
typedef struct tls_test_pair {
    SSL *client, *server;
    tls_test_wire_t c2s, s2c;
    int client_result, server_result;
    void (*record)(struct tls_test_pair *, tls_test_wire_t *, uint8_t *, size_t);
    void *context;
} tls_test_pair_t;
static inline void tls_test_pair_init(tls_test_pair_t *pair, SSL_CTX *client, SSL_CTX *server)
{
    memset(pair, 0, sizeof(*pair)); pair->client = SSL_new(client); pair->server = SSL_new(server);
    CHECK(pair->client && pair->server); SSL_set_connect_state(pair->client); SSL_set_accept_state(pair->server);
    BIO *client_write, *server_write;
    CHECK(BIO_new_bio_pair(&client_write, 7u, &pair->c2s.output, 7u));
    CHECK(BIO_new_bio_pair(&server_write, 7u, &pair->s2c.output, 7u));
    SSL_set_bio(pair->client, BIO_new(BIO_s_mem()), client_write);
    SSL_set_bio(pair->server, BIO_new(BIO_s_mem()), server_write);
    BIO_set_mem_eof_return(SSL_get_rbio(pair->client), -1);
    BIO_set_mem_eof_return(SSL_get_rbio(pair->server), -1);
    pair->s2c.from_server = 1;
}
static inline int tls_test_step(SSL *ssl)
{
    int rc = SSL_do_handshake(ssl); if (rc == 1) return 1;
    int error = SSL_get_error(ssl, rc);
    return error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE ? 0 : -1;
}
static inline void tls_test_transfer(tls_test_pair_t *pair, tls_test_wire_t *wire, SSL *destination)
{
    if (!wire->ready) {
        CHECK(wire->used < sizeof(wire->record));
        int n = BIO_read(wire->output, wire->record + wire->used, (int)(sizeof(wire->record) - wire->used));
        if (n > 0) wire->used += (size_t)n;
        if (wire->used < 5u) return;
        size_t size = 5u + ((size_t)wire->record[3] << 8) + wire->record[4]; CHECK(size <= sizeof(wire->record));
        if (wire->used < size) return;
        CHECK(wire->observed_size + size <= sizeof(wire->observed));
        memcpy(wire->observed + wire->observed_size, wire->record, size); wire->observed_size += size;
        wire->records++;
        if (wire->record[0] == SSL3_RT_CHANGE_CIPHER_SPEC) wire->protected_epoch = 1;
        else if (wire->record[0] == SSL3_RT_APPLICATION_DATA || wire->protected_epoch) wire->protected_records++;
        if (pair->record) pair->record(pair, wire, wire->record, size);
        wire->ready = size; wire->position = 0u;
    }
    size_t chunk = wire->ready - wire->position; if (chunk > 3u) chunk = 3u;
    CHECK(BIO_write(SSL_get_rbio(destination), wire->record + wire->position, (int)chunk) == (int)chunk);
    wire->position += chunk;
    if (wire->position == wire->ready) {
        wire->used -= wire->ready; memmove(wire->record, wire->record + wire->ready, wire->used); wire->ready = 0u;
    }
}
static inline int tls_test_handshake(tls_test_pair_t *pair)
{
    for (unsigned i = 0; i < 100000u; ++i) {
        pair->client_result = tls_test_step(pair->client);
        if (pair->client_result < 0) return 0;
        tls_test_transfer(pair, &pair->c2s, pair->server);
        pair->server_result = tls_test_step(pair->server);
        if (pair->server_result < 0) return 0;
        tls_test_transfer(pair, &pair->s2c, pair->client);
        if (pair->client_result == 1 && pair->server_result == 1) return 1;
    }
    CHECK(0); return 0;
}
static inline void tls_test_application(tls_test_pair_t *pair)
{
    static const uint8_t text[] = "verified record sequence";
    int sent = 0, received = 0;
    for (unsigned i = 0; i < 10000u && !received; ++i) {
        if (!sent) {
            int rc = SSL_write(pair->server, text, sizeof(text));
            if (rc == (int)sizeof(text)) sent = 1;
            else { int error = SSL_get_error(pair->server, rc); CHECK(error == SSL_ERROR_WANT_WRITE || error == SSL_ERROR_WANT_READ); }
        }
        tls_test_transfer(pair, &pair->s2c, pair->client);
        uint8_t reply[sizeof(text)]; int rc = SSL_read(pair->client, reply, sizeof(reply));
        if (rc > 0) { CHECK(rc == (int)sizeof(text) && memcmp(text, reply, sizeof(text)) == 0); received = 1; }
        else { int error = SSL_get_error(pair->client, rc); CHECK(error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE); }
        tls_test_transfer(pair, &pair->c2s, pair->server);
    }
    CHECK(sent && received);
}
static inline void tls_test_pair_free(tls_test_pair_t *pair)
{ SSL_free(pair->client); SSL_free(pair->server); BIO_free(pair->c2s.output); BIO_free(pair->s2c.output); ERR_clear_error(); }
#endif
