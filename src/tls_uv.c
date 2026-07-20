#include "tls_uv.h"

#include <assert.h>
#include <limits.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/base64.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/mem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "anytls/error.h"
#include "aproxy/address.h"
#include "aproxy/bufpool.h"
#include "aproxy/limits.h"

typedef struct anytls_uv_write {
    uv_write_t req;
    uv_buf_t buf;
    struct anytls_tls_client *tls;
    uint8_t *data;
    size_t length;
    size_t capacity;
    struct anytls_uv_write *next_free;
} anytls_uv_write_t;

#define TLS_WRITE_REQUEST_POOL_MAX_FREE 64u
#define TLS_READ_BUFFER_POOL_MAX_FREE 2u
#define TLS_WRITE_BUFFER_POOL_MAX_FREE 8u

struct aproxy_tls_context {
    SSL_CTX *ctx;
    atomic_size_t references;
    int insecure_skip_verify;
};

struct anytls_tls_client {
    uv_loop_t *loop;
    uv_tcp_t tcp;
    uv_connect_t connect_req;
    uv_getaddrinfo_t resolve_req;
    struct sockaddr_storage connect_address;
    aproxy_dns_resolver_t *resolver;
    aproxy_socket_protector_t socket_protector;
    aproxy_tls_context_t *context;
    SSL *ssl;
    BIO *rbio;
    BIO *wbio;
    aproxy_bufpool_t read_pool;
    aproxy_bufpool_t write_pool;
    char *host;
    char *port;
    char *sni;
    int ech_required;
    int insecure_skip_verify;
    int tcp_initialized;
    int tcp_closed;
    int resolve_pending;
    int protect_pending;
    int free_pending;
    unsigned int callback_depth;
    size_t writes_pending;
    size_t write_bytes_pending;
    size_t max_pending_bytes;
    anytls_uv_write_t *free_write_reqs;
    size_t free_write_req_count;
    int handshake_done;
    int raw_read;
    int raw_transitioning;
    int closed;
    anytls_tls_ready_cb on_ready;
    anytls_tls_data_cb on_data;
    anytls_tls_close_cb on_close;
    void *user_data;
};

static void close_cb(uv_handle_t *handle);
static void fail_and_close(anytls_tls_client_t *tls, int status);

int aproxy_ech_config_list_decode_base64(const char *encoded,
                                         uint8_t **out,
                                         size_t *out_len)
{
    if (encoded == NULL || out == NULL || out_len == NULL ||
        encoded[0] == '\0') {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    *out = NULL;
    *out_len = 0u;

    const size_t encoded_len = strlen(encoded);
    size_t capacity = 0u;
    if (!EVP_DecodedLength(&capacity, encoded_len) || capacity == 0u) {
        return APROXY_ERR_PARSE;
    }
    uint8_t *decoded = (uint8_t *)malloc(capacity);
    if (decoded == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    size_t decoded_len = 0u;
    if (!EVP_DecodeBase64(decoded, &decoded_len, capacity,
                          (const uint8_t *)encoded, encoded_len) ||
        decoded_len == 0u) {
        free(decoded);
        return APROXY_ERR_PARSE;
    }
    *out = decoded;
    *out_len = decoded_len;
    return APROXY_OK;
}

int aproxy_ech_config_list_validate(const uint8_t *config_list,
                                    size_t config_list_len)
{
    if (config_list == NULL || config_list_len == 0u) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    SSL_CTX *context = SSL_CTX_new(TLS_method());
    SSL *ssl = context == NULL ? NULL : SSL_new(context);
    const int valid = ssl != NULL &&
                      SSL_set1_ech_config_list(ssl, config_list,
                                               config_list_len);
    SSL_free(ssl);
    SSL_CTX_free(context);
    return valid ? APROXY_OK : APROXY_ERR_PARSE;
}

static int set_alpn_protocols(SSL *ssl, const char *protocols)
{
    if (protocols == NULL) {
        return ANYTLS_OK;
    }
    const size_t text_len = strlen(protocols);
    if (text_len == 0u || text_len > UINT_MAX - 1u) {
        return ANYTLS_ERR_INVALID_ARGUMENT;
    }

    uint8_t *wire = (uint8_t *)malloc(text_len + 1u);
    if (wire == NULL) {
        return ANYTLS_ERR_NO_MEMORY;
    }
    size_t wire_len = 0u;
    const char *cursor = protocols;
    for (;;) {
        while (*cursor == ' ' || *cursor == '\t') {
            cursor++;
        }
        const char *end = strchr(cursor, ',');
        if (end == NULL) {
            end = cursor + strlen(cursor);
        }
        const char *trimmed_end = end;
        while (trimmed_end > cursor &&
               (trimmed_end[-1] == ' ' || trimmed_end[-1] == '\t')) {
            trimmed_end--;
        }
        const size_t protocol_len = (size_t)(trimmed_end - cursor);
        if (protocol_len == 0u || protocol_len > UINT8_MAX) {
            free(wire);
            return ANYTLS_ERR_INVALID_ARGUMENT;
        }
        wire[wire_len++] = (uint8_t)protocol_len;
        memcpy(wire + wire_len, cursor, protocol_len);
        wire_len += protocol_len;
        if (*end == '\0') {
            break;
        }
        cursor = end + 1;
    }
    const int ok = SSL_set_alpn_protos(ssl, wire,
                                       (unsigned int)wire_len) == 0;
    free(wire);
    return ok ? ANYTLS_OK : ANYTLS_ERR_INVALID_ARGUMENT;
}

#if defined(BORINGSSL_HAS_REALITY_CLIENT)
static enum ssl_verify_result_t reality_verify_certificate(
    SSL *ssl, uint8_t *out_alert)
{
    const uint8_t *auth_key = NULL;
    size_t auth_key_len = 0u;
    STACK_OF(X509) *chain = SSL_get_peer_full_cert_chain(ssl);
    if (!SSL_get0_reality_auth_key(ssl, &auth_key, &auth_key_len) ||
        auth_key == NULL || auth_key_len != 32u || chain == NULL ||
        sk_X509_num(chain) < 1) {
        *out_alert = SSL_AD_BAD_CERTIFICATE;
        return ssl_verify_invalid;
    }
    X509 *certificate = sk_X509_value(chain, 0);
    EVP_PKEY *public_key = X509_get0_pubkey(certificate);
    if (public_key == NULL || EVP_PKEY_id(public_key) != EVP_PKEY_ED25519) {
        *out_alert = SSL_AD_BAD_CERTIFICATE;
        return ssl_verify_invalid;
    }

    uint8_t raw_public_key[32];
    size_t raw_public_key_len = sizeof(raw_public_key);
    const ASN1_BIT_STRING *signature = NULL;
    X509_get0_signature(&signature, NULL, certificate);
    if (!EVP_PKEY_get_raw_public_key(public_key, raw_public_key,
                                     &raw_public_key_len) ||
        raw_public_key_len != sizeof(raw_public_key) || signature == NULL ||
        ASN1_STRING_length((const ASN1_STRING *)signature) != 64) {
        OPENSSL_cleanse(raw_public_key, sizeof(raw_public_key));
        *out_alert = SSL_AD_BAD_CERTIFICATE;
        return ssl_verify_invalid;
    }

    uint8_t expected[EVP_MAX_MD_SIZE];
    unsigned int expected_len = 0u;
    const uint8_t *actual =
        ASN1_STRING_get0_data((const ASN1_STRING *)signature);
    const int valid =
        actual != NULL &&
        HMAC(EVP_sha512(), auth_key, auth_key_len, raw_public_key,
             sizeof(raw_public_key), expected, &expected_len) != NULL &&
        expected_len == 64u && CRYPTO_memcmp(expected, actual, 64u) == 0;
    OPENSSL_cleanse(raw_public_key, sizeof(raw_public_key));
    OPENSSL_cleanse(expected, sizeof(expected));
    if (!valid) {
        *out_alert = SSL_AD_BAD_CERTIFICATE;
        return ssl_verify_invalid;
    }
    return ssl_verify_ok;
}
#endif

int aproxy_tls_context_new(int insecure_skip_verify,
                           aproxy_tls_context_t **out)
{
    if (out == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    *out = NULL;
    aproxy_tls_context_t *context =
        (aproxy_tls_context_t *)calloc(1u, sizeof(*context));
    if (context == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    context->ctx = SSL_CTX_new(TLS_method());
    if (context->ctx == NULL) {
        free(context);
        return APROXY_ERR_NO_MEMORY;
    }
    context->insecure_skip_verify = insecure_skip_verify != 0;
    atomic_init(&context->references, 1u);
    if (context->insecure_skip_verify) {
        SSL_CTX_set_verify(context->ctx, SSL_VERIFY_NONE, NULL);
    } else {
        SSL_CTX_set_verify(context->ctx, SSL_VERIFY_PEER, NULL);
        (void)SSL_CTX_set_default_verify_paths(context->ctx);
    }
    *out = context;
    return APROXY_OK;
}

void aproxy_tls_context_retain(aproxy_tls_context_t *context)
{
    if (context == NULL) {
        return;
    }
    (void)atomic_fetch_add_explicit(&context->references, 1u,
                                    memory_order_relaxed);
}

void aproxy_tls_context_free(aproxy_tls_context_t *context)
{
    if (context == NULL) {
        return;
    }
    if (atomic_fetch_sub_explicit(&context->references, 1u,
                                  memory_order_acq_rel) == 1u) {
        SSL_CTX_free(context->ctx);
        free(context);
    }
}

static void tls_destroy(anytls_tls_client_t *tls)
{
    if (tls == NULL) {
        return;
    }
    SSL_free(tls->ssl);
    aproxy_tls_context_free(tls->context);
    aproxy_bufpool_destroy(&tls->read_pool);
    aproxy_bufpool_destroy(&tls->write_pool);
    while (tls->free_write_reqs != NULL) {
        anytls_uv_write_t *next = tls->free_write_reqs->next_free;
        free(tls->free_write_reqs);
        tls->free_write_reqs = next;
    }
    free(tls->host);
    free(tls->port);
    free(tls->sni);
    free(tls);
}

static anytls_uv_write_t *tls_write_req_acquire(anytls_tls_client_t *tls)
{
    anytls_uv_write_t *request = tls->free_write_reqs;
    if (request != NULL) {
        tls->free_write_reqs = request->next_free;
        tls->free_write_req_count--;
        memset(request, 0, sizeof(*request));
        return request;
    }
    return (anytls_uv_write_t *)calloc(1u, sizeof(*request));
}

static void tls_write_req_release(anytls_tls_client_t *tls,
                                  anytls_uv_write_t *request)
{
    if (tls->free_write_req_count >= TLS_WRITE_REQUEST_POOL_MAX_FREE) {
        free(request);
        return;
    }
    request->next_free = tls->free_write_reqs;
    tls->free_write_reqs = request;
    tls->free_write_req_count++;
}

static void tls_maybe_destroy(anytls_tls_client_t *tls)
{
    if (tls == NULL || !tls->free_pending || tls->resolve_pending ||
        tls->protect_pending || tls->callback_depth > 0u ||
        tls->writes_pending > 0u ||
        (tls->tcp_initialized && !tls->tcp_closed)) {
        return;
    }
    tls_destroy(tls);
}

static void tls_report_ready(anytls_tls_client_t *tls, int status)
{
    if (tls == NULL || tls->on_ready == NULL) {
        return;
    }
    tls->callback_depth++;
    tls->on_ready(tls, status, tls->user_data);
    tls->callback_depth--;
}

static void tls_report_data(anytls_tls_client_t *tls,
                            const uint8_t *data,
                            size_t len)
{
    if (tls == NULL || tls->on_data == NULL) {
        return;
    }
    tls->callback_depth++;
    tls->on_data(tls, data, len, tls->user_data);
    tls->callback_depth--;
}

static void tls_report_close(anytls_tls_client_t *tls, int status)
{
    if (tls == NULL || tls->on_close == NULL) {
        return;
    }
    tls->callback_depth++;
    tls->on_close(tls, status, tls->user_data);
    tls->callback_depth--;
}

static char *anytls_strdup(const char *s)
{
    if (s == NULL) {
        return NULL;
    }
    const size_t len = strlen(s);
    char *copy = (char *)malloc(len + 1u);
    if (copy == NULL) {
        return NULL;
    }
    memcpy(copy, s, len + 1u);
    return copy;
}

static void free_write_req(uv_write_t *req, int status)
{
    anytls_uv_write_t *write_req = (anytls_uv_write_t *)req;
    anytls_tls_client_t *tls = write_req->tls;
    const size_t length = write_req->length;
    aproxy_bufpool_release(&tls->write_pool, write_req->data,
                           write_req->capacity);
    tls_write_req_release(tls, write_req);
    if (tls->writes_pending > 0u) {
        tls->writes_pending--;
    }
    tls->write_bytes_pending =
        tls->write_bytes_pending >= length
            ? tls->write_bytes_pending - length
            : 0u;
    if (status != 0 && !tls->closed) {
        fail_and_close(tls, status);
    }
    tls_maybe_destroy(tls);
}

static int write_tcp_copy(anytls_tls_client_t *tls,
                          const uint8_t *data,
                          size_t len)
{
    if (tls == NULL || (data == NULL && len > 0u) || tls->closed ||
        !tls->tcp_initialized) {
        return ANYTLS_ERR_INVALID_ARGUMENT;
    }
    while (len > 0u) {
        size_t chunk_len = len > UINT_MAX ? UINT_MAX : len;
        size_t offset = 0u;
        if (tls->writes_pending == 0u) {
            uv_buf_t direct = uv_buf_init((char *)(uintptr_t)data,
                                          (unsigned int)chunk_len);
            const int written =
                uv_try_write((uv_stream_t *)&tls->tcp, &direct, 1u);
            if (written == (int)chunk_len) {
                data += chunk_len;
                len -= chunk_len;
                continue;
            }
            if (written > 0) {
                offset = (size_t)written;
            } else if (written != UV_EAGAIN && written != UV_ENOSYS) {
                return written;
            }
        }

        const size_t pending = chunk_len - offset;
        if (aproxy_size_add_exceeds(tls->write_bytes_pending, pending,
                                    tls->max_pending_bytes)) {
            return ANYTLS_ERR_FRAME_TOO_LARGE;
        }
        anytls_uv_write_t *write_req = tls_write_req_acquire(tls);
        if (write_req == NULL) {
            return ANYTLS_ERR_NO_MEMORY;
        }
        size_t capacity = 0u;
        uint8_t *copy = aproxy_bufpool_acquire(&tls->write_pool, pending,
                                               &capacity);
        if (copy == NULL) {
            tls_write_req_release(tls, write_req);
            return ANYTLS_ERR_NO_MEMORY;
        }
        memcpy(copy, data + offset, pending);
        write_req->tls = tls;
        write_req->data = copy;
        write_req->capacity = capacity;
        write_req->length = pending;
        write_req->buf = uv_buf_init((char *)copy, (unsigned int)pending);
        const int rc = uv_write(&write_req->req, (uv_stream_t *)&tls->tcp,
                                &write_req->buf, 1u, free_write_req);
        if (rc != 0) {
            aproxy_bufpool_release(&tls->write_pool, copy, capacity);
            tls_write_req_release(tls, write_req);
            return rc;
        }
        tls->writes_pending++;
        tls->write_bytes_pending += pending;
        data += chunk_len;
        len -= chunk_len;
    }
    return ANYTLS_OK;
}

static void alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf)
{
    anytls_tls_client_t *tls = (anytls_tls_client_t *)handle->data;
    (void)suggested_size;
    size_t capacity = 0u;
    uint8_t *data = tls == NULL
                        ? NULL
                        : aproxy_bufpool_acquire(&tls->read_pool,
                                                 16384u, &capacity);
    buf->base = (char *)data;
    buf->len = data == NULL ? 0u : capacity;
}

static int flush_wbio(anytls_tls_client_t *tls)
{
    if (tls == NULL || tls->closed) {
        return ANYTLS_ERR_INVALID_ARGUMENT;
    }
    while (BIO_ctrl_pending(tls->wbio) > 0u) {
        const uint8_t *contents = NULL;
        size_t contents_len = 0u;
        if (!BIO_mem_contents(tls->wbio, &contents, &contents_len) ||
            contents == NULL || contents_len == 0u ||
            contents_len > UINT_MAX) {
            return ANYTLS_ERR_INVALID_ARGUMENT;
        }

        int written = UV_EAGAIN;
        if (tls->writes_pending == 0u) {
            uv_buf_t direct = uv_buf_init((char *)(uintptr_t)contents,
                                          (unsigned int)contents_len);
            written =
                uv_try_write((uv_stream_t *)&tls->tcp, &direct, 1u);
        }
        if (written == (int)contents_len) {
            if (BIO_reset(tls->wbio) != 1) {
                return ANYTLS_ERR_INVALID_ARGUMENT;
            }
            continue;
        }
        size_t offset = 0u;
        if (written > 0) {
            offset = (size_t)written;
        } else if (written != UV_EAGAIN && written != UV_ENOSYS) {
            return written;
        }

        anytls_uv_write_t *write_req = tls_write_req_acquire(tls);
        if (write_req == NULL) {
            return ANYTLS_ERR_NO_MEMORY;
        }
        const size_t pending = contents_len - offset;
        if (aproxy_size_add_exceeds(tls->write_bytes_pending, pending,
                                    tls->max_pending_bytes)) {
            tls_write_req_release(tls, write_req);
            return ANYTLS_ERR_FRAME_TOO_LARGE;
        }
        size_t capacity = 0u;
        uint8_t *data = aproxy_bufpool_acquire(&tls->write_pool, pending,
                                               &capacity);
        if (data == NULL) {
            tls_write_req_release(tls, write_req);
            return ANYTLS_ERR_NO_MEMORY;
        }
        memcpy(data, contents + offset, pending);
        if (BIO_reset(tls->wbio) != 1) {
            aproxy_bufpool_release(&tls->write_pool, data, capacity);
            tls_write_req_release(tls, write_req);
            return ANYTLS_ERR_INVALID_ARGUMENT;
        }
        write_req->tls = tls;
        write_req->data = data;
        write_req->capacity = capacity;
        write_req->length = pending;
        write_req->buf = uv_buf_init((char *)data, (unsigned int)pending);
        const int rc = uv_write(&write_req->req, (uv_stream_t *)&tls->tcp,
                                &write_req->buf, 1u, free_write_req);
        if (rc != 0) {
            aproxy_bufpool_release(&tls->write_pool, data, capacity);
            tls_write_req_release(tls, write_req);
            return rc;
        }
        tls->writes_pending++;
        tls->write_bytes_pending += pending;
    }
    return ANYTLS_OK;
}

static void close_cb(uv_handle_t *handle)
{
    anytls_tls_client_t *tls = (anytls_tls_client_t *)handle->data;
    if (tls == NULL) {
        return;
    }
    tls->tcp_closed = 1;
    if (!tls->free_pending && tls->on_close != NULL) {
        tls_report_close(tls, 0);
    }
    tls_maybe_destroy(tls);
}

static void fail_and_close(anytls_tls_client_t *tls, int status)
{
    if (tls == NULL || tls->closed) {
        return;
    }
    if (!tls->handshake_done && tls->on_ready != NULL) {
        tls_report_ready(tls, status);
    }
    anytls_tls_client_close(tls);
}

static int drain_plaintext(anytls_tls_client_t *tls)
{
    uint8_t plain[16 * 1024];
    for (;;) {
        if (tls->raw_read) {
            return ANYTLS_OK;
        }
        const int n = SSL_read(tls->ssl, plain, (int)sizeof(plain));
        if (n > 0) {
            if (tls->on_data != NULL) {
                tls_report_data(tls, plain, (size_t)n);
                if (tls->free_pending || tls->closed) {
                    return ANYTLS_OK;
                }
                if (tls->raw_read) {
                    return ANYTLS_OK;
                }
            }
            continue;
        }

        const int ssl_err = SSL_get_error(tls->ssl, n);
        if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
            return flush_wbio(tls);
        }
        if (ssl_err == SSL_ERROR_ZERO_RETURN) {
            anytls_tls_client_close(tls);
            return ANYTLS_OK;
        }
        return ANYTLS_ERR_INVALID_ARGUMENT;
    }
}

static int drive_handshake(anytls_tls_client_t *tls)
{
    if (tls->handshake_done) {
        return drain_plaintext(tls);
    }

    const int rc = SSL_do_handshake(tls->ssl);
    if (rc == 1) {
        if (tls->ech_required && !SSL_ech_accepted(tls->ssl)) {
            return ANYTLS_ERR_CRYPTO;
        }
        tls->handshake_done = 1;
        int flush_rc = flush_wbio(tls);
        if (flush_rc != ANYTLS_OK) {
            return flush_rc;
        }
        if (tls->on_ready != NULL) {
            tls_report_ready(tls, ANYTLS_OK);
            if (tls->free_pending || tls->closed) {
                return ANYTLS_OK;
            }
        }
        return drain_plaintext(tls);
    }

    const int ssl_err = SSL_get_error(tls->ssl, rc);
    if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
        return flush_wbio(tls);
    }
    return ANYTLS_ERR_INVALID_ARGUMENT;
}

static void read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf)
{
    anytls_tls_client_t *tls = (anytls_tls_client_t *)stream->data;
    if (nread > 0) {
        if (tls->raw_read) {
            tls_report_data(tls, (const uint8_t *)buf->base, (size_t)nread);
            aproxy_bufpool_release(&tls->read_pool, (uint8_t *)buf->base,
                                   buf->len);
            return;
        }
        const int written = BIO_write(tls->rbio, buf->base, (int)nread);
        if (written != nread) {
            aproxy_bufpool_release(&tls->read_pool, (uint8_t *)buf->base,
                                   buf->len);
            fail_and_close(tls, ANYTLS_ERR_INVALID_ARGUMENT);
            return;
        }
        const int rc = drive_handshake(tls);
        if (rc != ANYTLS_OK) {
            aproxy_bufpool_release(&tls->read_pool, (uint8_t *)buf->base,
                                   buf->len);
            fail_and_close(tls, rc);
            return;
        }
    } else if (nread < 0) {
        fail_and_close(tls, (int)nread);
    }
    aproxy_bufpool_release(&tls->read_pool, (uint8_t *)buf->base, buf->len);
}

static void connect_cb(uv_connect_t *req, int status)
{
    anytls_tls_client_t *tls = (anytls_tls_client_t *)req->data;
    if (tls->free_pending) {
        tls_maybe_destroy(tls);
        return;
    }
    if (status != 0) {
        fail_and_close(tls, status);
        return;
    }
    const int read_rc = uv_read_start((uv_stream_t *)&tls->tcp, alloc_cb, read_cb);
    if (read_rc != 0) {
        fail_and_close(tls, read_rc);
        return;
    }
    const int hs_rc = drive_handshake(tls);
    if (hs_rc != ANYTLS_OK) {
        fail_and_close(tls, hs_rc);
    }
}

static int addr_to_sockaddr(const aproxy_addr_t *address,
                            struct sockaddr_storage *storage)
{
    memset(storage, 0, sizeof(*storage));
    if (address->family == APROXY_ADDR_IPV4) {
        struct sockaddr_in *out = (struct sockaddr_in *)storage;
        out->sin_family = AF_INET;
        out->sin_port = htons(address->port);
        memcpy(&out->sin_addr, address->addr, 4u);
        return ANYTLS_OK;
    }
    if (address->family == APROXY_ADDR_IPV6) {
        struct sockaddr_in6 *out = (struct sockaddr_in6 *)storage;
        out->sin6_family = AF_INET6;
        out->sin6_port = htons(address->port);
        memcpy(&out->sin6_addr, address->addr, 16u);
        return ANYTLS_OK;
    }
    return ANYTLS_ERR_INVALID_ARGUMENT;
}

static int start_tcp_connect(anytls_tls_client_t *tls)
{
    return uv_tcp_connect(
        &tls->connect_req, &tls->tcp,
        (const struct sockaddr *)&tls->connect_address, connect_cb);
}

static void close_tcp(anytls_tls_client_t *tls)
{
    if (tls->tcp_initialized && !tls->tcp_closed &&
        !uv_is_closing((uv_handle_t *)&tls->tcp)) {
        uv_close((uv_handle_t *)&tls->tcp, close_cb);
    } else if (!tls->free_pending && tls->on_close != NULL) {
        tls_report_close(tls, 0);
    }
    tls_maybe_destroy(tls);
}

static void socket_protect_result(void *context, int status)
{
    anytls_tls_client_t *tls = (anytls_tls_client_t *)context;
    if (tls == NULL || !tls->protect_pending) {
        return;
    }
    tls->protect_pending = 0;
    if (tls->free_pending || tls->closed) {
        tls->closed = 1;
        close_tcp(tls);
        return;
    }
    if (status == ANYTLS_OK) {
        status = start_tcp_connect(tls);
    }
    if (status != ANYTLS_OK) {
        fail_and_close(tls, status);
    }
}

static int init_tcp_handle(anytls_tls_client_t *tls, int family)
{
    const int rc = tls->socket_protector.submit == NULL
                       ? uv_tcp_init(tls->loop, &tls->tcp)
                       : uv_tcp_init_ex(tls->loop, &tls->tcp, family);
    if (rc != 0) {
        return rc;
    }
    tls->tcp_initialized = 1;
    tls->tcp.data = tls;
    tls->connect_req.data = tls;
    return ANYTLS_OK;
}

static void set_connect_address(anytls_tls_client_t *tls,
                                const struct sockaddr *address)
{
    const size_t address_len = address->sa_family == AF_INET
                                   ? sizeof(struct sockaddr_in)
                                   : sizeof(struct sockaddr_in6);
    memset(&tls->connect_address, 0, sizeof(tls->connect_address));
    memcpy(&tls->connect_address, address, address_len);
}

static int init_protected_tcp(anytls_tls_client_t *tls,
                              const struct sockaddr *address)
{
    if (address == NULL ||
        (address->sa_family != AF_INET && address->sa_family != AF_INET6)) {
        return ANYTLS_ERR_INVALID_ARGUMENT;
    }
    int rc = init_tcp_handle(tls, address->sa_family);
    if (rc != ANYTLS_OK) {
        return rc;
    }
    set_connect_address(tls, address);
    tls->protect_pending = 1;
    rc = aproxy_socket_protector_submit(
        &tls->socket_protector, (const uv_handle_t *)&tls->tcp,
        socket_protect_result, tls);
    if (rc != ANYTLS_OK) {
        tls->protect_pending = 0;
    }
    return rc;
}

static void shared_resolved_cb(aproxy_dns_resolver_t *resolver,
                               int status,
                               const aproxy_addr_t *addresses,
                               size_t count,
                               void *user_data)
{
    (void)resolver;
    anytls_tls_client_t *tls = (anytls_tls_client_t *)user_data;
    tls->resolve_pending = 0;
    if (tls->free_pending) {
        tls_maybe_destroy(tls);
        return;
    }
    if (tls->closed) {
        return;
    }
    if (status != APROXY_OK || addresses == NULL || count == 0u) {
        fail_and_close(tls, status != APROXY_OK
                                ? status
                                : ANYTLS_ERR_INVALID_ARGUMENT);
        return;
    }
    int rc = ANYTLS_ERR_INVALID_ARGUMENT;
    if (tls->socket_protector.submit == NULL) {
        rc = init_tcp_handle(tls, AF_UNSPEC);
        if (rc != ANYTLS_OK) {
            fail_and_close(tls, rc);
            return;
        }
    }
    for (size_t i = 0u; i < count; i++) {
        struct sockaddr_storage storage;
        if (addr_to_sockaddr(&addresses[i], &storage) != ANYTLS_OK) {
            continue;
        }
        if (tls->socket_protector.submit != NULL) {
            rc = init_protected_tcp(
                tls, (const struct sockaddr *)&storage);
            break;
        }
        set_connect_address(tls, (const struct sockaddr *)&storage);
        rc = start_tcp_connect(tls);
        if (rc == ANYTLS_OK) {
            break;
        }
    }
    if (rc == ANYTLS_OK) {
        return;
    }
    fail_and_close(tls, rc);
}

static void resolved_cb(uv_getaddrinfo_t *req,
                        int status,
                        struct addrinfo *res)
{
    anytls_tls_client_t *tls = (anytls_tls_client_t *)req->data;
    tls->resolve_pending = 0;
    if (tls->free_pending) {
        if (res != NULL) {
            uv_freeaddrinfo(res);
        }
        tls_maybe_destroy(tls);
        return;
    }
    if (tls->closed) {
        if (res != NULL) {
            uv_freeaddrinfo(res);
        }
        return;
    }
    if (status != 0) {
        fail_and_close(tls, status);
        if (res != NULL) {
            uv_freeaddrinfo(res);
        }
        return;
    }

    int connect_rc = ANYTLS_ERR_INVALID_ARGUMENT;
    if (tls->socket_protector.submit == NULL) {
        connect_rc = init_tcp_handle(tls, AF_UNSPEC);
        if (connect_rc != ANYTLS_OK) {
            uv_freeaddrinfo(res);
            fail_and_close(tls, connect_rc);
            return;
        }
    }
    for (const struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
        if (ai->ai_addr != NULL &&
            (ai->ai_family == AF_INET || ai->ai_family == AF_INET6)) {
            if (tls->socket_protector.submit != NULL) {
                connect_rc = init_protected_tcp(tls, ai->ai_addr);
                break;
            }
            set_connect_address(tls, ai->ai_addr);
            connect_rc = start_tcp_connect(tls);
            if (connect_rc == ANYTLS_OK) {
                break;
            }
        }
    }

    uv_freeaddrinfo(res);
    if (connect_rc == ANYTLS_OK) {
        return;
    }
    fail_and_close(tls, connect_rc);
}

int anytls_tls_client_new(const anytls_tls_client_config_t *config,
                          anytls_tls_client_t **out)
{
    if (config == NULL || out == NULL || config->loop == NULL ||
        config->host == NULL || config->port == NULL) {
        return ANYTLS_ERR_INVALID_ARGUMENT;
    }
    *out = NULL;

    anytls_tls_client_t *tls = (anytls_tls_client_t *)calloc(1u, sizeof(*tls));
    if (tls == NULL) {
        return ANYTLS_ERR_NO_MEMORY;
    }

    aproxy_bufpool_init(&tls->read_pool, 16384u,
                        TLS_READ_BUFFER_POOL_MAX_FREE);
    aproxy_bufpool_init(&tls->write_pool, 16384u,
                        TLS_WRITE_BUFFER_POOL_MAX_FREE);

    tls->loop = config->loop;
    tls->resolver = config->resolver;
    tls->host = anytls_strdup(config->host);
    tls->port = anytls_strdup(config->port);
    tls->sni = anytls_strdup(config->sni != NULL ? config->sni : config->host);
    tls->insecure_skip_verify = config->insecure_skip_verify;
    tls->max_pending_bytes =
        aproxy_stream_pending_limit(config->max_pending_bytes);
    tls->socket_protector = config->socket_protector;
    tls->on_ready = config->on_ready;
    tls->on_data = config->on_data;
    tls->on_close = config->on_close;
    tls->user_data = config->user_data;

    if (tls->host == NULL || tls->port == NULL || tls->sni == NULL) {
        anytls_tls_client_free(tls);
        return ANYTLS_ERR_NO_MEMORY;
    }

    if (config->context != NULL) {
        if (config->context->insecure_skip_verify !=
            (config->insecure_skip_verify != 0)) {
            anytls_tls_client_free(tls);
            return ANYTLS_ERR_INVALID_ARGUMENT;
        }
        tls->context = config->context;
        aproxy_tls_context_retain(tls->context);
    } else {
        const int rc = aproxy_tls_context_new(
            tls->insecure_skip_verify, &tls->context);
        if (rc != APROXY_OK) {
            anytls_tls_client_free(tls);
            return rc;
        }
    }

    tls->ssl = SSL_new(tls->context->ctx);
    if (tls->ssl == NULL) {
        anytls_tls_client_free(tls);
        return ANYTLS_ERR_NO_MEMORY;
    }
    SSL_set_connect_state(tls->ssl);
    SSL_set_tlsext_host_name(tls->ssl, tls->sni);
    int rc = set_alpn_protocols(tls->ssl, config->alpn);
    if (rc != ANYTLS_OK) {
        anytls_tls_client_free(tls);
        return rc;
    }
    if ((config->ech.config_list == NULL) !=
            (config->ech.config_list_len == 0u) ||
        (config->reality.enabled &&
         (config->ech.config_list_len > 0u || config->ech.grease ||
          config->ech.required))) {
        anytls_tls_client_free(tls);
        return ANYTLS_ERR_INVALID_ARGUMENT;
    }
    if (config->ech.config_list_len > 0u &&
        !SSL_set1_ech_config_list(tls->ssl, config->ech.config_list,
                                  config->ech.config_list_len)) {
        anytls_tls_client_free(tls);
        return ANYTLS_ERR_INVALID_ARGUMENT;
    }
    SSL_set_enable_ech_grease(tls->ssl, config->ech.grease != 0);
    tls->ech_required = config->ech.required != 0;
    if (config->reality.enabled) {
#if defined(BORINGSSL_HAS_REALITY_CLIENT)
        const uint16_t group = SSL_GROUP_X25519;
        static const uint16_t signature_algorithms[] = {
            SSL_SIGN_ED25519,
            SSL_SIGN_ECDSA_SECP256R1_SHA256,
            SSL_SIGN_RSA_PSS_RSAE_SHA256,
            SSL_SIGN_RSA_PKCS1_SHA256,
            SSL_SIGN_ECDSA_SECP384R1_SHA384,
            SSL_SIGN_RSA_PSS_RSAE_SHA384,
            SSL_SIGN_RSA_PKCS1_SHA384,
            SSL_SIGN_RSA_PSS_RSAE_SHA512,
            SSL_SIGN_RSA_PKCS1_SHA512,
        };
        if (!SSL_set_min_proto_version(tls->ssl, TLS1_3_VERSION) ||
            !SSL_set_max_proto_version(tls->ssl, TLS1_3_VERSION) ||
            !SSL_set1_group_ids(tls->ssl, &group, 1u) ||
            !SSL_set1_client_key_shares(tls->ssl, &group, 1u) ||
            !SSL_set_verify_algorithm_prefs(
                tls->ssl, signature_algorithms,
                sizeof(signature_algorithms) /
                    sizeof(signature_algorithms[0])) ||
            !SSL_set_reality_client_auth(tls->ssl,
                                         config->reality.public_key,
                                         config->reality.short_id)) {
            anytls_tls_client_free(tls);
            return ANYTLS_ERR_INVALID_ARGUMENT;
        }
        SSL_set_options(tls->ssl, SSL_OP_NO_TICKET);
        if (!tls->insecure_skip_verify) {
            SSL_set_custom_verify(tls->ssl, SSL_VERIFY_PEER,
                                  reality_verify_certificate);
        }
#else
        anytls_tls_client_free(tls);
        return ANYTLS_ERR_UNSUPPORTED;
#endif
    } else if (!tls->insecure_skip_verify &&
               !SSL_set1_host(tls->ssl, tls->sni)) {
        anytls_tls_client_free(tls);
        return ANYTLS_ERR_INVALID_ARGUMENT;
    }
    SSL_set_mode(tls->ssl, SSL_MODE_ENABLE_PARTIAL_WRITE |
                               SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

    tls->rbio = BIO_new(BIO_s_mem());
    tls->wbio = BIO_new(BIO_s_mem());
    if (tls->rbio == NULL || tls->wbio == NULL) {
        anytls_tls_client_free(tls);
        return ANYTLS_ERR_NO_MEMORY;
    }
    SSL_set_bio(tls->ssl, tls->rbio, tls->wbio);

    *out = tls;
    return ANYTLS_OK;
}

void anytls_tls_client_free(anytls_tls_client_t *tls)
{
    if (tls == NULL) {
        return;
    }
    tls->free_pending = 1;
    tls->on_ready = NULL;
    tls->on_data = NULL;
    tls->on_close = NULL;
    tls->user_data = NULL;
    if (tls->resolve_pending && tls->resolver == NULL) {
        (void)uv_cancel((uv_req_t *)&tls->resolve_req);
    }
    if (!tls->protect_pending && tls->tcp_initialized && !tls->tcp_closed &&
        !uv_is_closing((uv_handle_t *)&tls->tcp)) {
        uv_close((uv_handle_t *)&tls->tcp, close_cb);
    }
    tls_maybe_destroy(tls);
}

int anytls_tls_client_connect(anytls_tls_client_t *tls)
{
    if (tls == NULL || tls->closed) {
        return ANYTLS_ERR_INVALID_ARGUMENT;
    }

    if (tls->resolver != NULL) {
        char *end = NULL;
        const unsigned long port = strtoul(tls->port, &end, 10);
        if (end == tls->port || *end != '\0' || port == 0u ||
            port > UINT16_MAX) {
            return ANYTLS_ERR_INVALID_ARGUMENT;
        }
        tls->resolve_pending = 1;
        const int rc = aproxy_dns_resolve(
            tls->resolver, tls->host, (uint16_t)port, shared_resolved_cb, tls);
        if (rc != APROXY_OK) {
            tls->resolve_pending = 0;
        }
        return rc;
    }

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    tls->resolve_req.data = tls;
    const int rc = uv_getaddrinfo(tls->loop, &tls->resolve_req, resolved_cb,
                                  tls->host, tls->port, &hints);
    if (rc == 0) {
        tls->resolve_pending = 1;
    }
    return rc == 0 ? ANYTLS_OK : rc;
}

int anytls_tls_client_write(anytls_tls_client_t *tls,
                            const uint8_t *data,
                            size_t len)
{
    if (tls == NULL || (data == NULL && len > 0u) || tls->closed) {
        return ANYTLS_ERR_INVALID_ARGUMENT;
    }
    if (!tls->handshake_done) {
        return ANYTLS_ERR_INVALID_ARGUMENT;
    }

    size_t offset = 0u;
    while (offset < len) {
        const size_t remaining = len - offset;
        const int chunk = remaining > INT_MAX ? INT_MAX : (int)remaining;
        const int n = SSL_write(tls->ssl, data + offset, chunk);
        if (n > 0) {
            offset += (size_t)n;
            const int flush_rc = flush_wbio(tls);
            if (flush_rc != ANYTLS_OK) {
                return flush_rc;
            }
            continue;
        }
        const int ssl_err = SSL_get_error(tls->ssl, n);
        if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
            const int flush_rc = flush_wbio(tls);
            if (flush_rc != ANYTLS_OK) {
                return flush_rc;
            }
            continue;
        }
        return ANYTLS_ERR_INVALID_ARGUMENT;
    }
    return ANYTLS_OK;
}

int anytls_tls_client_write_raw(anytls_tls_client_t *tls,
                                const uint8_t *data,
                                size_t len)
{
    if (tls == NULL || !tls->handshake_done) {
        return ANYTLS_ERR_INVALID_ARGUMENT;
    }
    return write_tcp_copy(tls, data, len);
}

int anytls_tls_client_enable_raw_read(anytls_tls_client_t *tls)
{
    if (tls == NULL || !tls->handshake_done || tls->closed) {
        return ANYTLS_ERR_INVALID_ARGUMENT;
    }
    if (tls->raw_read || tls->raw_transitioning) {
        return ANYTLS_OK;
    }
    tls->raw_transitioning = 1;
    tls->raw_read = 1;

    uint8_t plaintext[16u * 1024u];
    while (SSL_pending(tls->ssl) > 0) {
        const int n = SSL_read(tls->ssl, plaintext, (int)sizeof(plaintext));
        if (n <= 0) {
            tls->raw_transitioning = 0;
            return ANYTLS_ERR_INVALID_ARGUMENT;
        }
        tls_report_data(tls, plaintext, (size_t)n);
        if (tls->free_pending || tls->closed) {
            tls->raw_transitioning = 0;
            return ANYTLS_OK;
        }
    }

    const uint8_t *pending = NULL;
    size_t pending_len = 0u;
    if (BIO_ctrl_pending(tls->rbio) > 0u) {
        if (!BIO_mem_contents(tls->rbio, &pending, &pending_len) ||
            pending == NULL) {
            tls->raw_transitioning = 0;
            return ANYTLS_ERR_INVALID_ARGUMENT;
        }
        if (pending_len > 0u) {
            tls_report_data(tls, pending, pending_len);
            if (tls->free_pending || tls->closed) {
                tls->raw_transitioning = 0;
                return ANYTLS_OK;
            }
        }
        if (BIO_reset(tls->rbio) != 1) {
            tls->raw_transitioning = 0;
            return ANYTLS_ERR_INVALID_ARGUMENT;
        }
    }
    tls->raw_transitioning = 0;
    return ANYTLS_OK;
}

int anytls_tls_client_alpn_is(const anytls_tls_client_t *tls,
                              const char *protocol)
{
    if (tls == NULL || protocol == NULL || !tls->handshake_done) {
        return 0;
    }
    const uint8_t *selected = NULL;
    unsigned int selected_len = 0u;
    SSL_get0_alpn_selected(tls->ssl, &selected, &selected_len);
    const size_t protocol_len = strlen(protocol);
    return protocol_len == selected_len && selected != NULL &&
           memcmp(selected, protocol, protocol_len) == 0;
}

void anytls_tls_client_close(anytls_tls_client_t *tls)
{
    if (tls == NULL || tls->closed) {
        return;
    }
    tls->closed = 1;
    if (tls->protect_pending) {
        return;
    }
    close_tcp(tls);
}
