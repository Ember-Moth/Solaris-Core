#include "transport/tls/tls.h"
#include <assert.h>
#include <limits.h>
#include <stdatomic.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#define TLS_RECORD_BYTES 16384u
#define TLS_BIO_BYTES 32768u
#define TLS_CERT_BYTES (256u * 1024u)
#define TLS_PUMP_STEPS 32u
enum { TLS_WRITE, TLS_SHUTDOWN, TLS_RAW };

struct solaris_tls_context { atomic_size_t references; SSL_CTX *native; };

solaris_status_t solaris_tls_context_create(solaris_budget_t *budget,
    const void *ca_pem, size_t ca_pem_length, solaris_tls_context_t **out)
{
    if (out == NULL) return SOLARIS_EINVAL;
    *out = NULL;
    if (budget == NULL || ca_pem == NULL || ca_pem_length == 0u || ca_pem_length > TLS_CERT_BYTES)
        return SOLARIS_EINVAL;
    solaris_tls_context_t *context = solaris_memory_allocate(budget, sizeof(*context));
    if (context == NULL) return SOLARIS_ENOMEM;
    atomic_init(&context->references, 1u);
    context->native = SSL_CTX_new(TLS_client_method());
    if (context->native == NULL) { solaris_memory_free(context); return SOLARIS_ENOMEM; }
    SSL_CTX_set_verify(context->native, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_max_cert_list(context->native, TLS_CERT_BYTES);
    SSL_CTX_set_session_cache_mode(context->native, SSL_SESS_CACHE_OFF);
    if (!SSL_CTX_set_min_proto_version(context->native, TLS1_2_VERSION)) {
        solaris_tls_context_release(context); return SOLARIS_EIO;
    }
    BIO *input = BIO_new_mem_buf(ca_pem, (int)ca_pem_length);
    if (input == NULL) { solaris_tls_context_release(context); return SOLARIS_ENOMEM; }
    size_t count = 0u;
    int valid = 1;
    for (;;) {
        X509 *cert = PEM_read_bio_X509(input, NULL, NULL, NULL);
        if (cert == NULL) break;
        if (!X509_STORE_add_cert(SSL_CTX_get_cert_store(context->native), cert)) valid = 0;
        X509_free(cert);
        count++;
    }
    BIO_free(input);
    ERR_clear_error();
    if (count == 0u || !valid) { solaris_tls_context_release(context); return SOLARIS_EINVAL; }
    *out = context;
    return SOLARIS_OK;
}

void solaris_tls_context_retain(solaris_tls_context_t *context)
{ (void)atomic_fetch_add_explicit(&context->references, 1u, memory_order_relaxed); }
void solaris_tls_context_release(solaris_tls_context_t *context)
{
    if (context != NULL && atomic_fetch_sub_explicit(&context->references, 1u, memory_order_acq_rel) == 1u) {
        SSL_CTX_free(context->native); solaris_memory_free(context);
    }
}

typedef struct tls_write {
    struct tls_write *next;
    solaris_slice_t slice;
    size_t offset;
    solaris_io_done_fn callback;
    void *context;
    int kind;
} tls_write_t;

typedef struct tls_stream {
    solaris_stream_t stream, *wire;
    solaris_scope_t scope;
    solaris_scope_t *parent_scope;
    solaris_deferred_t pump;
    solaris_deadline_t *deadline;
    uint64_t open_deadline_ns;
    solaris_tls_context_t *trust;
    SSL *ssl;
    BIO *bio;
    solaris_dialer_options_t options;
    solaris_stream_callbacks_t callbacks;
    void *context;
    solaris_io_snapshot_t stats;
    tls_write_t *head, *tail;
    const solaris_buffer_t *input;
    size_t input_offset;
    uint8_t record_header[5];
    size_t record_header_size, record_remaining;
    solaris_buffer_t *output;
    solaris_buffer_t *alpn_offer;
    uint8_t selected_alpn[SOLARIS_TLS_MAX_ALPN_PROTOCOL];
    size_t selected_alpn_length;
    solaris_status_t close_status;
    int accepted, connected, opened, handshake_done, reading;
    int close_requested, writable_requested, wire_writing, wire_shutting;
    int shutdown_requested, notify_sent, wire_eof, wire_gone, bio_eof;
    int record_complete, want_input, raw_requested;
    int require_alpn;
} tls_stream_t;

static void schedule(tls_stream_t *tls);
static void fail(tls_stream_t *tls, solaris_status_t status);

static void finish_request(tls_stream_t *tls, solaris_status_t status)
{
    tls_write_t *request = tls->head;
    tls->head = request->next;
    if (tls->head == NULL) tls->tail = NULL;
    if (request->kind == TLS_WRITE) {
        tls->stats.pending_bytes -= request->slice.length;
        tls->stats.pending_requests--;
        if (status == SOLARIS_OK) tls->stats.bytes_written += request->slice.length;
    } else if (status == SOLARIS_OK && request->kind == TLS_SHUTDOWN) tls->stats.write_shutdown = 1u;
    request->callback(request->context, status);
    solaris_buffer_release(request->slice.buffer);
    solaris_memory_free(request);
    if (tls->writable_requested && !tls->scope.cancelled && !tls->shutdown_requested) {
        tls->writable_requested = 0;
        if (tls->callbacks.on_writable != NULL) tls->callbacks.on_writable(tls->context, &tls->stream);
    }
}

static void cancel(void *context)
{
    tls_stream_t *tls = context;
    if (!tls->close_requested) { tls->close_requested = 1; tls->close_status = SOLARIS_ECANCELLED; }
    if (tls->wire != NULL) (void)solaris_stream_close(tls->wire);
    if (tls->deadline != NULL) solaris_deadline_cancel(tls->deadline);
    if (tls->accepted) schedule(tls);
}

static void destroyed(void *context)
{
    tls_stream_t *tls = context;
    assert(tls->head == NULL && tls->wire == NULL);
    if (tls->accepted) tls->callbacks.on_close(tls->context, &tls->stream, tls->close_status);
    SSL_free(tls->ssl); BIO_free(tls->bio);
    solaris_tls_context_release(tls->trust);
    solaris_buffer_release(tls->input); solaris_buffer_release(tls->output);
    solaris_buffer_release(tls->alpn_offer);
    solaris_scope_t *parent = tls->parent_scope;
    solaris_memory_free(tls);
    if (parent) solaris_scope_release(parent);
}

static solaris_status_t select_alpn(tls_stream_t *tls)
{
    const uint8_t *selected = NULL; unsigned length = 0;
    SSL_get0_alpn_selected(tls->ssl, &selected, &length);
    if (!length) return tls->require_alpn ? SOLARIS_ENOTSUP : SOLARIS_OK;
    if (!selected || length > sizeof(tls->selected_alpn) || !tls->alpn_offer) return SOLARIS_EIO;
    const uint8_t *offer = solaris_buffer_data(tls->alpn_offer);
    size_t size = solaris_buffer_length(tls->alpn_offer);
    for (size_t offset = 0; offset < size;) {
        size_t count = offer[offset++];
        if (count == length && !memcmp(offer + offset, selected, count)) {
            memcpy(tls->selected_alpn, selected, count); tls->selected_alpn_length = count; return SOLARIS_OK;
        }
        offset += count;
    }
    return SOLARIS_EIO;
}

static void fail(tls_stream_t *tls, solaris_status_t status)
{
    if (tls->close_requested) return;
    tls->close_requested = 1; tls->close_status = status;
    solaris_scope_cancel(&tls->scope);
}

static void deadline(void *context, solaris_status_t status)
{
    tls_stream_t *tls = context;
    tls->deadline = NULL;
    if (status == SOLARIS_OK && !tls->handshake_done) fail(tls, SOLARIS_ETIMEDOUT);
    solaris_scope_release(&tls->scope);
}

static void wire_open(void *context, solaris_stream_t *wire, solaris_status_t status)
{
    (void)wire;
    tls_stream_t *tls = context;
    if (!tls->scope.cancelled) {
        if (status != SOLARIS_OK) fail(tls, status);
        else { tls->connected = 1; schedule(tls); }
    }
}

static void wire_data(void *context, solaris_stream_t *wire, const solaris_buffer_t *buffer)
{
    tls_stream_t *tls = context;
    if (tls->scope.cancelled) return;
    assert(tls->input == NULL);
    tls->input = buffer; tls->input_offset = 0u; solaris_buffer_retain(buffer);
    (void)solaris_stream_set_reading(wire, 0);
    schedule(tls);
}

static void wire_eof(void *context, solaris_stream_t *wire)
{
    (void)wire;
    tls_stream_t *tls = context;
    tls->wire_eof = 1;
    if (!tls->scope.cancelled) schedule(tls);
}
static void wire_writable(void *context, solaris_stream_t *wire)
{ (void)wire; if (!((tls_stream_t *)context)->scope.cancelled) schedule(context); }
static void wire_close(void *context, solaris_stream_t *wire, solaris_status_t status)
{
    (void)wire;
    tls_stream_t *tls = context;
    tls->wire = NULL; tls->wire_gone = 1;
    if (!tls->scope.cancelled) {
        if (status == SOLARIS_OK && tls->wire_eof) schedule(tls);
        else fail(tls, status == SOLARIS_OK ? SOLARIS_EIO : status);
    }
    solaris_scope_release(&tls->scope);
}

static const solaris_stream_callbacks_t wire_callbacks = {
    wire_open, wire_data, wire_eof, wire_writable, wire_close
};

static void wire_written(void *context, solaris_status_t status)
{
    tls_stream_t *tls = context;
    tls->wire_writing = 0;
    solaris_buffer_release(tls->output); tls->output = NULL;
    if (!tls->scope.cancelled) {
        if (status != SOLARIS_OK) fail(tls, status);
        else schedule(tls);
    }
    solaris_scope_release(&tls->scope);
}

static void wire_shutdown(void *context, solaris_status_t status)
{
    tls_stream_t *tls = context;
    tls->wire_shutting = 0;
    if (!tls->scope.cancelled) {
        assert(tls->head != NULL && tls->head->kind == TLS_SHUTDOWN);
        finish_request(tls, status);
        if (status != SOLARIS_OK || tls->stats.read_eof) fail(tls, status);
        else schedule(tls);
    }
    solaris_scope_release(&tls->scope);
}

/* Returns true only when every encrypted byte has reached a write completion. */
static int flush_wire(tls_stream_t *tls)
{
    if (tls->wire_writing) return 0;
    if (tls->output == NULL) {
        size_t count = BIO_pending(tls->bio);
        if (count == 0u) return 1;
        /* After a write transition an outer TLS control record cannot be
         * injected into the raw stream. Fail instead of corrupting it. */
        if (tls->stats.raw_write) { fail(tls, SOLARIS_EIO); return 0; }
        if (count > TLS_RECORD_BYTES) count = TLS_RECORD_BYTES;
        solaris_status_t rc = solaris_buffer_allocate(solaris_executor_budget(tls->scope.owner), count, &tls->output);
        if (rc != SOLARIS_OK) { fail(tls, rc); return 0; }
        int got = BIO_read(tls->bio, solaris_buffer_mutable_data(tls->output), (int)count);
        if (got <= 0) { fail(tls, SOLARIS_EIO); return 0; }
        (void)solaris_buffer_set_length(tls->output, (size_t)got);
        solaris_buffer_publish(tls->output);
    }
    solaris_slice_t slice = {tls->output, 0u, solaris_buffer_length(tls->output)};
    solaris_status_t rc = solaris_stream_write(tls->wire, &slice, wire_written, tls);
    if (rc == SOLARIS_OK) {
        tls->wire_writing = 1; solaris_scope_retain(&tls->scope);
    } else if (rc != SOLARIS_EAGAIN) fail(tls, rc);
    return 0;
}

static int feed_wire(tls_stream_t *tls)
{
    if (tls->stats.raw_read || !tls->want_input || (tls->handshake_done && !tls->reading)) return 0;
    if (tls->input == NULL) {
        if (tls->wire_eof && !tls->bio_eof) { (void)BIO_shutdown_wr(tls->bio); tls->bio_eof = 1; return 1; }
        return 0;
    }
    if (tls->record_complete) {
        tls->record_complete = 0; tls->record_header_size = 0u; tls->record_remaining = 0u;
    }
    size_t remaining = solaris_buffer_length(tls->input) - tls->input_offset;
    size_t amount = tls->record_header_size < 5u ? 5u - tls->record_header_size : tls->record_remaining;
    if (amount > remaining) amount = remaining;
    const uint8_t *input = solaris_buffer_data(tls->input) + tls->input_offset;
    int written = BIO_write(tls->bio, input, (int)amount);
    if (written > 0) {
        tls->input_offset += (size_t)written;
        if (tls->record_header_size < 5u) {
            memcpy(tls->record_header + tls->record_header_size, input, (size_t)written);
            tls->record_header_size += (size_t)written;
            if (tls->record_header_size == 5u) {
                tls->record_remaining = ((size_t)tls->record_header[3] << 8u) | tls->record_header[4];
                if (tls->record_header[1] != 3u || tls->record_header[0] < 20u || tls->record_header[0] > 23u ||
                    tls->record_remaining > TLS_RECORD_BYTES + 2048u) { fail(tls, SOLARIS_EIO); return 0; }
            }
        } else tls->record_remaining -= (size_t)written;
        if (tls->record_header_size == 5u && tls->record_remaining == 0u) {
            tls->record_complete = 1; tls->want_input = 0;
        }
    }
    else if (!BIO_should_retry(tls->bio)) { fail(tls, SOLARIS_EIO); return 0; }
    if (tls->input_offset == solaris_buffer_length(tls->input)) {
        solaris_buffer_release(tls->input); tls->input = NULL; tls->input_offset = 0u;
    }
    return written > 0;
}

/* SSL_get_error must immediately follow its SSL operation, before callbacks
 * or BIO work can alter the thread's error queue. */
static int ssl_result(tls_stream_t *tls, int result)
{
    int error = SSL_get_error(tls->ssl, result);
    if (error == SSL_ERROR_WANT_READ) {
        int changed = !tls->want_input; tls->want_input = 1; return changed;
    }
    if (error == SSL_ERROR_WANT_WRITE) return 0;
    if (error == SSL_ERROR_ZERO_RETURN && tls->handshake_done) {
        if (!tls->stats.read_eof) {
            tls->stats.read_eof = 1u;
            if (tls->callbacks.on_eof != NULL) tls->callbacks.on_eof(tls->context, &tls->stream);
            if (tls->stats.write_shutdown && !tls->scope.cancelled) fail(tls, SOLARIS_OK);
        }
        return 0;
    }
    tls->stats.last_system_error = (int32_t)ERR_peek_error();
    fail(tls, SSL_get_verify_result(tls->ssl) == X509_V_OK ? SOLARIS_EIO : SOLARIS_EACCESS);
    ERR_clear_error();
    return 0;
}

static int read_raw_data(tls_stream_t *tls)
{
    size_t pending = (size_t)SSL_pending(tls->ssl);
    size_t amount = pending != 0u ? pending : tls->input != NULL ? solaris_buffer_length(tls->input) - tls->input_offset : 0u;
    if (amount == 0u) {
        if (tls->wire_eof && !tls->stats.read_eof) {
            tls->stats.read_eof = 1u;
            if (tls->callbacks.on_eof != NULL) tls->callbacks.on_eof(tls->context, &tls->stream);
            if (!tls->scope.cancelled && (tls->stats.write_shutdown || tls->wire_gone)) fail(tls, SOLARIS_OK);
            return 1;
        }
        return 0;
    }
    if (amount > tls->options.read_chunk_size) amount = tls->options.read_chunk_size;
    solaris_buffer_t *buffer;
    solaris_status_t rc = solaris_buffer_allocate(solaris_executor_budget(tls->scope.owner), amount, &buffer);
    if (rc != SOLARIS_OK) { fail(tls, rc); return 0; }
    if (pending != 0u) {
        /* Only plaintext from the already authenticated current record is
         * drained here. No subsequent record is fed to SSL after transition. */
        int count = SSL_read(tls->ssl, solaris_buffer_mutable_data(buffer), (int)amount);
        if (count <= 0) { solaris_buffer_release(buffer); fail(tls, SOLARIS_EIO); return 0; }
        amount = (size_t)count;
    } else {
        memcpy(solaris_buffer_mutable_data(buffer), solaris_buffer_data(tls->input) + tls->input_offset, amount);
        tls->input_offset += amount;
        if (tls->input_offset == solaris_buffer_length(tls->input)) {
            solaris_buffer_release(tls->input); tls->input = NULL; tls->input_offset = 0u;
        }
    }
    (void)solaris_buffer_set_length(buffer, amount); solaris_buffer_publish(buffer);
    tls->stats.bytes_read += amount; tls->callbacks.on_data(tls->context, &tls->stream, buffer);
    solaris_buffer_release(buffer); return 1;
}

static void pump(void *context)
{
    tls_stream_t *tls = context;
    unsigned int step = 0u;
    while (!tls->scope.cancelled && tls->connected && step++ < TLS_PUMP_STEPS) {
        int progress = feed_wire(tls);
        if (tls->scope.cancelled) break;
        if (!tls->handshake_done) {
            if (solaris_executor_now_ns(tls->scope.owner) >= tls->open_deadline_ns) {
                fail(tls, SOLARIS_ETIMEDOUT); break;
            }
            ERR_clear_error();
            int rc = SSL_do_handshake(tls->ssl);
            if (rc == 1) {
                if (solaris_executor_now_ns(tls->scope.owner) >= tls->open_deadline_ns) {
                    fail(tls, SOLARIS_ETIMEDOUT); break;
                }
                solaris_status_t alpn_status = select_alpn(tls);
                if (alpn_status != SOLARIS_OK) { fail(tls, alpn_status); break; }
                tls->handshake_done = 1;
                if (tls->deadline != NULL) solaris_deadline_cancel(tls->deadline);
                tls->opened = 1;
                tls->callbacks.on_open(tls->context, &tls->stream, SOLARIS_OK);
                progress = 1;
            } else progress |= ssl_result(tls, rc);
        }
        if (tls->scope.cancelled) break;
        int flushed = flush_wire(tls);
        if (tls->scope.cancelled) break;
        if (tls->handshake_done && tls->head != NULL && flushed && !tls->wire_shutting) {
            tls_write_t *request = tls->head;
            if (request->kind == TLS_RAW) {
                tls->stats.raw_write = 1u; finish_request(tls, SOLARIS_OK); progress = 1;
            } else if (request->kind == TLS_SHUTDOWN) {
                if (!tls->notify_sent && !tls->stats.raw_write && !tls->stats.raw_read) {
                    ERR_clear_error();
                    int rc = SSL_shutdown(tls->ssl);
                    if (rc >= 0) { tls->notify_sent = 1; progress = 1; }
                    else progress |= ssl_result(tls, rc);
                } else {
                    solaris_status_t rc = solaris_stream_shutdown_write(tls->wire, wire_shutdown, tls);
                    if (rc == SOLARIS_OK) { tls->wire_shutting = 1; solaris_scope_retain(&tls->scope); }
                    else fail(tls, rc);
                }
            } else if (request->offset == request->slice.length) {
                finish_request(tls, SOLARIS_OK); progress = 1;
            } else {
                size_t amount = request->slice.length - request->offset;
                if (amount > TLS_RECORD_BYTES) amount = TLS_RECORD_BYTES;
                const uint8_t *input = solaris_buffer_data(request->slice.buffer) + request->slice.offset + request->offset;
                if (tls->stats.raw_write) {
                    solaris_status_t rc = solaris_buffer_copy(solaris_executor_budget(tls->scope.owner), input, amount, &tls->output);
                    if (rc != SOLARIS_OK) fail(tls, rc);
                    else { request->offset += amount; progress = 1; }
                } else {
                    ERR_clear_error();
                    int rc = SSL_write(tls->ssl, input, (int)amount);
                    if (rc > 0) { request->offset += (size_t)rc; progress = 1; }
                    else progress |= ssl_result(tls, rc);
                }
            }
        }
        if (tls->scope.cancelled) break;
        if (tls->handshake_done && tls->reading && !tls->stats.read_eof) {
            if (tls->stats.raw_read) progress |= read_raw_data(tls);
            else {
            solaris_buffer_t *buffer = NULL;
            solaris_status_t rc = solaris_buffer_allocate(solaris_executor_budget(tls->scope.owner),
                tls->options.read_chunk_size, &buffer);
            if (rc != SOLARIS_OK) { fail(tls, rc); break; }
            ERR_clear_error();
            int count = SSL_read(tls->ssl, solaris_buffer_mutable_data(buffer), (int)tls->options.read_chunk_size);
            if (count > 0) {
                (void)solaris_buffer_set_length(buffer, (size_t)count); solaris_buffer_publish(buffer);
                tls->stats.bytes_read += (uint64_t)count;
                tls->callbacks.on_data(tls->context, &tls->stream, buffer); progress = 1;
            } else progress |= ssl_result(tls, count);
            solaris_buffer_release(buffer);
            }
        }
        if (tls->scope.cancelled) break;
        (void)flush_wire(tls);
        if (!progress) break;
    }
    if (tls->scope.cancelled) {
        solaris_status_t status = tls->close_status == SOLARIS_OK ? SOLARIS_ECANCELLED : tls->close_status;
        if (!tls->opened) { tls->opened = 1; tls->callbacks.on_open(tls->context, &tls->stream, status); }
        while (tls->head != NULL) finish_request(tls, status);
    } else {
        if (tls->wire != NULL && !tls->wire_eof) {
            int want = tls->input == NULL && (!tls->handshake_done || (tls->reading && !tls->stats.read_eof));
            solaris_status_t rc = solaris_stream_set_reading(tls->wire, want);
            if (rc != SOLARIS_OK) fail(tls, rc);
        }
        if (step > TLS_PUMP_STEPS && !tls->scope.cancelled) schedule(tls);
    }
    solaris_scope_release(&tls->scope);
}

static void schedule(tls_stream_t *tls)
{
    if (tls->pump.queued) return;
    solaris_scope_retain(&tls->scope);
    solaris_status_t rc = solaris_executor_defer(tls->scope.owner, &tls->pump);
    assert(rc == SOLARIS_OK); (void)rc;
}

static solaris_status_t enqueue(tls_stream_t *tls, const solaris_slice_t *slice,
    int kind, solaris_io_done_fn done, void *context)
{
    if (tls->scope.cancelled || tls->shutdown_requested || !solaris_executor_accepting(tls->scope.owner))
        return SOLARIS_ECLOSED;
    if (!tls->handshake_done) return SOLARIS_EBUSY;
    if (kind == TLS_RAW && tls->raw_requested) return SOLARIS_EBUSY;
    if (slice != NULL) {
        if (slice->length > tls->options.pending_byte_limit) return SOLARIS_EMSGSIZE;
        if (tls->stats.pending_requests >= tls->options.pending_request_limit ||
            tls->stats.pending_bytes > tls->options.pending_byte_limit - slice->length) {
            tls->writable_requested = 1; return SOLARIS_EAGAIN;
        }
    }
    tls_write_t *request = solaris_memory_allocate(solaris_executor_budget(tls->scope.owner), sizeof(*request));
    if (request == NULL) return SOLARIS_ENOMEM;
    memset(request, 0, sizeof(*request));
    request->callback = done; request->context = context; request->kind = kind;
    if (slice != NULL) {
        request->slice = *slice; solaris_buffer_retain(slice->buffer);
        tls->stats.pending_requests++; tls->stats.pending_bytes += slice->length;
    } else if (kind == TLS_SHUTDOWN) tls->shutdown_requested = 1;
    else tls->raw_requested = 1;
    if (tls->tail != NULL) tls->tail->next = request;
    else tls->head = request;
    tls->tail = request;
    schedule(tls);
    return SOLARIS_OK;
}
static solaris_status_t write_stream(void *state, const solaris_slice_t *slice, solaris_io_done_fn done, void *context)
{ return enqueue(state, slice, TLS_WRITE, done, context); }
static solaris_status_t shutdown_stream(void *state, solaris_io_done_fn done, void *context)
{ return enqueue(state, NULL, TLS_SHUTDOWN, done, context); }
static uint32_t raw_capabilities(void *state)
{ return ((tls_stream_t *)state)->scope.cancelled ? 0u : SOLARIS_STREAM_RAW_READ | SOLARIS_STREAM_RAW_WRITE; }
static solaris_status_t read_raw(void *state)
{
    tls_stream_t *tls = state;
    if (tls->scope.cancelled) return SOLARIS_ECLOSED;
    if (tls->stats.raw_read) return SOLARIS_OK;
    if (!tls->handshake_done || !tls->record_complete || BIO_pending(SSL_get_rbio(tls->ssl)) != 0u) return SOLARIS_EBUSY;
    tls->stats.raw_read = 1u; schedule(tls); return SOLARIS_OK;
}
static solaris_status_t write_raw(void *state, solaris_io_done_fn done, void *context)
{ return enqueue(state, NULL, TLS_RAW, done, context); }
static solaris_status_t reading(void *state, int enabled)
{
    tls_stream_t *tls = state;
    if (tls->scope.cancelled || (enabled && tls->stats.read_eof)) return SOLARIS_ECLOSED;
    tls->reading = enabled;
    if (!enabled && tls->handshake_done && tls->wire != NULL) (void)solaris_stream_set_reading(tls->wire, 0);
    schedule(tls); return SOLARIS_OK;
}
static solaris_status_t close_stream(void *state)
{ fail(state, SOLARIS_OK); return SOLARIS_OK; }
static solaris_status_t snapshot(void *state, solaris_io_snapshot_t *out)
{ *out = ((tls_stream_t *)state)->stats; return SOLARIS_OK; }
static const solaris_stream_raw_ops_t raw_operations = {raw_capabilities, read_raw, write_raw};
static const solaris_stream_ops_t operations = {write_stream, shutdown_stream, reading, close_stream, snapshot, &raw_operations};

solaris_status_t solaris_tls_open_ex(solaris_executor_t *owner,
    solaris_tls_context_t *trust, const char *identity, uint16_t minimum_version,
    const solaris_tls_open_options_t *tls_options,
    const solaris_stream_factory_t *carrier, const solaris_dialer_options_t *options,
    const solaris_address_t *peer, const solaris_stream_callbacks_t *callbacks,
    void *callback_context, solaris_stream_t **out)
{
    if (out == NULL) return SOLARIS_EINVAL;
    *out = NULL;
    if (owner == NULL || trust == NULL || identity == NULL || identity[0] == '\0' ||
        strlen(identity) > 253u || (minimum_version != SOLARIS_TLS_1_2 && minimum_version != SOLARIS_TLS_1_3) ||
        peer == NULL || callbacks == NULL || callbacks->on_open == NULL ||
        callbacks->on_data == NULL || callbacks->on_close == NULL) return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(owner)) return SOLARIS_ETHREAD;
    solaris_tls_open_options_t extra = {0}; if (tls_options) extra = *tls_options;
    if ((extra.require_alpn != 0 && extra.require_alpn != 1) ||
        extra.cipher_profile > SOLARIS_TLS_CIPHERS_HTTP2 ||
        (extra.alpn_length && !extra.alpn) || extra.alpn_length > SOLARIS_TLS_MAX_ALPN_OFFER ||
        (extra.require_alpn && !extra.alpn_length)) return SOLARIS_EINVAL;
    for (size_t offset = 0; offset < extra.alpn_length;) {
        size_t count = extra.alpn[offset++];
        if (!count || count > extra.alpn_length - offset) return SOLARIS_EINVAL;
        offset += count;
    }
    solaris_address_t name;
    if (solaris_address_parse(identity, 443u, &name) != SOLARIS_OK) return SOLARIS_EINVAL;
    tls_stream_t *tls = solaris_memory_allocate(solaris_executor_budget(owner), sizeof(*tls));
    if (tls == NULL) return SOLARIS_ENOMEM;
    memset(tls, 0, sizeof(*tls));
    solaris_status_t rc = solaris_dialer_options_normalize(options, &tls->options);
    if (rc != SOLARIS_OK) { solaris_memory_free(tls); return rc; }
    if (tls->options.parent_scope) {
        if (tls->options.parent_scope->owner != owner) { solaris_memory_free(tls); return SOLARIS_ETHREAD; }
        if (tls->options.parent_scope->cancelled || tls->options.parent_scope->finishing) { solaris_memory_free(tls); return SOLARIS_ECLOSED; }
    }
    tls->require_alpn = extra.require_alpn;
    if (extra.alpn_length) {
        rc = solaris_buffer_copy(solaris_executor_budget(owner), extra.alpn, extra.alpn_length, &tls->alpn_offer);
        if (rc != SOLARIS_OK) { destroyed(tls); return rc; }
    }
    tls->ssl = SSL_new(trust->native);
    BIO *internal = NULL;
    if (tls->ssl == NULL || !BIO_new_bio_pair(&internal, TLS_BIO_BYTES, &tls->bio, TLS_BIO_BYTES)) {
        BIO_free(internal); destroyed(tls); return SOLARIS_ENOMEM;
    }
    SSL_set_bio(tls->ssl, internal, internal);
    SSL_set_connect_state(tls->ssl);
    if (!SSL_set_min_proto_version(tls->ssl, minimum_version)) {
        destroyed(tls); return SOLARIS_EINVAL;
    }
    if (extra.cipher_profile == SOLARIS_TLS_CIPHERS_HTTP2 && !SSL_set_strict_cipher_list(tls->ssl,
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305")) {
        destroyed(tls); return SOLARIS_EINVAL;
    }
    if (tls->alpn_offer && SSL_set_alpn_protos(tls->ssl,
        solaris_buffer_data(tls->alpn_offer), solaris_buffer_length(tls->alpn_offer)) != 0) {
        destroyed(tls); return SOLARIS_EINVAL;
    }
    int valid = name.family == SOLARIS_ADDRESS_DOMAIN ?
        SSL_set1_host(tls->ssl, identity) && SSL_set_tlsext_host_name(tls->ssl, identity) :
        X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(tls->ssl), identity);
    if (!valid) { destroyed(tls); return SOLARIS_EINVAL; }
    tls->trust = trust; solaris_tls_context_retain(trust);
    tls->stream = (solaris_stream_t){&operations, tls, owner};
    tls->callbacks = *callbacks; tls->context = callback_context; tls->reading = 1; tls->want_input = 1;
    tls->stats.max_message_bytes = tls->options.pending_byte_limit;
    tls->pump.run = pump; tls->pump.context = tls;
    rc = solaris_scope_init(&tls->scope, owner, cancel, destroyed, tls);
    if (rc != SOLARIS_OK) { destroyed(tls); return rc; }
    if (tls->options.parent_scope) {
        tls->parent_scope = tls->options.parent_scope; solaris_scope_retain(tls->parent_scope);
    }
    uint64_t now = solaris_executor_now_ns(owner), duration = tls->options.open_timeout_ms * UINT64_C(1000000);
    if (extra.deadline_ns) {
        if (extra.deadline_ns <= now) { fail(tls, SOLARIS_ETIMEDOUT); return SOLARIS_ETIMEDOUT; }
        tls->open_deadline_ns = extra.deadline_ns;
    } else {
        if (duration > UINT64_MAX - now) { fail(tls, SOLARIS_EOVERFLOW); return SOLARIS_EOVERFLOW; }
        tls->open_deadline_ns = now + duration;
    }
    uint64_t delay = (tls->open_deadline_ns - now - 1) / UINT64_C(1000000) + 1;
    solaris_scope_retain(&tls->scope);
    rc = solaris_deadline_start(owner, delay, deadline, tls, &tls->deadline);
    if (rc != SOLARIS_OK) { solaris_scope_release(&tls->scope); fail(tls, rc); return rc; }
    /* Encrypted records must fit even if a caller selects tiny plaintext
     * limits. There is only one in-flight wire write, bounded to one record. */
    solaris_dialer_options_t wire_options = tls->options;
    wire_options.parent_scope = &tls->scope;
    now = solaris_executor_now_ns(owner);
    if (now >= tls->open_deadline_ns) { fail(tls, SOLARIS_ETIMEDOUT); return SOLARIS_ETIMEDOUT; }
    wire_options.open_timeout_ms = (tls->open_deadline_ns - now - 1) / UINT64_C(1000000) + 1;
    if (wire_options.pending_byte_limit < TLS_RECORD_BYTES) wire_options.pending_byte_limit = TLS_RECORD_BYTES;
    wire_options.pending_request_limit = 1u;
    wire_options.read_chunk_size = TLS_RECORD_BYTES;
    rc = solaris_carrier_open(carrier, owner, &wire_options, peer, &wire_callbacks, tls, &tls->wire);
    if (rc != SOLARIS_OK) { fail(tls, rc); return rc; }
    solaris_scope_retain(&tls->scope);
    tls->accepted = 1; *out = &tls->stream;
    return SOLARIS_OK;
}

solaris_status_t solaris_tls_open(solaris_executor_t *owner,
    solaris_tls_context_t *trust, const char *identity, uint16_t minimum_version,
    const solaris_stream_factory_t *carrier, const solaris_dialer_options_t *options,
    const solaris_address_t *peer, const solaris_stream_callbacks_t *callbacks,
    void *callback_context, solaris_stream_t **out)
{
    return solaris_tls_open_ex(owner, trust, identity, minimum_version, NULL,
        carrier, options, peer, callbacks, callback_context, out);
}
solaris_status_t solaris_tls_selected_alpn(solaris_stream_t *stream, void *out, size_t capacity, size_t *length)
{
    if (length) *length = 0;
    if (!stream || !length || (capacity && !out)) return SOLARIS_EINVAL;
    if (stream->ops != &operations) return SOLARIS_ENOTSUP;
    if (!solaris_executor_is_owner(stream->owner)) return SOLARIS_ETHREAD;
    tls_stream_t *tls = stream->state;
    if (!tls->handshake_done) return SOLARIS_EAGAIN;
    *length = tls->selected_alpn_length;
    if (capacity < *length) return SOLARIS_EMSGSIZE;
    if (*length) memcpy(out, tls->selected_alpn, *length);
    return SOLARIS_OK;
}
