#ifndef SOLARIS_TLS_H
#define SOLARIS_TLS_H

#include "contracts/io/carrier.h"

typedef struct solaris_tls_context solaris_tls_context_t;
enum { SOLARIS_TLS_1_2 = 0x0303, SOLARIS_TLS_1_3 = 0x0304 };
enum { SOLARIS_TLS_CIPHERS_DEFAULT = 0, SOLARIS_TLS_CIPHERS_HTTP2 = 1 };
#define SOLARIS_TLS_MAX_ALPN_OFFER 1024u
#define SOLARIS_TLS_MAX_ALPN_PROTOCOL 255u
typedef struct solaris_tls_open_options {
    /* TLS wire format: nonempty one-byte-length-prefixed binary protocol names.
     * Copied before return; zero length disables ALPN. No implicit protocol. */
    const uint8_t *alpn;
    size_t alpn_length;
    int require_alpn;
    /* Opt-in HTTP/2 profile: TLS 1.2 only ECDHE + AEAD; TLS 1.3 is unchanged.
     * The default/legacy API does not change its existing cipher policy. */
    uint32_t cipher_profile;
    /* Optional absolute owner-clock deadline for TCP connect + TLS handshake.
     * Zero preserves the existing dialer.open_timeout_ms behavior. */
    uint64_t deadline_ns;
} solaris_tls_open_options_t;

/* Immutable, shareable trust configuration. PEM roots are copied/parsed now;
 * no network/filesystem I/O or implicit system trust lookup. At least one CA
 * is required. TLS >= 1.2; chain and DNS/IP identity verification are mandatory.
 * BoringSSL's internal allocations are not part of the Solaris buffer budget.
 * SSL handshake size and BIO capacity are bounded independently. */
solaris_status_t solaris_tls_context_create(solaris_budget_t *budget,
    const void *ca_pem, size_t ca_pem_length, solaris_tls_context_t **out);
void solaris_tls_context_retain(solaris_tls_context_t *context);
void solaris_tls_context_release(solaris_tls_context_t *context);

/* identity is a DNS name or numerical IP, never an empty name. The factory,
 * identity and options are copied/consumed before return; factory.context is
 * borrowed as documented by the carrier contract. A context reference is
 * retained until close. Pending writes count plaintext; wire buffers have
 * independent fixed bounds. Successful write completion means all generated
 * records have completed their underlying writes. */
solaris_status_t solaris_tls_open(solaris_executor_t *owner,
    solaris_tls_context_t *context, const char *identity, uint16_t minimum_version,
    const solaris_stream_factory_t *carrier, const solaris_dialer_options_t *options,
    const solaris_address_t *peer, const solaris_stream_callbacks_t *callbacks,
    void *callback_context, solaris_stream_t **out);

/* Extended opt-in form; old open has no ALPN offer/requirement. The outer
 * dialer.parent_scope is a same-owner, live cleanup fence. TLS retains it
 * through SSL/BIO/inner transport destruction, including rejected opens.
 * Inner carrier options carry the TLS scope as their parent. Custom carriers
 * must honor that fence for asynchronous cleanup after rejection. */
solaris_status_t solaris_tls_open_ex(solaris_executor_t *owner,
    solaris_tls_context_t *context, const char *identity, uint16_t minimum_version,
    const solaris_tls_open_options_t *tls_options,
    const solaris_stream_factory_t *carrier, const solaris_dialer_options_t *options,
    const solaris_address_t *peer, const solaris_stream_callbacks_t *callbacks,
    void *callback_context, solaris_stream_t **out);
/* Owner-only, copies binary bytes without a NUL terminator. Before successful
 * handshake: EAGAIN. A successful handshake without ALPN returns length zero.
 * EMSGSIZE reports required length; length may be queried with NULL/zero buffer.
 * Only the actual TLS stream is accepted, not an arbitrary outer wrapper. */
solaris_status_t solaris_tls_selected_alpn(solaris_stream_t *stream,
    void *out, size_t capacity, size_t *length);

#endif
