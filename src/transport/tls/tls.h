#ifndef SOLARIS_TLS_H
#define SOLARIS_TLS_H

#include "contracts/io/carrier.h"

typedef struct solaris_tls_context solaris_tls_context_t;
enum { SOLARIS_TLS_1_2 = 0x0303, SOLARIS_TLS_1_3 = 0x0304 };

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

#endif
