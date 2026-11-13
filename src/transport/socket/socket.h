#ifndef SOLARIS_SOCKET_TRANSPORT_H
#define SOLARIS_SOCKET_TRANSPORT_H

#include "contracts/io/channel.h"
#include "runtime/executor/executor.h"
#include "contracts/runtime/traffic.h"
#include "contracts/dns/lookup.h"
#include "contracts/runtime/socket_policy.h"

enum { SOLARIS_SOCKET_TCP = 1, SOLARIS_SOCKET_UDP = 2 };

/* Nonblocking synchronous socket preparation, called before TCP connect or
 * the first UDP send. Used for protect/interface binding; rejection prevents
 * network traffic. async_policy below is an optional second stage. */
typedef solaris_status_t (*solaris_socket_prepare_fn)(void *context, uintptr_t handle,
                                                     uint32_t family, uint32_t kind);

typedef struct solaris_dialer_options {
    solaris_address_t local_bind; /* family 0 means automatic ephemeral binding */
    solaris_socket_prepare_fn prepare_socket;
    /* Optional second asynchronous protect/bind stage; both stages must pass. */
    solaris_socket_policy_t async_policy;
    void *policy_context;
    size_t pending_byte_limit;
    size_t pending_request_limit;
    size_t read_chunk_size;
    uint64_t open_timeout_ms;
    solaris_traffic_counter_t *traffic;
    solaris_dns_lookup_t lookup;
    solaris_dns_lookup_view_t lookup_view;
    /* Strict domain targets require lookup; numeric bootstrap needs no DNS.
     * Lookup context, like policy_context, outlives all dependent channels. */
    int require_lookup;
    /* Optional host network family restriction: bit 0 IPv4, bit 1 IPv6.
     * A present view with mask zero is disconnected, never an automatic mode. */
    uint32_t network_view_present, allowed_families;
    /* Optional same-owner outbound-open drain barrier. Retained after scope
     * creation, including rejected opens with asynchronous native cleanup.
     * Accepted listener streams do not inherit this outbound-only parent. */
    solaris_scope_t *parent_scope;
} solaris_dialer_options_t;

/* Options are copied. policy_context remains borrowed until every channel
 * opened with these options has delivered its close callback. Preparation may
 * run concurrently on different workers; the policy context must support it.
 * async_policy's paired hooks retain its context for the complete outbound
 * channel lifetime, including retries and rejected-open cleanup. Without the
 * pair, that context is borrowed for the same lifetime. Each preparation also
 * owns its independent context reference until the host ACK has drained. */
/* traffic is borrowed by factories/options and retained by each physical
 * channel. The host keeps its reference while instances can create sockets. */

void solaris_dialer_options_init(solaris_dialer_options_t *options);
solaris_status_t solaris_dialer_options_normalize(const solaris_dialer_options_t *input,
                                                  solaris_dialer_options_t *output);
solaris_status_t solaris_dialer_open_stream(solaris_executor_t *executor,
                                            const solaris_dialer_options_t *options,
                                            const solaris_address_t *destination,
                                            const solaris_stream_callbacks_t *callbacks,
                                            void *context, solaris_stream_t **out);
/* UDP is unconnected and supports many numeric destinations of this family.
 * Domain-to-endpoint mapping belongs to the resolver/association layer. */
solaris_status_t solaris_dialer_open_datagram(solaris_executor_t *executor,
                                              const solaris_dialer_options_t *options,
                                              uint32_t family,
                                              const solaris_datagram_callbacks_t *callbacks,
                                              void *context, solaris_datagram_t **out);

#endif
