#ifndef SOLARIS_PLATFORM_H
#define SOLARIS_PLATFORM_H

#include <stddef.h>
#include <stdint.h>
#include <solaris/error.h>

#ifdef __cplusplus
extern "C" {
#endif

enum { SOLARIS_SOCKET_FAMILY_IPV4 = 4, SOLARIS_SOCKET_FAMILY_IPV6 = 6 };
enum { SOLARIS_SOCKET_POLICY_TCP = 1, SOLARIS_SOCKET_POLICY_UDP = 2 };
typedef struct solaris_socket_token solaris_socket_token_t;
typedef struct solaris_socket_policy {
    void *context;
    /* Optional pair for a NULL, stateless context; required by network snapshot
     * creation for a non-NULL context. Hooks must be thread-safe and promptly
     * manage lifetime only. A snapshot, outbound channel and accepted request
     * each retain their own reference. The last release can run on any thread. */
    void (*retain)(void *context);
    void (*release)(void *context);
    /* Runs promptly on a core I/O thread, not the UI thread. handle is a
     * CORE-OWNED socket duplicate, family/kind use the constants above.
     * Never close it. OK promises one final complete, including after cancel;
     * rejection promises no complete. Synchronous complete before OK is valid.
     * Multiple I/O threads may invoke this policy concurrently. */
    solaris_status_t (*start)(void *context, solaris_socket_token_t *token,
        uintptr_t handle, uint32_t family, uint32_t kind);
    /* At most one notification on the requesting I/O thread. Returning is NOT
     * an ACK: complete only after all queued/running handle use ends. It may
     * complete synchronously. Cancellation can race a foreign ACK; tolerate an
     * already completed request without a second ACK. The token is freshly
     * borrowed for this callback only. Keep completion queues alive during stop. */
    void (*cancel)(void *context, solaris_socket_token_t *token);
} solaris_socket_policy_t;

/* Thread-safe final host ACK, promising no further host handle/token use
 * (except a fresh borrow during a racing cancel callback). Duplicate ACK while
 * token is still alive returns ECLOSED; an expired token must never be probed.
 * Final request completion is deferred on its I/O thread. Logical cancellation
 * or deadline can win before that processing. The duplicate/context remain
 * held until accepted host work and core cleanup drain. */
SOLARIS_API solaris_status_t solaris_socket_policy_complete(solaris_socket_token_t *token, solaris_status_t status);

#define SOLARIS_NETWORK_MAX_DNS_SERVERS 16u
#define SOLARIS_NETWORK_MAX_SYSTEM_HOSTS 4096u
#define SOLARIS_NETWORK_MAX_HOST_ADDRESSES 16u
#define SOLARIS_NETWORK_MAX_TOTAL_HOST_ADDRESSES 16384u
#define SOLARIS_NETWORK_DEFAULT_MEMORY_LIMIT_BYTES ((size_t)16777216u)
#define SOLARIS_NETWORK_MAX_MEMORY_LIMIT_BYTES ((size_t)67108864u)

typedef struct solaris_network_snapshot solaris_network_snapshot_t;
typedef struct solaris_network_server_input {
    /* Numeric IPv4/IPv6 only, optionally IPv6 with %<nonzero decimal scope ID>.
     * No bracket/URI/interface-name parsing. Zero port means DNS port 53. */
    const char *address;
    uint16_t port;
} solaris_network_server_input_t;
typedef struct solaris_network_host_input {
    /* Exact ASCII DNS name, case-folded with one trailing dot removed.
     * At most 253 normalized bytes. No patterns or alias target strings. */
    const char *name;
    const char *const *addresses; /* Numeric, unscoped, portless IP strings. */
    size_t address_count;
} solaris_network_host_input_t;
typedef struct solaris_network_options {
    /* All three revisions are nonzero and independently host-assigned.
     * revision orders host events; physical network and DNS/hosts revisions
     * need not change together. network_id is opaque; zero is unspecified. */
    uint64_t revision, network_revision, resolver_revision, network_id;
    /* Boolean 0/1. Both families unavailable is a valid disconnected view.
     * Server/hosts records remain metadata, not proof of current reachability. */
    uint32_t ipv4_available, ipv6_available, strict_dns;
    solaris_socket_policy_t socket_policy;
    const solaris_network_server_input_t *dns_servers;
    size_t dns_server_count;
    const solaris_network_host_input_t *system_hosts;
    size_t system_host_count;
    size_t memory_limit_bytes; /* Zero uses 16 MiB; hard maximum 64 MiB. */
} solaris_network_options_t;
typedef struct solaris_network_snapshot_info {
    uint64_t revision, network_revision, resolver_revision, network_id;
    uint32_t ipv4_available, ipv6_available, strict_dns, socket_policy_configured;
    size_t dns_server_count, system_host_count, system_host_address_count;
} solaris_network_snapshot_info_t;
typedef struct solaris_network_endpoint_info {
    uint32_t family, scope_id;
    uint16_t port;
    char address[64]; /* Canonical numeric text, including a nonzero scope. */
} solaris_network_endpoint_info_t;
typedef struct solaris_network_host_info {
    char name[254];
    size_t address_count;
} solaris_network_host_info_t;
typedef struct solaris_platform_capabilities {
    /* OK means this build implements real socket duplication for async policy;
     * ENOTSUP currently applies to Windows. This is not a VPN/device claim. */
    solaris_status_t async_socket_policy_status;
    size_t dns_server_limit, system_host_limit, addresses_per_host_limit, total_host_address_limit;
} solaris_platform_capabilities_t;

SOLARIS_API solaris_status_t solaris_platform_get_capabilities(solaris_platform_capabilities_t *out);
SOLARIS_API void solaris_network_options_init(solaris_network_options_t *options);
/* Pure bounded construction: no sockets, resolver, files, interface discovery,
 * or host start/cancel callbacks. Copies all arrays/strings; retains a supplied
 * policy context once after validation. Failure sets *out=NULL and reports a
 * static explanation without copying input contents into diagnostics.
 * System hosts contain ONLY supplied entries: no synthetic localhost.
 * strict_dns is a declared requirement; runtime activation checks its actual
 * DNS/policy path separately. No engine or TUN activation occurs here. */
SOLARIS_API solaris_status_t solaris_network_snapshot_create(const solaris_network_options_t *options,
    solaris_network_snapshot_t **out, solaris_error_t *error);
SOLARIS_API void solaris_network_snapshot_retain(solaris_network_snapshot_t *snapshot);
SOLARIS_API void solaris_network_snapshot_release(solaris_network_snapshot_t *snapshot);
/* Concurrent immutable copy-out. Outputs contain no borrowed pointers. */
SOLARIS_API solaris_status_t solaris_network_snapshot_get_info(const solaris_network_snapshot_t *snapshot,
    solaris_network_snapshot_info_t *out);
SOLARIS_API solaris_status_t solaris_network_snapshot_get_dns_server(const solaris_network_snapshot_t *snapshot,
    size_t index, solaris_network_endpoint_info_t *out);
SOLARIS_API solaris_status_t solaris_network_snapshot_get_host(const solaris_network_snapshot_t *snapshot,
    size_t index, solaris_network_host_info_t *out);
SOLARIS_API solaris_status_t solaris_network_snapshot_get_host_address(const solaris_network_snapshot_t *snapshot,
    size_t host_index, size_t address_index, solaris_network_endpoint_info_t *out);

#ifdef __cplusplus
}
#endif
#endif
