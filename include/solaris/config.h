#ifndef SOLARIS_CONFIG_H
#define SOLARIS_CONFIG_H
#include <stddef.h>
#include <stdint.h>
#include <solaris/error.h>
#include <solaris/engine.h>
#ifdef __cplusplus
extern "C" {
#endif

typedef struct solaris_config solaris_config_t;
typedef struct solaris_diagnostics solaris_diagnostics_t;
typedef uint32_t solaris_mode_t;
enum { SOLARIS_MODE_RULE = 1, SOLARIS_MODE_GLOBAL = 2, SOLARIS_MODE_DIRECT = 3 };
enum { SOLARIS_DIAGNOSTIC_ERROR = 1, SOLARIS_DIAGNOSTIC_WARNING = 2 };
enum { SOLARIS_CONFIG_PARSE = 1, SOLARIS_CONFIG_NORMALIZE = 2, SOLARIS_CONFIG_VALIDATE = 3,
       SOLARIS_CONFIG_PREPARE = 4, SOLARIS_CONFIG_COMMIT = 5 };
typedef struct solaris_config_options {
    /* Optional source metadata. Conf v1 does not load external resources.
     * All strings are borrowed only until the compile call returns. */
    const char *base_directory, *source_name;
    size_t input_limit_bytes, memory_limit_bytes, string_limit_bytes;
    uint32_t line_limit_bytes, node_limit, entry_limit, diagnostic_limit;
} solaris_config_options_t;
typedef struct solaris_config_diagnostic {
    uint32_t severity, stage, line, column, related_line, related_column;
    solaris_status_t status;
    char source[512], path[256], message[192];
} solaris_config_diagnostic_t;
typedef struct solaris_config_snapshot {
    solaris_mode_t mode;
    size_t node_count, group_count, rule_count, listener_count;
    /* Non-cryptographic structural summary; excludes credentials. Never use
     * equality here to skip config/auth updates or as a security identity. */
    uint64_t fingerprint;
} solaris_config_snapshot_t;
typedef struct solaris_config_node_info {
    uint64_t id;
    /* type is the normalized registry name (ss -> shadowsocks, reject -> block). */
    char name[128], type[32];
    uint32_t udp_enabled;
} solaris_config_node_info_t;

typedef struct solaris_prepared_config solaris_prepared_config_t;
enum {
    SOLARIS_LISTENER_HTTP = 1,
    SOLARIS_LISTENER_SOCKS5 = 2,
    SOLARIS_LISTENER_MIXED = 3,
    SOLARIS_LISTENER_DNS = 4
};
typedef struct solaris_config_listener_info {
    uint64_t id;
    char name[128], address[256];
    uint16_t port;
    /* Configured value, host-requested value, and actual address/port above. */
    char configured_address[256], requested_address[256];
    uint16_t configured_port, requested_port;
    uint32_t binding_overridden;
    /* SOLARIS_LISTENER_* protocol. DNS uses one listener ID and address/port
     * for both TCP and UDP, including after a host ephemeral override. */
    uint32_t protocol, udp_enabled, authentication_required;
    /* UINT32_MAX for a compiled listener not assigned to a runtime owner. */
    uint32_t worker_id;
} solaris_config_listener_info_t;
typedef struct solaris_config_bind_override {
    uint64_t listener_id;
    /* Numeric address, or NULL to preserve the compiled address. A zero port
     * explicitly requests a host ephemeral port; it does not disable the listener. */
    const char *address;
    uint16_t port;
} solaris_config_bind_override_t;
typedef struct solaris_config_prepare_options {
    /* Copied before acceptance, bounded to 256 KiB. No implicit system trust. */
    const void *trust_pem;
    size_t trust_length;
    const solaris_config_bind_override_t *bindings;
    size_t binding_count;
} solaris_config_prepare_options_t;
/* COMMITTED records a historical successful application, not current active
 * state. It remains readable after stop/destroy; query the engine for activity. */
enum { SOLARIS_PREPARED_READY = 1, SOLARIS_PREPARED_COMMITTING = 2,
       SOLARIS_PREPARED_COMMITTED = 3, SOLARIS_PREPARED_CLOSED = 4 };
typedef struct solaris_prepared_config_snapshot {
    uint64_t base_revision, runtime_generation, applied_revision;
    uint32_t state;
    size_t listener_count;
} solaris_prepared_config_snapshot_t;
typedef struct solaris_active_config_snapshot {
    /* publication_revision also advances when stop publishes an empty view.
     * active_revision is zero whenever no proxy configuration is active. */
    uint64_t publication_revision, active_revision, runtime_generation;
    solaris_mode_t mode;
    size_t listener_count, node_count, group_count;
} solaris_active_config_snapshot_t;
/* Typed callbacks execute on the control owner before the generic event.
 * error is borrowed until return. Success transfers one OWNED prepared ref;
 * failure returns prepared=NULL only after candidate resources have drained. */
typedef void (*solaris_config_prepare_callback_t)(void *context, solaris_status_t status,
    solaris_prepared_config_t *prepared, const solaris_error_t *error);
typedef void (*solaris_config_commit_callback_t)(void *context, solaris_status_t status,
    uint64_t applied_revision, const solaris_error_t *error);
SOLARIS_API void solaris_config_prepare_options_init(solaris_config_prepare_options_t *options);
/* Thread-safe asynchronous prepare; requires a running runtime. The image is
 * retained on acceptance, and options/PEM/override strings are copied. Rejection
 * sets operation_id=0, retains nothing, and has no callback. callback required.
 * Only one prepare runs per engine; an accepted overlapping operation may
 * complete with EBUSY. Base revision is pinned when preparation starts.
 * Preparing may bind candidate ports. Proxy and DNS admission begins at commit. */
SOLARIS_API solaris_status_t solaris_engine_prepare_config(solaris_engine_t *engine,
    solaris_config_t *image, const solaris_config_prepare_options_t *options,
    solaris_config_prepare_callback_t callback, void *context,
    uint64_t *operation_id, solaris_error_t *error);
/* Acceptance retains prepared without consuming the caller's reference.
 * Cancellation before start leaves it reusable; after start it is single-use.
 * A stale base revision fails with EAGAIN and drains the claimed candidate.
 * Publication and cancellation linearize together; an applied revision is
 * never reported as an unapplied cancellation. callback may be NULL. */
SOLARIS_API solaris_status_t solaris_engine_commit_config(solaris_engine_t *engine,
    solaris_prepared_config_t *prepared, solaris_config_commit_callback_t callback,
    void *context, uint64_t *operation_id, solaris_error_t *error);
SOLARIS_API void solaris_prepared_config_retain(solaris_prepared_config_t *prepared);
/* Thread-safe. Last external release abandons an unclaimed candidate and
 * requests asynchronous cleanup. stop/destroy wait for all such cleanup.
 * Committed handles never own active I/O. Metadata remains readable after
 * engine destruction while the caller retains the handle. */
SOLARIS_API void solaris_prepared_config_release(solaris_prepared_config_t *prepared);
SOLARIS_API solaris_status_t solaris_prepared_config_get_snapshot(
    const solaris_prepared_config_t *prepared, solaris_prepared_config_snapshot_t *out);
SOLARIS_API solaris_status_t solaris_prepared_config_get_listener(
    const solaris_prepared_config_t *prepared, size_t index, solaris_config_listener_info_t *out);
SOLARIS_API solaris_status_t solaris_engine_get_config_snapshot(solaris_engine_t *engine,
    solaris_active_config_snapshot_t *out, solaris_error_t *error);
/* Copies metadata only. EAGAIN means active_revision changed; ECLOSED means
 * there is no active configuration. No borrowed runtime pointers are exposed. */
SOLARIS_API solaris_status_t solaris_engine_get_bound_listener(solaris_engine_t *engine,
    uint64_t active_revision, size_t index, solaris_config_listener_info_t *out,
    solaris_error_t *error);
SOLARIS_API solaris_status_t solaris_config_get_listener(const solaris_config_t *config,
    size_t index, solaris_config_listener_info_t *out);

/* These entry points accept Solaris Conf v1 only, with config-version = 1
 * in [General]. Syntax/static checks perform no network or resource I/O.
 * compile_file reads only the explicitly requested file; no format fallback. */
SOLARIS_API void solaris_config_options_init(solaris_config_options_t *options);
/* Offline and synchronous; do not call on I/O/control callbacks. No resolver,
 * socket, TLS handshake or listener activation. Input is copied into owned,
 * immutable records, independent of the caller buffer and parser lifetime.
 * On failure out_config=NULL; diagnostics may still be returned and must be
 * released. A successful image does not imply runtime resources are prepared.
 * Trust PEM is supplied explicitly to prepare by the host. */
SOLARIS_API solaris_status_t solaris_config_compile_bytes(const void *bytes, size_t length,
    const solaris_config_options_t *options, solaris_config_t **out_config,
    solaris_diagnostics_t **out_diagnostics, solaris_error_t *error);
/* Reads only this bounded configuration file. If base_directory is NULL, use
 * its parent as source metadata. Never recursively includes other files. */
SOLARIS_API solaris_status_t solaris_config_compile_file(const char *path,
    const solaris_config_options_t *options, solaris_config_t **out_config,
    solaris_diagnostics_t **out_diagnostics, solaris_error_t *error);
SOLARIS_API void solaris_config_retain(solaris_config_t *config);
SOLARIS_API void solaris_config_release(solaris_config_t *config);
SOLARIS_API solaris_status_t solaris_config_get_snapshot(const solaris_config_t *config, solaris_config_snapshot_t *out);
SOLARIS_API solaris_status_t solaris_config_get_node(const solaris_config_t *config, size_t index, solaris_config_node_info_t *out);
SOLARIS_API void solaris_diagnostics_retain(solaris_diagnostics_t *diagnostics);
SOLARIS_API void solaris_diagnostics_release(solaris_diagnostics_t *diagnostics);
SOLARIS_API size_t solaris_diagnostics_count(const solaris_diagnostics_t *diagnostics);
SOLARIS_API solaris_status_t solaris_diagnostics_get(const solaris_diagnostics_t *diagnostics,
    size_t index, solaris_config_diagnostic_t *out);
#ifdef __cplusplus
}
#endif
#endif
