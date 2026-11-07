#ifndef SOLARIS_PROBE_H
#define SOLARIS_PROBE_H
#include <solaris/engine.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C"
{
#endif
    typedef struct solaris_probe_options
    {
        /* Zero captures the current configuration when execution starts. A nonzero
         * stale revision completes with EAGAIN. target_id is a leaf or flat group. */
        uint64_t config_revision, target_id, timeout_ms;
        const char *url;
        const void *trust_pem;
        size_t trust_length;
    } solaris_probe_options_t;
    typedef struct solaris_probe_result
    {
        solaris_status_t status;
        uint16_t http_status;
        uint64_t target_id, node_id, config_revision, selection_revision, runtime_generation, connection_id;
        uint64_t started_ns, completed_ns, duration_ns, bytes_written, bytes_read;
    } solaris_probe_result_t;
    /* Borrowed result on the control owner, before the generic event. The result
     * may be copied and retained. Delivery follows all probe resource cleanup. */
    typedef void (*solaris_probe_callback_t)(void *context, const solaris_probe_result_t *result);
    SOLARIS_API void solaris_probe_options_init(solaris_probe_options_t *options);
    /* Thread-safe, cancelable via engine_cancel. One HTTP(S) HEAD request; complete
     * 2xx/3xx response headers plus a completed write mean success. No redirects,
     * retries or body throughput measurement. timeout defaults to 5000 ms.
     * URL (<=2048 bytes) and PEM (<=256 KiB) are copied before acceptance. HTTPS
     * requires explicit trust; no implicit system trust. callback is required.
     * Rejection sets operation_id=0 and has no callback. Accepted work completes
     * once after cleanup, including cancellation and engine stop/destroy.
     * Generic event.config_revision is zero: only the typed result identifies the
     * observed configuration. PROBE traffic is separate from USER logical bytes. */
    SOLARIS_API solaris_status_t solaris_engine_probe(solaris_engine_t *engine,
                                                      const solaris_probe_options_t *options,
                                                      solaris_probe_callback_t callback, void *context,
                                                      uint64_t *operation_id, solaris_error_t *error);
#ifdef __cplusplus
}
#endif
#endif
