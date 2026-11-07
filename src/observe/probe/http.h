#ifndef SOLARIS_HTTP_PROBE_H
#define SOLARIS_HTTP_PROBE_H
#include "observe/connections/tracker.h"
#include "policy/select/select.h"
#include "transport/tls/tls.h"

typedef struct solaris_http_probe solaris_http_probe_t;
typedef struct solaris_http_probe_options {
    const char *url;
    uint64_t timeout_ms;
    solaris_tls_context_t *trust; /* required for https, chain/identity checked */
    solaris_tracker_t *tracker; /* optional separate PROBE traffic bucket */
    solaris_select_control_t *health; /* optional node health publication */
    /* Optional same-owner full cleanup fence, including rejection after the
     * probe scope was admitted. Its storage outlives the probe destructor. */
    solaris_scope_t *parent_scope;
    /* Optional owner-clock absolute deadline, including caller queue/trust
     * preparation. Zero preserves the standalone relative-timeout contract. */
    uint64_t deadline_ns;
    uint64_t config_revision;
} solaris_http_probe_options_t;
typedef struct solaris_http_probe_result {
    solaris_status_t status;
    uint16_t http_status;
    uint64_t node_id, selection_revision, connection_id;
    uint64_t started_ns, completed_ns, duration_ns;
    size_t bytes_written, bytes_read;
} solaris_http_probe_result_t;
typedef void (*solaris_http_probe_fn)(void *context, solaris_http_probe_t *probe, const solaris_http_probe_result_t *result);

/* Owner-only, one HEAD request. 2xx/3xx complete headers plus a completed
 * request write are success. At most four informational responses; no body
 * throughput test, redirects, retries or application-data replay. Success
 * moves source and clears it; rejection leaves source with the caller and
 * never calls done. An accepted probe completes once after its stream/write/
 * deadline callbacks drain. A slow OS cancellation may delay delivery, while
 * duration records the deadline/result decision rather than cleanup time.
 * The handle expires after done returns. */
solaris_status_t solaris_http_probe_start(solaris_executor_t *owner, solaris_dial_plan_t *source,
    const solaris_http_probe_options_t *options, solaris_http_probe_fn done, void *context, solaris_http_probe_t **out);
solaris_status_t solaris_http_probe_cancel(solaris_http_probe_t *probe);
#endif
