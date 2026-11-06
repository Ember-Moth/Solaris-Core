#ifndef SOLARIS_DIAGNOSTIC_H
#define SOLARIS_DIAGNOSTIC_H
#include <stddef.h>
#include <stdint.h>
#include <solaris/error.h>
/* Optional host sink for component diagnostics. Called on the owning worker;
 * a shared sink must support concurrent workers. Strings/bytes are borrowed
 * for the call. Peer text is untrusted and may need escaping for display.
 * The context outlives all dependent instances/channels. No implicit stderr. */
typedef struct solaris_diagnostic_sink {
    void *context;
    void (*report)(void *context, const char *component, solaris_status_t status,
                   const uint8_t *message, size_t length);
} solaris_diagnostic_sink_t;
#endif
