#ifndef SOLARIS_STREAM_PLUGIN_H
#define SOLARIS_STREAM_PLUGIN_H

#include "contracts/io/carrier.h"

/* Optional internal host injection point, not a plugin implementation or an
 * external-process launcher. Names/options are opaque to the common layer. */
typedef struct solaris_stream_plugin_request {
    const char *name;
    const char *options;
    solaris_executor_t *owner;
    solaris_scope_t *scope;
    solaris_address_t server;
    solaris_stream_factory_t upstream;
} solaris_stream_plugin_request_t;

typedef struct solaris_stream_plugin_binding {
    solaris_stream_factory_t carrier;
    void *state;
    void (*retire)(void *state);
    void (*destroy)(void *state);
} solaris_stream_plugin_binding_t;

typedef struct solaris_stream_plugin_provider {
    void *context;
    /* Called on owner without I/O or process launch. Copies any borrowed
     * request data it needs. Unknown name/options return ENOTSUP; a successful
     * binding supplies all callbacks, including carrier.open. Null upstream
     * means the physical dialer via solaris_carrier_open.
     *
     * Provider/context outlive all dependent instances. The binding retains
     * request.scope for its asynchronous resources and dependent channels;
     * retire closes admission and starts draining, destroy runs after those
     * references drain. Failed create cleans all of its partial resources and
     * leaves out zeroed. No plugin may silently bypass an unsupported mode. */
    solaris_status_t (*create)(void *context, const solaris_stream_plugin_request_t *request,
        solaris_stream_plugin_binding_t *out, solaris_error_t *error);
} solaris_stream_plugin_provider_t;

#endif
