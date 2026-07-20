#include <stdio.h>
#include <string.h>

#include <solaris/core.h>

static void emit_event(void *context, const aproxy_engine_event_v2_t *event)
{
    (void)context;
    if (event == NULL || event->message.data == NULL) {
        return;
    }
    printf("event type=%u state=%u op=%llu status=%d message=%.*s\n",
           event->type,
           event->state,
           (unsigned long long)event->operation_id,
           event->status,
           (int)event->message.len,
           event->message.data);
}

static int capture_capabilities(void *context, const aproxy_value_t *value)
{
    (void)context;
    if (value == NULL || value->type != APROXY_VALUE_OBJECT) {
        return -1;
    }
    printf("Solaris core capabilities object entries=%zu\n",
           value->as.object.count);
    return 0;
}

int main(void)
{
    const solaris_core_api_t *api = NULL;
    int rc = solaris_core_get_api(&api);
    if (rc != 0 || api == NULL ||
        api->abi_version != SOLARIS_CORE_ENGINE_ABI_VERSION ||
        api->struct_size < sizeof(*api)) {
        fprintf(stderr, "Solaris core API mismatch: %d\n", rc);
        return 1;
    }

    solaris_core_host_t host;
    memset(&host, 0, sizeof(host));
    host.abi_version = SOLARIS_CORE_ENGINE_ABI_VERSION;
    host.struct_size = sizeof(host);
    host.emit_event = emit_event;

    solaris_core_engine_t *engine = NULL;
    rc = api->create(&host, &engine);
    if (rc != 0 || engine == NULL) {
        fprintf(stderr, "Solaris core create failed: %d\n", rc);
        return 1;
    }

    rc = api->get_capabilities(engine, capture_capabilities, NULL);
    api->destroy(engine);
    return rc == 0 ? 0 : 1;
}
