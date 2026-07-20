#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <solaris/core.h>

static int saw_expected_capability;

static const solaris_core_value_t *object_get(
    const solaris_core_value_t *object,
    const char *key)
{
    if (object == NULL || key == NULL ||
        object->type != APROXY_VALUE_OBJECT) {
        return NULL;
    }
    const size_t len = strlen(key);
    for (size_t i = 0u; i < object->as.object.count; i++) {
        const aproxy_object_entry_t *entry = &object->as.object.entries[i];
        if (entry->key.len == len &&
            memcmp(entry->key.data, key, len) == 0) {
            return entry->value;
        }
    }
    return NULL;
}

static int capture_capabilities(void *context,
                                const solaris_core_value_t *value)
{
    (void)context;
    const solaris_core_value_t *schema = object_get(value, "configSchema");
    const solaris_core_value_t *version = object_get(value, "schemaVersion");
    if (schema == NULL || schema->type != APROXY_VALUE_STRING ||
        schema->as.string.len != strlen(SOLARIS_CORE_CONFIG_SCHEMA) ||
        memcmp(schema->as.string.data,
               SOLARIS_CORE_CONFIG_SCHEMA,
               schema->as.string.len) != 0 ||
        version == NULL || version->type != APROXY_VALUE_U64 ||
        version->as.u64 != SOLARIS_CORE_CONFIG_SCHEMA_VERSION) {
        return -1;
    }
    saw_expected_capability = 1;
    return 0;
}

static int capture_status(void *context,
                          const solaris_core_status_t *status)
{
    (void)context;
    if (status == NULL ||
        status->abi_version != SOLARIS_CORE_ENGINE_ABI_VERSION ||
        status->struct_size < sizeof(*status) ||
        status->state != APROXY_ENGINE_IDLE) {
        return -1;
    }
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

    solaris_core_engine_t *engine = NULL;
    rc = api->create(&host, &engine);
    if (rc != 0 || engine == NULL) {
        fprintf(stderr, "Solaris core create failed: %d\n", rc);
        return 1;
    }

    rc = api->get_capabilities(engine, capture_capabilities, NULL);
    if (rc == 0 && !saw_expected_capability) {
        rc = -1;
    }
    if (rc == 0) {
        rc = api->get_status(engine, capture_status, NULL);
    }
    api->destroy(engine);
    if (rc != 0) {
        fprintf(stderr, "Solaris core ABI smoke failed: %d\n", rc);
        return 1;
    }
    return 0;
}
