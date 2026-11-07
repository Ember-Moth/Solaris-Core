#include "runtime/config/modules.h"
#include "api/common/error.h"
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

struct solaris_config_module_set {
    atomic_size_t references;
    solaris_config_t *image;
    size_t count;
    solaris_module_config_t *configs[];
};
void solaris_config_module_set_retain(solaris_config_module_set_t *set)
{
    if (set)
        (void)atomic_fetch_add_explicit(&set->references, 1, memory_order_relaxed);
}
void solaris_config_module_set_release(solaris_config_module_set_t *set)
{
    if (!set || atomic_fetch_sub_explicit(&set->references, 1, memory_order_acq_rel) != 1)
        return;
    for (size_t i = 0; i < set->count; ++i)
        solaris_module_config_release(set->configs[i]);
    solaris_config_release(set->image);
    solaris_memory_free(set);
}
solaris_config_t *solaris_config_module_set_image(const solaris_config_module_set_t *set)
{
    return set ? set->image : NULL;
}
size_t solaris_config_module_set_count(const solaris_config_module_set_t *set)
{
    return set ? set->count : 0;
}
solaris_module_config_t *solaris_config_module_set_at(const solaris_config_module_set_t *set, size_t index)
{
    return set && index < set->count ? set->configs[index] : NULL;
}
solaris_status_t solaris_config_module_set_create(solaris_budget_t *budget, solaris_config_t *image,
                                                  const void *trust_pem, size_t trust_length,
                                                  solaris_config_module_set_t **out, solaris_error_t *error)
{
    if (!out)
        return solaris_error_set(error, SOLARIS_EINVAL, 0, "module set output is required");
    *out = NULL;
    if (!budget || !image || (trust_length && !trust_pem))
        return solaris_error_set(error, SOLARIS_EINVAL, 0, "invalid module set inputs");
    size_t count;
    const solaris_config_node_t *nodes = solaris_config_nodes(image, &count);
    if ((count && !nodes) ||
        count > (SIZE_MAX - sizeof(solaris_config_module_set_t)) / sizeof(solaris_module_config_t *))
        return solaris_error_set(error, SOLARIS_EINVAL, 0, "invalid module set node count");
    solaris_config_module_set_t *set = solaris_memory_allocate(budget, sizeof(*set) + count * sizeof(*set->configs));
    if (!set)
        return solaris_error_set(error, SOLARIS_ENOMEM, 0, NULL);
    memset(set, 0, sizeof(*set) + count * sizeof(*set->configs));
    atomic_init(&set->references, 1);
    set->image = image;
    solaris_config_retain(image);
    solaris_registry_t *registry = NULL;
    solaris_status_t rc = solaris_builtin_registry_create(budget, &registry, error);
    for (size_t i = 0; rc == SOLARIS_OK && i < count; ++i) {
        const solaris_config_view_t *original = nodes[i].fields;
        if (!original || original->kind != SOLARIS_CONFIG_MAP ||
            (original->value.map.count && !original->value.map.fields)) {
            rc = solaris_error_set(error, SOLARIS_EINVAL, 0, "invalid normalized module fields");
            break;
        }
        solaris_config_view_t normalized = *original;
        solaris_config_field_t *injected = NULL;
        const solaris_config_view_t *tls = solaris_config_get(original, "tls");
        if (tls && tls->kind == SOLARIS_CONFIG_BOOL && tls->value.boolean) {
            if (!trust_pem || !trust_length) {
                rc = solaris_error_set(error, SOLARIS_EINVAL, 0, "host TLS trust bundle is required");
            } else if (trust_length > 256u * 1024u || original->value.map.count >= SIZE_MAX / sizeof(*injected)) {
                rc = solaris_error_set(error, SOLARIS_EMSGSIZE, 0,
                                       "host TLS trust bundle or field count exceeds its limit");
            } else if (solaris_config_get(original, "ca-pem")) {
                rc = solaris_error_set(error, SOLARIS_EINVAL, 0,
                                       "configuration image cannot supply private TLS trust fields");
            } else {
                size_t fields = original->value.map.count;
                injected = solaris_memory_allocate(budget, (fields + 1) * sizeof(*injected));
                if (!injected)
                    rc = solaris_error_set(error, SOLARIS_ENOMEM, 0, NULL);
                else {
                    if (fields)
                        memcpy(injected, original->value.map.fields, fields * sizeof(*injected));
                    injected[fields] = (solaris_config_field_t){
                        .name = "ca-pem",
                        .value = {.kind = SOLARIS_CONFIG_STRING, .value.string = {trust_pem, trust_length}}};
                    normalized.value.map.fields = injected;
                    normalized.value.map.count = fields + 1;
                }
            }
        }
        if (rc == SOLARIS_OK)
            rc = solaris_registry_compile(registry, nodes[i].type, &normalized, &set->configs[i], error);
        solaris_memory_free(injected);
        if (rc == SOLARIS_OK)
            set->count++;
        else if (error) {
            char reason[SOLARIS_ERROR_MESSAGE_CAPACITY];
            memcpy(reason, error->message, sizeof(reason));
            reason[sizeof(reason) - 1] = 0;
            (void)snprintf(error->message, sizeof(error->message), "node %.63s at %u:%u: %.88s", nodes[i].name,
                           nodes[i].line, nodes[i].column, reason[0] ? reason : solaris_status_string(rc));
            error->code = rc;
        }
    }
    solaris_registry_destroy(registry);
    if (rc != SOLARIS_OK) {
        solaris_config_module_set_release(set);
        if (error && error->code == SOLARIS_OK)
            solaris_error_set(error, rc, 0, NULL);
        return rc;
    }
    *out = set;
    return solaris_error_set(error, SOLARIS_OK, 0, NULL);
}
