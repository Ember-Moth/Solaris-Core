#include "contracts/module/module.h"
#include "api/common/error.h"
#include <assert.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

enum { MODULE_LIMIT = 256, NAME_LIMIT = 127, ALIAS_LIMIT = 32 };
struct solaris_registry {
    solaris_budget_t *budget;
    size_t count;
    const solaris_outbound_module_t *modules[];
};
struct solaris_module_config {
    atomic_size_t references;
    const solaris_outbound_module_t *module;
    void *payload;
};
struct solaris_module_instance {
    solaris_scope_t scope;
    solaris_module_config_t *config;
    void *state;
    solaris_outbound_t *outbound;
    void (*on_close)(void *);
    void *context;
    size_t leases;
    solaris_scope_t *parent_scope;
};

static int valid_name(const char *name)
{
    if (name == NULL || name[0] == '\0') return 0;
    size_t i = 0;
    for (; i <= NAME_LIMIT && name[i] != '\0'; ++i) {
        const char c = name[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_')) return 0;
    }
    return i <= NAME_LIMIT;
}
static solaris_status_t registry_error(solaris_error_t *error, solaris_status_t status,
                                        const char *reason, const char *name)
{
    char message[SOLARIS_ERROR_MESSAGE_CAPACITY];
    (void)snprintf(message, sizeof(message), "%s: %s", reason, name == NULL ? "(null)" : name);
    return solaris_error_set(error, status, 0, message);
}
static const char *module_name(const solaris_outbound_module_t *module, size_t index)
{
    return index == 0u ? module->name : module->aliases[index - 1u];
}
static size_t find_index(const solaris_registry_t *registry, const char *name)
{
    for (size_t i = 0; i < registry->count; ++i)
        for (size_t j = 0; j <= registry->modules[i]->alias_count; ++j)
            if (strcmp(module_name(registry->modules[i], j), name) == 0) return i;
    return registry->count;
}
static solaris_status_t visit(const solaris_registry_t *registry, size_t index,
                               unsigned char *marks, solaris_error_t *error)
{
    const solaris_outbound_module_t *module = registry->modules[index];
    if (marks[index] == 2u) return SOLARIS_OK;
    if (marks[index] == 1u) return registry_error(error, SOLARIS_EINVAL, "module dependency cycle", module->name);
    marks[index] = 1u;
    for (size_t i = 0; i < module->dependency_count; ++i) {
        size_t dependency = find_index(registry, module->dependencies[i]);
        if (dependency == registry->count) {
            char reason[64];
            (void)snprintf(reason, sizeof(reason), "missing dependency of %.32s", module->name);
            return registry_error(error, SOLARIS_ENOTSUP, reason, module->dependencies[i]);
        }
        solaris_status_t rc = visit(registry, dependency, marks, error);
        if (rc != SOLARIS_OK) return rc;
    }
    marks[index] = 2u;
    return SOLARIS_OK;
}

solaris_status_t solaris_registry_create(const solaris_outbound_module_t *const *modules,
                                          size_t count, solaris_budget_t *budget,
                                          solaris_registry_t **out, solaris_error_t *error)
{
    if (out == NULL) return solaris_error_set(error, SOLARIS_EINVAL, 0, "registry output is required");
    *out = NULL;
    if (budget == NULL || count > MODULE_LIMIT || (count != 0u && modules == NULL))
        return solaris_error_set(error, SOLARIS_EINVAL, 0, "invalid registry input or module limit exceeded");
    /* Validate names before any cross-descriptor lookup. */
    for (size_t i = 0; i < count; ++i) {
        const solaris_outbound_module_t *m = modules[i];
        if (m == NULL || !valid_name(m->name) || m->alias_count > ALIAS_LIMIT ||
            m->dependency_count > MODULE_LIMIT || (m->alias_count != 0u && m->aliases == NULL) ||
            (m->dependency_count != 0u && m->dependencies == NULL) || m->compile == NULL ||
            m->free_config == NULL || m->create == NULL || m->retire == NULL || m->destroy == NULL)
            return registry_error(error, SOLARIS_EINVAL, "invalid module descriptor", m == NULL ? NULL : m->name);
        for (size_t j = 0; j < m->dependency_count; ++j)
            if (!valid_name(m->dependencies[j]))
                return registry_error(error, SOLARIS_EINVAL, "invalid dependency name", m->name);
        for (size_t j = 0; j <= m->alias_count; ++j) {
            const char *name = module_name(m, j);
            if (!valid_name(name)) return registry_error(error, SOLARIS_EINVAL, "invalid module name or alias", m->name);
            for (size_t k = 0; k <= i; ++k) {
                size_t limit = k == i ? j : modules[k]->alias_count + 1u;
                for (size_t n = 0; n < limit; ++n)
                    if (strcmp(name, module_name(modules[k], n)) == 0)
                        return registry_error(error, SOLARIS_EINVAL, "duplicate module name or alias", name);
            }
        }
    }
    solaris_registry_t *registry = solaris_memory_allocate(budget, sizeof(*registry) + count * sizeof(*modules));
    if (registry == NULL) return solaris_error_set(error, SOLARIS_ENOMEM, 0, NULL);
    registry->budget = budget; registry->count = count;
    for (size_t i = 0; i < count; ++i) registry->modules[i] = modules[i];
    unsigned char marks[MODULE_LIMIT] = {0};
    for (size_t i = 0; i < count; ++i) {
        solaris_status_t rc = visit(registry, i, marks, error);
        if (rc != SOLARIS_OK) { solaris_memory_free(registry); return rc; }
    }
    *out = registry;
    return solaris_error_set(error, SOLARIS_OK, 0, NULL);
}

void solaris_registry_destroy(solaris_registry_t *registry) { solaris_memory_free(registry); }
size_t solaris_registry_count(const solaris_registry_t *registry) { return registry == NULL ? 0u : registry->count; }
const solaris_outbound_module_t *solaris_registry_find(const solaris_registry_t *registry, const char *name)
{
    if (registry == NULL || name == NULL) return NULL;
    size_t index = find_index(registry, name);
    return index == registry->count ? NULL : registry->modules[index];
}

solaris_status_t solaris_registry_compile(const solaris_registry_t *registry, const char *name,
                                           const solaris_config_view_t *view,
                                           solaris_module_config_t **out, solaris_error_t *error)
{
    if (out == NULL) return solaris_error_set(error, SOLARIS_EINVAL, 0, "config output is required");
    *out = NULL;
    if (registry == NULL || name == NULL || view == NULL)
        return solaris_error_set(error, SOLARIS_EINVAL, 0, "invalid config input");
    const solaris_outbound_module_t *module = solaris_registry_find(registry, name);
    if (module == NULL) return registry_error(error, SOLARIS_ENOTSUP, "module is unknown or disabled", name);
    solaris_module_config_t *config = solaris_memory_allocate(registry->budget, sizeof(*config));
    if (config == NULL) return solaris_error_set(error, SOLARIS_ENOMEM, 0, NULL);
    atomic_init(&config->references, 1u); config->module = module; config->payload = NULL;
    solaris_error_set(error, SOLARIS_OK, 0, NULL);
    solaris_status_t rc = module->compile(view, registry->budget, &config->payload, error);
    if (rc != SOLARIS_OK) {
        module->free_config(config->payload);
        solaris_memory_free(config);
        if (error != NULL && error->code == SOLARIS_OK) solaris_error_set(error, rc, 0, NULL);
        return rc;
    }
    *out = config;
    return solaris_error_set(error, SOLARIS_OK, 0, NULL);
}
void solaris_module_config_retain(solaris_module_config_t *config)
{
    if (config != NULL) (void)atomic_fetch_add_explicit(&config->references, 1u, memory_order_relaxed);
}
void solaris_module_config_release(solaris_module_config_t *config)
{
    if (config != NULL && atomic_fetch_sub_explicit(&config->references, 1u, memory_order_acq_rel) == 1u) {
        config->module->free_config(config->payload);
        solaris_memory_free(config);
    }
}
static void retire_instance(void *context)
{
    solaris_module_instance_t *instance = context;
    if (instance->state != NULL) instance->config->module->retire(instance->state);
}
static void destroy_instance(void *context)
{
    solaris_module_instance_t *instance = context;
    if (instance->on_close != NULL) instance->on_close(instance->context);
    if (instance->state != NULL) instance->config->module->destroy(instance->state);
    solaris_module_config_release(instance->config);
    solaris_scope_t *parent = instance->parent_scope;
    solaris_memory_free(instance);
    if (parent != NULL) solaris_scope_release(parent);
}
solaris_status_t solaris_module_create(solaris_module_config_t *config,
                                        const solaris_module_services_t *services,
                                        void (*on_close)(void *), void *context,
                                        solaris_module_instance_t **out, solaris_error_t *error)
{
    if (out == NULL) return solaris_error_set(error, SOLARIS_EINVAL, 0, "instance output is required");
    *out = NULL;
    if (config == NULL || services == NULL || services->owner == NULL)
        return solaris_error_set(error, SOLARIS_EINVAL, 0, "invalid module services");
    if (!solaris_executor_is_owner(services->owner)) return solaris_error_set(error, SOLARIS_ETHREAD, 0, NULL);
    if (services->parent_scope != NULL) {
        if (services->parent_scope->owner != services->owner)
            return solaris_error_set(error, SOLARIS_ETHREAD, 0, "module parent scope has a different owner");
        if (services->parent_scope->cancelled || services->parent_scope->finishing)
            return solaris_error_set(error, SOLARIS_ECLOSED, 0, "module parent scope is closing");
    }
    solaris_module_instance_t *instance = solaris_memory_allocate(solaris_executor_budget(services->owner), sizeof(*instance));
    if (instance == NULL) return solaris_error_set(error, SOLARIS_ENOMEM, 0, NULL);
    memset(instance, 0, sizeof(*instance));
    solaris_status_t rc = solaris_scope_init(&instance->scope, services->owner, retire_instance, destroy_instance, instance);
    if (rc != SOLARIS_OK) { solaris_memory_free(instance); return solaris_error_set(error, rc, 0, NULL); }
    instance->config = config;
    instance->parent_scope = services->parent_scope;
    if (instance->parent_scope != NULL) solaris_scope_retain(instance->parent_scope);
    solaris_module_config_retain(config);
    solaris_module_services_t injected = *services;
    injected.scope = &instance->scope;
    solaris_error_set(error, SOLARIS_OK, 0, NULL);
    rc = config->module->create(config->payload, &injected, &instance->state, &instance->outbound, error);
    if (rc == SOLARIS_OK && (instance->state == NULL || instance->outbound == NULL ||
        instance->outbound->owner != services->owner || instance->outbound->ops == NULL))
        rc = solaris_error_set(error, SOLARIS_EINVAL, 0, "factory returned an invalid outbound");
    if (rc != SOLARIS_OK) {
        solaris_scope_cancel(&instance->scope);
        if (error != NULL && error->code == SOLARIS_OK) solaris_error_set(error, rc, 0, NULL);
        return rc;
    }
    instance->on_close = on_close; instance->context = context;
    *out = instance;
    return solaris_error_set(error, SOLARIS_OK, 0, NULL);
}
solaris_outbound_t *solaris_module_outbound(solaris_module_instance_t *instance)
{
    return instance != NULL && solaris_executor_is_owner(instance->scope.owner) && !instance->scope.cancelled ? instance->outbound : NULL;
}
solaris_status_t solaris_module_retire(solaris_module_instance_t *instance)
{
    if (instance == NULL) return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(instance->scope.owner)) return SOLARIS_ETHREAD;
    solaris_scope_cancel(&instance->scope);
    return SOLARIS_OK;
}
solaris_status_t solaris_module_retain(solaris_module_instance_t *instance)
{
    if (instance == NULL) return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(instance->scope.owner)) return SOLARIS_ETHREAD;
    if (instance->scope.cancelled || instance->scope.finishing) return SOLARIS_ECLOSED;
    if (instance->leases == SIZE_MAX || instance->scope.references == SIZE_MAX) return SOLARIS_EOVERFLOW;
    instance->leases++;
    solaris_scope_retain(&instance->scope);
    return SOLARIS_OK;
}
solaris_status_t solaris_module_release(solaris_module_instance_t *instance)
{
    if (instance == NULL) return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(instance->scope.owner)) return SOLARIS_ETHREAD;
    if (instance->leases == 0u) return SOLARIS_EINVAL;
    instance->leases--;
    solaris_scope_release(&instance->scope);
    return SOLARIS_OK;
}
static void release_plan(void *context)
{ solaris_status_t rc = solaris_module_release(context); assert(rc == SOLARIS_OK); (void)rc; }
solaris_status_t solaris_module_plan_acquire(solaris_module_instance_t *instance, uint64_t node_id, solaris_dial_plan_t *out)
{
    if (out == NULL) return SOLARIS_EINVAL;
    memset(out, 0, sizeof(*out));
    if (node_id == 0u) return SOLARIS_EINVAL;
    solaris_status_t rc = solaris_module_retain(instance);
    if (rc != SOLARIS_OK) return rc;
    *out = (solaris_dial_plan_t){.outbound = instance->outbound, .context = instance, .release = release_plan, .node_id = node_id};
    return SOLARIS_OK;
}
