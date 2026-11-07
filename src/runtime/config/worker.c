#include "runtime/config/worker.h"
#include "api/common/error.h"
#include <assert.h>
#include <string.h>

typedef struct config_node_slot {
    struct solaris_config_worker *worker;
    solaris_module_instance_t *instance;
    solaris_outbound_t guarded;
    const solaris_config_node_t *node;
    int retired;
} config_node_slot_t;
struct solaris_config_worker {
    solaris_scope_t scope;
    solaris_config_worker_options_t options;
    size_t count;
    int accepted;
    config_node_slot_t nodes[];
};
typedef struct config_plan {
    solaris_dial_plan_t underlying;
    void *lease_context;
    void (*lease_release)(void *context);
} config_plan_t;
static uint32_t guarded_capabilities(void *state)
{
    config_node_slot_t *slot = state;
    if (slot->retired || slot->worker->scope.cancelled || !slot->instance)
        return 0;
    solaris_outbound_t *outbound = solaris_module_outbound(slot->instance);
    uint32_t capabilities = 0;
    if (!outbound || solaris_outbound_capabilities(outbound, &capabilities) != SOLARIS_OK)
        return 0;
    if (!slot->node->udp_enabled)
        capabilities &=
            ~(SOLARIS_OUTBOUND_DATAGRAM | SOLARIS_OUTBOUND_DATAGRAM_MULTI | SOLARIS_OUTBOUND_DATAGRAM_DOMAIN);
    return capabilities;
}
static solaris_status_t guarded_stream(void *state, const solaris_address_t *target,
                                       const solaris_stream_callbacks_t *callbacks, void *context,
                                       solaris_stream_t **out)
{
    config_node_slot_t *slot = state;
    *out = NULL;
    if (slot->retired || slot->worker->scope.cancelled || !slot->instance)
        return SOLARIS_ECLOSED;
    solaris_outbound_t *outbound = solaris_module_outbound(slot->instance);
    return outbound ? solaris_outbound_open_stream(outbound, target, callbacks, context, out) : SOLARIS_ECLOSED;
}
static solaris_status_t guarded_datagram(void *state, uint32_t family, const solaris_datagram_callbacks_t *callbacks,
                                         void *context, solaris_datagram_t **out)
{
    config_node_slot_t *slot = state;
    *out = NULL;
    if (slot->retired || slot->worker->scope.cancelled || !slot->instance)
        return SOLARIS_ECLOSED;
    if (!slot->node->udp_enabled)
        return SOLARIS_ENOTSUP;
    solaris_outbound_t *outbound = solaris_module_outbound(slot->instance);
    return outbound ? solaris_outbound_open_datagram(outbound, family, callbacks, context, out) : SOLARIS_ECLOSED;
}
static void guarded_retire(void *state)
{
    ((config_node_slot_t *)state)->retired = 1;
}
static const solaris_outbound_ops_t guarded_operations = {guarded_capabilities, guarded_stream, guarded_datagram,
                                                          guarded_retire};
static void module_closed(void *context)
{
    config_node_slot_t *slot = context;
    slot->instance = NULL;
    /* The registry releases our parent scope after the module's destructor,
     * not here, so worker completion cannot race a trailing destructor. */
}
static void worker_cancelled(void *context)
{
    solaris_config_worker_t *worker = context;
    for (size_t i = 0; i < worker->count; ++i)
        if (worker->nodes[i].instance)
            (void)solaris_module_retire(worker->nodes[i].instance);
}
static void worker_destroyed(void *context)
{
    solaris_config_worker_t *worker = context;
    for (size_t i = 0; i < worker->count; ++i)
        assert(!worker->nodes[i].instance);
    if (worker->accepted && worker->options.on_close)
        worker->options.on_close(worker->options.context);
    solaris_scope_t *parent = worker->options.parent_scope;
    solaris_config_module_set_release(worker->options.set);
    solaris_memory_free(worker);
    if (parent)
        solaris_scope_release(parent);
}
solaris_status_t solaris_config_worker_create(const solaris_config_worker_options_t *options,
                                              solaris_config_worker_t **out, solaris_error_t *error)
{
    if (!out)
        return solaris_error_set(error, SOLARIS_EINVAL, 0, "worker output is required");
    *out = NULL;
    if (!options || !options->owner || !options->set || (!!options->lease_retain != !!options->lease_release))
        return solaris_error_set(error, SOLARIS_EINVAL, 0, "invalid configuration worker options");
    if (!solaris_executor_is_owner(options->owner) ||
        (options->services.owner && options->services.owner != options->owner))
        return solaris_error_set(error, SOLARIS_ETHREAD, 0, NULL);
    if (options->parent_scope) {
        if (options->parent_scope->owner != options->owner)
            return solaris_error_set(error, SOLARIS_ETHREAD, 0, NULL);
        if (options->parent_scope->cancelled || options->parent_scope->finishing)
            return solaris_error_set(error, SOLARIS_ECLOSED, 0, "worker parent scope is closing");
    }
    size_t count = solaris_config_module_set_count(options->set), image_count;
    const solaris_config_node_t *nodes =
        solaris_config_nodes(solaris_config_module_set_image(options->set), &image_count);
    if (count != image_count || (count && !nodes) ||
        count > (SIZE_MAX - sizeof(solaris_config_worker_t)) / sizeof(config_node_slot_t))
        return solaris_error_set(error, SOLARIS_EINVAL, 0, "invalid configuration worker nodes");
    solaris_config_worker_t *worker = solaris_memory_allocate(solaris_executor_budget(options->owner),
                                                              sizeof(*worker) + count * sizeof(*worker->nodes));
    if (!worker)
        return solaris_error_set(error, SOLARIS_ENOMEM, 0, NULL);
    memset(worker, 0, sizeof(*worker) + count * sizeof(*worker->nodes));
    worker->options = *options;
    solaris_status_t rc =
        solaris_scope_init(&worker->scope, options->owner, worker_cancelled, worker_destroyed, worker);
    if (rc != SOLARIS_OK) {
        solaris_memory_free(worker);
        return solaris_error_set(error, rc, 0, NULL);
    }
    solaris_config_module_set_retain(options->set);
    if (options->parent_scope)
        solaris_scope_retain(options->parent_scope);
    solaris_module_services_t services = options->services;
    services.owner = options->owner;
    services.parent_scope = &worker->scope;
    for (size_t i = 0; i < count; ++i) {
        config_node_slot_t *slot = &worker->nodes[i];
        slot->worker = worker;
        slot->node = &nodes[i];
        slot->guarded = (solaris_outbound_t){&guarded_operations, slot, options->owner};
        worker->count++;
        rc = solaris_module_create(solaris_config_module_set_at(options->set, i), &services, module_closed, slot,
                                   &slot->instance, error);
        if (rc != SOLARIS_OK) {
            solaris_scope_cancel(&worker->scope);
            return rc;
        }
    }
    worker->accepted = 1;
    *out = worker;
    return solaris_error_set(error, SOLARIS_OK, 0, NULL);
}
static void plan_released(void *context)
{
    config_plan_t *lease = context;
    solaris_status_t rc = solaris_dial_plan_release(&lease->underlying);
    assert(rc == SOLARIS_OK);
    (void)rc;
    if (lease->lease_release)
        lease->lease_release(lease->lease_context);
    solaris_memory_free(lease);
}
solaris_status_t solaris_config_worker_acquire(solaris_config_worker_t *worker, uint64_t id,
                                               uint64_t selection_revision, solaris_dial_plan_t *out,
                                               uint32_t *capabilities)
{
    if (out)
        memset(out, 0, sizeof(*out));
    if (capabilities)
        *capabilities = 0;
    if (!worker || !id || !out || !capabilities)
        return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(worker->scope.owner))
        return SOLARIS_ETHREAD;
    if (worker->scope.cancelled || !solaris_executor_accepting(worker->scope.owner))
        return SOLARIS_ECLOSED;
    config_node_slot_t *slot = NULL;
    for (size_t i = 0; i < worker->count; ++i)
        if (worker->nodes[i].node->id == id) {
            slot = &worker->nodes[i];
            break;
        }
    if (!slot)
        return SOLARIS_EINVAL;
    if (!slot->instance || slot->retired)
        return SOLARIS_ECLOSED;
    config_plan_t *lease = solaris_memory_allocate(solaris_executor_budget(worker->scope.owner), sizeof(*lease));
    if (!lease)
        return SOLARIS_ENOMEM;
    memset(lease, 0, sizeof(*lease));
    solaris_status_t rc = solaris_module_plan_acquire(slot->instance, id, &lease->underlying);
    if (rc != SOLARIS_OK) {
        solaris_memory_free(lease);
        return rc;
    }
    uint32_t effective = guarded_capabilities(slot);
    lease->lease_context = worker->options.lease_context;
    lease->lease_release = worker->options.lease_release;
    if (worker->options.lease_retain)
        worker->options.lease_retain(worker->options.lease_context);
    if (worker->scope.cancelled) {
        plan_released(lease);
        return SOLARIS_ECLOSED;
    }
    *out = lease->underlying;
    out->outbound = &slot->guarded;
    out->context = lease;
    out->release = plan_released;
    out->selection_revision = selection_revision;
    *capabilities = effective;
    return SOLARIS_OK;
}
solaris_status_t solaris_config_worker_retire(solaris_config_worker_t *worker)
{
    if (!worker)
        return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(worker->scope.owner))
        return SOLARIS_ETHREAD;
    solaris_scope_cancel(&worker->scope);
    return SOLARIS_OK;
}
