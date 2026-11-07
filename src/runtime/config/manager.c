#include "runtime/config/manager.h"
#include "solaris_builtin_modules.h"
#include "runtime/config/modules.h"
#include "runtime/config/worker.h"
#include "runtime/config/slots.h"
#include "runtime/config/publication.h"
#include "runtime/config/control.h"
#include "observe/log/service.h"
#include "runtime/engine/internal.h"
#include "contracts/inbound/proxy.h"
#include "api/common/error.h"
#include <assert.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <uv.h>

typedef struct bundle bundle_t;
typedef struct owner_state owner_state_t;
typedef struct binding binding_t;
typedef struct request request_t;
enum { BUNDLE_PREPARING, BUNDLE_READY, BUNDLE_ACTIVE, BUNDLE_RETIRING, BUNDLE_ABORTING };
struct solaris_prepared_config {
    atomic_size_t references, external;
    atomic_uint state;
    atomic_uint_fast64_t applied_revision;
    solaris_config_manager_t *manager;
    bundle_t *bundle; /* protected by manager mutex; external refs do not pin it */
    solaris_prepared_config_snapshot_t info;
    solaris_config_listener_info_t listeners[];
};
struct binding {
    bundle_t *bundle;
    const solaris_config_listener_t *definition;
    solaris_config_slot_key_t key;
    solaris_config_slot_t *slot;      /* owner-only */
    solaris_proxy_inbound_t *inbound; /* owner-only */
    uint32_t owner_index;
    uint64_t slot_id, auth_revision;
};
struct owner_state {
    bundle_t *bundle;
    solaris_executor_t *owner;
    uint32_t index;
    solaris_scope_t scope;
    int initialized;
    solaris_config_worker_t *worker;
    solaris_deferred_t action;
    atomic_int desired; /* 0 none, 1 detach listeners, 2 graceful retirement, 3 force */
    solaris_control_completion_t ready_node, done_node;
    solaris_status_t status;
    solaris_error_t error;
    int ready, drained; /* control-only acknowledgements */
};
struct bundle {
    bundle_t *next;
    solaris_config_manager_t *manager;
    atomic_size_t references; /* manager list plus publication/flow/route leases */
    solaris_config_module_set_t *set;
    owner_state_t *owners;
    binding_t *bindings;
    solaris_config_listener_info_t *infos;
    solaris_control_view_t *control;
    size_t owner_count, binding_count, group_count;
    uint64_t base_revision, revision, runtime_generation;
    int state, detached, retirement_sent;
    request_t *request;
    solaris_prepared_config_t *prepared;
};
struct request {
    solaris_config_manager_t *manager;
    solaris_runtime_operation_t *operation;
    solaris_config_t *image;
    solaris_config_bind_override_t *overrides;
    solaris_address_t *override_addresses;
    size_t override_count;
    void *trust;
    size_t trust_length;
    uv_work_t work;
    int work_active, cancelled, kind;
    uint64_t operation_id;
    solaris_status_t status;
    solaris_error_t error;
    solaris_config_module_set_t *set;
    solaris_snapshot_ref_t base;
    bundle_t *bundle;
    solaris_prepared_config_t *prepared, *output;
    solaris_config_prepare_callback_t prepare_callback;
    solaris_config_commit_callback_t commit_callback;
    void *user;
};
struct solaris_config_manager {
    atomic_size_t references;
    uv_mutex_t mutex, policy_mutex;
    solaris_engine_t *engine;
    solaris_budget_t *budget;
    solaris_publication_t *publication;
    solaris_config_slots_t *slots;
    solaris_replay_store_t *replay;
    solaris_tracker_t *tracker;
    solaris_traffic_counter_t *traffic;
    solaris_log_service_t *log;
    bundle_t *bundles;
    request_t *preparing;
    solaris_control_completion_t wake;
    int wake_pending, stopping, destroying, progressing;
    uint64_t generation, auth_serial, selection_serial;
};
static void manager_progress(solaris_config_manager_t *manager);
static void manager_schedule(solaris_config_manager_t *manager);
static void bundle_abort(bundle_t *bundle);
static void owner_action(void *context);
static void prepare_start_owners(request_t *request);
static void manager_retain(solaris_config_manager_t *manager)
{
    atomic_fetch_add_explicit(&manager->references, 1, memory_order_relaxed);
}
static void manager_release(solaris_config_manager_t *manager)
{
    if (atomic_fetch_sub_explicit(&manager->references, 1, memory_order_acq_rel) == 1) {
        assert(!manager->engine && !manager->bundles && !manager->preparing);
        uv_mutex_destroy(&manager->policy_mutex);
        uv_mutex_destroy(&manager->mutex);
        free(manager);
    }
}
static void prepared_drop(solaris_prepared_config_t *prepared)
{
    if (atomic_fetch_sub_explicit(&prepared->references, 1, memory_order_acq_rel) == 1) {
        solaris_config_manager_t *manager = prepared->manager;
        free(prepared);
        manager_release(manager);
    }
}
void solaris_prepared_config_retain(solaris_prepared_config_t *prepared)
{
    if (!prepared)
        return;
    atomic_fetch_add_explicit(&prepared->references, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&prepared->external, 1, memory_order_relaxed);
}
void solaris_prepared_config_release(solaris_prepared_config_t *prepared)
{
    if (!prepared)
        return;
    if (atomic_fetch_sub_explicit(&prepared->external, 1, memory_order_acq_rel) == 1)
        manager_schedule(prepared->manager);
    prepared_drop(prepared);
}
solaris_status_t solaris_prepared_config_get_snapshot(const solaris_prepared_config_t *prepared,
                                                      solaris_prepared_config_snapshot_t *out)
{
    if (!prepared || !out)
        return SOLARIS_EINVAL;
    *out = prepared->info;
    out->state = atomic_load_explicit(&prepared->state, memory_order_acquire);
    out->applied_revision = out->state == SOLARIS_PREPARED_COMMITTED
                                ? atomic_load_explicit(&prepared->applied_revision, memory_order_acquire)
                                : 0;
    return SOLARIS_OK;
}
solaris_status_t solaris_prepared_config_get_listener(const solaris_prepared_config_t *prepared, size_t index,
                                                      solaris_config_listener_info_t *out)
{
    if (!prepared || !out || index >= prepared->info.listener_count)
        return SOLARIS_EINVAL;
    *out = prepared->listeners[index];
    return SOLARIS_OK;
}
static solaris_status_t address_text(const solaris_address_t *address, char out[256])
{
    int family = address->family == SOLARIS_ADDRESS_IPV4   ? AF_INET
                 : address->family == SOLARIS_ADDRESS_IPV6 ? AF_INET6
                                                           : 0;
    return family && uv_inet_ntop(family, address->ip, out, 256) == 0 ? SOLARIS_OK : SOLARIS_EINVAL;
}
solaris_status_t solaris_config_get_listener(const solaris_config_t *config, size_t index,
                                             solaris_config_listener_info_t *out)
{
    size_t count;
    const solaris_config_listener_t *listeners = solaris_config_listeners(config, &count);
    if (!config || !out || index >= count)
        return SOLARIS_EINVAL;
    memset(out, 0, sizeof(*out));
    const solaris_config_listener_t *source = &listeners[index];
    out->id = source->id;
    (void)snprintf(out->name, sizeof(out->name), "%s", source->name);
    solaris_status_t rc = address_text(&source->listen, out->address);
    if (rc != SOLARIS_OK)
        return rc;
    memcpy(out->configured_address, out->address, sizeof(out->address));
    memcpy(out->requested_address, out->address, sizeof(out->address));
    out->port = out->configured_port = out->requested_port = source->listen.port;
    out->protocol = source->protocol;
    out->udp_enabled = source->udp;
    out->authentication_required = source->auth_count != 0;
    out->worker_id = UINT32_MAX;
    return SOLARIS_OK;
}
static void bundle_retain(void *context)
{
    atomic_fetch_add_explicit(&((bundle_t *)context)->references, 1, memory_order_relaxed);
}
static void bundle_release(void *context)
{
    bundle_t *bundle = context;
    solaris_config_manager_t *manager = bundle->manager;
    manager_retain(manager);
    size_t previous = atomic_fetch_sub_explicit(&bundle->references, 1, memory_order_acq_rel);
    assert(previous > 1); /* manager owns the final list reference */
    if (previous == 2)
        manager_schedule(manager);
    manager_release(manager);
}
struct solaris_config_admission {
    atomic_size_t references;
    bundle_t *bundle;
    solaris_control_view_t *control;
    binding_t *binding; /* optional logical/auth identity for TCP-to-UDP admission */
};
void solaris_config_admission_retain(solaris_config_admission_t *admission)
{
    if (admission)
        (void)atomic_fetch_add_explicit(&admission->references, 1, memory_order_relaxed);
}
void solaris_config_admission_release(solaris_config_admission_t *admission)
{
    if (!admission || atomic_fetch_sub_explicit(&admission->references, 1, memory_order_acq_rel) != 1)
        return;
    solaris_control_view_release(admission->control);
    bundle_release(admission->bundle);
    solaris_memory_free(admission);
}

#if SOLARIS_HAS_PROXY_INBOUND
static void admission_retain(void *context)
{
    solaris_config_admission_retain(context);
}
static void admission_release(void *context)
{
    solaris_config_admission_release(context);
}
#endif
static solaris_status_t capture_current(solaris_config_manager_t *manager, uint64_t expected,
                                        solaris_config_admission_t **out)
{
    *out = NULL;
    solaris_snapshot_ref_t active = {0};
    solaris_control_view_t *control = NULL;
    uv_mutex_lock(&manager->policy_mutex);
    solaris_status_t rc = solaris_publication_acquire(manager->publication, &active);
    if (rc == SOLARIS_OK) {
        bundle_t *bundle = active.context;
        if (!bundle)
            rc = SOLARIS_ECLOSED;
        else if (expected && expected != active.revision)
            rc = SOLARIS_EAGAIN;
        else {
            control = bundle->control;
            solaris_control_view_retain(control);
        }
    }
    uv_mutex_unlock(&manager->policy_mutex);
    if (rc != SOLARIS_OK) {
        solaris_snapshot_ref_release(&active);
        return rc;
    }
    solaris_config_admission_t *admission = solaris_memory_allocate(manager->budget, sizeof(*admission));
    if (!admission) {
        solaris_control_view_release(control);
        solaris_snapshot_ref_release(&active);
        return SOLARIS_ENOMEM;
    }
    memset(admission, 0, sizeof(*admission));
    atomic_init(&admission->references, 1);
    admission->bundle = active.context;
    admission->control = control;
    *out = admission;
    return SOLARIS_OK;
}
solaris_status_t solaris_config_admission_acquire(solaris_engine_t *engine, uint64_t expected,
                                                  solaris_config_admission_t **out)
{
    if (!out)
        return SOLARIS_EINVAL;
    *out = NULL;
    if (!engine)
        return SOLARIS_EINVAL;
    solaris_config_manager_t *manager = solaris_config_manager_find(engine);
    return manager ? capture_current(manager, expected, out) : SOLARIS_ECLOSED;
}
solaris_status_t solaris_config_admission_get_state(const solaris_config_admission_t *admission,
                                                    solaris_control_info_t *out)
{
    if (!admission || !out)
        return SOLARIS_EINVAL;
    bundle_t *bundle = admission->bundle;
    solaris_config_snapshot_t image;
    (void)solaris_config_get_snapshot(solaris_config_module_set_image(bundle->set), &image);
    *out = (solaris_control_info_t){.config_revision = bundle->revision,
                                    .selection_revision = admission->control->revision,
                                    .runtime_generation = bundle->runtime_generation,
                                    .mode = admission->control->mode,
                                    .node_count = image.node_count,
                                    .group_count = image.group_count};
    return SOLARIS_OK;
}
solaris_status_t solaris_config_admission_acquire_plan(solaris_config_admission_t *admission, solaris_executor_t *owner,
                                                       uint64_t target, solaris_dial_plan_t *plan,
                                                       uint32_t *capabilities)
{
    if (plan)
        memset(plan, 0, sizeof(*plan));
    if (capabilities)
        *capabilities = 0;
    if (!admission || !owner || !plan || !capabilities)
        return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(owner))
        return SOLARIS_ETHREAD;
    bundle_t *bundle = admission->bundle;
    size_t count;
    const solaris_config_group_t *groups = solaris_config_groups(solaris_config_module_set_image(bundle->set), &count);
    for (size_t i = 0; i < count; ++i)
        if (groups[i].id == target) {
            target = admission->control->groups[i].selected;
            break;
        }
    uint32_t index = solaris_executor_id(owner);
    if (index >= bundle->owner_count || bundle->owners[index].owner != owner || !bundle->owners[index].worker)
        return SOLARIS_ECLOSED;
    return solaris_config_worker_acquire(bundle->owners[index].worker, target, admission->control->revision, plan,
                                         capabilities);
}
#if SOLARIS_HAS_PROXY_INBOUND
static void binding_retain(void *context)
{
    bundle_retain(((binding_t *)context)->bundle);
}
static void binding_release(void *context)
{
    bundle_release(((binding_t *)context)->bundle);
}
#endif
static int auth_equal(const solaris_config_listener_t *a, const solaris_config_listener_t *b)
{
    if (a->auth_count != b->auth_count)
        return 0;
    for (size_t i = 0; i < a->auth_count; ++i) {
        size_t j = 0;
        for (; j < b->auth_count; ++j)
            if (!strcmp(a->auth[i].username, b->auth[j].username) && !strcmp(a->auth[i].password, b->auth[j].password))
                break;
        if (j == b->auth_count)
            return 0;
    }
    return 1;
}
#if SOLARIS_HAS_PROXY_INBOUND
static solaris_status_t authenticate(void *context, const uint8_t *username, size_t user_length,
                                     const uint8_t *password, size_t password_length)
{
    binding_t *binding = context;
    for (size_t i = 0; i < binding->definition->auth_count; ++i) {
        const solaris_config_auth_t *auth = &binding->definition->auth[i];
        if (strlen(auth->username) != user_length || strlen(auth->password) != password_length)
            continue;
        unsigned difference = 0;
        for (size_t j = 0; j < user_length; ++j)
            difference |= (unsigned char)auth->username[j] ^ username[j];
        for (size_t j = 0; j < password_length; ++j)
            difference |= (unsigned char)auth->password[j] ^ password[j];
        if (!difference)
            return SOLARIS_OK;
    }
    return SOLARIS_EACCESS;
}
static solaris_status_t acquire_plan(void *context, solaris_executor_t *owner, uint64_t target,
                                     solaris_dial_plan_t *plan, uint32_t *capabilities)
{
    return solaris_config_admission_acquire_plan(context, owner, target, plan, capabilities);
}
static solaris_status_t route(void *context, solaris_executor_t *owner, const solaris_inbound_request_t *request,
                              solaris_route_options_t *out)
{
    solaris_config_admission_t *captured = context, *admission = captured;
    if (request->network == SOLARIS_INBOUND_UDP) {
        solaris_status_t rc = capture_current(captured->bundle->manager, 0, &admission);
        if (rc != SOLARIS_OK)
            return rc;
        binding_t *next = NULL;
        bundle_t *current = admission->bundle;
        for (size_t i = 0; i < current->binding_count; ++i)
            if (current->bindings[i].definition->id == captured->binding->definition->id) {
                next = &current->bindings[i];
                break;
            }
        if (!next || !next->definition->udp || next->auth_revision != captured->binding->auth_revision) {
            solaris_config_admission_release(admission);
            return SOLARIS_EACCESS;
        }
        admission->binding = next;
    } else
        solaris_config_admission_retain(admission);
    bundle_t *bundle = admission->bundle;
    solaris_config_t *image = solaris_config_module_set_image(bundle->set);
    memset(out, 0, sizeof(*out));
    out->owner = owner;
    out->context = admission;
    out->retain = admission_retain;
    out->release = admission_release;
    out->acquire = acquire_plan;
    out->mode = admission->control->mode;
    out->rules = solaris_config_rules(image, &out->rule_count);
    out->direct_target = solaris_config_direct_target(image);
    out->global_target = solaris_config_global_target(image);
    out->timeout_ms = 10000;
    out->metadata.config_revision = bundle->revision;
    out->metadata.selection_revision = admission->control->revision;
    return SOLARIS_OK;
}
#endif
static solaris_status_t slot_accept(void *context, solaris_config_slot_t *slot, solaris_executor_t *owner,
                                    const solaris_address_t *peer, const solaris_address_t *local,
                                    solaris_stream_t *stream, solaris_stream_callbacks_t *callbacks,
                                    void **stream_context)
{
    solaris_config_admission_t *admission;
    solaris_status_t rc = capture_current(context, 0, &admission);
    if (rc != SOLARIS_OK)
        return rc;
    bundle_t *bundle = admission->bundle;
    uint64_t id = solaris_config_slot_id(slot);
    binding_t *binding = NULL;
    for (size_t i = 0; i < bundle->binding_count; ++i)
        if (bundle->bindings[i].slot_id == id && bundle->owners[bundle->bindings[i].owner_index].owner == owner) {
            binding = &bundle->bindings[i];
            break;
        }
#if SOLARIS_HAS_PROXY_INBOUND
    admission->binding = binding;
    solaris_proxy_context_t capture = {.context = admission,
                                       .retain = admission_retain,
                                       .release = admission_release,
                                       .config_revision = bundle->revision,
                                       .selection_revision = admission->control->revision};
    rc = binding && binding->inbound ? solaris_proxy_inbound_accept_with_context(binding->inbound, peer, local, stream,
                                                                                 callbacks, stream_context, &capture)
                                     : SOLARIS_ECLOSED;
#else
    (void)binding;
    (void)peer;
    (void)local;
    (void)stream;
    (void)callbacks;
    (void)stream_context;
    rc = SOLARIS_ENOTSUP;
#endif
    solaris_config_admission_release(admission);
    return rc;
}
static void manager_wake(void *context)
{
    solaris_config_manager_t *manager = context;
    uv_mutex_lock(&manager->mutex);
    manager->wake_pending = 0;
    uv_mutex_unlock(&manager->mutex);
    manager_progress(manager);
}
static void manager_schedule(solaris_config_manager_t *manager)
{
    uv_mutex_lock(&manager->mutex);
    solaris_engine_t *engine = manager->engine;
    int post = engine && !manager->wake_pending;
    if (post)
        manager->wake_pending = 1;
    if (post) {
        /* Serialize the borrowed engine pointer with attachment destruction.
         * Publication actions never acquire this mutex or post control work. */
        solaris_status_t rc = solaris_runtime_control_post(engine, &manager->wake);
        if (rc == SOLARIS_ECLOSED)
            manager->wake_pending = 0;
        else {
            assert(rc == SOLARIS_OK);
            (void)rc;
        }
    }
    uv_mutex_unlock(&manager->mutex);
}
#if SOLARIS_HAS_PROXY_INBOUND
static void inbound_closed(void *context, const solaris_proxy_inbound_snapshot_t *snapshot, solaris_status_t status)
{
    (void)snapshot;
    (void)status;
    ((binding_t *)context)->inbound = NULL;
}
#endif
static void worker_closed(void *context)
{
    ((owner_state_t *)context)->worker = NULL;
}
static void owner_detach(owner_state_t *owner, int force)
{
    bundle_t *bundle = owner->bundle;
    for (size_t i = 0; i < bundle->binding_count; ++i) {
        binding_t *binding = &bundle->bindings[i];
        if (binding->owner_index != owner->index)
            continue;
        if (binding->slot) {
            solaris_config_slot_t *slot = binding->slot;
            binding->slot = NULL;
            solaris_config_slot_release(slot, owner->scope.cancelled ? NULL : &owner->scope);
        }
#if SOLARIS_HAS_PROXY_INBOUND
        if (binding->inbound) {
            if (force)
                (void)solaris_proxy_inbound_close(binding->inbound);
            else
                (void)solaris_proxy_inbound_retire(binding->inbound);
        }
#else
        (void)force;
#endif
    }
}
static void owner_cancelled(void *context)
{
    owner_state_t *owner = context;
    atomic_store_explicit(&owner->desired, 3, memory_order_release);
    owner_detach(owner, 1);
    if (owner->worker)
        (void)solaris_config_worker_retire(owner->worker);
}
static void owner_done_control(void *context)
{
    owner_state_t *owner = context;
    owner->drained = 1;
    manager_progress(owner->bundle->manager);
}
static void owner_done(void *context)
{
    owner_state_t *owner = context;
    solaris_status_t rc = solaris_runtime_control_post(owner->bundle->manager->engine, &owner->done_node);
    assert(rc == SOLARIS_OK);
    (void)rc;
}
static void owner_ready_control(void *context)
{
    owner_state_t *owner = context;
    owner->ready = 1;
    manager_progress(owner->bundle->manager);
}
static void owner_prepare(void *context, solaris_status_t status)
{
    owner_state_t *owner = context;
    bundle_t *bundle = owner->bundle;
    if (status == SOLARIS_OK)
        status = solaris_scope_init(&owner->scope, owner->owner, owner_cancelled, owner_done, owner);
    if (status == SOLARIS_OK) {
        owner->initialized = 1;
        solaris_config_worker_options_t options = {.owner = owner->owner,
                                                   .set = bundle->set,
                                                   .parent_scope = &owner->scope,
                                                   .lease_context = bundle,
                                                   .lease_retain = bundle_retain,
                                                   .lease_release = bundle_release,
                                                   .on_close = worker_closed,
                                                   .context = owner};
        options.services.replay = bundle->manager->replay;
        options.services.dialer.traffic = bundle->manager->traffic;
        options.services.diagnostic = solaris_log_service_diagnostic(bundle->manager->log);
        status = solaris_config_worker_create(&options, &owner->worker, &owner->error);
    }
    for (size_t i = 0; status == SOLARIS_OK && i < bundle->binding_count; ++i) {
        binding_t *binding = &bundle->bindings[i];
        if (binding->owner_index != owner->index)
            continue;
        solaris_address_t bound;
        status = solaris_config_slot_acquire(bundle->manager->slots, owner->owner, &owner->scope, &binding->key,
                                             &binding->slot, &bound);
        if (status != SOLARIS_OK) {
            solaris_error_set(&owner->error, status, 0,
                              status == SOLARIS_ENOTSUP ? "overlapping listener binding requires stop/start"
                                                        : "listener binding failed");
            break;
        }
        binding->slot_id = solaris_config_slot_id(binding->slot);
        bundle->infos[i].port = bound.port;
        (void)address_text(&bound, bundle->infos[i].address);
#if SOLARIS_HAS_PROXY_INBOUND
        solaris_proxy_inbound_options_t inbound;
        solaris_proxy_inbound_options_init(&inbound);
        inbound.owner = owner->owner;
        inbound.parent_scope = &owner->scope;
        inbound.protocol = binding->definition->protocol;
        inbound.listen = bound;
        inbound.inbound_id = binding->definition->id;
        inbound.udp = binding->definition->udp;
        inbound.context = binding;
        inbound.retain = binding_retain;
        inbound.release = binding_release;
        inbound.authenticate = binding->definition->auth_count ? authenticate : NULL;
        inbound.route = route;
        inbound.tracker = bundle->manager->tracker;
        inbound.on_close = inbound_closed;
        status = solaris_proxy_inbound_detached_create(&inbound, &binding->inbound);
        if (status != SOLARIS_OK)
            solaris_error_set(&owner->error, status, 0, "detached inbound preparation failed");
#else
        status = SOLARIS_ENOTSUP;
#endif
    }
    owner->status = status;
    if (status != SOLARIS_OK && owner->initialized) {
        owner_detach(owner, 1);
        if (owner->worker)
            (void)solaris_config_worker_retire(owner->worker);
        solaris_scope_cancel(&owner->scope);
    }
    solaris_status_t rc = solaris_runtime_control_post(bundle->manager->engine, &owner->ready_node);
    assert(rc == SOLARIS_OK);
    (void)rc;
    if (!owner->initialized) {
        rc = solaris_runtime_control_post(bundle->manager->engine, &owner->done_node);
        assert(rc == SOLARIS_OK);
        (void)rc;
    }
}
static void owner_action(void *context)
{
    owner_state_t *owner = context;
    int action = atomic_load_explicit(&owner->desired, memory_order_acquire);
    if (owner->initialized && !owner->scope.finishing) {
        owner_detach(owner, action >= 3);
        if (action >= 2) {
            if (owner->worker)
                (void)solaris_config_worker_retire(owner->worker);
            solaris_scope_cancel(&owner->scope);
        }
    }
    bundle_release(owner->bundle);
}
static void send_action(bundle_t *bundle, int action)
{
    for (size_t i = 0; i < bundle->owner_count; ++i) {
        owner_state_t *owner = &bundle->owners[i];
        if (owner->drained || !owner->ready)
            continue;
        int previous = atomic_load_explicit(&owner->desired, memory_order_relaxed);
        while (action > previous &&
               !atomic_compare_exchange_weak_explicit(&owner->desired, &previous, action, memory_order_acq_rel,
                                                      memory_order_acquire)) {
        }
        if (action <= previous)
            continue;
        bundle_retain(bundle);
        solaris_status_t rc = solaris_executor_defer(owner->owner, &owner->action);
        if (rc != SOLARIS_OK)
            bundle_release(bundle);
        assert(rc == SOLARIS_OK || rc == SOLARIS_EBUSY);
        (void)rc;
    }
}
static void bundle_abort(bundle_t *bundle)
{
    bundle->state = BUNDLE_ABORTING;
    bundle->detached = bundle->retirement_sent = 1;
    if (bundle->prepared)
        atomic_store_explicit(&bundle->prepared->state, SOLARIS_PREPARED_CLOSED, memory_order_release);
    send_action(bundle, 3);
}
static void bundle_free(bundle_t *bundle)
{
    solaris_config_manager_t *manager = bundle->manager;
    assert(atomic_load_explicit(&bundle->references, memory_order_acquire) == 1);
    bundle_t **cursor = &manager->bundles;
    while (*cursor != bundle) {
        assert(*cursor);
        cursor = &(*cursor)->next;
    }
    *cursor = bundle->next;
    if (bundle->prepared) {
        bundle->prepared->bundle = NULL;
        atomic_store_explicit(&bundle->prepared->state, SOLARIS_PREPARED_CLOSED, memory_order_release);
        prepared_drop(bundle->prepared);
    }
    solaris_config_module_set_release(bundle->set);
    solaris_control_view_release(bundle->control);
    solaris_memory_free(bundle->infos);
    solaris_memory_free(bundle->bindings);
    solaris_memory_free(bundle->owners);
    solaris_memory_free(bundle);
}
static void finish_request(request_t *request, solaris_status_t status)
{
    solaris_config_manager_t *manager = request->manager;
    if (manager->preparing == request)
        manager->preparing = NULL;
    request->status = status;
    solaris_runtime_operation_t *operation = request->operation;
    request->operation = NULL;
    solaris_runtime_operation_complete(operation, status, 0);
}
static solaris_status_t prepare_publish(void *context, uint64_t *revision)
{
    request_t *request = context;
    bundle_t *bundle = request->bundle;
    *revision = 0;
    solaris_config_manager_t *manager = request->manager;
    if (manager->stopping || manager->destroying)
        return SOLARIS_ECANCELLED;
    atomic_store_explicit(&bundle->prepared->state, SOLARIS_PREPARED_READY, memory_order_release);
    solaris_prepared_config_retain(bundle->prepared);
    request->output = bundle->prepared;
    bundle->state = BUNDLE_READY;
    bundle->request = NULL;
    manager->preparing = NULL;
    return SOLARIS_OK;
}
static void manager_progress(solaris_config_manager_t *manager)
{
    if (manager->progressing)
        return;
    manager->progressing = 1;
    for (bundle_t *bundle = manager->bundles, *next; bundle; bundle = next) {
        next = bundle->next;
        int ready = 1, drained = 1;
        for (size_t i = 0; i < bundle->owner_count; ++i) {
            ready &= bundle->owners[i].ready;
            drained &= bundle->owners[i].drained;
        }
        if (bundle->state == BUNDLE_PREPARING && ready) {
            request_t *request = bundle->request;
            solaris_status_t status = request->cancelled || manager->stopping ? SOLARIS_ECANCELLED : SOLARIS_OK;
            for (size_t i = 0; i < bundle->owner_count; ++i)
                if (status == SOLARIS_OK && bundle->owners[i].status != SOLARIS_OK) {
                    status = bundle->owners[i].status;
                    request->error = bundle->owners[i].error;
                }
            for (size_t i = 0; status == SOLARIS_OK && i < bundle->binding_count; ++i)
                for (size_t j = 0; j < i; ++j)
                    if (bundle->bindings[i].slot_id == bundle->bindings[j].slot_id) {
                        status = SOLARIS_EINVAL;
                        solaris_error_set(&request->error, status, 0,
                                          "multiple logical listeners resolve to one physical socket");
                        break;
                    }
            if (status == SOLARIS_OK) {
                memcpy(bundle->prepared->listeners, bundle->infos, bundle->binding_count * sizeof(*bundle->infos));
                status = solaris_runtime_operation_finish(request->operation, prepare_publish, request);
                if (status == SOLARIS_OK) {
                    request->operation = NULL;
                    request->bundle = NULL;
                }
            }
            if (status != SOLARIS_OK) {
                request->status = status;
                bundle_abort(bundle);
            }
        }
        if (bundle->state == BUNDLE_READY && !atomic_load_explicit(&bundle->prepared->external, memory_order_acquire))
            bundle_abort(bundle);
        if (bundle->state == BUNDLE_RETIRING && !bundle->detached) {
            bundle->detached = 1;
            send_action(bundle, 1);
        }
        if (bundle->state == BUNDLE_ABORTING)
            send_action(bundle, 3);
        if (bundle->state == BUNDLE_RETIRING && !bundle->retirement_sent &&
            atomic_load_explicit(&bundle->references, memory_order_acquire) == 1) {
            bundle->retirement_sent = 1;
            send_action(bundle, 2);
        }
        if ((bundle->state == BUNDLE_ABORTING || bundle->state == BUNDLE_RETIRING) && drained &&
            atomic_load_explicit(&bundle->references, memory_order_acquire) == 1 &&
            (!manager->stopping || solaris_config_slots_drained(manager->slots))) {
            request_t *request = bundle->request;
            if (request) {
                request->bundle = NULL;
                bundle->request = NULL;
            }
            bundle_free(bundle);
            if (request)
                finish_request(request, request->status == SOLARIS_OK ? SOLARIS_ECANCELLED : request->status);
        }
    }
    manager->progressing = 0;
}
static void prepare_work(uv_work_t *work)
{
    request_t *request = work->data;
    request->status = solaris_config_module_set_create(request->manager->budget, request->image, request->trust,
                                                       request->trust_length, &request->set, &request->error);
}
static void prepare_after_work(uv_work_t *work, int status)
{
    request_t *request = work->data;
    request->work_active = 0;
    if (status == UV_ECANCELED || request->cancelled || request->manager->stopping ||
        solaris_runtime_operation_cancelled(request->operation))
        request->status = SOLARIS_ECANCELLED;
    if (request->status != SOLARIS_OK) {
        solaris_config_module_set_release(request->set);
        request->set = NULL;
        solaris_snapshot_ref_release(&request->base);
        finish_request(request, request->status);
        return;
    }
    prepare_start_owners(request);
}
static void prepare_start_owners(request_t *request)
{
    solaris_config_manager_t *manager = request->manager;
    solaris_budget_t *budget = manager->budget;
    size_t listener_count, group_count, node_count;
    const solaris_config_listener_t *listeners = solaris_config_listeners(request->image, &listener_count);
    (void)solaris_config_groups(request->image, &group_count);
    const solaris_config_node_t *nodes = solaris_config_nodes(request->image, &node_count);
    uint32_t owner_count = solaris_runtime_worker_count(manager->engine);
    solaris_status_t rc = SOLARIS_OK;
    if (!manager->replay)
        for (size_t i = 0; i < node_count; ++i)
            if (!strcmp(nodes[i].type, "shadowsocks")) {
                rc = solaris_replay_create(budget, 16384, 0, NULL, NULL, &manager->replay);
                break;
            }
    bundle_t *bundle = rc == SOLARIS_OK ? solaris_memory_allocate(budget, sizeof(*bundle)) : NULL;
    if (!bundle) {
        solaris_snapshot_ref_release(&request->base);
        finish_request(request, rc == SOLARIS_OK ? SOLARIS_ENOMEM : rc);
        return;
    }
    memset(bundle, 0, sizeof(*bundle));
    bundle->manager = manager;
    atomic_init(&bundle->references, 1);
    bundle->owner_count = owner_count;
    bundle->binding_count = listener_count;
    bundle->group_count = group_count;
    bundle->owners = solaris_memory_allocate(budget, owner_count * sizeof(*bundle->owners));
    bundle->bindings =
        solaris_memory_allocate(budget, (listener_count ? listener_count : 1) * sizeof(*bundle->bindings));
    bundle->infos = solaris_memory_allocate(budget, (listener_count ? listener_count : 1) * sizeof(*bundle->infos));
    rc = solaris_control_view_create(budget, request->image, &bundle->control);
    if (!owner_count || !bundle->owners || !bundle->bindings || !bundle->infos || !bundle->control ||
        listener_count > (SIZE_MAX - sizeof(solaris_prepared_config_t)) / sizeof(solaris_config_listener_info_t)) {
        rc = SOLARIS_ENOMEM;
        goto failed;
    }
    memset(bundle->owners, 0, owner_count * sizeof(*bundle->owners));
    memset(bundle->bindings, 0, listener_count * sizeof(*bundle->bindings));
    memset(bundle->infos, 0, listener_count * sizeof(*bundle->infos));
    /* The base was pinned before asynchronous module preparation. Never
     * silently rebase a candidate over a commit that happened meanwhile. */
    solaris_snapshot_ref_t active = request->base;
    bundle_t *previous = active.context;
    bundle->base_revision = active.revision;
    /* Keep the final revision available for a stop tombstone, even at the
     * counter boundary; an active MAX revision could otherwise never drain. */
    if (active.revision >= UINT64_MAX - 1) {
        rc = SOLARIS_EOVERFLOW;
        goto failed;
    }
    bundle->revision = active.revision + 1;
    bundle->runtime_generation = manager->generation;
    for (size_t i = 0; i < owner_count; ++i) {
        owner_state_t *owner = &bundle->owners[i];
        owner->bundle = bundle;
        owner->index = (uint32_t)i;
        owner->owner = solaris_runtime_executor(manager->engine, i);
        if (!owner->owner) {
            rc = SOLARIS_ECANCELLED;
            break;
        }
        atomic_init(&owner->desired, 0);
        owner->action = (solaris_deferred_t){.run = owner_action, .context = owner};
        owner->ready_node = (solaris_control_completion_t){.run = owner_ready_control, .context = owner};
        owner->done_node = (solaris_control_completion_t){.run = owner_done_control, .context = owner};
    }
    for (size_t i = 0; rc == SOLARIS_OK && i < listener_count; ++i) {
        binding_t *binding = &bundle->bindings[i];
        binding->bundle = bundle;
        binding->definition = &listeners[i];
        binding->key.address = listeners[i].listen;
        (void)solaris_config_get_listener(request->image, i, &bundle->infos[i]);
        for (size_t j = 0; j < request->override_count; ++j)
            if (request->overrides[j].listener_id == listeners[i].id) {
                binding->key.address = request->override_addresses[j];
                binding->key.ephemeral_id = binding->key.address.port == 0 ? listeners[i].id : 0;
                bundle->infos[i].binding_overridden = 1;
                (void)address_text(&binding->key.address, bundle->infos[i].requested_address);
                bundle->infos[i].requested_port = binding->key.address.port;
                break;
            }
        for (size_t j = 0; j < i; ++j)
            if (binding->key.address.port &&
                solaris_address_equal(&binding->key.address, &bundle->bindings[j].key.address)) {
                rc = SOLARIS_EINVAL;
                solaris_error_set(&request->error, rc, 0, "duplicate effective listener endpoint");
                break;
            }
        if (rc != SOLARIS_OK)
            break;
        solaris_executor_t *preferred = bundle->owners[listeners[i].id % owner_count].owner;
        solaris_executor_t *owner = solaris_config_slot_owner(manager->slots, &binding->key, preferred);
        binding->owner_index = solaris_executor_id(owner);
        bundle->infos[i].worker_id = binding->owner_index;
        if (binding->owner_index >= owner_count || bundle->owners[binding->owner_index].owner != owner) {
            rc = SOLARIS_EINVAL;
            break;
        }
        if (previous)
            for (size_t j = 0; j < previous->binding_count; ++j) {
                binding_t *old = &previous->bindings[j];
                if (old->definition->id == listeners[i].id && auth_equal(old->definition, &listeners[i])) {
                    binding->auth_revision = old->auth_revision;
                    break;
                }
            }
        if (!binding->auth_revision) {
            if (manager->auth_serial == UINT64_MAX) {
                rc = SOLARIS_EOVERFLOW;
                break;
            }
            binding->auth_revision = ++manager->auth_serial;
        }
    }
    if (rc != SOLARIS_OK)
        goto failed;
    /* Public metadata deliberately uses library-default allocation: it can
     * outlive engine destruction and therefore cannot retain host allocator
     * callbacks whose lifetime ends with that engine. */
    bundle->prepared = calloc(1, sizeof(*bundle->prepared) + listener_count * sizeof(*bundle->infos));
    if (!bundle->prepared) {
        rc = SOLARIS_ENOMEM;
        goto failed;
    }
    atomic_init(&bundle->prepared->references, 1);
    atomic_init(&bundle->prepared->external, 0);
    atomic_init(&bundle->prepared->state, SOLARIS_PREPARED_COMMITTING);
    atomic_init(&bundle->prepared->applied_revision, 0);
    manager_retain(manager);
    bundle->prepared->manager = manager;
    bundle->prepared->bundle = bundle;
    bundle->prepared->info = (solaris_prepared_config_snapshot_t){.base_revision = bundle->base_revision,
                                                                  .runtime_generation = bundle->runtime_generation,
                                                                  .listener_count = listener_count};
    bundle->set = request->set;
    request->set = NULL;
    bundle->state = BUNDLE_PREPARING;
    bundle->request = request;
    request->bundle = bundle;
    bundle->next = manager->bundles;
    manager->bundles = bundle;
    /* Base/auth metadata is now copied. Do not keep the old runtime lease
     * through rollback callbacks: stop must be able to drain that old bundle. */
    solaris_snapshot_ref_release(&request->base);
    for (size_t i = 0; i < owner_count; ++i) {
        owner_state_t *owner = &bundle->owners[i];
        rc = solaris_executor_post(owner->owner, owner_prepare, owner);
        if (rc != SOLARIS_OK) {
            owner->ready = owner->drained = 1;
            owner->status = rc;
        }
    }
    manager_progress(manager);
    return;
failed:
    solaris_control_view_release(bundle->control);
    solaris_memory_free(bundle->infos);
    solaris_memory_free(bundle->bindings);
    solaris_memory_free(bundle->owners);
    solaris_memory_free(bundle);
    solaris_snapshot_ref_release(&request->base);
    finish_request(request, rc);
}
static solaris_status_t prepare_start(void *context, solaris_engine_t *engine, solaris_runtime_operation_t *operation)
{
    request_t *request = context;
    request->operation_id = solaris_runtime_operation_id(operation);
    solaris_config_manager_t *manager = request->manager;
    solaris_engine_snapshot_t runtime;
    (void)solaris_engine_get_snapshot(engine, &runtime, NULL);
    if (manager->destroying || (manager->stopping && runtime.generation == manager->generation))
        return SOLARIS_ECLOSED;
    if (manager->preparing)
        return SOLARIS_EBUSY;
    solaris_status_t acquired = solaris_publication_acquire(manager->publication, &request->base);
    if (acquired != SOLARIS_OK)
        return acquired;
    manager->stopping = 0;
    manager->generation = runtime.generation;
    manager->preparing = request;
    request->operation = operation;
    request->work.data = request;
    int rc = uv_queue_work(solaris_runtime_control_loop(engine), &request->work, prepare_work, prepare_after_work);
    if (rc != 0) {
        manager->preparing = NULL;
        request->operation = NULL;
        solaris_snapshot_ref_release(&request->base);
        return rc == UV_ENOMEM ? SOLARIS_ENOMEM : SOLARIS_EIO;
    }
    request->work_active = 1;
    return SOLARIS_OK;
}
typedef struct commit_action {
    request_t *request;
    solaris_snapshot_ref_t previous;
} commit_action_t;
static solaris_status_t commit_publish(void *context, uint64_t *revision)
{
    commit_action_t *action = context;
    request_t *request = action->request;
    solaris_config_manager_t *manager = request->manager;
    bundle_t *bundle = request->bundle;
    if (manager->stopping || manager->destroying)
        return SOLARIS_ECANCELLED;
    if (manager->selection_serial == UINT64_MAX)
        return SOLARIS_EOVERFLOW;
    bundle_t *old = action->previous.context;
    uv_mutex_lock(&manager->policy_mutex);
    solaris_control_view_migrate(bundle->control, solaris_config_module_set_image(bundle->set),
                                 old ? old->control : NULL, old ? solaris_config_module_set_image(old->set) : NULL,
                                 manager->selection_serial + 1);
    solaris_snapshot_ref_t next = {
        .context = bundle, .retain = bundle_retain, .release = bundle_release, .revision = bundle->revision};
    uint64_t actual;
    solaris_status_t rc = solaris_publication_publish(manager->publication, bundle->base_revision, &next, &actual);
    if (rc == SOLARIS_OK) {
        manager->selection_serial++;
        bundle->state = BUNDLE_ACTIVE;
        bundle->request = NULL;
        if (old)
            old->state = BUNDLE_RETIRING;
        atomic_store_explicit(&request->prepared->applied_revision, actual, memory_order_release);
        atomic_store_explicit(&request->prepared->state, SOLARIS_PREPARED_COMMITTED, memory_order_release);
        request->prepared->bundle = NULL;
        bundle->prepared = NULL;
        *revision = actual;
    }
    uv_mutex_unlock(&manager->policy_mutex);
    return rc;
}
static solaris_status_t commit_start(void *context, solaris_engine_t *engine, solaris_runtime_operation_t *operation)
{
    request_t *request = context;
    request->operation_id = solaris_runtime_operation_id(operation);
    solaris_config_manager_t *manager = request->manager;
    (void)engine;
    solaris_prepared_config_t *prepared = request->prepared;
    if (prepared->manager != manager ||
        atomic_load_explicit(&prepared->state, memory_order_acquire) != SOLARIS_PREPARED_READY || !prepared->bundle ||
        manager->stopping || prepared->info.runtime_generation != manager->generation)
        return SOLARIS_ECLOSED;
    atomic_store_explicit(&prepared->state, SOLARIS_PREPARED_COMMITTING, memory_order_release);
    bundle_t *bundle = prepared->bundle;
    request->bundle = bundle;
    request->operation = operation;
    bundle->request = request;
    commit_action_t action = {.request = request};
    solaris_status_t rc = solaris_publication_acquire(manager->publication, &action.previous);
    if (rc == SOLARIS_OK)
        rc = solaris_runtime_operation_finish(operation, commit_publish, &action);
    /* Old bundle's extra lease prevents publication.release from posting to
     * the engine while the cancellation fence holds its mutex. */
    solaris_snapshot_ref_release(&action.previous);
    if (rc == SOLARIS_OK) {
        request->operation = NULL;
        request->bundle = NULL;
        prepared_drop(prepared); /* release candidate's internal metadata ref */
        manager_schedule(manager);
    } else {
        request->status = rc;
        solaris_error_set(&request->error, rc, 0,
                          rc == SOLARIS_EAGAIN ? "prepared configuration base revision is stale" : NULL);
        bundle_abort(bundle);
        manager_progress(manager);
    }
    return SOLARIS_OK;
}
static void request_cancel(void *context)
{
    request_t *request = context;
    request->cancelled = 1;
    if (request->work_active)
        (void)uv_cancel((uv_req_t *)&request->work);
    if (request->bundle) {
        request->status = SOLARIS_ECANCELLED;
        bundle_abort(request->bundle);
        manager_progress(request->manager);
    }
}
static void request_complete(void *context, solaris_status_t status, uint64_t revision)
{
    request_t *request = context;
    if (request->error.code != status)
        solaris_error_set(&request->error, status, 0, NULL);
    solaris_log_record_t record = {.runtime_generation = request->manager->generation,
                                   .config_revision = revision,
                                   .operation_id = request->operation_id,
                                   .event = request->kind == SOLARIS_OPERATION_CONFIG_PREPARE ? SOLARIS_LOG_PREPARE
                                                                                              : SOLARIS_LOG_COMMIT,
                                   .level = status == SOLARIS_OK           ? SOLARIS_LOG_INFO
                                            : status == SOLARIS_ECANCELLED ? SOLARIS_LOG_WARNING
                                                                           : SOLARIS_LOG_ERROR,
                                   .status = status,
                                   .component = "config"};
    solaris_log_service_emit(request->manager->log, &record);
    if (request->kind == SOLARIS_OPERATION_CONFIG_PREPARE) {
        solaris_prepared_config_t *output = status == SOLARIS_OK ? request->output : NULL;
        if (output)
            request->output = NULL;
        request->prepare_callback(request->user, status, output, &request->error);
    } else if (request->commit_callback)
        request->commit_callback(request->user, status, revision, &request->error);
}
static void request_dispose(void *context)
{
    request_t *request = context;
    if (request->output)
        solaris_prepared_config_release(request->output);
    if (request->prepared)
        solaris_prepared_config_release(request->prepared);
    solaris_snapshot_ref_release(&request->base);
    solaris_config_module_set_release(request->set);
    solaris_config_release(request->image);
    if (request->trust) {
        for (size_t i = 0; i < request->trust_length; ++i)
            ((volatile uint8_t *)request->trust)[i] = 0;
    }
    solaris_memory_free(request->trust);
    solaris_memory_free(request->overrides);
    solaris_memory_free(request->override_addresses);
    solaris_memory_free(request);
}
static solaris_status_t manager_stop(void *context, int destroy)
{
    solaris_config_manager_t *manager = context;
    manager->stopping = 1;
    manager->destroying |= destroy;
    solaris_snapshot_ref_t old = {0};
    uv_mutex_lock(&manager->policy_mutex);
    solaris_status_t rc = solaris_publication_acquire(manager->publication, &old);
    if (rc == SOLARIS_OK) {
        if (old.revision != UINT64_MAX) {
            solaris_snapshot_ref_t empty = {.revision = old.revision + 1};
            uint64_t actual;
            rc = solaris_publication_publish(manager->publication, old.revision, &empty, &actual);
        } else if (old.context)
            rc = SOLARIS_EOVERFLOW;
    }
    uv_mutex_unlock(&manager->policy_mutex);
    solaris_snapshot_ref_release(&old);
    solaris_log_service_stop(manager->log, destroy);
    if (manager->preparing)
        request_cancel(manager->preparing);
    for (bundle_t *bundle = manager->bundles; bundle; bundle = bundle->next) {
        if (bundle->request) {
            bundle->request->cancelled = 1;
            bundle->request->status = SOLARIS_ECANCELLED;
        }
        bundle_abort(bundle);
    }
    manager_progress(manager);
    return rc;
}
static int manager_drained(void *context)
{
    solaris_config_manager_t *manager = context;
    manager_progress(manager);
    uv_mutex_lock(&manager->mutex);
    int queued = manager->wake_pending;
    uv_mutex_unlock(&manager->mutex);
    return !manager->bundles && !manager->preparing && !queued && solaris_config_slots_drained(manager->slots) &&
           solaris_tracker_drained(manager->tracker) && solaris_log_service_drained(manager->log);
}
static void manager_destroy(void *context)
{
    solaris_config_manager_t *manager = context;
    assert(!manager->bundles && !manager->preparing);
    uv_mutex_lock(&manager->mutex);
    manager->engine = NULL;
    manager->wake_pending = 0;
    uv_mutex_unlock(&manager->mutex);
    solaris_publication_destroy(manager->publication);
    manager->publication = NULL;
    solaris_status_t rc = solaris_config_slots_destroy(manager->slots);
    assert(rc == SOLARIS_OK);
    (void)rc;
    manager->slots = NULL;
    solaris_replay_release(manager->replay);
    manager->replay = NULL;
    rc = solaris_tracker_destroy(manager->tracker);
    assert(rc == SOLARIS_OK);
    (void)rc;
    manager->tracker = NULL;
    solaris_traffic_counter_release(manager->traffic);
    manager->traffic = NULL;
    solaris_log_service_destroy(manager->log);
    manager->log = NULL;
    manager_release(manager);
}
solaris_config_manager_t *solaris_config_manager_find(solaris_engine_t *engine)
{
    return engine ? solaris_runtime_attachment_get(engine) : NULL;
}
solaris_status_t solaris_config_manager_ensure(solaris_engine_t *engine, solaris_config_manager_t **out)
{
    if (!engine || !out)
        return SOLARIS_EINVAL;
    *out = solaris_config_manager_find(engine);
    if (*out)
        return SOLARIS_OK;
    solaris_config_manager_t *manager = calloc(1, sizeof(*manager));
    if (!manager)
        return SOLARIS_ENOMEM;
    atomic_init(&manager->references, 1);
    if (uv_mutex_init(&manager->mutex)) {
        free(manager);
        return SOLARIS_EIO;
    }
    if (uv_mutex_init(&manager->policy_mutex)) {
        uv_mutex_destroy(&manager->mutex);
        free(manager);
        return SOLARIS_EIO;
    }
    manager->engine = engine;
    manager->budget = solaris_runtime_budget(engine);
    manager->wake = (solaris_control_completion_t){.run = manager_wake, .context = manager};
    solaris_status_t rc = solaris_publication_create(manager->budget, &manager->publication);
    if (rc == SOLARIS_OK)
        rc = solaris_config_slots_create(manager->budget, slot_accept, manager, &manager->slots);
    if (rc == SOLARIS_OK)
        rc = solaris_tracker_create(manager->budget, 4096, 256, &manager->tracker);
    if (rc == SOLARIS_OK)
        rc = solaris_traffic_counter_create(manager->budget, &manager->traffic);
    if (rc == SOLARIS_OK)
        rc = solaris_log_service_create(manager->budget, &manager->log);
    if (rc == SOLARIS_OK) {
        solaris_runtime_attachment_t attachment = {
            .context = manager, .stop = manager_stop, .drained = manager_drained, .destroy = manager_destroy};
        void *existing = NULL;
        rc = solaris_runtime_attachment_install(engine, &attachment, &existing);
        if (rc == SOLARIS_OK) {
            *out = manager;
            return SOLARIS_OK;
        }
        if (rc == SOLARIS_EBUSY) {
            *out = existing;
            rc = SOLARIS_OK;
        }
    }
    if (manager->log)
        solaris_log_service_destroy(manager->log);
    if (manager->traffic)
        solaris_traffic_counter_release(manager->traffic);
    if (manager->tracker)
        (void)solaris_tracker_destroy(manager->tracker);
    if (manager->slots)
        (void)solaris_config_slots_destroy(manager->slots);
    solaris_publication_destroy(manager->publication);
    manager->engine = NULL;
    manager_release(manager);
    return rc;
}
void solaris_config_prepare_options_init(solaris_config_prepare_options_t *options)
{
    if (options)
        memset(options, 0, sizeof(*options));
}
solaris_status_t solaris_engine_prepare_config(solaris_engine_t *engine, solaris_config_t *image,
                                               const solaris_config_prepare_options_t *options,
                                               solaris_config_prepare_callback_t callback, void *context,
                                               uint64_t *operation_id, solaris_error_t *error)
{
    if (operation_id)
        *operation_id = 0;
    if (!engine || !image || !callback || !operation_id ||
        (options && ((options->trust_length && !options->trust_pem) || options->trust_length > 262144 ||
                     (options->binding_count && !options->bindings))))
        return solaris_error_set(error, SOLARIS_EINVAL, 0, "invalid configuration prepare inputs");
    size_t count;
    const solaris_config_listener_t *listeners = solaris_config_listeners(image, &count);
    size_t overrides = options ? options->binding_count : 0;
    if (overrides > count)
        return solaris_error_set(error, SOLARIS_EINVAL, 0, "too many listener overrides");
    solaris_config_manager_t *manager;
    solaris_status_t rc = solaris_config_manager_ensure(engine, &manager);
    if (rc != SOLARIS_OK)
        return solaris_error_set(error, rc, 0, NULL);
    request_t *request = solaris_memory_allocate(manager->budget, sizeof(*request));
    if (!request)
        return solaris_error_set(error, SOLARIS_ENOMEM, 0, NULL);
    memset(request, 0, sizeof(*request));
    request->manager = manager;
    request->kind = SOLARIS_OPERATION_CONFIG_PREPARE;
    request->prepare_callback = callback;
    request->user = context;
    request->image = image;
    solaris_config_retain(image);
    request->override_count = overrides;
    if (overrides) {
        request->overrides = solaris_memory_allocate(manager->budget, overrides * sizeof(*request->overrides));
        request->override_addresses =
            solaris_memory_allocate(manager->budget, overrides * sizeof(*request->override_addresses));
        if (!request->overrides || !request->override_addresses) {
            rc = SOLARIS_ENOMEM;
            goto rejected;
        }
        memset(request->overrides, 0, overrides * sizeof(*request->overrides));
        for (size_t i = 0; i < overrides; ++i) {
            const solaris_config_bind_override_t *binding = &options->bindings[i];
            size_t j = 0;
            for (; j < count && listeners[j].id != binding->listener_id; ++j) {
            }
            if (j == count) {
                rc = SOLARIS_EINVAL;
                goto rejected;
            }
            for (size_t k = 0; k < i; ++k)
                if (request->overrides[k].listener_id == binding->listener_id) {
                    rc = SOLARIS_EINVAL;
                    goto rejected;
                }
            request->overrides[i].listener_id = binding->listener_id;
            request->overrides[i].port = binding->port;
            request->override_addresses[i] = listeners[j].listen;
            request->override_addresses[i].port = binding->port;
            if (binding->address) {
                rc = solaris_address_parse(binding->address, binding->port, &request->override_addresses[i]);
                if (rc != SOLARIS_OK || request->override_addresses[i].family == SOLARIS_ADDRESS_DOMAIN) {
                    rc = SOLARIS_EINVAL;
                    goto rejected;
                }
            }
        }
    }
    request->trust_length = options ? options->trust_length : 0;
    if (request->trust_length) {
        request->trust = solaris_memory_allocate(manager->budget, request->trust_length);
        if (!request->trust) {
            rc = SOLARIS_ENOMEM;
            goto rejected;
        }
        memcpy(request->trust, options->trust_pem, request->trust_length);
    }
    solaris_runtime_request_t operation = {.operation = SOLARIS_OPERATION_CONFIG_PREPARE,
                                           .requires_running = 1,
                                           .context = request,
                                           .start = prepare_start,
                                           .cancel = request_cancel,
                                           .complete = request_complete,
                                           .dispose = request_dispose};
    rc = solaris_runtime_request_submit(engine, &operation, operation_id, error);
    if (rc == SOLARIS_OK)
        return SOLARIS_OK;
rejected:
    request_dispose(request);
    return solaris_error_set(error, rc, 0, "configuration prepare was not accepted");
}
solaris_status_t solaris_engine_commit_config(solaris_engine_t *engine, solaris_prepared_config_t *prepared,
                                              solaris_config_commit_callback_t callback, void *context,
                                              uint64_t *operation_id, solaris_error_t *error)
{
    if (operation_id)
        *operation_id = 0;
    if (!engine || !prepared || !operation_id)
        return solaris_error_set(error, SOLARIS_EINVAL, 0, NULL);
    solaris_config_manager_t *manager = solaris_config_manager_find(engine);
    if (!manager || manager != prepared->manager)
        return solaris_error_set(error, SOLARIS_EINVAL, 0, "prepared configuration belongs to another engine");
    request_t *request = solaris_memory_allocate(manager->budget, sizeof(*request));
    if (!request)
        return solaris_error_set(error, SOLARIS_ENOMEM, 0, NULL);
    memset(request, 0, sizeof(*request));
    request->manager = manager;
    request->kind = SOLARIS_OPERATION_CONFIG_APPLY;
    request->prepared = prepared;
    solaris_prepared_config_retain(prepared);
    request->commit_callback = callback;
    request->user = context;
    solaris_runtime_request_t operation = {.operation = SOLARIS_OPERATION_CONFIG_APPLY,
                                           .requires_running = 1,
                                           .context = request,
                                           .start = commit_start,
                                           .cancel = request_cancel,
                                           .complete = request_complete,
                                           .dispose = request_dispose};
    solaris_status_t rc = solaris_runtime_request_submit(engine, &operation, operation_id, error);
    if (rc != SOLARIS_OK)
        request_dispose(request);
    return rc;
}
solaris_status_t solaris_engine_get_config_snapshot(solaris_engine_t *engine, solaris_active_config_snapshot_t *out,
                                                    solaris_error_t *error)
{
    if (!engine || !out)
        return solaris_error_set(error, SOLARIS_EINVAL, 0, NULL);
    memset(out, 0, sizeof(*out));
    solaris_engine_snapshot_t runtime;
    solaris_status_t rc = solaris_engine_get_snapshot(engine, &runtime, error);
    if (rc != SOLARIS_OK)
        return rc;
    out->runtime_generation = runtime.generation;
    solaris_config_manager_t *manager = solaris_config_manager_find(engine);
    if (!manager)
        return solaris_error_set(error, SOLARIS_OK, 0, NULL);
    solaris_snapshot_ref_t active;
    uv_mutex_lock(&manager->policy_mutex);
    rc = solaris_publication_acquire(manager->publication, &active);
    if (rc != SOLARIS_OK) {
        uv_mutex_unlock(&manager->policy_mutex);
        return solaris_error_set(error, rc, 0, NULL);
    }
    out->publication_revision = active.revision;
    bundle_t *bundle = active.context;
    if (bundle) {
        solaris_config_snapshot_t compiled;
        (void)solaris_config_get_snapshot(solaris_config_module_set_image(bundle->set), &compiled);
        out->active_revision = active.revision;
        out->runtime_generation = bundle->runtime_generation;
        out->mode = bundle->control->mode;
        out->listener_count = bundle->binding_count;
        out->node_count = compiled.node_count;
        out->group_count = compiled.group_count;
    }
    uv_mutex_unlock(&manager->policy_mutex);
    solaris_snapshot_ref_release(&active);
    return solaris_error_set(error, SOLARIS_OK, 0, NULL);
}
solaris_status_t solaris_engine_get_bound_listener(solaris_engine_t *engine, uint64_t active_revision, size_t index,
                                                   solaris_config_listener_info_t *out, solaris_error_t *error)
{
    if (!engine || !out)
        return solaris_error_set(error, SOLARIS_EINVAL, 0, NULL);
    memset(out, 0, sizeof(*out));
    solaris_config_manager_t *manager = solaris_config_manager_find(engine);
    if (!manager)
        return solaris_error_set(error, SOLARIS_ECLOSED, 0, NULL);
    solaris_snapshot_ref_t active;
    solaris_status_t rc = solaris_publication_acquire(manager->publication, &active);
    if (rc != SOLARIS_OK)
        return solaris_error_set(error, rc, 0, NULL);
    bundle_t *bundle = active.context;
    if (!bundle)
        rc = SOLARIS_ECLOSED;
    else if (active.revision != active_revision)
        rc = SOLARIS_EAGAIN;
    else if (index >= bundle->binding_count)
        rc = SOLARIS_EINVAL;
    else
        *out = bundle->infos[index];
    solaris_snapshot_ref_release(&active);
    return solaris_error_set(error, rc, 0, NULL);
}

solaris_tracker_t *solaris_config_manager_tracker(solaris_config_manager_t *manager)
{
    return manager ? manager->tracker : NULL;
}
solaris_traffic_counter_t *solaris_config_manager_traffic(solaris_config_manager_t *manager)
{
    return manager ? manager->traffic : NULL;
}
solaris_log_service_t *solaris_config_manager_log(solaris_config_manager_t *manager)
{
    return manager ? manager->log : NULL;
}
solaris_status_t solaris_engine_get_control_snapshot(solaris_engine_t *engine, solaris_control_snapshot_t **out,
                                                     solaris_error_t *error)
{
    if (!out)
        return solaris_error_set(error, SOLARIS_EINVAL, 0, NULL);
    *out = NULL;
    solaris_config_admission_t *admission;
    solaris_status_t rc = solaris_config_admission_acquire(engine, 0, &admission);
    if (rc != SOLARIS_OK)
        return solaris_error_set(error, rc, 0, NULL);
    bundle_t *bundle = admission->bundle;
    rc = solaris_control_snapshot_copy(solaris_config_module_set_image(bundle->set), admission->control,
                                       bundle->revision, bundle->runtime_generation, out);
    solaris_config_admission_release(admission);
    return solaris_error_set(error, rc, 0, NULL);
}
typedef struct control_request {
    solaris_config_manager_t *manager;
    solaris_config_admission_t *admission;
    solaris_control_view_t *next, *replaced;
    uint64_t expected, group_id, node_id, operation_id;
    size_t group_index;
    solaris_mode_t mode;
    solaris_operation_t kind;
    solaris_control_callback_t callback;
    void *context;
    solaris_control_result_t result;
    solaris_error_t error;
} control_request_t;
static solaris_status_t control_publish(void *context, uint64_t *revision)
{
    control_request_t *request = context;
    solaris_config_manager_t *manager = request->manager;
    solaris_snapshot_ref_t active = {0};
    solaris_status_t status;
    uv_mutex_lock(&manager->policy_mutex);
    status = solaris_publication_acquire(manager->publication, &active);
    bundle_t *bundle = active.context;
    if (status == SOLARIS_OK) {
        if (!bundle || manager->stopping || manager->destroying)
            status = SOLARIS_ECLOSED;
        else if (active.revision != request->expected || bundle != request->admission->bundle ||
                 bundle->control != request->admission->control)
            status = SOLARIS_EAGAIN;
        else if (request->next && manager->selection_serial == UINT64_MAX)
            status = SOLARIS_EOVERFLOW;
    }
    if (status == SOLARIS_OK) {
        if (request->next) {
            request->next->revision = ++manager->selection_serial;
            if (request->kind == SOLARIS_OPERATION_SELECT)
                request->next->groups[request->group_index].reason_revision = request->next->revision;
            request->replaced = bundle->control;
            bundle->control = request->next;
            request->next = NULL;
        }
        request->result = (solaris_control_result_t){.config_revision = active.revision,
                                                     .selection_revision = bundle->control->revision,
                                                     .mode = bundle->control->mode,
                                                     .group_id = request->group_id,
                                                     .selected_id = request->node_id};
        *revision = active.revision;
    }
    uv_mutex_unlock(&manager->policy_mutex);
    /* The active publication itself and manager list still pin this bundle;
     * this temporary release cannot enqueue retirement under engine's fence. */
    solaris_snapshot_ref_release(&active);
    return status;
}
static solaris_status_t control_start(void *context, solaris_engine_t *engine, solaris_runtime_operation_t *operation)
{
    control_request_t *request = context;
    request->operation_id = solaris_runtime_operation_id(operation);
    (void)engine;
    solaris_status_t rc = capture_current(request->manager, request->expected, &request->admission);
    if (rc != SOLARIS_OK)
        return solaris_error_set(&request->error, rc, 0, "active configuration revision does not match");
    solaris_control_view_t *current = request->admission->control;
    int unchanged = 0;
    if (request->kind == SOLARIS_OPERATION_SET_MODE)
        unchanged = current->mode == request->mode;
    else {
        size_t count;
        const solaris_config_group_t *groups =
            solaris_config_groups(solaris_config_module_set_image(request->admission->bundle->set), &count);
        size_t index = 0;
        while (index < count && groups[index].id != request->group_id)
            index++;
        if (index == count)
            return solaris_error_set(&request->error, SOLARIS_EINVAL, 0, "unknown select group");
        size_t member = 0;
        while (member < groups[index].member_count && groups[index].members[member] != request->node_id)
            member++;
        if (member == groups[index].member_count)
            return solaris_error_set(&request->error, SOLARIS_EINVAL, 0, "node is not a member of the select group");
        request->group_index = index;
        unchanged = current->groups[index].selected == request->node_id;
    }
    if (!unchanged) {
        rc = solaris_control_view_clone(request->manager->budget, current, &request->next);
        if (rc != SOLARIS_OK)
            return solaris_error_set(&request->error, rc, 0, NULL);
        if (request->kind == SOLARIS_OPERATION_SET_MODE)
            request->next->mode = request->mode;
        else {
            solaris_control_selection_t *selection = &request->next->groups[request->group_index];
            selection->previous = selection->selected;
            selection->selected = request->node_id;
            selection->reason = SOLARIS_SELECTION_USER;
        }
    }
    rc = solaris_runtime_operation_finish(operation, control_publish, request);
    solaris_control_view_release(request->replaced);
    request->replaced = NULL;
    if (rc != SOLARIS_OK)
        solaris_error_set(&request->error, rc, 0, NULL);
    return rc;
}
static void control_complete(void *context, solaris_status_t status, uint64_t revision)
{
    control_request_t *request = context;
    if (status != SOLARIS_OK) {
        memset(&request->result, 0, sizeof(request->result));
        if (request->error.code != status)
            solaris_error_set(&request->error, status, 0, NULL);
    }
    solaris_log_record_t record = {.config_revision = revision,
                                   .operation_id = request->operation_id,
                                   .node_id = request->result.selected_id,
                                   .runtime_generation =
                                       request->admission ? request->admission->bundle->runtime_generation : 0,
                                   .level = status == SOLARIS_OK           ? SOLARIS_LOG_INFO
                                            : status == SOLARIS_ECANCELLED ? SOLARIS_LOG_WARNING
                                                                           : SOLARIS_LOG_ERROR,
                                   .event = SOLARIS_LOG_CONTROL,
                                   .status = status,
                                   .component = "control"};
    solaris_log_service_emit(request->manager->log, &record);
    if (request->callback)
        request->callback(request->context, status, &request->result, &request->error);
}
static void control_dispose(void *context)
{
    control_request_t *request = context;
    solaris_control_view_release(request->next);
    solaris_control_view_release(request->replaced);
    solaris_config_admission_release(request->admission);
    solaris_memory_free(request);
}
static solaris_status_t control_submit(solaris_engine_t *engine, uint64_t expected, solaris_mode_t mode, uint64_t group,
                                       uint64_t node, solaris_operation_t kind, solaris_control_callback_t callback,
                                       void *context, uint64_t *id, solaris_error_t *error)
{
    if (id)
        *id = 0;
    if (!engine || !id || !expected ||
        (kind == SOLARIS_OPERATION_SET_MODE && (mode < SOLARIS_MODE_RULE || mode > SOLARIS_MODE_DIRECT)) ||
        (kind == SOLARIS_OPERATION_SELECT && (!group || !node)))
        return solaris_error_set(error, SOLARIS_EINVAL, 0, NULL);
    solaris_config_manager_t *manager = solaris_config_manager_find(engine);
    if (!manager)
        return solaris_error_set(error, SOLARIS_ECLOSED, 0, NULL);
    control_request_t *request = solaris_memory_allocate(manager->budget, sizeof(*request));
    if (!request)
        return solaris_error_set(error, SOLARIS_ENOMEM, 0, NULL);
    memset(request, 0, sizeof(*request));
    request->manager = manager;
    request->expected = expected;
    request->mode = mode;
    request->group_id = group;
    request->node_id = node;
    request->kind = kind;
    request->callback = callback;
    request->context = context;
    solaris_runtime_request_t descriptor = {.operation = kind,
                                            .requires_running = 1,
                                            .context = request,
                                            .start = control_start,
                                            .complete = control_complete,
                                            .dispose = control_dispose};
    solaris_status_t status = solaris_runtime_request_submit(engine, &descriptor, id, error);
    if (status != SOLARIS_OK)
        control_dispose(request);
    return status;
}
solaris_status_t solaris_engine_set_mode(solaris_engine_t *engine, uint64_t expected, solaris_mode_t mode,
                                         solaris_control_callback_t callback, void *context, uint64_t *id,
                                         solaris_error_t *error)
{
    return control_submit(engine, expected, mode, 0, 0, SOLARIS_OPERATION_SET_MODE, callback, context, id, error);
}
solaris_status_t solaris_engine_select(solaris_engine_t *engine, uint64_t expected, uint64_t group, uint64_t node,
                                       solaris_control_callback_t callback, void *context, uint64_t *id,
                                       solaris_error_t *error)
{
    return control_submit(engine, expected, 0, group, node, SOLARIS_OPERATION_SELECT, callback, context, id, error);
}
