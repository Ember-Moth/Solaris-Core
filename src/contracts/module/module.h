#ifndef SOLARIS_MODULE_H
#define SOLARIS_MODULE_H

#include "contracts/module/config.h"
#include "contracts/io/outbound.h"
#include "transport/socket/socket.h"
#include "contracts/io/carrier.h"
#include "contracts/io/plugin.h"
#include "contracts/runtime/replay.h"
#include "contracts/runtime/crypto.h"
#include "contracts/flow/plan.h"
#include "contracts/runtime/diagnostic.h"

typedef struct solaris_registry solaris_registry_t;
typedef struct solaris_module_config solaris_module_config_t;
typedef struct solaris_module_instance solaris_module_instance_t;

typedef struct solaris_module_services {
    solaris_executor_t *owner;
    /* The factory receives an instance scope. Instance-owned asynchronous
     * resources retain it until closed; channels have independent scopes. */
    solaris_scope_t *scope;
    solaris_dialer_options_t dialer;
    /* Optional carrier injection for stream-based modules. Null open uses
     * the physical dialer. Its context outlives every dependent channel. */
    solaris_stream_factory_t carrier;
    const solaris_stream_plugin_provider_t *stream_plugin;
    /* Shared across workers/configuration generations; channels retain it.
     * Required by protocols with connection-independent replay state. */
    solaris_replay_store_t *replay;
    solaris_crypto_source_t crypto;
    solaris_diagnostic_sink_t diagnostic;
} solaris_module_services_t;

/* Descriptors and their strings have process lifetime. compile/create never
 * perform network I/O. Config is immutable and may be shared across workers.
 * retire closes admission and instance-owned resources; destroy runs only
 * after scope references drain. Channels must retain any config they use.
 * free_config also receives NULL or partial payloads after a rejected compile. */
typedef struct solaris_outbound_module {
    const char *name;
    const char *const *aliases;
    size_t alias_count;
    const char *const *dependencies;
    size_t dependency_count;
    uint32_t capabilities;
    solaris_status_t (*compile)(const solaris_config_view_t *view, solaris_budget_t *budget,
                                void **out, solaris_error_t *error);
    void (*free_config)(void *config);
    solaris_status_t (*create)(const void *config, const solaris_module_services_t *services,
                               void **state, solaris_outbound_t **out, solaris_error_t *error);
    void (*retire)(void *state);
    void (*destroy)(void *state);
} solaris_outbound_module_t;

/* Creation validates the entire set, including aliases/dependency cycles,
 * then publishes a frozen registry. No partially populated result on error. */
solaris_status_t solaris_registry_create(const solaris_outbound_module_t *const *modules,
                                          size_t count, solaris_budget_t *budget,
                                          solaris_registry_t **out, solaris_error_t *error);
solaris_status_t solaris_builtin_registry_create(solaris_budget_t *budget,
                                                  solaris_registry_t **out, solaris_error_t *error);
void solaris_registry_destroy(solaris_registry_t *registry);
size_t solaris_registry_count(const solaris_registry_t *registry);
const solaris_outbound_module_t *solaris_registry_find(const solaris_registry_t *registry, const char *name);
solaris_status_t solaris_registry_compile(const solaris_registry_t *registry, const char *name,
                                           const solaris_config_view_t *view,
                                           solaris_module_config_t **out, solaris_error_t *error);
void solaris_module_config_retain(solaris_module_config_t *config);
void solaris_module_config_release(solaris_module_config_t *config);

/* services.scope is filled by the framework, not the caller. Accepted factory
 * instances are engine-owned. on_close runs on owner after retire/drain and
 * immediately before destruction; the handle then expires. */
solaris_status_t solaris_module_create(solaris_module_config_t *config,
                                        const solaris_module_services_t *services,
                                        void (*on_close)(void *), void *context,
                                        solaris_module_instance_t **out, solaris_error_t *error);
solaris_outbound_t *solaris_module_outbound(solaris_module_instance_t *instance);
solaris_status_t solaris_module_retire(solaris_module_instance_t *instance);
/* Owner-only leases keep a pinned plan's handle/state alive through engine
 * stop. Retirement still closes new I/O admission. Each successful retain
 * requires release; on_close/destroy wait for those releases. */
solaris_status_t solaris_module_retain(solaris_module_instance_t *instance);
solaris_status_t solaris_module_release(solaris_module_instance_t *instance);
solaris_status_t solaris_module_plan_acquire(solaris_module_instance_t *instance,
                                             uint64_t node_id, solaris_dial_plan_t *out);

#endif
