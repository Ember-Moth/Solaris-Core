#ifndef SOLARIS_CONFIG_WORKER_H
#define SOLARIS_CONFIG_WORKER_H
#include "runtime/config/modules.h"

typedef struct solaris_config_worker solaris_config_worker_t;
typedef struct solaris_config_worker_options {
    solaris_executor_t *owner;
    solaris_config_module_set_t *set;
    /* owner and parent_scope are supplied by the worker. Other borrowed host
     * contexts outlive its final on_close, including all rejected factories. */
    solaris_module_services_t services;
    /* Optional same-owner transaction scope. Its drain includes a rejected
     * worker creation and all partial module factory cleanup. */
    solaris_scope_t *parent_scope;
    void *lease_context;
    /* Optional paired thread-safe hooks. A runtime coordinator supplies both
     * so each returned plan pins its full generation bundle. The worker itself
     * never retains this lease, avoiding a bundle/container reference cycle. */
    void (*lease_retain)(void *context);
    void (*lease_release)(void *context);
    /* Owner callback after all modules, accepted plans and resources drain.
     * Rejected create has no user callback; use parent_scope as its barrier. */
    void (*on_close)(void *context);
    void *context;
} solaris_config_worker_options_t;
solaris_status_t solaris_config_worker_create(const solaris_config_worker_options_t *options,
                                              solaris_config_worker_t **out, solaris_error_t *error);
/* Owner-only leaf acquisition. Group/mode resolution belongs to the caller's
 * immutable control view. Output owns a module lease AND the coordinator's
 * bundle lease, released in that order. UDP-disabled wrappers reject actual
 * datagram opens as well as removing the datagram capability bits. */
solaris_status_t solaris_config_worker_acquire(solaris_config_worker_t *worker, uint64_t node_id,
                                               uint64_t selection_revision, solaris_dial_plan_t *out,
                                               uint32_t *capabilities);
/* Owner-only asynchronous drain. For normal reload the coordinator calls this
 * only after all generation use leases are gone; engine stop may force it.
 * The pointer expires when on_close returns. */
solaris_status_t solaris_config_worker_retire(solaris_config_worker_t *worker);
#endif
