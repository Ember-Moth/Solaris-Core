#ifndef SOLARIS_RESOLVER_H
#define SOLARIS_RESOLVER_H

#include "contracts/io/address.h"
#include "runtime/executor/executor.h"

#define SOLARIS_RESOLVER_MAX_ADDRESSES 16u
typedef struct solaris_resolve solaris_resolve_t;
typedef void (*solaris_resolve_fn)(void *context, solaris_status_t status,
                                    const solaris_address_t *addresses, size_t count);

/* Owner-only. Zero timeout delegates the deadline to the caller. Results are
 * borrowed during the callback. Request expires when its callback returns;
 * underlying uncancellable OS work remains scoped until it actually ends. */
solaris_status_t solaris_resolve_start(solaris_executor_t *executor,
                                       const solaris_address_t *target, uint64_t timeout_ms,
                                       solaris_resolve_fn callback, void *context,
                                       solaris_resolve_t **out);
/* Same callback semantics, plus a same-owner drain fence retained until the
 * underlying OS request, timer and result callback have all ended. Includes
 * asynchronous cleanup after a rejected start. Result delivery alone is not
 * this resource barrier; an uncancellable OS query may finish later. */
solaris_status_t solaris_resolve_start_scoped(solaris_executor_t *executor,
    solaris_scope_t *parent_scope, const solaris_address_t *target, uint64_t timeout_ms,
    solaris_resolve_fn callback, void *context, solaris_resolve_t **out);
void solaris_resolve_cancel(solaris_resolve_t *request);

#endif
