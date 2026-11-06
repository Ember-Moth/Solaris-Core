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
void solaris_resolve_cancel(solaris_resolve_t *request);

#endif
