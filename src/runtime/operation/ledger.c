#include "runtime/operation/ledger.h"
#include <string.h>
solaris_status_t solaris_operation_ledger_init(solaris_operation_ledger_t *l, solaris_budget_t *budget, size_t capacity)
{
    if (!l) return SOLARIS_EINVAL;
    memset(l, 0, sizeof(*l));
    if (!budget || !capacity || capacity > SIZE_MAX / sizeof(*l->slots)) return SOLARIS_EINVAL;
    l->slots = solaris_memory_allocate(budget, capacity * sizeof(*l->slots));
    if (!l->slots) return SOLARIS_ENOMEM;
    memset(l->slots, 0, capacity * sizeof(*l->slots)); l->capacity = capacity; return SOLARIS_OK;
}
solaris_status_t solaris_operation_ledger_accept(solaris_operation_ledger_t *l, uint64_t *id)
{
    if (id) *id = 0;
    if (!l || !l->slots || !id) return SOLARIS_EINVAL;
    if (l->accepted == UINT64_MAX) return SOLARIS_EOVERFLOW;
    if (l->accepted - l->watermark == l->capacity) return SOLARIS_EBUSY;
    *id = ++l->accepted;
    l->slots[*id % l->capacity] = (solaris_operation_slot_t){*id, 0}; return SOLARIS_OK;
}
solaris_status_t solaris_operation_ledger_rollback(solaris_operation_ledger_t *l, uint64_t id)
{
    if (!l || !l->slots || !id || id != l->accepted || id <= l->watermark) return SOLARIS_EINVAL;
    solaris_operation_slot_t *s = &l->slots[id % l->capacity];
    if (s->id != id || s->completed) return SOLARIS_EINVAL;
    memset(s, 0, sizeof(*s)); --l->accepted; return SOLARIS_OK;
}
solaris_status_t solaris_operation_ledger_complete(solaris_operation_ledger_t *l, uint64_t id)
{
    if (!l || !l->slots || !id || id <= l->watermark || id > l->accepted) return SOLARIS_EINVAL;
    solaris_operation_slot_t *s = &l->slots[id % l->capacity];
    if (s->id != id || s->completed) return SOLARIS_EINVAL;
    s->completed = 1; ++l->completed;
    while (l->watermark < l->accepted) {
        s = &l->slots[(l->watermark + 1) % l->capacity];
        if (s->id != l->watermark + 1 || !s->completed) break;
        memset(s, 0, sizeof(*s)); ++l->watermark;
    }
    return SOLARIS_OK;
}
solaris_status_t solaris_operation_ledger_dispose(solaris_operation_ledger_t *l)
{
    if (!l) return SOLARIS_EINVAL;
    if (l->accepted != l->watermark) return SOLARIS_EBUSY;
    solaris_memory_free(l->slots); memset(l, 0, sizeof(*l)); return SOLARIS_OK;
}
