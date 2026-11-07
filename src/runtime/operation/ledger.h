#ifndef SOLARIS_OPERATION_LEDGER_H
#define SOLARIS_OPERATION_LEDGER_H
#include "contracts/io/buffer.h"

typedef struct solaris_operation_slot { uint64_t id; int completed; } solaris_operation_slot_t;
typedef struct solaris_operation_ledger {
    solaris_operation_slot_t *slots;
    size_t capacity;
    uint64_t accepted, completed, watermark;
} solaris_operation_ledger_t;
/* Caller serializes every access (normally the engine mutex). The bounded
 * window includes out-of-order completions until the contiguous watermark
 * advances. Complete only after the result callback has returned. */
solaris_status_t solaris_operation_ledger_init(solaris_operation_ledger_t *ledger,
    solaris_budget_t *budget, size_t capacity);
solaris_status_t solaris_operation_ledger_accept(solaris_operation_ledger_t *ledger, uint64_t *id);
/* Only for a not-yet-published last acceptance, under the same submission lock.
 * No callback or observer may have seen the ID; earlier accepted IDs are kept. */
solaris_status_t solaris_operation_ledger_rollback(solaris_operation_ledger_t *ledger, uint64_t id);
solaris_status_t solaris_operation_ledger_complete(solaris_operation_ledger_t *ledger, uint64_t id);
/* Busy until every accepted operation and callback has completed. */
solaris_status_t solaris_operation_ledger_dispose(solaris_operation_ledger_t *ledger);
#endif
