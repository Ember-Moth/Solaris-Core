#ifndef SOLARIS_CONFIG_SLOTS_H
#define SOLARIS_CONFIG_SLOTS_H
#include "transport/socket/tcp.h"

typedef struct solaris_config_slots solaris_config_slots_t;
typedef struct solaris_config_slot solaris_config_slot_t;
typedef struct solaris_config_slot_key
{
    solaris_address_t address;
    /* Zero for fixed ports. Explicit host ephemeral overrides use their
     * logical listener ID, preserving a bound port across compatible reloads. */
    uint64_t ephemeral_id;
} solaris_config_slot_key_t;
typedef solaris_status_t (*solaris_config_slot_accept_fn)(
    void *context, solaris_config_slot_t *slot, solaris_executor_t *owner, const solaris_address_t *peer,
    const solaris_address_t *local, solaris_stream_t *stream, solaris_stream_callbacks_t *callbacks,
    void **stream_context);
/* The registry owns no published dispatch. The callback acquires the one
 * active publication and resolves this physical slot to an immutable inbound.
 * All prepares are serialized by the transaction coordinator. */
solaris_status_t solaris_config_slots_create(solaris_budget_t *budget, solaris_config_slot_accept_fn accept,
                                             void *context, solaris_config_slots_t **out);
/* Thread-safe owner lookup; does not borrow a slot pointer. */
solaris_executor_t *solaris_config_slot_owner(solaris_config_slots_t *slots,
                                              const solaris_config_slot_key_t *key,
                                              solaris_executor_t *preferred);
/* Owner-only. A non-NULL same-owner parent counts rejected-open cleanup;
 * successful acquisition releases that temporary parent before returning.
 * Compatible slots are reused. Closing slots return EAGAIN; overlapping
 * wildcard/specific endpoints return ENOTSUP and require stop/start. A failed
 * bind never closes or modifies another slot. Each success owns one reference.
 */
solaris_status_t solaris_config_slot_acquire(solaris_config_slots_t *slots, solaris_executor_t *owner,
                                             solaris_scope_t *parent, const solaris_config_slot_key_t *key,
                                             solaris_config_slot_t **out, solaris_address_t *bound);
void solaris_config_slot_retain(solaris_config_slot_t *slot);
/* Owner-only. If this is the last reference, retain optional parent through
 * complete physical cleanup. Reused slots release synchronously. */
void solaris_config_slot_release(solaris_config_slot_t *slot, solaris_scope_t *parent);
uint64_t solaris_config_slot_id(const solaris_config_slot_t *slot);
/* Thread-safe. Drained includes rejected-open and last-release cleanup. */
int solaris_config_slots_drained(solaris_config_slots_t *slots);
/* Exclusive, returns EBUSY while any slot/cleanup remains. */
solaris_status_t solaris_config_slots_destroy(solaris_config_slots_t *slots);
#endif
