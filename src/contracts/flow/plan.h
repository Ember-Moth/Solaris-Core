#ifndef SOLARIS_DIAL_PLAN_H
#define SOLARIS_DIAL_PLAN_H
#include "contracts/io/outbound.h"

enum { SOLARIS_PLAN_OBSERVED = 1u };
/* One owner-thread lease. The chosen outbound and selection revision remain
 * fixed until release, including all later family lanes of a UDP association.
 * Move a plan by value only when its original is cleared; do not duplicate it.
 * node_id is a host-assigned identity, never a protocol discriminator. */
typedef struct solaris_dial_plan {
    solaris_outbound_t *outbound;
    void *context;
    void (*release)(void *context);
    uint64_t node_id, selection_revision;
    uint32_t flags;
} solaris_dial_plan_t;
solaris_status_t solaris_dial_plan_release(solaris_dial_plan_t *plan);
#endif
