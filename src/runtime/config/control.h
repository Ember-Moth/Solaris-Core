#ifndef SOLARIS_RUNTIME_CONFIG_CONTROL_H
#define SOLARIS_RUNTIME_CONFIG_CONTROL_H
#include <solaris/control.h>
#include "contracts/config/image.h"
#include "contracts/io/buffer.h"
#include <stdatomic.h>
typedef struct solaris_control_selection {
    uint64_t selected, previous, reason_revision;
    uint32_t reason;
} solaris_control_selection_t;
typedef struct solaris_control_view {
    atomic_size_t references;
    uint64_t revision;
    solaris_mode_t mode;
    size_t count;
    solaris_control_selection_t groups[];
} solaris_control_view_t;
/* Views become immutable when published; clone/migrate only touch an owned,
 * unpublished view. Pointer publication is coordinated by manager policy_mutex. */
solaris_status_t solaris_control_view_create(solaris_budget_t *budget, solaris_config_t *image,
                                             solaris_control_view_t **out);
solaris_status_t solaris_control_view_clone(solaris_budget_t *budget, const solaris_control_view_t *source,
                                            solaris_control_view_t **out);
void solaris_control_view_retain(solaris_control_view_t *view);
void solaris_control_view_release(solaris_control_view_t *view);
void solaris_control_view_migrate(solaris_control_view_t *view, solaris_config_t *image,
                                  const solaris_control_view_t *old, solaris_config_t *old_image, uint64_t revision);
solaris_status_t solaris_control_snapshot_copy(solaris_config_t *image, const solaris_control_view_t *view,
                                               uint64_t config_revision, uint64_t runtime_generation,
                                               solaris_control_snapshot_t **out);
#endif
