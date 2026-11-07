#ifndef SOLARIS_CONFIG_MANAGER_H
#define SOLARIS_CONFIG_MANAGER_H
#include <solaris/control.h>
#include "contracts/policy/route.h"
#include "observe/connections/tracker.h"
#include "contracts/runtime/traffic.h"
typedef struct solaris_config_manager solaris_config_manager_t;
typedef struct solaris_config_admission solaris_config_admission_t;
typedef struct solaris_log_service solaris_log_service_t;
/* Borrowed while the caller owns a valid engine lifetime. ensure is thread-safe
 * and creates only idle services; it does not activate listeners or outbounds. */
solaris_config_manager_t *solaris_config_manager_find(solaris_engine_t *engine);
solaris_status_t solaris_config_manager_ensure(solaris_engine_t *engine, solaris_config_manager_t **out);
solaris_tracker_t *solaris_config_manager_tracker(solaris_config_manager_t *manager);
solaris_traffic_counter_t *solaris_config_manager_traffic(solaris_config_manager_t *manager);
solaris_log_service_t *solaris_config_manager_log(solaris_config_manager_t *manager);
/* A single immutable capture pins configuration AND control revisions. Thread-
 * safe acquire; expected=0 means current, otherwise stale configuration is
 * EAGAIN. No active configuration is ECLOSED. Owner resources remain subject to
 * engine stop, so probes/jobs must finish before the accepted operation drains.
 * Public owned snapshots copy records and never expose this runtime lease. */
solaris_status_t solaris_config_admission_acquire(solaris_engine_t *engine, uint64_t expected_config_revision,
                                                  solaris_config_admission_t **out);
void solaris_config_admission_retain(solaris_config_admission_t *admission);
void solaris_config_admission_release(solaris_config_admission_t *admission);
solaris_status_t solaris_config_admission_get_state(const solaris_config_admission_t *admission,
                                                    solaris_control_info_t *out);
/* Owner-only. Resolves a flat group using only captured selected members;
 * explicit leaf probes do not apply the captured routing mode. Success owns
 * the returned plan, including its complete runtime bundle lease. */
solaris_status_t solaris_config_admission_acquire_plan(solaris_config_admission_t *admission, solaris_executor_t *owner,
                                                       uint64_t target_id, solaris_dial_plan_t *out,
                                                       uint32_t *capabilities);
#endif
