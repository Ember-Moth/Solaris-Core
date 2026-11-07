#ifndef SOLARIS_LOG_SERVICE_H
#define SOLARIS_LOG_SERVICE_H
#include <solaris/log.h>
#include "contracts/io/buffer.h"
#include "contracts/runtime/diagnostic.h"
typedef struct solaris_log_service solaris_log_service_t;
/* One bounded synchronous ring per engine. Module contexts borrow it until
 * their full drain barrier. There is no callback or lifecycle mailbox usage. */
solaris_status_t solaris_log_service_create(solaris_budget_t *budget, solaris_log_service_t **out);
void solaris_log_service_stop(solaris_log_service_t *service, int destroy);
int solaris_log_service_drained(solaris_log_service_t *service);
void solaris_log_service_destroy(solaris_log_service_t *service);
/* Sequence/time are assigned here. Only whitelisted component identifiers are
 * retained; callers never pass arbitrary text as a public record. */
void solaris_log_service_emit(solaris_log_service_t *service, const solaris_log_record_t *record);
solaris_diagnostic_sink_t solaris_log_service_diagnostic(solaris_log_service_t *service);
solaris_status_t solaris_log_service_snapshot(solaris_log_service_t *service, uint64_t after_sequence,
                                              size_t max_records, solaris_log_snapshot_t **out);
#endif
