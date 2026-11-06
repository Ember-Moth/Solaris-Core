#include "contracts/flow/plan.h"
#include "runtime/executor/executor.h"
#include <string.h>

solaris_status_t solaris_dial_plan_release(solaris_dial_plan_t *plan)
{
    if (plan == NULL) return SOLARIS_EINVAL;
    if (plan->outbound == NULL) return plan->context == NULL && plan->release == NULL ? SOLARIS_OK : SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(plan->outbound->owner)) return SOLARIS_ETHREAD;
    if (plan->release == NULL) return SOLARIS_EINVAL;
    void (*release)(void *) = plan->release; void *context = plan->context;
    memset(plan, 0, sizeof(*plan)); release(context); return SOLARIS_OK;
}
