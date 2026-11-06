#ifndef SOLARIS_EXECUTOR_UV_H
#define SOLARIS_EXECUTOR_UV_H

/* Backend-only escape hatch. Protocol adapters use executor/socket services. */
#include <uv.h>
#include "runtime/executor/executor.h"
uv_loop_t *solaris_executor_loop(solaris_executor_t *executor);

#endif
