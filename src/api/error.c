#include "api/error_internal.h"

#include <stdio.h>
#include <string.h>

const char *solaris_status_string(solaris_status_t status)
{
    switch (status) {
    case SOLARIS_OK: return "success";
    case SOLARIS_EINVAL: return "invalid argument";
    case SOLARIS_ENOMEM: return "out of memory";
    case SOLARIS_ENOTSUP: return "unsupported capability";
    case SOLARIS_EBUSY: return "engine or queue is busy";
    case SOLARIS_ECLOSED: return "engine is closing";
    case SOLARIS_ETIMEDOUT: return "deadline exceeded";
    case SOLARIS_EDEADLOCK: return "operation would wait for its own callback";
    case SOLARIS_EIO: return "runtime failure";
    case SOLARIS_ECANCELLED: return "operation cancelled";
    case SOLARIS_EOVERFLOW: return "operation identifier exhausted";
    default: return "unknown Solaris status";
    }
}

solaris_status_t solaris_error_set(solaris_error_t *error,
                                   solaris_status_t code,
                                   int system_code,
                                   const char *message)
{
    if (error != NULL) {
        memset(error, 0, sizeof(*error));
        error->code = code;
        error->system_code = (int32_t)system_code;
        if (code != SOLARIS_OK) {
            (void)snprintf(error->message, sizeof(error->message), "%s",
                          message == NULL ? solaris_status_string(code) : message);
        }
    }
    return code;
}
