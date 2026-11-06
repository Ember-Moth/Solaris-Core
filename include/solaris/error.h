#ifndef SOLARIS_ERROR_H
#define SOLARIS_ERROR_H

#include <stdint.h>
#include <solaris/export.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int32_t solaris_status_t;
enum {
    SOLARIS_OK = 0,
    SOLARIS_EINVAL = -1,
    SOLARIS_ENOMEM = -2,
    SOLARIS_ENOTSUP = -3,
    SOLARIS_EBUSY = -4,
    SOLARIS_ECLOSED = -5,
    SOLARIS_ETIMEDOUT = -6,
    SOLARIS_EDEADLOCK = -7,
    SOLARIS_EIO = -8,
    SOLARIS_ECANCELLED = -9,
    SOLARIS_EOVERFLOW = -10,
    SOLARIS_EAGAIN = -11,
    SOLARIS_ETHREAD = -12,
    SOLARIS_EACCESS = -13,
    SOLARIS_EMSGSIZE = -14
};

#define SOLARIS_ERROR_MESSAGE_CAPACITY 192u

/* Caller-owned output; no pointers, heap allocation, or global last error. */
typedef struct solaris_error {
    solaris_status_t code;
    int32_t system_code;
    char message[SOLARIS_ERROR_MESSAGE_CAPACITY];
} solaris_error_t;

/* Returns a process-lifetime string, including for unknown status codes. */
SOLARIS_API const char *solaris_status_string(solaris_status_t status);

#ifdef __cplusplus
}
#endif

#endif
