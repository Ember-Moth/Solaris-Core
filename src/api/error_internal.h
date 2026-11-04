#ifndef SOLARIS_ERROR_INTERNAL_H
#define SOLARIS_ERROR_INTERNAL_H

#include <solaris/error.h>

solaris_status_t solaris_error_set(solaris_error_t *error,
                                   solaris_status_t code,
                                   int system_code,
                                   const char *message);

#endif
