#ifndef SOLARIS_VERSION_H
#define SOLARIS_VERSION_H

#include <solaris/export.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Product version, not an ABI/schema negotiation protocol. Static storage. */
SOLARIS_API const char *solaris_version_string(void);

#ifdef __cplusplus
}
#endif

#endif
