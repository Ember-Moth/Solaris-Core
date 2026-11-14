#ifndef SOLARIS_LWIP_CC_H
#define SOLARIS_LWIP_CC_H
#include <stdint.h>
#ifdef _MSC_VER
/* Share the pointer-sized Windows definition with libuv, even in lwIP
 * translation units which do not include uv.h. MSVC has no unistd.h. */
#if !defined(_SSIZE_T_) && !defined(_SSIZE_T_DEFINED)
typedef intptr_t ssize_t;
#define _SSIZE_T_
#define _SSIZE_T_DEFINED
#endif
#ifndef SSIZE_MAX
#define SSIZE_MAX INTPTR_MAX
#endif
#define LWIP_NO_UNISTD_H 1
#define PACK_STRUCT_BEGIN __pragma(pack(push, 1))
#define PACK_STRUCT_END __pragma(pack(pop))
#endif
#include <stdio.h>
#include <stdlib.h>
uint32_t solaris_lwip_random(void);
#define LWIP_RAND() solaris_lwip_random()
#define LWIP_PLATFORM_DIAG(message) do { } while (0)
#define LWIP_PLATFORM_ASSERT(message) do { fprintf(stderr, "lwIP: %s\n", message); abort(); } while (0)
#ifndef BYTE_ORDER
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define BYTE_ORDER BIG_ENDIAN
#else
#define BYTE_ORDER LITTLE_ENDIAN
#endif
#endif
#endif
