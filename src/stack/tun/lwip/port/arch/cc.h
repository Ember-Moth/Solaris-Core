#ifndef SOLARIS_LWIP_CC_H
#define SOLARIS_LWIP_CC_H
#include <stdint.h>
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
