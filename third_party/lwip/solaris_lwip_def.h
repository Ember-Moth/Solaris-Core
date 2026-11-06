#ifndef SOLARIS_LWIP_DEF_H
#define SOLARIS_LWIP_DEF_H
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
/* lwIP explicitly permits platform replacements of these helpers. Defining
 * the hooks avoids a second copy of its unprefixed portability functions. */
static inline uint16_t solaris_lwip_lwip_htons(uint16_t value)
{
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return value;
#else
    return (uint16_t)((value >> 8u) | (value << 8u));
#endif
}
static inline uint32_t solaris_lwip_lwip_htonl(uint32_t value)
{
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return value;
#else
    return (value >> 24u) | ((value >> 8u) & UINT32_C(0xff00)) |
        ((value << 8u) & UINT32_C(0xff0000)) | (value << 24u);
#endif
}
static inline void solaris_lwip_lwip_itoa(char *result, size_t size, int number)
{ if (size) (void)snprintf(result, size, "%d", number); }
#endif
