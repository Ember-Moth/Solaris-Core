#ifndef APROXY_MOBILE_LWIP_ARCH_CC_H
#define APROXY_MOBILE_LWIP_ARCH_CC_H

#include <stdlib.h>

#ifndef BYTE_ORDER
#define BYTE_ORDER LITTLE_ENDIAN
#endif
#define LWIP_DONT_PROVIDE_BYTEORDER_FUNCTIONS
#define LWIP_RAND() ((unsigned int)arc4random())
#define LOCK_TCPIP_CORE() ((void)0)
#define UNLOCK_TCPIP_CORE() ((void)0)

#endif
