#ifndef APROXY_PLATFORM_H
#define APROXY_PLATFORM_H

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#define strcasecmp _stricmp
#define strncasecmp _strnicmp
#define strdup _strdup
#else
#include <arpa/inet.h>
#endif

#endif
