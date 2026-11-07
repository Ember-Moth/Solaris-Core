#ifndef SOLARIS_ROUTE_INTERNAL_H
#define SOLARIS_ROUTE_INTERNAL_H
#include "contracts/policy/route.h"
solaris_status_t solaris_route_normalize_domain(const char *text, size_t length, int suffix, int keyword,
    char out[256]);
#endif
