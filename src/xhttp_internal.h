#ifndef APROXY_XHTTP_INTERNAL_H
#define APROXY_XHTTP_INTERNAL_H

#include "aproxy/xhttp.h"

int aproxy_xhttp_range_is_zero(aproxy_xhttp_range_t value);
int aproxy_xhttp_range_random(aproxy_xhttp_range_t value, int32_t *out);

#endif
