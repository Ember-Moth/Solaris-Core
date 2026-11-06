#ifndef SOLARIS_BLOCK_OUTBOUND_H
#define SOLARIS_BLOCK_OUTBOUND_H

#include "contracts/io/outbound.h"

typedef struct solaris_block_outbound {
    solaris_outbound_t outbound;
    int retired;
} solaris_block_outbound_t;

solaris_status_t solaris_block_outbound_init(solaris_block_outbound_t *block,
                                             solaris_executor_t *executor);

#endif
