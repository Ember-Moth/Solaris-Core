#ifndef SOLARIS_DNS_WIRE_INTERNAL_H
#define SOLARIS_DNS_WIRE_INTERNAL_H
#include "contracts/dns/wire.h"
#include <stdatomic.h>

struct solaris_dns_wire {
    atomic_size_t references;
    solaris_buffer_t *buffer;
    solaris_dns_header_t header;
    solaris_dns_question_t question;
    solaris_dns_edns_t edns;
    size_t question_end, record_count;
    solaris_dns_record_t records[];
};
static inline uint16_t dns_u16(const uint8_t *p)
{ return (uint16_t)(((uint16_t)p[0] << 8) | p[1]); }
static inline uint32_t dns_u32(const uint8_t *p)
{ return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; }
static inline void dns_put16(uint8_t *p, uint16_t value)
{ p[0] = (uint8_t)(value >> 8); p[1] = (uint8_t)value; }
static inline void dns_put32(uint8_t *p, uint32_t value)
{ p[0] = (uint8_t)(value >> 24); p[1] = (uint8_t)(value >> 16); p[2] = (uint8_t)(value >> 8); p[3] = (uint8_t)value; }
int dns_name_valid(const solaris_dns_name_t *name);
solaris_status_t dns_limits(const solaris_dns_wire_limits_t *input, solaris_dns_wire_limits_t *out);
solaris_status_t dns_error(solaris_error_t *error, solaris_status_t status, size_t offset, const char *reason);
solaris_status_t dns_empty_response(solaris_budget_t *budget, const solaris_dns_wire_t *source,
    uint16_t flags, uint16_t rcode, solaris_buffer_t **out);
#endif
