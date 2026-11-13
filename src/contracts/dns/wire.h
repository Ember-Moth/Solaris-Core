#ifndef SOLARIS_DNS_WIRE_H
#define SOLARIS_DNS_WIRE_H

#include "contracts/io/buffer.h"

#define SOLARIS_DNS_MAX_MESSAGE 65535u
#define SOLARIS_DNS_MAX_NAME 255u
#define SOLARIS_DNS_DEFAULT_UDP_SIZE 1232u
#define SOLARIS_DNS_DEFAULT_RECORDS 256u
#define SOLARIS_DNS_MAX_RECORDS 4096u
#define SOLARIS_DNS_DEFAULT_POINTER_HOPS 32u
#define SOLARIS_DNS_MAX_POINTER_HOPS 128u

enum {
    SOLARIS_DNS_A = 1, SOLARIS_DNS_NS = 2, SOLARIS_DNS_CNAME = 5,
    SOLARIS_DNS_SOA = 6, SOLARIS_DNS_PTR = 12, SOLARIS_DNS_AAAA = 28,
    SOLARIS_DNS_OPT = 41, SOLARIS_DNS_IN = 1
};
enum {
    SOLARIS_DNS_QR = 0x8000, SOLARIS_DNS_AA = 0x0400,
    SOLARIS_DNS_TC = 0x0200, SOLARIS_DNS_RD = 0x0100,
    SOLARIS_DNS_RA = 0x0080, SOLARIS_DNS_AD = 0x0020,
    SOLARIS_DNS_CD = 0x0010, SOLARIS_DNS_DO = 0x8000
};
enum { SOLARIS_DNS_ANSWER = 0, SOLARIS_DNS_AUTHORITY = 1, SOLARIS_DNS_ADDITIONAL = 2 };
enum {
    SOLARIS_DNS_RDATA_OPAQUE = 0, SOLARIS_DNS_RDATA_ADDRESS = 1,
    SOLARIS_DNS_RDATA_NAME = 2, SOLARIS_DNS_RDATA_SOA = 3,
    SOLARIS_DNS_RDATA_OPT = 4
};

/* An uncompressed DNS name, including the final root octet. Labels can contain
 * arbitrary bytes, including NUL and '.'. Never treat bytes as a C string. */
typedef struct solaris_dns_name {
    uint16_t length;
    uint8_t bytes[SOLARIS_DNS_MAX_NAME];
} solaris_dns_name_t;
typedef struct solaris_dns_question {
    solaris_dns_name_t name;
    uint16_t type, class_code;
} solaris_dns_question_t;
typedef struct solaris_dns_soa {
    solaris_dns_name_t primary, mailbox;
    uint32_t serial, refresh, retry, expire, minimum;
} solaris_dns_soa_t;
typedef struct solaris_dns_record {
    solaris_dns_name_t name;
    uint16_t type, class_code;
    uint32_t ttl;
    uint8_t section, kind;
    /* Absolute offsets in the immutable DNS body, excluding TCP framing.
     * OPT's TTL word is extended RCODE/version/flags, never a cache TTL. */
    size_t offset, end, ttl_offset, rdata_offset, rdata_length;
    union {
        uint8_t address[16];
        solaris_dns_name_t target;
        solaris_dns_soa_t soa;
    } value;
} solaris_dns_record_t;
typedef struct solaris_dns_header {
    uint16_t id, flags, rcode;
    uint16_t questions, answers, authorities, additional;
} solaris_dns_header_t;
typedef struct solaris_dns_edns {
    uint16_t udp_size, flags;
    uint8_t present, version, extended_rcode;
    size_t option_count, options_offset, options_length;
} solaris_dns_edns_t;
typedef struct solaris_dns_option {
    uint16_t code;
    /* Borrowed slice; retain the message while using it, or retain its buffer. */
    solaris_slice_t data;
} solaris_dns_option_t;
typedef struct solaris_dns_wire_limits {
    size_t message_bytes;
    uint32_t records, pointer_hops;
} solaris_dns_wire_limits_t;
typedef struct solaris_dns_wire solaris_dns_wire_t;

void solaris_dns_wire_limits_init(solaris_dns_wire_limits_t *limits);
/* Zero limit fields use defaults. Hard maxima are the constants above.
 * Input is copied before return. Every view below is immutable and borrowed
 * from the owned message; retain/release may cross threads. No I/O occurs.
 * One question and QUERY opcode only. AXFR/IXFR/TKEY/TSIG/SIG(0), nonzero EDNS
 * version and unknown EDNS flag bits are explicitly unsupported. DNSSEC RRs
 * and EDNS option payloads are opaque; no authentication is implied.
 * Compression pointers must point backward to previously validated name-label
 * boundaries (never into headers/opaque RDATA). Loops, out-of-range targets,
 * reserved label encodings, trailing bytes and inconsistent counts fail. */
solaris_status_t solaris_dns_wire_parse(solaris_budget_t *budget,
    const void *bytes, size_t length, const solaris_dns_wire_limits_t *limits,
    solaris_dns_wire_t **out, solaris_error_t *error);
void solaris_dns_wire_retain(const solaris_dns_wire_t *message);
void solaris_dns_wire_release(const solaris_dns_wire_t *message);
const solaris_buffer_t *solaris_dns_wire_buffer(const solaris_dns_wire_t *message);
const solaris_dns_header_t *solaris_dns_wire_header(const solaris_dns_wire_t *message);
const solaris_dns_question_t *solaris_dns_wire_question(const solaris_dns_wire_t *message);
const solaris_dns_edns_t *solaris_dns_wire_edns(const solaris_dns_wire_t *message);
size_t solaris_dns_wire_record_count(const solaris_dns_wire_t *message);
const solaris_dns_record_t *solaris_dns_wire_record(const solaris_dns_wire_t *message, size_t index);
solaris_status_t solaris_dns_wire_option(const solaris_dns_wire_t *message, size_t index,
    solaris_dns_option_t *out);

/* Plain printable ASCII labels, optional one final dot, '.' for the root.
 * Backslash escapes are unsupported. Parsed wire names remain binary-safe.
 * Equality folds only ASCII A-Z in label data, never label lengths/binary bytes. */
solaris_status_t solaris_dns_name_from_text(const char *text, solaris_dns_name_t *out);
int solaris_dns_name_equal(const solaris_dns_name_t *a, const solaris_dns_name_t *b);
/* Validates QR, ID, opcode and the complete question. Source endpoint matching
 * belongs to the transport; this function alone does not authenticate a reply. */
solaris_status_t solaris_dns_wire_validate_reply(const solaris_dns_wire_t *query,
    const solaris_dns_wire_t *response);
size_t solaris_dns_wire_udp_limit(const solaris_dns_wire_t *query, size_t service_limit);

/* Returns a new published buffer. Only ID and real RR TTL words change; TTL
 * subtraction saturates at zero. Unknown RDATA/OPT stay byte-for-byte intact.
 * No minimum-TTL/cache-policy or DNSSEC validation decisions are made here. */
solaris_status_t solaris_dns_wire_rewrite(const solaris_dns_wire_t *message,
    solaris_budget_t *budget, uint16_t id, uint32_t elapsed_seconds, solaris_buffer_t **out);
/* Response only. Fits complete RR boundaries without relocating retained name
 * pointers. If opaque retained RDATA makes safety unprovable, returns a
 * question-only TC response. A bare OPT preserves extended RCODE/DO when needed;
 * EDNS options are not reconstructed. Truncation clears AD. Too small to hold
 * the question and necessary OPT returns EMSGSIZE. Never truncates input. */
solaris_status_t solaris_dns_wire_truncate(const solaris_dns_wire_t *message,
    solaris_budget_t *budget, size_t limit, solaris_buffer_t **out);

/* Builders encode uncompressed names and copy caller records before return.
 * Query flags: RD/CD/AD. EDNS, when supplied, must be version zero with no
 * options; it is a per-hop object, not copied from an upstream packet.
 * Response flags: AA/RA/TC only; RD/CD are echoed, AD is never synthesized.
 * Response records must be in section order and have supported typed IN RDATA
 * (A/AAAA/NS/CNAME/PTR/SOA). Opaque RDATA must use original-wire forwarding.
 * A request OPT produces one bare response OPT advertising 1232 bytes.
 * Extended RCODE requires OPT. */
solaris_status_t solaris_dns_wire_make_query(solaris_budget_t *budget, uint16_t id,
    uint16_t flags, const solaris_dns_question_t *question,
    const solaris_dns_edns_t *edns, solaris_buffer_t **out);
solaris_status_t solaris_dns_wire_make_response(solaris_budget_t *budget,
    const solaris_dns_wire_t *query, uint16_t flags, uint16_t rcode,
    const solaris_dns_record_t *records, size_t count, solaris_buffer_t **out);

/* TCP/DoT framing helper consumes exactly one complete frame. Partial input is
 * EAGAIN with consumed=0/out=NULL; a successful parse owns a body copy. */
solaris_status_t solaris_dns_wire_parse_frame(solaris_budget_t *budget,
    const void *bytes, size_t length, const solaris_dns_wire_limits_t *limits,
    size_t *consumed, solaris_dns_wire_t **out, solaris_error_t *error);
solaris_status_t solaris_dns_wire_frame(const solaris_dns_wire_t *message,
    solaris_budget_t *budget, solaris_buffer_t **out);

#endif
