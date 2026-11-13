#include "contracts/dns/wire.h"
#include "fixtures.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)
typedef struct allocation_state { size_t calls, fail_at, outstanding; } allocation_state_t;
static void *allocate(void *context, size_t size)
{
    allocation_state_t *state = context; ++state->calls;
    if (state->fail_at && state->calls == state->fail_at) return NULL;
    void *p = malloc(size); if (p) ++state->outstanding; return p;
}
static void deallocate(void *context, void *pointer)
{ allocation_state_t *state = context; CHECK(state->outstanding); --state->outstanding; free(pointer); }
static uint64_t now(void *context) { (void)context; return 1; }
static unsigned nibble(char c)
{
    if (c >= '0' && c <= '9') return (unsigned)(c - '0');
    CHECK(c >= 'a' && c <= 'f'); return (unsigned)(c - 'a' + 10);
}
static size_t hex(const char *source, uint8_t *out, size_t capacity)
{
    size_t length = 0;
    while (*source) {
        if (*source == ' ') { ++source; continue; }
        CHECK(source[1] && length < capacity);
        out[length++] = (uint8_t)((nibble(source[0]) << 4) | nibble(source[1])); source += 2;
    }
    return length;
}
static void put16(uint8_t *out, unsigned value) { out[0] = (uint8_t)(value >> 8); out[1] = (uint8_t)value; }
static void put32(uint8_t *out, uint32_t value)
{ out[0] = (uint8_t)(value >> 24); out[1] = (uint8_t)(value >> 16); out[2] = (uint8_t)(value >> 8); out[3] = (uint8_t)value; }
static solaris_dns_wire_t *parse(solaris_budget_t *budget, const void *bytes, size_t length)
{
    solaris_dns_wire_t *message = NULL; solaris_error_t error;
    solaris_status_t rc = solaris_dns_wire_parse(budget, bytes, length, NULL, &message, &error);
    if (rc != SOLARIS_OK) fprintf(stderr, "parse failed: %d %s (length %zu)\n", rc, error.message, length);
    CHECK(rc == SOLARIS_OK && message && error.code == SOLARIS_OK);
    return message;
}
static solaris_dns_wire_t *parse_buffer(solaris_budget_t *budget, const solaris_buffer_t *buffer)
{ return parse(budget, solaris_buffer_data(buffer), solaris_buffer_length(buffer)); }
static void invalid(solaris_budget_t *budget, const void *bytes, size_t length,
    const solaris_dns_wire_limits_t *limits, solaris_status_t expected)
{
    size_t before = solaris_budget_used(budget); solaris_dns_wire_t *message = (void *)1; solaris_error_t error;
    solaris_status_t rc = solaris_dns_wire_parse(budget, bytes, length, limits, &message, &error);
    if (rc != expected) fprintf(stderr, "expected %d got %d: %s\n", expected, rc, error.message);
    CHECK(rc == expected && !message && error.code == rc);
    CHECK(error.message[0] && memchr(error.message, 0, sizeof(error.message)));
    CHECK(solaris_budget_used(budget) == before);
}
static void equals_hex(const solaris_buffer_t *buffer, const char *expected)
{
    uint8_t bytes[512]; size_t length = hex(expected, bytes, sizeof(bytes));
    CHECK(solaris_buffer_length(buffer) == length && !memcmp(solaris_buffer_data(buffer), bytes, length));
    CHECK(solaris_buffer_mutable_data((solaris_buffer_t *)buffer) == NULL);
}
static solaris_dns_name_t name(const char *text)
{ solaris_dns_name_t value; CHECK(solaris_dns_name_from_text(text, &value) == SOLARIS_OK); return value; }

static void golden(solaris_budget_t *budget)
{
    uint8_t bytes[512], original[512]; size_t length = hex(dns_response_hex, bytes, sizeof(bytes));
    CHECK(length == 215); memcpy(original, bytes, length);
    solaris_dns_wire_t *message = parse(budget, bytes, length);
    memset(bytes, 0xee, length); /* caller input is no longer relevant */
    solaris_dns_wire_retain(message); solaris_dns_wire_release(message);
    const solaris_dns_header_t *header = solaris_dns_wire_header(message);
    CHECK(header->id == 0x1234 && header->flags == 0x81a0 && header->rcode == 0);
    CHECK(header->questions == 1 && header->answers == 3 && header->authorities == 1 && header->additional == 3);
    CHECK(solaris_dns_wire_record_count(message) == 7 && !solaris_dns_wire_record(message, 7));
    const solaris_dns_question_t *question = solaris_dns_wire_question(message);
    solaris_dns_name_t expected = name("WWW.EXAMPLE.COM.");
    CHECK(solaris_dns_name_equal(&question->name, &expected) && question->type == 1 && question->class_code == 1);
    expected = name("alias.example.com");
    const solaris_dns_record_t *r = solaris_dns_wire_record(message, 0);
    CHECK(r->offset == 33 && r->end == 53 && r->rdata_offset == 45 && r->rdata_length == 8);
    CHECK(r->ttl_offset == 39 && r->ttl == 300 && r->kind == SOLARIS_DNS_RDATA_NAME);
    CHECK(solaris_dns_name_equal(&r->value.target, &expected));
    r = solaris_dns_wire_record(message, 1);
    CHECK(r->end == 69 && r->ttl == 60 && r->type == SOLARIS_DNS_A && r->value.address[0] == 127 && r->value.address[3] == 9);
    CHECK(solaris_dns_name_equal(&r->name, &expected));
    r = solaris_dns_wire_record(message, 2);
    CHECK(r->end == 97 && r->ttl == 120 && r->type == SOLARIS_DNS_AAAA);
    for (size_t i = 0; i < 15; ++i) CHECK(r->value.address[i] == 0);
    CHECK(r->value.address[15] == 1);
    r = solaris_dns_wire_record(message, 3);
    CHECK(r->end == 141 && r->section == SOLARIS_DNS_AUTHORITY && r->kind == SOLARIS_DNS_RDATA_SOA);
    expected = name("ns.example.com"); CHECK(solaris_dns_name_equal(&r->value.soa.primary, &expected));
    expected = name("host.example.com"); CHECK(solaris_dns_name_equal(&r->value.soa.mailbox, &expected));
    CHECK(r->value.soa.serial == 1 && r->value.soa.refresh == 2 && r->value.soa.retry == 3 && r->value.soa.expire == 4 && r->value.soa.minimum == 5);
    r = solaris_dns_wire_record(message, 4);
    CHECK(r->end == 177 && r->type == SOLARIS_DNS_PTR && r->section == SOLARIS_DNS_ADDITIONAL);
    expected = name("9.0.0.127.in-addr.arpa"); CHECK(solaris_dns_name_equal(&r->name, &expected));
    r = solaris_dns_wire_record(message, 5);
    CHECK(r->kind == SOLARIS_DNS_RDATA_OPAQUE && r->type == 65000 && r->rdata_length == 4);
    CHECK(!memcmp(solaris_buffer_data(solaris_dns_wire_buffer(message)) + r->rdata_offset, "\xc0\xff\xde\xad", 4));
    const solaris_dns_edns_t *edns = solaris_dns_wire_edns(message);
    CHECK(edns->present && edns->udp_size == 1232 && edns->flags == SOLARIS_DNS_DO && edns->option_count == 2);
    solaris_dns_option_t option;
    CHECK(solaris_dns_wire_option(message, 0, &option) == SOLARIS_OK && option.code == 65001 && option.data.length == 3);
    CHECK(solaris_slice_valid(&option.data) && !memcmp(solaris_buffer_data(option.data.buffer) + option.data.offset, "abc", 3));
    solaris_buffer_retain(option.data.buffer);
    const solaris_buffer_t *retained = option.data.buffer;
    CHECK(solaris_dns_wire_option(message, 1, &option) == SOLARIS_OK && option.code == 12 && !option.data.length);
    CHECK(solaris_dns_wire_option(message, 2, &option) == SOLARIS_EINVAL && !option.data.buffer);
    solaris_buffer_t *rewritten;
    CHECK(solaris_dns_wire_rewrite(message, budget, 0xabcd, 70, &rewritten) == SOLARIS_OK);
    solaris_dns_wire_t *aged = parse_buffer(budget, rewritten);
    CHECK(solaris_dns_wire_header(aged)->id == 0xabcd);
    const uint32_t ages[] = {230, 0, 50, 1730, 0, 0};
    for (size_t i = 0; i < 6; ++i) CHECK(solaris_dns_wire_record(aged, i)->ttl == ages[i]);
    CHECK(solaris_dns_wire_record(aged, 6)->ttl == SOLARIS_DNS_DO);
    for (size_t i = 2; i < length; ++i) {
        int ttl_byte = 0;
        for (size_t j = 0; j < 6; ++j) {
            size_t offset = solaris_dns_wire_record(message, j)->ttl_offset;
            ttl_byte |= i >= offset && i < offset + 4;
        }
        if (!ttl_byte) CHECK(solaris_buffer_data(rewritten)[i] == original[i]);
    }
    CHECK(!memcmp(solaris_buffer_data(solaris_dns_wire_buffer(message)), original, length));
    solaris_dns_wire_release(aged); solaris_buffer_release(rewritten);
    CHECK(solaris_dns_wire_rewrite(message, budget, 0x1234, UINT32_MAX, &rewritten) == SOLARIS_OK);
    aged = parse_buffer(budget, rewritten);
    for (size_t i = 0; i < 6; ++i) CHECK(solaris_dns_wire_record(aged, i)->ttl == 0);
    solaris_dns_wire_release(aged); solaris_buffer_release(rewritten);
    solaris_dns_wire_release(message);
    CHECK(solaris_buffer_length(retained) == length && !memcmp(solaris_buffer_data(retained), original, length));
    solaris_buffer_release(retained); CHECK(solaris_budget_used(budget) == 0);
}
static void names(solaris_budget_t *budget)
{
    solaris_dns_name_t a = name("ExAmPlE.com"), b = name("example.COM.");
    CHECK(solaris_dns_name_equal(&a, &b));
    a = name("."); CHECK(a.length == 1 && a.bytes[0] == 0);
    const char *bad[] = {"", "..", "a..b", ".a", "a..", "a b", "a\n"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(*bad); ++i) CHECK(solaris_dns_name_from_text(bad[i], &a) == SOLARIS_EINVAL && !a.length);
    CHECK(solaris_dns_name_from_text("a\\046b", &a) == SOLARIS_ENOTSUP && !a.length);
    char text[300]; size_t offset = 0;
    for (unsigned i = 0; i < 4; ++i) { size_t n = i == 3 ? 61 : 63; memset(text + offset, 'x', n); offset += n; if (i != 3) text[offset++] = '.'; }
    text[offset] = 0; a = name(text); CHECK(a.length == 255);
    solaris_dns_question_t q = {.name = a, .type = 1, .class_code = 1}; solaris_buffer_t *wire;
    CHECK(solaris_dns_wire_make_query(budget, 1, 0, &q, NULL, &wire) == SOLARIS_OK);
    solaris_dns_wire_t *message = parse_buffer(budget, wire); CHECK(solaris_dns_wire_question(message)->name.length == 255);
    solaris_dns_wire_release(message); solaris_buffer_release(wire);
    memset(text, 'x', 64); text[64] = 0;
    CHECK(solaris_dns_name_from_text(text, &a) == SOLARIS_EMSGSIZE);
    memset(text, 'x', 255); text[255] = 0;
    CHECK(solaris_dns_name_from_text(text, &a) == SOLARIS_EMSGSIZE);
    /* A binary label has literal NUL/dot/high bytes; these are not separators. */
    uint8_t binary[] = {0,1,1,0,0,1,0,0,0,0,0,0, 4,'A',0,'.',0xff,0, 0,1,0,1};
    message = parse(budget, binary, sizeof(binary));
    a = solaris_dns_wire_question(message)->name; b = a; b.bytes[1] = 'a';
    CHECK(a.length == 6 && solaris_dns_name_equal(&a, &b));
    b.bytes[4] = 0xfe; CHECK(!solaris_dns_name_equal(&a, &b));
    b = a; b.bytes[0] = 64; CHECK(!solaris_dns_name_equal(&a, &b));
    solaris_dns_wire_release(message);
}
static void builders(solaris_budget_t *budget)
{
    uint8_t bytes[512]; size_t length = hex(dns_query_hex, bytes, sizeof(bytes));
    solaris_dns_wire_t *query = parse(budget, bytes, length); solaris_buffer_t *wire;
    const solaris_dns_question_t *q = solaris_dns_wire_question(query);
    CHECK(solaris_dns_wire_make_query(budget, 0x1234, SOLARIS_DNS_RD, q, NULL, &wire) == SOLARIS_OK);
    equals_hex(wire, dns_query_hex); solaris_buffer_release(wire);
    solaris_dns_edns_t edns = {.present = 1, .udp_size = 1232, .flags = SOLARIS_DNS_DO};
    CHECK(solaris_dns_wire_make_query(budget, 0x1234, SOLARIS_DNS_RD, q, &edns, &wire) == SOLARIS_OK);
    equals_hex(wire, dns_query_edns_hex); solaris_dns_wire_t *query_edns = parse_buffer(budget, wire); solaris_buffer_release(wire);
    solaris_dns_record_t rr = {.name = q->name, .type = SOLARIS_DNS_A, .class_code = SOLARIS_DNS_IN,
        .ttl = 60, .kind = SOLARIS_DNS_RDATA_ADDRESS, .value.address = {127, 0, 0, 9}};
    CHECK(solaris_dns_wire_make_response(budget, query, SOLARIS_DNS_AA | SOLARIS_DNS_RA, 0, &rr, 1, &wire) == SOLARIS_OK);
    equals_hex(wire, dns_built_a_hex); solaris_dns_wire_t *response = parse_buffer(budget, wire); solaris_buffer_release(wire);
    CHECK(solaris_dns_wire_validate_reply(query, response) == SOLARIS_OK);
    CHECK(solaris_dns_wire_validate_reply(query, query) == SOLARIS_EINVAL);
    CHECK(solaris_dns_wire_validate_reply(response, query) == SOLARIS_EINVAL);
    CHECK(solaris_dns_wire_make_response(budget, query_edns, SOLARIS_DNS_RA, 3, NULL, 0, &wire) == SOLARIS_OK);
    equals_hex(wire, dns_empty_edns_hex); solaris_buffer_release(wire);
    CHECK(solaris_dns_wire_make_response(budget, query_edns, SOLARIS_DNS_RA, 16, NULL, 0, &wire) == SOLARIS_OK);
    solaris_dns_wire_t *extended = parse_buffer(budget, wire);
    CHECK(solaris_dns_wire_header(extended)->rcode == 16 && solaris_dns_wire_edns(extended)->extended_rcode == 1);
    solaris_dns_wire_release(extended); solaris_buffer_release(wire);
    CHECK(solaris_dns_wire_make_response(budget, query, 0, 16, NULL, 0, &wire) == SOLARIS_ENOTSUP && !wire);
    CHECK(solaris_dns_wire_make_response(budget, query, SOLARIS_DNS_AD, 0, NULL, 0, &wire) == SOLARIS_EINVAL && !wire);
    CHECK(solaris_dns_wire_make_response(budget, response, 0, 0, NULL, 0, &wire) == SOLARIS_EINVAL && !wire);
    edns.option_count = 1;
    CHECK(solaris_dns_wire_make_query(budget, 1, 0, q, &edns, &wire) == SOLARIS_ENOTSUP && !wire);
    edns.option_count = 0; edns.version = 1;
    CHECK(solaris_dns_wire_make_query(budget, 1, 0, q, &edns, &wire) == SOLARIS_ENOTSUP && !wire);
    CHECK(solaris_dns_wire_make_query(budget, 1, SOLARIS_DNS_QR, q, NULL, &wire) == SOLARIS_EINVAL && !wire);
    rr.type = 65000; rr.kind = SOLARIS_DNS_RDATA_OPAQUE;
    CHECK(solaris_dns_wire_make_response(budget, query, 0, 0, &rr, 1, &wire) == SOLARIS_ENOTSUP && !wire);
    /* Exercise all typed encoders with parsed, independently authored inputs. */
    length = hex(dns_response_hex, bytes, sizeof(bytes)); solaris_dns_wire_t *gold = parse(budget, bytes, length);
    solaris_dns_record_t records[5]; for (size_t i = 0; i < 5; ++i) records[i] = *solaris_dns_wire_record(gold, i);
    solaris_dns_wire_release(gold);
    CHECK(solaris_dns_wire_make_response(budget, query_edns, SOLARIS_DNS_RA, 0, records, 5, &wire) == SOLARIS_OK);
    solaris_dns_wire_t *rebuilt = parse_buffer(budget, wire); solaris_buffer_release(wire);
    CHECK(solaris_dns_wire_record_count(rebuilt) == 6 && solaris_dns_wire_record(rebuilt, 3)->value.soa.minimum == 5);
    CHECK(solaris_dns_name_equal(&solaris_dns_wire_record(rebuilt, 4)->value.target, &records[4].value.target));
    solaris_dns_wire_release(rebuilt);
    records[0].section = SOLARIS_DNS_ADDITIONAL;
    CHECK(solaris_dns_wire_make_response(budget, query, 0, 0, records, 5, &wire) == SOLARIS_EINVAL && !wire);
    /* Match is case-insensitive, but not type/class/ID-insensitive. */
    length = hex(dns_built_a_hex, bytes, sizeof(bytes)); bytes[13] = 'W';
    rebuilt = parse(budget, bytes, length); CHECK(solaris_dns_wire_validate_reply(query, rebuilt) == SOLARIS_OK); solaris_dns_wire_release(rebuilt);
    bytes[0] ^= 1; rebuilt = parse(budget, bytes, length); CHECK(solaris_dns_wire_validate_reply(query, rebuilt) == SOLARIS_EINVAL); solaris_dns_wire_release(rebuilt);
    bytes[0] ^= 1; bytes[30] = 28; rebuilt = parse(budget, bytes, length); CHECK(solaris_dns_wire_validate_reply(query, rebuilt) == SOLARIS_EINVAL); solaris_dns_wire_release(rebuilt);
    solaris_dns_wire_release(response); solaris_dns_wire_release(query_edns); solaris_dns_wire_release(query);
}
static void truncation_and_frames(solaris_budget_t *budget)
{
    uint8_t bytes[1024]; size_t length = hex(dns_response_hex, bytes, sizeof(bytes));
    solaris_dns_wire_t *message = parse(budget, bytes, length); solaris_buffer_t *wire;
    CHECK(solaris_dns_wire_truncate(message, budget, length, &wire) == SOLARIS_OK);
    equals_hex(wire, dns_response_hex); solaris_buffer_release(wire);
    CHECK(solaris_dns_wire_truncate(message, budget, 80, &wire) == SOLARIS_OK && solaris_buffer_length(wire) == 80);
    solaris_dns_wire_t *small = parse_buffer(budget, wire); solaris_buffer_release(wire);
    const solaris_dns_header_t *h = solaris_dns_wire_header(small);
    CHECK(h->answers == 2 && h->authorities == 0 && h->additional == 1 && (h->flags & SOLARIS_DNS_TC) && !(h->flags & SOLARIS_DNS_AD));
    CHECK(solaris_dns_wire_record(small, 1)->value.address[3] == 9 && solaris_dns_wire_edns(small)->option_count == 0);
    solaris_dns_wire_release(small);
    /* Opaque pointer-looking RDATA would fit: conservative question-only TC. */
    CHECK(solaris_dns_wire_truncate(message, budget, 210, &wire) == SOLARIS_OK && solaris_buffer_length(wire) == 44);
    small = parse_buffer(budget, wire); solaris_buffer_release(wire);
    h = solaris_dns_wire_header(small); CHECK(!h->answers && !h->authorities && h->additional == 1 && (h->flags & SOLARIS_DNS_TC));
    solaris_dns_wire_release(small);
    CHECK(solaris_dns_wire_truncate(message, budget, 43, &wire) == SOLARIS_EMSGSIZE && !wire);
    CHECK(solaris_dns_wire_frame(message, budget, &wire) == SOLARIS_OK);
    CHECK(solaris_buffer_length(wire) == length + 2 && solaris_buffer_data(wire)[0] == 0 && solaris_buffer_data(wire)[1] == length);
    for (size_t n = 0; n < length + 2; ++n) {
        size_t consumed = 99; small = (void *)1;
        CHECK(solaris_dns_wire_parse_frame(budget, solaris_buffer_data(wire), n, NULL, &consumed, &small, NULL) == SOLARIS_EAGAIN);
        CHECK(!small && !consumed);
    }
    memcpy(bytes, solaris_buffer_data(wire), length + 2); memcpy(bytes + length + 2, solaris_buffer_data(wire), length + 2);
    size_t consumed;
    CHECK(solaris_dns_wire_parse_frame(budget, bytes, (length + 2) * 2, NULL, &consumed, &small, NULL) == SOLARIS_OK && consumed == length + 2);
    memset(bytes, 0, sizeof(bytes)); CHECK(solaris_dns_wire_header(small)->id == 0x1234);
    solaris_dns_wire_release(small); solaris_buffer_release(wire); solaris_dns_wire_release(message);
}
static size_t cname_chain(uint8_t *bytes, unsigned count)
{
    size_t position = hex(dns_query_hex, bytes, 8192); put16(bytes + 2, 0x8180); put16(bytes + 6, count);
    size_t previous = 12;
    for (unsigned i = 0; i < count; ++i) {
        put16(bytes + position, 0xc00c); put16(bytes + position + 2, 5); put16(bytes + position + 4, 1);
        put32(bytes + position + 6, 30); put16(bytes + position + 10, 2);
        put16(bytes + position + 12, (unsigned)(0xc000u | previous)); previous = position + 12; position += 14;
    }
    return position;
}
static void malformed(solaris_budget_t *budget)
{
    uint8_t bytes[8192]; size_t length = hex(dns_response_hex, bytes, sizeof(bytes));
    for (size_t n = 0; n < length; ++n) {
        solaris_dns_wire_t *m = NULL; size_t before = solaris_budget_used(budget);
        CHECK(solaris_dns_wire_parse(budget, bytes, n, NULL, &m, NULL) != SOLARIS_OK && !m);
        CHECK(solaris_budget_used(budget) == before);
    }
    bytes[length] = 0; invalid(budget, bytes, length + 1, NULL, SOLARIS_EINVAL);
    const unsigned qcounts[] = {0, 2};
    for (size_t i = 0; i < 2; ++i) { put16(bytes + 4, qcounts[i]); invalid(budget, bytes, length, NULL, SOLARIS_ENOTSUP); }
    put16(bytes + 4, 1); put16(bytes + 2, 0xa9a0); invalid(budget, bytes, length, NULL, SOLARIS_ENOTSUP);
    put16(bytes + 2, 0x81e0); invalid(budget, bytes, length, NULL, SOLARIS_EINVAL);
    put16(bytes + 2, 0x81a0); put16(bytes + 6, 4); invalid(budget, bytes, length, NULL, SOLARIS_EINVAL);
    put16(bytes + 6, 65535); invalid(budget, bytes, length, NULL, SOLARIS_EOVERFLOW);
    hex(dns_response_hex, bytes, sizeof(bytes));
    const unsigned targets[] = {0, 13, 33, 214, 16383};
    for (size_t i = 0; i < sizeof(targets) / sizeof(*targets); ++i) {
        put16(bytes + 33, 0xc000u | targets[i]); invalid(budget, bytes, length, NULL, SOLARIS_EINVAL);
    }
    hex(dns_response_hex, bytes, sizeof(bytes)); bytes[33] = 0x40; invalid(budget, bytes, length, NULL, SOLARIS_EINVAL);
    hex(dns_response_hex, bytes, sizeof(bytes)); bytes[33] = 0x80; invalid(budget, bytes, length, NULL, SOLARIS_EINVAL);
    hex(dns_response_hex, bytes, sizeof(bytes)); put16(bytes + 63, 3); invalid(budget, bytes, length, NULL, SOLARIS_EINVAL);
    hex(dns_response_hex, bytes, sizeof(bytes)); put16(bytes + 107, 31); invalid(budget, bytes, length, NULL, SOLARIS_EINVAL);
    /* A known-name cycle entirely inside CNAME RDATA, with backward pointers. */
    length = cname_chain(bytes, 1); put16(bytes + 43, 4); bytes[45] = 1; bytes[46] = 'x'; put16(bytes + 47, 0xc02d);
    invalid(budget, bytes, length + 2, NULL, SOLARIS_EINVAL);
    length = cname_chain(bytes, 32); solaris_dns_wire_t *m = parse(budget, bytes, length); solaris_dns_wire_release(m);
    length = cname_chain(bytes, 33); invalid(budget, bytes, length, NULL, SOLARIS_EOVERFLOW);
    solaris_dns_wire_limits_t limits; solaris_dns_wire_limits_init(&limits); limits.pointer_hops = 33;
    CHECK(solaris_dns_wire_parse(budget, bytes, length, &limits, &m, NULL) == SOLARIS_OK); solaris_dns_wire_release(m);
    limits.records = 32; invalid(budget, bytes, length, &limits, SOLARIS_EOVERFLOW);
    limits.records = 33; limits.message_bytes = length - 1; invalid(budget, bytes, length, &limits, SOLARIS_EMSGSIZE);
    limits.message_bytes = 65536; invalid(budget, bytes, length, &limits, SOLARIS_EINVAL);
    solaris_dns_wire_limits_init(&limits); limits.pointer_hops = 129; invalid(budget, bytes, length, &limits, SOLARIS_EINVAL);
    solaris_dns_wire_limits_init(&limits); limits.records = 4097; invalid(budget, bytes, length, &limits, SOLARIS_EINVAL);
    length = hex(dns_query_hex, bytes, sizeof(bytes));
    for (unsigned type = 249; type <= 252; ++type) { put16(bytes + 29, type); invalid(budget, bytes, length, NULL, SOLARIS_ENOTSUP); }
    length = hex(dns_response_hex, bytes, sizeof(bytes)); put16(bytes + 179, 250); invalid(budget, bytes, length, NULL, SOLARIS_ENOTSUP);
    /* A private RR's RDATA is not a validated pointer target for later names. */
    length = hex(dns_response_hex, bytes, sizeof(bytes)); put16(bytes + 35, 65000); invalid(budget, bytes, length, NULL, SOLARIS_EINVAL);
    length = hex(dns_response_hex, bytes, sizeof(bytes)); bytes[199] = 1; invalid(budget, bytes, length, NULL, SOLARIS_ENOTSUP);
    length = hex(dns_response_hex, bytes, sizeof(bytes)); bytes[201] = 1; invalid(budget, bytes, length, NULL, SOLARIS_ENOTSUP);
    length = hex(dns_response_hex, bytes, sizeof(bytes)); put16(bytes + 206, 30); invalid(budget, bytes, length, NULL, SOLARIS_EINVAL);
    length = hex(dns_response_hex, bytes, sizeof(bytes)); put16(bytes + 10, 4);
    static const uint8_t opt[] = {0,0,41,4,208,0,0,0,0,0,0}; memcpy(bytes + length, opt, sizeof(opt));
    invalid(budget, bytes, length + sizeof(opt), NULL, SOLARIS_EINVAL);
    length = hex(dns_query_edns_hex, bytes, sizeof(bytes)); bytes[38] = 1; invalid(budget, bytes, length, NULL, SOLARIS_EINVAL);
    length = hex(dns_query_edns_hex, bytes, sizeof(bytes)); put16(bytes + 2, 0x8180); put16(bytes + 6, 1); put16(bytes + 10, 0);
    invalid(budget, bytes, length, NULL, SOLARIS_EINVAL);
    length = hex(dns_query_edns_hex, bytes, sizeof(bytes)); put16(bytes + 36, 0); m = parse(budget, bytes, length);
    CHECK(solaris_dns_wire_udp_limit(m, 1232) == 512); solaris_dns_wire_release(m);
    put16(bytes + 36, 4096); m = parse(budget, bytes, length);
    CHECK(solaris_dns_wire_udp_limit(m, 1232) == 1232); solaris_dns_wire_release(m);
    size_t consumed = 99; m = (void *)1; uint8_t prefix[] = {0, 0};
    CHECK(solaris_dns_wire_parse_frame(budget, prefix, 2, NULL, &consumed, &m, NULL) == SOLARIS_EINVAL && !m && !consumed);
    prefix[0] = 1; prefix[1] = 1; solaris_dns_wire_limits_init(&limits); limits.message_bytes = 256;
    CHECK(solaris_dns_wire_parse_frame(budget, prefix, 2, &limits, &consumed, &m, NULL) == SOLARIS_EMSGSIZE && !m && !consumed);
    /* Maximum uncompressed wire name is 255 octets, including the root. */
    memset(bytes, 0, 300); put16(bytes + 4, 1);
    length = 12;
    for (unsigned i = 0; i < 4; ++i) { bytes[length++] = 63; memset(bytes + length, 'a', 63); length += 63; }
    bytes[length++] = 0; put16(bytes + length, 1); put16(bytes + length + 2, 1); length += 4;
    invalid(budget, bytes, length, NULL, SOLARIS_EOVERFLOW);
    length = hex(dns_query_hex, bytes, sizeof(bytes)); put16(bytes + 31, 0);
    invalid(budget, bytes, length, NULL, SOLARIS_EINVAL);
    length = hex(dns_query_edns_hex, bytes, sizeof(bytes));
    memmove(bytes + 35, bytes + 34, length - 34); put16(bytes + 33, 0xc01c);
    invalid(budget, bytes, length + 1, NULL, SOLARIS_EINVAL); /* compressed OPT root */
    length = hex(dns_response_hex, bytes, sizeof(bytes)); put16(bytes + 179, 24);
    invalid(budget, bytes, length, NULL, SOLARIS_ENOTSUP); /* SIG(0) */
    length = hex(dns_response_hex, bytes, sizeof(bytes)); put16(bytes + 35, 2);
    m = parse(budget, bytes, length); CHECK(solaris_dns_wire_record(m, 0)->kind == SOLARIS_DNS_RDATA_NAME); solaris_dns_wire_release(m);
}
static void mutations(solaris_budget_t *budget)
{
    uint8_t original[512], bytes[512]; size_t length = hex(dns_response_hex, original, sizeof(original));
    static const uint8_t values[] = {0, 1, 0x3f, 0x40, 0xc0, 0xff};
    for (size_t offset = 0; offset < length; ++offset) for (size_t i = 0; i < sizeof(values); ++i) {
        memcpy(bytes, original, length); bytes[offset] = values[i];
        solaris_dns_wire_t *message = NULL;
        if (solaris_dns_wire_parse(budget, bytes, length, NULL, &message, NULL) == SOLARIS_OK) {
            solaris_buffer_t *wire;
            CHECK(solaris_dns_wire_rewrite(message, budget, 0x4321, 1, &wire) == SOLARIS_OK);
            solaris_dns_wire_t *copy = parse_buffer(budget, wire); solaris_dns_wire_release(copy); solaris_buffer_release(wire);
            if (solaris_dns_wire_header(message)->flags & SOLARIS_DNS_QR) {
                solaris_status_t rc = solaris_dns_wire_truncate(message, budget, 128, &wire);
                CHECK(rc == SOLARIS_OK || rc == SOLARIS_EMSGSIZE);
                if (rc == SOLARIS_OK) {
                    CHECK(solaris_buffer_length(wire) <= 128);
                    copy = parse_buffer(budget, wire); solaris_dns_wire_release(copy); solaris_buffer_release(wire);
                }
            }
            solaris_dns_wire_release(message);
        } else CHECK(!message);
        CHECK(solaris_budget_used(budget) == 0);
    }
}
static void maximum_and_failure(solaris_budget_t *budget, allocation_state_t *allocation)
{
    uint8_t *bytes = calloc(1, 65538); CHECK(bytes);
    size_t position = hex(dns_query_hex, bytes, 65538); put16(bytes + 2, 0x8180); put16(bytes + 6, 1);
    put16(bytes + position, 0xc00c); put16(bytes + position + 2, 65000); put16(bytes + position + 4, 1);
    put32(bytes + position + 6, 60); put16(bytes + position + 10, (unsigned)(65535 - position - 12));
    solaris_dns_wire_t *message = parse(budget, bytes, 65535); solaris_buffer_t *wire;
    CHECK(solaris_dns_wire_frame(message, budget, &wire) == SOLARIS_OK && solaris_buffer_length(wire) == 65537);
    size_t consumed; solaris_dns_wire_t *framed;
    CHECK(solaris_dns_wire_parse_frame(budget, solaris_buffer_data(wire), 65537, NULL, &consumed, &framed, NULL) == SOLARIS_OK && consumed == 65537);
    solaris_dns_wire_release(framed); solaris_buffer_release(wire); solaris_dns_wire_release(message);
    invalid(budget, bytes, 65536, NULL, SOLARIS_EMSGSIZE);
    size_t length = hex(dns_response_hex, bytes, 65538);
    for (size_t failure = 1; failure <= 3; ++failure) {
        allocation->calls = 0; allocation->fail_at = failure; message = (void *)1;
        solaris_status_t rc = solaris_dns_wire_parse(budget, bytes, length, NULL, &message, NULL);
        if (failure <= 2) CHECK(rc == SOLARIS_ENOMEM && !message);
        else { CHECK(rc == SOLARIS_OK); solaris_dns_wire_release(message); }
        CHECK(solaris_budget_used(budget) == 0);
    }
    allocation->fail_at = 0; message = parse(budget, bytes, length); size_t baseline = solaris_budget_used(budget);
    for (unsigned operation = 0; operation < 3; ++operation) {
        allocation->calls = 0; allocation->fail_at = 1; wire = (void *)1;
        solaris_status_t rc = operation == 0 ? solaris_dns_wire_rewrite(message, budget, 9, 1, &wire) :
            operation == 1 ? solaris_dns_wire_truncate(message, budget, 210, &wire) : solaris_dns_wire_frame(message, budget, &wire);
        CHECK(rc == SOLARIS_ENOMEM && !wire && solaris_budget_used(budget) == baseline);
    }
    allocation->fail_at = 0; solaris_dns_wire_release(message);
    length = hex(dns_query_hex, bytes, 65538); message = parse(budget, bytes, length); baseline = solaris_budget_used(budget);
    allocation->calls = 0; allocation->fail_at = 1;
    CHECK(solaris_dns_wire_make_query(budget, 1, 0, solaris_dns_wire_question(message), NULL, &wire) == SOLARIS_ENOMEM && !wire);
    allocation->calls = 0;
    CHECK(solaris_dns_wire_make_response(budget, message, 0, 0, NULL, 0, &wire) == SOLARIS_ENOMEM && !wire);
    CHECK(solaris_budget_used(budget) == baseline);
    allocation->fail_at = 0; solaris_dns_wire_release(message);
    solaris_budget_t *tiny; CHECK(solaris_budget_create(1, NULL, &tiny) == SOLARIS_OK);
    invalid(tiny, bytes, length, NULL, SOLARIS_ENOMEM); CHECK(!solaris_budget_used(tiny)); solaris_budget_release(tiny);
    free(bytes); CHECK(solaris_budget_used(budget) == 0);
}
int main(void)
{
    allocation_state_t allocation = {0};
    solaris_runtime_services_t services = {&allocation, allocate, deallocate, now, NULL};
    solaris_budget_t *budget; CHECK(solaris_budget_create(8u * 1024u * 1024u, &services, &budget) == SOLARIS_OK);
    golden(budget); names(budget); builders(budget); truncation_and_frames(budget); malformed(budget); mutations(budget); maximum_and_failure(budget, &allocation);
    CHECK(solaris_budget_used(budget) == 0); solaris_budget_release(budget); CHECK(allocation.outstanding == 0);
    puts("DNS wire: independent query/response fixtures, typed records, EDNS, pointer policy, safe rewrite/truncate/framing and allocation cleanup passed");
    return 0;
}
