#include "codec/dns/internal.h"
#include <string.h>

static int question_valid(const solaris_dns_question_t *question)
{
    return question && dns_name_valid(&question->name) && question->type && question->class_code;
}
static solaris_status_t edns_valid(const solaris_dns_edns_t *edns)
{
    if (!edns || !edns->present) return SOLARIS_OK;
    if (edns->present != 1) return SOLARIS_EINVAL;
    if (edns->version || edns->options_length || edns->option_count ||
        (edns->flags & (uint16_t)~SOLARIS_DNS_DO)) return SOLARIS_ENOTSUP;
    return SOLARIS_OK;
}
static size_t write_question(uint8_t *wire, const solaris_dns_question_t *question)
{
    size_t position = 12;
    memcpy(wire + position, question->name.bytes, question->name.length); position += question->name.length;
    dns_put16(wire + position, question->type); dns_put16(wire + position + 2, question->class_code);
    return position + 4;
}
static void write_opt(uint8_t *wire, const solaris_dns_edns_t *edns)
{
    wire[0] = 0; dns_put16(wire + 1, SOLARIS_DNS_OPT); dns_put16(wire + 3, edns->udp_size);
    dns_put32(wire + 5, ((uint32_t)edns->extended_rcode << 24) | ((uint32_t)edns->version << 16) | edns->flags);
    dns_put16(wire + 9, 0);
}
static solaris_status_t allocate_message(solaris_budget_t *budget, size_t size,
    uint16_t id, uint16_t flags, uint16_t answers, uint16_t authorities, uint16_t additional,
    solaris_buffer_t **out)
{
    solaris_status_t rc = solaris_buffer_allocate(budget, size, out);
    if (rc != SOLARIS_OK) return rc;
    uint8_t *wire = solaris_buffer_mutable_data(*out);
    dns_put16(wire, id); dns_put16(wire + 2, flags); dns_put16(wire + 4, 1);
    dns_put16(wire + 6, answers); dns_put16(wire + 8, authorities); dns_put16(wire + 10, additional);
    return SOLARIS_OK;
}
static void finish(solaris_buffer_t *buffer, size_t length)
{
    (void)solaris_buffer_set_length(buffer, length); solaris_buffer_publish(buffer);
}
solaris_status_t solaris_dns_wire_make_query(solaris_budget_t *budget, uint16_t id,
    uint16_t flags, const solaris_dns_question_t *question, const solaris_dns_edns_t *edns, solaris_buffer_t **out)
{
    if (out) *out = NULL;
    if (!out || !budget || !question_valid(question) || (flags & (uint16_t)~(SOLARIS_DNS_RD | SOLARIS_DNS_CD | SOLARIS_DNS_AD)))
        return SOLARIS_EINVAL;
    if (question->type >= 249 && question->type <= 252) return SOLARIS_ENOTSUP;
    solaris_status_t rc = edns_valid(edns);
    if (rc != SOLARIS_OK) return rc;
    int has_opt = edns && edns->present;
    if (has_opt && edns->extended_rcode) return SOLARIS_EINVAL;
    size_t size = 12u + question->name.length + 4u + (has_opt ? 11u : 0u);
    rc = allocate_message(budget, size, id, flags, 0, 0, (uint16_t)has_opt, out);
    if (rc != SOLARIS_OK) return rc;
    uint8_t *wire = solaris_buffer_mutable_data(*out);
    size_t position = write_question(wire, question);
    if (has_opt) write_opt(wire + position, edns);
    finish(*out, size); return SOLARIS_OK;
}
static solaris_status_t payload_size(const solaris_dns_record_t *record, size_t *size)
{
    if (!dns_name_valid(&record->name) || record->section > SOLARIS_DNS_ADDITIONAL) return SOLARIS_EINVAL;
    if (record->class_code != SOLARIS_DNS_IN) return SOLARIS_ENOTSUP;
    switch (record->type) {
    case SOLARIS_DNS_A: case SOLARIS_DNS_AAAA:
        if (record->kind != SOLARIS_DNS_RDATA_ADDRESS) return SOLARIS_EINVAL;
        *size = record->type == SOLARIS_DNS_A ? 4 : 16; break;
    case SOLARIS_DNS_NS: case SOLARIS_DNS_CNAME: case SOLARIS_DNS_PTR:
        if (record->kind != SOLARIS_DNS_RDATA_NAME || !dns_name_valid(&record->value.target)) return SOLARIS_EINVAL;
        *size = record->value.target.length; break;
    case SOLARIS_DNS_SOA:
        if (record->kind != SOLARIS_DNS_RDATA_SOA || !dns_name_valid(&record->value.soa.primary) ||
            !dns_name_valid(&record->value.soa.mailbox)) return SOLARIS_EINVAL;
        *size = (size_t)record->value.soa.primary.length + record->value.soa.mailbox.length + 20; break;
    default: return SOLARIS_ENOTSUP;
    }
    return SOLARIS_OK;
}
static size_t write_record(uint8_t *wire, const solaris_dns_record_t *record, size_t payload)
{
    size_t position = 0;
    memcpy(wire, record->name.bytes, record->name.length); position += record->name.length;
    dns_put16(wire + position, record->type); dns_put16(wire + position + 2, record->class_code);
    dns_put32(wire + position + 4, record->ttl); dns_put16(wire + position + 8, (uint16_t)payload); position += 10;
    switch (record->kind) {
    case SOLARIS_DNS_RDATA_ADDRESS: memcpy(wire + position, record->value.address, payload); break;
    case SOLARIS_DNS_RDATA_NAME: memcpy(wire + position, record->value.target.bytes, payload); break;
    case SOLARIS_DNS_RDATA_SOA: {
        const solaris_dns_soa_t *soa = &record->value.soa; size_t offset = position;
        memcpy(wire + offset, soa->primary.bytes, soa->primary.length); offset += soa->primary.length;
        memcpy(wire + offset, soa->mailbox.bytes, soa->mailbox.length); offset += soa->mailbox.length;
        dns_put32(wire + offset, soa->serial); dns_put32(wire + offset + 4, soa->refresh);
        dns_put32(wire + offset + 8, soa->retry); dns_put32(wire + offset + 12, soa->expire);
        dns_put32(wire + offset + 16, soa->minimum); break;
    }
    default: break; /* payload_size validated the discriminant */
    }
    return position + payload;
}
solaris_status_t solaris_dns_wire_make_response(solaris_budget_t *budget, const solaris_dns_wire_t *query,
    uint16_t flags, uint16_t rcode, const solaris_dns_record_t *records, size_t count, solaris_buffer_t **out)
{
    if (out) *out = NULL;
    if (!out || !budget || !query || (query->header.flags & SOLARIS_DNS_QR) ||
        (flags & (uint16_t)~(SOLARIS_DNS_AA | SOLARIS_DNS_RA | SOLARIS_DNS_TC)) ||
        rcode > 4095 || (count && !records)) return SOLARIS_EINVAL;
    if (count > SOLARIS_DNS_MAX_RECORDS) return SOLARIS_EOVERFLOW;
    if (rcode > 15 && !query->edns.present) return SOLARIS_ENOTSUP;
    size_t size = 12u + query->question.name.length + 4u + (query->edns.present ? 11u : 0u);
    uint16_t counts[3] = {0}; uint8_t previous = SOLARIS_DNS_ANSWER;
    for (size_t i = 0; i < count; ++i) {
        size_t payload;
        solaris_status_t rc = payload_size(&records[i], &payload);
        if (rc != SOLARIS_OK) return rc;
        if (records[i].section < previous) return SOLARIS_EINVAL;
        previous = records[i].section; ++counts[previous];
        size_t added = records[i].name.length + 10u + payload;
        if (added > SOLARIS_DNS_MAX_MESSAGE - size) return SOLARIS_EMSGSIZE;
        size += added;
    }
    if (query->edns.present) ++counts[SOLARIS_DNS_ADDITIONAL];
    flags |= (uint16_t)(SOLARIS_DNS_QR | (query->header.flags & (SOLARIS_DNS_RD | SOLARIS_DNS_CD)) | (rcode & 15u));
    solaris_status_t rc = allocate_message(budget, size, query->header.id, flags, counts[0], counts[1], counts[2], out);
    if (rc != SOLARIS_OK) return rc;
    uint8_t *wire = solaris_buffer_mutable_data(*out); size_t position = write_question(wire, &query->question);
    for (size_t i = 0; i < count; ++i) {
        size_t payload = 0; (void)payload_size(&records[i], &payload);
        position += write_record(wire + position, &records[i], payload);
    }
    if (query->edns.present) {
        solaris_dns_edns_t edns = {.present = 1, .udp_size = SOLARIS_DNS_DEFAULT_UDP_SIZE,
            .extended_rcode = (uint8_t)(rcode >> 4), .flags = (uint16_t)(query->edns.flags & SOLARIS_DNS_DO)};
        write_opt(wire + position, &edns);
    }
    finish(*out, size); return SOLARIS_OK;
}
solaris_status_t dns_empty_response(solaris_budget_t *budget, const solaris_dns_wire_t *source,
    uint16_t flags, uint16_t rcode, solaris_buffer_t **out)
{
    size_t size = 12u + source->question.name.length + 4u + (source->edns.present ? 11u : 0u);
    solaris_status_t rc = allocate_message(budget, size, source->header.id, flags, 0, 0, source->edns.present, out);
    if (rc != SOLARIS_OK) return rc;
    uint8_t *wire = solaris_buffer_mutable_data(*out); size_t position = write_question(wire, &source->question);
    if (source->edns.present) {
        solaris_dns_edns_t edns = source->edns; edns.extended_rcode = (uint8_t)(rcode >> 4);
        write_opt(wire + position, &edns);
    }
    finish(*out, size); return SOLARIS_OK;
}
solaris_status_t solaris_dns_wire_rewrite(const solaris_dns_wire_t *message, solaris_budget_t *budget,
    uint16_t id, uint32_t elapsed_seconds, solaris_buffer_t **out)
{
    if (out) *out = NULL;
    if (!out || !budget || !message) return SOLARIS_EINVAL;
    size_t size = solaris_buffer_length(message->buffer);
    solaris_status_t rc = solaris_buffer_allocate(budget, size, out);
    if (rc != SOLARIS_OK) return rc;
    uint8_t *wire = solaris_buffer_mutable_data(*out); memcpy(wire, solaris_buffer_data(message->buffer), size);
    dns_put16(wire, id);
    for (size_t i = 0; i < message->record_count; ++i) {
        const solaris_dns_record_t *record = &message->records[i];
        if (record->type != SOLARIS_DNS_OPT)
            dns_put32(wire + record->ttl_offset, record->ttl > elapsed_seconds ? record->ttl - elapsed_seconds : 0);
    }
    finish(*out, size); return SOLARIS_OK;
}
solaris_status_t solaris_dns_wire_truncate(const solaris_dns_wire_t *message, solaris_budget_t *budget,
    size_t limit, solaris_buffer_t **out)
{
    if (out) *out = NULL;
    if (!out || !budget || !message || !(message->header.flags & SOLARIS_DNS_QR)) return SOLARIS_EINVAL;
    size_t original = solaris_buffer_length(message->buffer);
    if (original <= limit) return solaris_buffer_copy(budget, solaris_buffer_data(message->buffer), original, out);
    size_t opt = message->edns.present ? 11u : 0u;
    if (12u + message->question.name.length + 4u + opt > limit) return SOLARIS_EMSGSIZE;
    uint16_t flags = (uint16_t)((message->header.flags | SOLARIS_DNS_TC) & (uint16_t)~SOLARIS_DNS_AD);
    size_t end = message->question_end; uint16_t counts[3] = {0};
    for (size_t i = 0; i < message->record_count; ++i) {
        const solaris_dns_record_t *record = &message->records[i];
        if (record->kind == SOLARIS_DNS_RDATA_OPT || record->end + opt > limit) break;
        if (record->kind == SOLARIS_DNS_RDATA_OPAQUE)
            return dns_empty_response(budget, message, flags, message->header.rcode, out);
        end = record->end; ++counts[record->section];
    }
    if (message->edns.present) ++counts[SOLARIS_DNS_ADDITIONAL];
    solaris_status_t rc = solaris_buffer_allocate(budget, end + opt, out);
    if (rc != SOLARIS_OK) return rc;
    uint8_t *wire = solaris_buffer_mutable_data(*out); memcpy(wire, solaris_buffer_data(message->buffer), end);
    dns_put16(wire + 2, flags); dns_put16(wire + 6, counts[0]); dns_put16(wire + 8, counts[1]); dns_put16(wire + 10, counts[2]);
    if (message->edns.present) write_opt(wire + end, &message->edns);
    finish(*out, end + opt); return SOLARIS_OK;
}
