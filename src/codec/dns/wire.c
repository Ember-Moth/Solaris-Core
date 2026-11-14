#include "codec/dns/internal.h"
#include <stdio.h>
#include <string.h>

typedef struct dns_reader {
    const uint8_t *bytes;
    size_t length;
    uint32_t pointer_hops;
    /* A pointer may only reference a name boundary already validated while
     * reading this packet, including suffixes of earlier known RDATA names. */
    uint8_t starts[(SOLARIS_DNS_MAX_MESSAGE + 7u) / 8u];
    solaris_error_t *error;
} dns_reader_t;

solaris_status_t dns_error(solaris_error_t *error, solaris_status_t status,
    size_t offset, const char *reason)
{
    if (error) {
        memset(error, 0, sizeof(*error)); error->code = status;
        if (status != SOLARIS_OK)
            (void)snprintf(error->message, sizeof(error->message), "DNS wire at byte %zu: %s", offset, reason);
    }
    return status;
}
void solaris_dns_wire_limits_init(solaris_dns_wire_limits_t *limits)
{
    if (limits) *limits = (solaris_dns_wire_limits_t){SOLARIS_DNS_MAX_MESSAGE,
        SOLARIS_DNS_DEFAULT_RECORDS, SOLARIS_DNS_DEFAULT_POINTER_HOPS};
}
solaris_status_t dns_limits(const solaris_dns_wire_limits_t *input, solaris_dns_wire_limits_t *out)
{
    solaris_dns_wire_limits_init(out);
    if (input) {
        if (input->message_bytes) out->message_bytes = input->message_bytes;
        if (input->records) out->records = input->records;
        if (input->pointer_hops) out->pointer_hops = input->pointer_hops;
    }
    if (out->message_bytes < 12 || out->message_bytes > SOLARIS_DNS_MAX_MESSAGE ||
        out->records > SOLARIS_DNS_MAX_RECORDS || out->pointer_hops > SOLARIS_DNS_MAX_POINTER_HOPS)
        return SOLARIS_EINVAL;
    return SOLARIS_OK;
}
static solaris_status_t read_name(dns_reader_t *reader, size_t start, size_t end,
    solaris_dns_name_t *out, size_t *consumed)
{
    size_t cursor = start, written = 0, used = 0;
    uint16_t targets[SOLARIS_DNS_MAX_POINTER_HOPS]; unsigned hops = 0;
    int jumped = 0;
    memset(out, 0, sizeof(*out)); *consumed = 0;
    for (;;) {
        if (cursor >= end) return dns_error(reader->error, SOLARIS_EINVAL, cursor, "truncated name");
        uint8_t label = reader->bytes[cursor];
        reader->starts[cursor / 8] |= (uint8_t)(1u << (cursor % 8));
        if ((label & 0xc0u) == 0xc0u) {
            if (end - cursor < 2) return dns_error(reader->error, SOLARIS_EINVAL, cursor, "truncated pointer");
            size_t target = ((size_t)(label & 0x3fu) << 8) | reader->bytes[cursor + 1];
            if (target < 12 || target >= cursor || target >= reader->length ||
                !(reader->starts[target / 8] & (uint8_t)(1u << (target % 8))))
                return dns_error(reader->error, SOLARIS_EINVAL, cursor, "pointer must reference an earlier name boundary");
            for (unsigned i = 0; i < hops; ++i) if (targets[i] == target)
                return dns_error(reader->error, SOLARIS_EINVAL, cursor, "name pointer cycle");
            if (hops == reader->pointer_hops)
                return dns_error(reader->error, SOLARIS_EOVERFLOW, cursor, "name pointer limit");
            targets[hops++] = (uint16_t)target;
            if (!jumped) used = cursor + 2 - start;
            jumped = 1; cursor = target; end = reader->length;
            continue;
        }
        if (label & 0xc0u) return dns_error(reader->error, SOLARIS_EINVAL, cursor, "reserved label encoding");
        if (end - cursor - 1 < label) return dns_error(reader->error, SOLARIS_EINVAL, cursor, "truncated label");
        if (written + 1u + label > SOLARIS_DNS_MAX_NAME)
            return dns_error(reader->error, SOLARIS_EOVERFLOW, cursor, "expanded name limit");
        out->bytes[written++] = label;
        if (label) { memcpy(out->bytes + written, reader->bytes + cursor + 1, label); written += label; }
        cursor += 1u + label;
        if (!label) {
            out->length = (uint16_t)written;
            *consumed = jumped ? used : cursor - start;
            return SOLARIS_OK;
        }
    }
}
static solaris_status_t read_edns(dns_reader_t *reader, solaris_dns_wire_t *message,
    const solaris_dns_record_t *record, size_t owner_length)
{
    if (record->section != SOLARIS_DNS_ADDITIONAL || record->name.length != 1 || owner_length != 1 ||
        message->edns.present)
        return dns_error(reader->error, SOLARIS_EINVAL, record->offset, "invalid or duplicate OPT record");
    solaris_dns_edns_t *edns = &message->edns;
    edns->present = 1; edns->udp_size = record->class_code;
    edns->extended_rcode = (uint8_t)(record->ttl >> 24);
    edns->version = (uint8_t)(record->ttl >> 16); edns->flags = (uint16_t)record->ttl;
    if (edns->version || (edns->flags & (uint16_t)~SOLARIS_DNS_DO))
        return dns_error(reader->error, SOLARIS_ENOTSUP, record->ttl_offset, "unsupported EDNS version or flags");
    if (!(message->header.flags & SOLARIS_DNS_QR) && edns->extended_rcode)
        return dns_error(reader->error, SOLARIS_EINVAL, record->ttl_offset, "query has extended response code");
    message->header.rcode |= (uint16_t)((uint16_t)edns->extended_rcode << 4);
    edns->options_offset = record->rdata_offset; edns->options_length = record->rdata_length;
    for (size_t offset = record->rdata_offset; offset < record->end;) {
        if (record->end - offset < 4)
            return dns_error(reader->error, SOLARIS_EINVAL, offset, "truncated EDNS option header");
        size_t length = dns_u16(reader->bytes + offset + 2); offset += 4;
        if (length > record->end - offset)
            return dns_error(reader->error, SOLARIS_EINVAL, offset, "truncated EDNS option payload");
        offset += length; ++edns->option_count;
    }
    return SOLARIS_OK;
}
static solaris_status_t read_record(dns_reader_t *reader, solaris_dns_wire_t *message,
    solaris_dns_record_t *record, size_t *position)
{
    size_t offset = *position, consumed;
    record->offset = offset;
    solaris_status_t rc = read_name(reader, offset, reader->length, &record->name, &consumed);
    if (rc != SOLARIS_OK) return rc;
    size_t owner_length = consumed; offset += consumed;
    if (reader->length - offset < 10)
        return dns_error(reader->error, SOLARIS_EINVAL, offset, "truncated resource header");
    record->type = dns_u16(reader->bytes + offset); record->class_code = dns_u16(reader->bytes + offset + 2);
    record->ttl_offset = offset + 4; record->ttl = dns_u32(reader->bytes + record->ttl_offset);
    record->rdata_length = dns_u16(reader->bytes + offset + 8);
    record->rdata_offset = offset + 10;
    if (record->rdata_length > reader->length - record->rdata_offset)
        return dns_error(reader->error, SOLARIS_EINVAL, offset, "truncated resource payload");
    record->end = record->rdata_offset + record->rdata_length;
    if (!record->type || (!record->class_code && record->type != SOLARIS_DNS_OPT))
        return dns_error(reader->error, SOLARIS_EINVAL, offset, "zero resource type or class");
    if (record->type == 249 || record->type == 250 ||
        (record->type == 24 && record->section == SOLARIS_DNS_ADDITIONAL))
        return dns_error(reader->error, SOLARIS_ENOTSUP, offset, "authenticated transaction records unsupported");
    if (record->type == SOLARIS_DNS_OPT) {
        record->kind = SOLARIS_DNS_RDATA_OPT;
        rc = read_edns(reader, message, record, owner_length);
    } else if (record->class_code == SOLARIS_DNS_IN) {
        switch (record->type) {
        case SOLARIS_DNS_A: case SOLARIS_DNS_AAAA: {
            size_t expected = record->type == SOLARIS_DNS_A ? 4 : 16;
            if (record->rdata_length != expected)
                return dns_error(reader->error, SOLARIS_EINVAL, record->rdata_offset, "invalid address payload length");
            record->kind = SOLARIS_DNS_RDATA_ADDRESS;
            memcpy(record->value.address, reader->bytes + record->rdata_offset, expected); break;
        }
        case SOLARIS_DNS_NS: case SOLARIS_DNS_CNAME: case SOLARIS_DNS_PTR:
            record->kind = SOLARIS_DNS_RDATA_NAME;
            rc = read_name(reader, record->rdata_offset, record->end, &record->value.target, &consumed);
            if (rc == SOLARIS_OK && consumed != record->rdata_length)
                rc = dns_error(reader->error, SOLARIS_EINVAL, record->rdata_offset + consumed, "trailing name payload");
            break;
        case SOLARIS_DNS_SOA: {
            record->kind = SOLARIS_DNS_RDATA_SOA; offset = record->rdata_offset;
            rc = read_name(reader, offset, record->end, &record->value.soa.primary, &consumed);
            if (rc != SOLARIS_OK) break;
            offset += consumed;
            rc = read_name(reader, offset, record->end, &record->value.soa.mailbox, &consumed);
            if (rc != SOLARIS_OK) break;
            offset += consumed;
            if (record->end - offset != 20)
                return dns_error(reader->error, SOLARIS_EINVAL, offset, "invalid SOA payload length");
            record->value.soa.serial = dns_u32(reader->bytes + offset);
            record->value.soa.refresh = dns_u32(reader->bytes + offset + 4);
            record->value.soa.retry = dns_u32(reader->bytes + offset + 8);
            record->value.soa.expire = dns_u32(reader->bytes + offset + 12);
            record->value.soa.minimum = dns_u32(reader->bytes + offset + 16); break;
        }
        default: break; /* opaque bytes remain at their original offsets */
        }
    }
    if (rc == SOLARIS_OK) *position = record->end;
    return rc;
}
solaris_status_t solaris_dns_wire_parse(solaris_budget_t *budget, const void *bytes,
    size_t length, const solaris_dns_wire_limits_t *limits, solaris_dns_wire_t **out, solaris_error_t *error)
{
    if (out) *out = NULL;
    dns_error(error, SOLARIS_OK, 0, "");
    solaris_dns_wire_limits_t selected;
    if (!out || !budget || !bytes || dns_limits(limits, &selected) != SOLARIS_OK)
        return dns_error(error, SOLARIS_EINVAL, 0, "invalid parse arguments or limits");
    if (length > selected.message_bytes)
        return dns_error(error, SOLARIS_EMSGSIZE, 0, "message byte limit");
    if (length < 12) return dns_error(error, SOLARIS_EINVAL, length, "truncated header");
    const uint8_t *wire = bytes;
    solaris_dns_header_t header = {.id = dns_u16(wire), .flags = dns_u16(wire + 2),
        .questions = dns_u16(wire + 4), .answers = dns_u16(wire + 6),
        .authorities = dns_u16(wire + 8), .additional = dns_u16(wire + 10)};
    header.rcode = (uint16_t)(header.flags & 15u);
    if (header.flags & 0x0040u) return dns_error(error, SOLARIS_EINVAL, 2, "reserved header bit");
    if ((header.flags & 0x7800u) || header.questions != 1)
        return dns_error(error, SOLARIS_ENOTSUP, 2, "only QUERY with one question is supported");
    if (!(header.flags & SOLARIS_DNS_QR) && (header.answers || header.authorities || header.rcode))
        return dns_error(error, SOLARIS_ENOTSUP, 2, "query contains response fields");
    size_t count = (size_t)header.answers + header.authorities + header.additional;
    if (count > selected.records)
        return dns_error(error, SOLARIS_EOVERFLOW, 6, "resource record limit");
    if (length < 17 || count > (length - 17) / 11)
        return dns_error(error, SOLARIS_EINVAL, 6, "record counts exceed message length");
    solaris_dns_wire_t *message = solaris_memory_allocate(budget, sizeof(*message) + count * sizeof(message->records[0]));
    if (!message) return dns_error(error, SOLARIS_ENOMEM, 0, "message allocation failed");
    memset(message, 0, sizeof(*message) + count * sizeof(message->records[0]));
    atomic_init(&message->references, 1); message->header = header; message->record_count = count;
    solaris_status_t rc = solaris_buffer_copy(budget, bytes, length, &message->buffer);
    if (rc != SOLARIS_OK) {
        solaris_memory_free(message); return dns_error(error, rc, 0, "wire copy allocation failed");
    }
    dns_reader_t reader = {.bytes = solaris_buffer_data(message->buffer), .length = length,
        .pointer_hops = selected.pointer_hops, .error = error};
    size_t consumed = 0, position = 12;
    rc = read_name(&reader, position, length, &message->question.name, &consumed);
    position += consumed;
    if (rc == SOLARIS_OK && length - position < 4)
        rc = dns_error(error, SOLARIS_EINVAL, position, "truncated question");
    if (rc == SOLARIS_OK) {
        message->question.type = dns_u16(reader.bytes + position);
        message->question.class_code = dns_u16(reader.bytes + position + 2); position += 4;
        if (!message->question.type || !message->question.class_code)
            rc = dns_error(error, SOLARIS_EINVAL, position - 4, "zero question type or class");
        else if (message->question.type >= 249 && message->question.type <= 252)
            rc = dns_error(error, SOLARIS_ENOTSUP, position - 4, "transfer or key exchange unsupported");
        message->question_end = position;
    }
    for (size_t i = 0; rc == SOLARIS_OK && i < count; ++i) {
        message->records[i].section = i < header.answers ? SOLARIS_DNS_ANSWER :
            i < (size_t)header.answers + header.authorities ? SOLARIS_DNS_AUTHORITY : SOLARIS_DNS_ADDITIONAL;
        rc = read_record(&reader, message, &message->records[i], &position);
    }
    if (rc == SOLARIS_OK && position != length)
        rc = dns_error(error, SOLARIS_EINVAL, position, "trailing bytes after declared sections");
    if (rc != SOLARIS_OK) { solaris_dns_wire_release(message); return rc; }
    *out = message; return SOLARIS_OK;
}
void solaris_dns_wire_retain(const solaris_dns_wire_t *message)
{
    if (message) (void)atomic_fetch_add_explicit(&((solaris_dns_wire_t *)message)->references, 1, memory_order_relaxed);
}
void solaris_dns_wire_release(const solaris_dns_wire_t *message)
{
    if (message && atomic_fetch_sub_explicit(&((solaris_dns_wire_t *)message)->references, 1, memory_order_acq_rel) == 1) {
        solaris_buffer_release(message->buffer); solaris_memory_free((void *)message);
    }
}
const solaris_buffer_t *solaris_dns_wire_buffer(const solaris_dns_wire_t *m) { return m ? m->buffer : NULL; }
const solaris_dns_header_t *solaris_dns_wire_header(const solaris_dns_wire_t *m) { return m ? &m->header : NULL; }
const solaris_dns_question_t *solaris_dns_wire_question(const solaris_dns_wire_t *m) { return m ? &m->question : NULL; }
const solaris_dns_edns_t *solaris_dns_wire_edns(const solaris_dns_wire_t *m) { return m ? &m->edns : NULL; }
size_t solaris_dns_wire_record_count(const solaris_dns_wire_t *m) { return m ? m->record_count : 0; }
const solaris_dns_record_t *solaris_dns_wire_record(const solaris_dns_wire_t *m, size_t i)
{ return m && i < m->record_count ? &m->records[i] : NULL; }
solaris_status_t solaris_dns_wire_option(const solaris_dns_wire_t *message, size_t index, solaris_dns_option_t *out)
{
    if (out) memset(out, 0, sizeof(*out));
    if (!out || !message || index >= message->edns.option_count) return SOLARIS_EINVAL;
    const uint8_t *wire = solaris_buffer_data(message->buffer); size_t offset = message->edns.options_offset;
    for (size_t i = 0; i < index; ++i) offset += 4u + dns_u16(wire + offset + 2);
    out->code = dns_u16(wire + offset);
    out->data = (solaris_slice_t){message->buffer, offset + 4, dns_u16(wire + offset + 2)};
    return SOLARIS_OK;
}
solaris_status_t solaris_dns_wire_validate_reply(const solaris_dns_wire_t *query, const solaris_dns_wire_t *response)
{
    if (!query || !response || (query->header.flags & SOLARIS_DNS_QR) || !(response->header.flags & SOLARIS_DNS_QR) ||
        query->header.id != response->header.id || (query->header.flags & 0x7800u) != (response->header.flags & 0x7800u) ||
        query->question.type != response->question.type || query->question.class_code != response->question.class_code ||
        !solaris_dns_name_equal(&query->question.name, &response->question.name)) return SOLARIS_EINVAL;
    return SOLARIS_OK;
}
size_t solaris_dns_wire_udp_limit(const solaris_dns_wire_t *query, size_t service_limit)
{
    if (!query || !service_limit) return 0;
    size_t result = query->edns.present && query->edns.udp_size > 512 ? query->edns.udp_size : 512;
    return result < service_limit ? result : service_limit;
}
solaris_status_t solaris_dns_wire_parse_frame(solaris_budget_t *budget, const void *bytes, size_t length,
    const solaris_dns_wire_limits_t *limits, size_t *consumed, solaris_dns_wire_t **out, solaris_error_t *error)
{
    if (consumed) *consumed = 0;
    if (out) *out = NULL;
    dns_error(error, SOLARIS_OK, 0, "");
    solaris_dns_wire_limits_t selected;
    if (!consumed || !out || !budget || (!bytes && length) || dns_limits(limits, &selected) != SOLARIS_OK)
        return dns_error(error, SOLARIS_EINVAL, 0, "invalid frame arguments");
    if (length < 2) return dns_error(error, SOLARIS_EAGAIN, length, "partial frame prefix");
    const uint8_t *wire = bytes; size_t body = dns_u16(wire);
    if (body < 12) return dns_error(error, SOLARIS_EINVAL, 0, "invalid frame body length");
    if (body > selected.message_bytes) return dns_error(error, SOLARIS_EMSGSIZE, 0, "frame byte limit");
    if (length - 2 < body) return dns_error(error, SOLARIS_EAGAIN, length, "partial frame body");
    solaris_status_t rc = solaris_dns_wire_parse(budget, wire + 2, body, &selected, out, error);
    if (rc == SOLARIS_OK) *consumed = body + 2;
    return rc;
}
solaris_status_t solaris_dns_wire_frame(const solaris_dns_wire_t *message, solaris_budget_t *budget, solaris_buffer_t **out)
{
    if (out) *out = NULL;
    if (!out || !message || !budget) return SOLARIS_EINVAL;
    size_t length = solaris_buffer_length(message->buffer);
    solaris_status_t rc = solaris_buffer_allocate(budget, length + 2, out);
    if (rc != SOLARIS_OK) return rc;
    uint8_t *wire = solaris_buffer_mutable_data(*out); dns_put16(wire, (uint16_t)length);
    memcpy(wire + 2, solaris_buffer_data(message->buffer), length);
    (void)solaris_buffer_set_length(*out, length + 2); solaris_buffer_publish(*out); return SOLARIS_OK;
}
