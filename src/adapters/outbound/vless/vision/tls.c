#include "adapters/outbound/vless/vision/tls.h"
#include <string.h>

static uint16_t read16(const uint8_t *p) { return (uint16_t)(((uint16_t)p[0] << 8u) | p[1]); }
static int server_hello(solaris_vless_tls_hello_t *hello)
{
    const uint8_t *body = hello->bytes + 4u; size_t size = hello->expected - 4u;
    static const uint8_t retry_random[32] = {
        0xcf,0x21,0xad,0x74,0xe5,0x9a,0x61,0x11,0xbe,0x1d,0x8c,0x02,0x1e,0x65,0xb8,0x91,
        0xc2,0xa2,0x11,0x16,0x7a,0xbb,0x8c,0x5e,0x07,0x9e,0x09,0xe2,0xc8,0xa8,0x33,0x9c
    };
    if (size < 38u || body[0] != 3u || body[1] != 3u || body[34] > 32u) return 0;
    size_t offset = 35u + body[34];
    if (offset > size || size - offset < 3u) return 0;
    hello->cipher = read16(body + offset); offset += 2u;
    if (body[offset++] != 0u || size - offset < 2u) return 0;
    size_t extensions = read16(body + offset); offset += 2u;
    if (extensions != size - offset) return 0;
    int supported = 0;
    while (offset < size) {
        if (size - offset < 4u) return 0;
        uint16_t type = read16(body + offset); size_t length = read16(body + offset + 2u); offset += 4u;
        if (length > size - offset) return 0;
        if (type == 43u) {
            if (supported || length != 2u || read16(body + offset) != 0x0304u) return 0;
            supported = 1;
        }
        offset += length;
    }
    if (!supported || hello->cipher < 0x1301u || hello->cipher > 0x1304u) return 0;
    if (memcmp(body + 2u, retry_random, sizeof(retry_random)) == 0) return 2;
    return 1;
}
static void observe_hello(solaris_vless_tls_hello_t *hello, const uint8_t *data, size_t size)
{
    while (size != 0u && !hello->done) {
        size_t need = hello->used < 4u ? 4u - hello->used : hello->expected - hello->used;
        size_t count = size < need ? size : need;
        memcpy(hello->bytes + hello->used, data, count); hello->used += count; data += count; size -= count;
        if (hello->used == 4u && hello->expected == 0u) {
            size_t body = ((size_t)hello->bytes[1] << 16u) | ((size_t)hello->bytes[2] << 8u) | hello->bytes[3];
            if (hello->bytes[0] != 2u || body < 38u || body > sizeof(hello->bytes) - 4u) { hello->done = 1; return; }
            hello->expected = body + 4u;
        }
        if (hello->expected != 0u && hello->used == hello->expected) {
            int result = server_hello(hello);
            if (result == 2 && hello->retries++ == 0u) { hello->used = hello->expected = 0u; continue; }
            hello->tls13 = result == 1; hello->done = 1;
        }
    }
}
void solaris_vless_tls_observe(solaris_vless_tls_records_t *records,
    solaris_vless_tls_hello_t *hello, const uint8_t *data, size_t size)
{
    records->application_records = 0u;
    while (size != 0u && !records->invalid) {
        if (records->header_size < 5u) {
            size_t count = 5u - records->header_size; if (count > size) count = size;
            memcpy(records->header + records->header_size, data, count); records->header_size += count;
            data += count; size -= count;
            if (records->header_size < 5u) break;
            records->remaining = records->record_length = read16(records->header + 3u);
            if (records->header[0] < 20u || records->header[0] > 23u || records->header[1] != 3u ||
                records->header[2] < 1u || records->header[2] > 3u || records->remaining > 18432u ||
                (records->header[0] == 23u && records->remaining < 17u)) { records->invalid = 1; break; }
        }
        size_t count = records->remaining; if (count > size) count = size;
        if (records->header[0] == 22u && count != 0u) {
            if (records->remaining == records->record_length && (data[0] == 1u || data[0] == 2u)) records->tls = 1;
            if (hello != NULL) observe_hello(hello, data, count);
        }
        data += count; size -= count; records->remaining -= count;
        if (records->remaining == 0u) {
            records->last_type = records->header[0];
            if (records->last_type == 23u && records->header[2] == 3u) records->application_records++;
            records->header_size = 0u;
        }
    }
}
int solaris_vless_tls_application_boundary(const solaris_vless_tls_records_t *records)
{
    return !records->invalid && records->header_size == 0u && records->remaining == 0u &&
        records->last_type == 23u && records->application_records != 0u;
}
