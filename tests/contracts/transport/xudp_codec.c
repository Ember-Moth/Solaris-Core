#include "support/runtime/files.h"
#include "codec/xudp/codec.h"
#include "codec/address/socks.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)
static const solaris_datagram_codec_ops_t *ops = &solaris_xudp_codec;
static size_t load(const char *directory, const char *kind, unsigned int id, uint8_t *out, size_t capacity)
{
    char path[1024]; CHECK(snprintf(path, sizeof(path), "%s/%s-%u.bin", directory, kind, id) > 0);
    FILE *file = solaris_test_fopen(path, "rb"); CHECK(file != NULL);
    size_t size = fread(out, 1u, capacity, file); CHECK(size > 0u && feof(file)); fclose(file); return size;
}
static void *allocate(void *context, size_t size) { return *(int *)context ? NULL : malloc(size); }
int main(int argc, char **argv)
{
    CHECK(argc == 2);
    int fail = 0; solaris_runtime_services_t services; solaris_runtime_services_init(&services);
    services.context = &fail; services.allocate = allocate;
    solaris_budget_t *budget; CHECK(solaris_budget_create(4u * 1024u * 1024u, &services, &budget) == SOLARIS_OK);
    char domain[256]; memset(domain, 'a', 255u); domain[255] = '\0';
    const char *hosts[] = {"127.0.0.1", "::1", "example.com", "127.0.0.1", "::1", domain};
    const uint16_t ports[] = {53u, 443u, 8443u, 53u, 65535u, 443u};
    const size_t lengths[] = {17u, 1025u, 31u, 0u, 65535u, 9u};
    for (unsigned int i = 0u; i < 6u; ++i) {
        void *codec = NULL; CHECK(ops->create(NULL, budget, &codec) == SOLARIS_OK);
        solaris_buffer_t *preface = NULL; CHECK(ops->start(codec, &preface) == SOLARIS_OK && preface == NULL);
        solaris_address_t destination; CHECK(solaris_address_parse(hosts[i], ports[i], &destination) == SOLARIS_OK);
        solaris_buffer_t *payload; CHECK(solaris_buffer_allocate(budget, lengths[i], &payload) == SOLARIS_OK);
        for (size_t n = 0u; n < lengths[i]; ++n) solaris_buffer_mutable_data(payload)[n] = (uint8_t)(i + n * 17u);
        CHECK(solaris_buffer_set_length(payload, lengths[i]) == SOLARIS_OK);
        solaris_slice_t plain = {payload, 0u, lengths[i]};
        solaris_buffer_t *encoded = NULL;
        fail = 1; CHECK(ops->encode(codec, &destination, &plain, &encoded) == SOLARIS_ENOMEM && encoded == NULL); fail = 0;
        uint8_t expected[66100]; size_t size = load(argv[1], "first", i, expected, sizeof(expected));
        CHECK(ops->encode(codec, &destination, &plain, &encoded) == SOLARIS_OK);
        CHECK(solaris_buffer_length(encoded) == size && memcmp(solaris_buffer_data(encoded), expected, size) == 0);
        solaris_buffer_release(encoded);
        size = load(argv[1], "frame", i, expected, sizeof(expected));
        CHECK(ops->encode(codec, &destination, &plain, &encoded) == SOLARIS_OK);
        CHECK(solaris_buffer_length(encoded) == size && memcmp(solaris_buffer_data(encoded), expected, size) == 0);
        solaris_buffer_release(encoded);
        size_t fragments[] = {0u, 1u, 2u, 3u, size / 2u, size - 1u};
        for (size_t n = 0u; n < sizeof(fragments) / sizeof(fragments[0]); ++n) {
            size_t consumed = 999u; solaris_address_t source; solaris_buffer_t *out = NULL;
            CHECK(ops->decode(codec, expected, fragments[n], &consumed, &source, &out) == SOLARIS_EAGAIN);
            CHECK(consumed == 0u && out == NULL);
        }
        size_t consumed; solaris_address_t source; solaris_buffer_t *out = NULL;
        fail = 1; CHECK(ops->decode(codec, expected, size, &consumed, &source, &out) == SOLARIS_ENOMEM && consumed == 0u); fail = 0;
        CHECK(ops->decode(codec, expected, size, &consumed, &source, &out) == SOLARIS_OK);
        CHECK(consumed == size && solaris_address_equal(&source, &destination) && solaris_buffer_length(out) == lengths[i]);
        CHECK(memcmp(solaris_buffer_data(out), solaris_buffer_data(payload), lengths[i]) == 0);
        solaris_buffer_release(out);
        CHECK(ops->finish(codec) == SOLARIS_OK); ops->destroy(codec);
        solaris_xudp_parameters_t identity = {{1,2,3,4,5,6,7,8}};
        for (unsigned int generation = 0u; generation < 2u; ++generation) {
            CHECK(ops->create(&identity, budget, &codec) == SOLARIS_OK);
            fail = 1; CHECK(ops->encode(codec, &destination, &plain, &encoded) == SOLARIS_ENOMEM && encoded == NULL); fail = 0;
            size = load(argv[1], "global", i, expected, sizeof(expected));
            CHECK(ops->encode(codec, &destination, &plain, &encoded) == SOLARIS_OK);
            CHECK(solaris_buffer_length(encoded) == size && memcmp(solaris_buffer_data(encoded), expected, size) == 0);
            solaris_buffer_release(encoded);
            size = load(argv[1], "frame", i, expected, sizeof(expected));
            CHECK(ops->encode(codec, &destination, &plain, &encoded) == SOLARIS_OK);
            CHECK(solaris_buffer_length(encoded) == size && memcmp(solaris_buffer_data(encoded), expected, size) == 0);
            solaris_buffer_release(encoded); ops->destroy(codec);
        }
        solaris_buffer_release(payload);
    }
    void *codec = NULL; CHECK(ops->create(NULL, budget, &codec) == SOLARIS_OK);
    /* No response data can precede the first accepted request. */
    const uint8_t fallback[] = {0, 4, 0, 0, 2, 1, 0, 1, 42};
    size_t consumed; solaris_address_t source; solaris_buffer_t *packet = NULL;
    CHECK(ops->decode(codec, fallback, sizeof(fallback), &consumed, &source, &packet) == SOLARIS_EIO);
    solaris_address_t first; CHECK(solaris_address_parse("127.0.0.1", 53u, &first) == SOLARIS_OK);
    solaris_buffer_t *empty, *wire;
    CHECK(solaris_buffer_allocate(budget, 0u, &empty) == SOLARIS_OK);
    solaris_slice_t zero = {empty, 0u, 0u};
    CHECK(ops->encode(codec, &first, &zero, &wire) == SOLARIS_OK); solaris_buffer_release(wire);
    static const uint8_t invalid[][16] = {
        {0,3}, {1,10}, {0,4,0,1,2,0}, {0,4,0,0,1,0}, {0,4,0,0,5,0},
        {0,4,0,0,2,4}, {0,4,0,0,2,2}, {0,4,0,0,3,2},
        {0,12,0,0,2,1,1,0,53,1,127,0,0,1}, /* TCP network */
        {0,12,0,0,2,1,2,0,0,1,127,0,0,1}, /* zero port */
        {0,12,0,0,2,1,2,0,53,9,127,0,0,1}, /* invalid address */
        {0,8,0,0,2,1,2,0,53,1}, /* address exceeds metadata */
        {0,13,0,0,2,0,2,0,53,1,127,0,0,1,42}, /* trailing metadata */
        {0,5,0,0,3,0,42}, /* END has no address */
    };
    for (size_t i = 0u; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        CHECK(ops->decode(codec, invalid[i], sizeof(invalid[i]), &consumed, &source, &packet) == SOLARIS_EIO);
        CHECK(consumed == 0u && packet == NULL);
    }
    CHECK(ops->decode(codec, fallback, sizeof(fallback), &consumed, &source, &packet) == SOLARIS_OK);
    CHECK(consumed == sizeof(fallback) && solaris_address_equal(&first, &source) && solaris_buffer_length(packet) == 1u);
    CHECK(solaris_buffer_data(packet)[0] == 42u); solaris_buffer_release(packet);
    const uint8_t keepalive[] = {0,4,12,34,4,1,0,3,1,2,3};
    CHECK(ops->decode(codec, keepalive, sizeof(keepalive) - 1u, &consumed, &source, &packet) == SOLARIS_EAGAIN);
    CHECK(consumed == 0u && packet == NULL);
    CHECK(ops->decode(codec, keepalive, sizeof(keepalive), &consumed, &source, &packet) == SOLARIS_OK);
    CHECK(consumed == sizeof(keepalive) && packet == NULL);
    const uint8_t keep[] = {0,4,0,0,2,0};
    CHECK(ops->decode(codec, keep, sizeof(keep), &consumed, &source, &packet) == SOLARIS_OK && packet == NULL);
    const uint8_t end[] = {0,4,0,0,3,1,0,1,99};
    fail = 1; CHECK(ops->decode(codec, end, sizeof(end), &consumed, &source, &packet) == SOLARIS_ENOMEM); fail = 0;
    CHECK(consumed == 0u && packet == NULL);
    CHECK(ops->decode(codec, end, sizeof(end), &consumed, &source, &packet) == SOLARIS_ECLOSED);
    CHECK(consumed == sizeof(end) && solaris_buffer_data(packet)[0] == 99u); solaris_buffer_release(packet);
    CHECK(ops->encode(codec, &first, &zero, &wire) == SOLARIS_ECLOSED && wire == NULL);
    solaris_buffer_release(empty); ops->destroy(codec);
    CHECK(ops->create(NULL, budget, &codec) == SOLARIS_OK);
    solaris_buffer_t *large; CHECK(solaris_buffer_allocate(budget, 65536u, &large) == SOLARIS_OK);
    CHECK(solaris_buffer_set_length(large, 65536u) == SOLARIS_OK);
    solaris_slice_t plain = {large, 0u, 65536u}; solaris_address_t address;
    CHECK(solaris_address_parse("127.0.0.1", 53u, &address) == SOLARIS_OK);
    solaris_buffer_t *out = NULL; CHECK(ops->encode(codec, &address, &plain, &out) == SOLARIS_EMSGSIZE && out == NULL);
    plain.length = 0u; address.port = 0u;
    CHECK(ops->encode(codec, &address, &plain, &out) == SOLARIS_EINVAL && out == NULL);
    uint8_t bytes[32]; size_t size;
    CHECK(solaris_socks_address_write(&address, bytes, sizeof(bytes), &size) == SOLARIS_EINVAL);
    CHECK(solaris_socks_address_encode(&address, bytes, sizeof(bytes), &size) == SOLARIS_OK && size == 7u);
    solaris_buffer_release(large); ops->destroy(codec);
    CHECK(solaris_budget_used(budget) == 0u); solaris_budget_release(budget);
    puts("XUDP: independent request/frame fixtures, lengths, partial input, invalid addresses and allocation failures passed");
    return 0;
}
