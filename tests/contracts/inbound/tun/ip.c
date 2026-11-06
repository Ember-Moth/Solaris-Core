#include "codec/ip/packet.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)
static uint32_t get32(FILE *file)
{
    uint8_t p[4]; CHECK(fread(p, 1, 4, file) == 4);
    return (uint32_t)p[0] << 24u | (uint32_t)p[1] << 16u | (uint32_t)p[2] << 8u | p[3];
}
int main(int argc, char **argv)
{
    CHECK(argc == 2); FILE *file = fopen(argv[1], "rb"); CHECK(file);
    uint32_t count = get32(file);
    solaris_budget_t *budget; CHECK(solaris_budget_create(300000, NULL, &budget) == SOLARIS_OK);
    for (uint32_t i = 0; i < count; ++i) {
        uint32_t mode = get32(file), n = get32(file), expected_length = get32(file);
        solaris_status_t expected_status = (int32_t)get32(file);
        CHECK(n <= 65575 && expected_length <= 65575);
        uint8_t *input = malloc(n ? n : 1), *expected = malloc(expected_length ? expected_length : 1);
        CHECK(input && expected); CHECK(fread(input, 1, n, file) == n);
        CHECK(fread(expected, 1, expected_length, file) == expected_length);
        solaris_ip_packet_t ip;
        solaris_status_t rc = solaris_ip_parse(input, n, 1, &ip);
        if (rc != expected_status) fprintf(stderr, "case %u mode %u: %d != %d\n", i, mode, rc, expected_status);
        CHECK(rc == expected_status);
        if (rc == SOLARIS_OK && mode == 1) {
            solaris_address_t source, destination;
            CHECK(solaris_address_parse(ip.source.family == 4 ? "10.89.0.11" : "fd00:89::11", 5011, &source) == SOLARIS_OK);
            CHECK(solaris_address_parse(ip.source.family == 4 ? "10.89.0.12" : "fd00:89::12", 5012, &destination) == SOLARIS_OK);
            CHECK(solaris_ip_rewrite(input, n, &source, &destination) == SOLARIS_OK);
            CHECK(n == expected_length && !memcmp(input, expected, n));
            CHECK(solaris_ip_parse(input, n, 1, &ip) == SOLARIS_OK);
        } else if (rc == SOLARIS_OK && mode == 2) {
            solaris_buffer_t *output;
            CHECK(solaris_ip_udp(budget, &ip.source, &ip.destination, input + ip.payload_offset,
                ip.payload_length, &output) == SOLARIS_OK);
            CHECK(solaris_buffer_length(output) == expected_length);
            CHECK(!memcmp(solaris_buffer_data(output), expected, expected_length));
            solaris_buffer_release(output);
        }
        free(expected); free(input);
    }
    CHECK(fgetc(file) == EOF); fclose(file);
    CHECK(solaris_budget_used(budget) == 0); solaris_budget_release(budget);
    printf("%u independent IP packet fixtures passed\n", count); return 0;
}
