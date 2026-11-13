#ifndef SOLARIS_DNS_TEST_FIXTURES_H
#define SOLARIS_DNS_TEST_FIXTURES_H
/* Independently authored DNS wire octets. These never use the codec's builders.
 * Question: www.example.com IN A. The response contains CNAME -> alias.example.com,
 * A 127.0.0.9, AAAA ::1, an authority SOA, PTR, opaque private-use RR and EDNS0.
 * Known compression targets: question 12/16/24/28; alias label at byte 45. */
static const char dns_query_hex[] =
    "1234 0100 0001 0000 0000 0000"
    "03 777777 07 6578616d706c65 03 636f6d 00 0001 0001";
static const char dns_response_hex[] =
    "1234 81a0 0001 0003 0001 0003"
    "03 777777 07 6578616d706c65 03 636f6d 00 0001 0001"
    "c00c 0005 0001 0000012c 0008 05 616c696173 c010"
    "c02d 0001 0001 0000003c 0004 7f000009"
    "c02d 001c 0001 00000078 0010 00000000000000000000000000000001"
    "c010 0006 0001 00000708 0020 02 6e73 c010 04 686f7374 c010"
    "00000001 00000002 00000003 00000004 00000005"
    "01 39 01 30 01 30 03 313237 07 696e2d61646472 04 61727061 00"
    "000c 0001 0000000a 0002 c02d"
    "c00c fde8 0001 00000009 0004 c0ffdead"
    "00 0029 04d0 00008000 000b fde9 0003 616263 000c 0000";
static const char dns_query_edns_hex[] =
    "1234 0100 0001 0000 0000 0001"
    "03 777777 07 6578616d706c65 03 636f6d 00 0001 0001"
    "00 0029 04d0 00008000 0000";
static const char dns_built_a_hex[] =
    "1234 8580 0001 0001 0000 0000"
    "03 777777 07 6578616d706c65 03 636f6d 00 0001 0001"
    "03 777777 07 6578616d706c65 03 636f6d 00 0001 0001 0000003c 0004 7f000009";
static const char dns_empty_edns_hex[] =
    "1234 8183 0001 0000 0000 0001"
    "03 777777 07 6578616d706c65 03 636f6d 00 0001 0001"
    "00 0029 04d0 00008000 0000";
#endif
