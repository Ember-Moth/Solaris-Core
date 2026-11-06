#ifndef SOLARIS_IP_PACKET_H
#define SOLARIS_IP_PACKET_H
#include "contracts/io/address.h"
#include "contracts/io/buffer.h"
enum { SOLARIS_IP_ICMP = 1, SOLARIS_IP_TCP = 6, SOLARIS_IP_UDP = 17, SOLARIS_IP_ICMP6 = 58 };
typedef struct solaris_ip_packet {
    solaris_address_t source, destination;
    uint8_t protocol, hop_limit;
    size_t length, transport_offset, transport_length, payload_offset, payload_length;
    uint8_t tcp_flags;
} solaris_ip_packet_t;
/* Exact lengths, IPv4 header and transport checksums; IPv4 UDP checksum zero
 * is valid. Reject fragments, IPv6 jumbograms, routing/AH/ESP headers, source
 * route IPv4 options. Bounded IPv6 hop/destination option chains supported. */
solaris_status_t solaris_ip_parse(const uint8_t *packet, size_t length,
                                  int verify_checksums, solaris_ip_packet_t *out);
/* In-place tuple rewrite with complete IPv4/TCP/UDP checksum repair. */
solaris_status_t solaris_ip_rewrite(uint8_t *packet, size_t length,
                                    const solaris_address_t *source,
                                    const solaris_address_t *destination);
solaris_status_t solaris_ip_udp(solaris_budget_t *budget,
                                const solaris_address_t *source,
                                const solaris_address_t *destination,
                                const uint8_t *payload, size_t length,
                                solaris_buffer_t **out);
uint16_t solaris_ip_checksum(const uint8_t *bytes, size_t length);
#endif
