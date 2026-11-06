#include "codec/ip/packet.h"
#include <string.h>

static uint16_t read16(const uint8_t *p) { return (uint16_t)((uint16_t)p[0] << 8u | p[1]); }
static void write16(uint8_t *p, uint16_t n) { p[0] = (uint8_t)(n >> 8u); p[1] = (uint8_t)n; }
static uint32_t sum_bytes(const uint8_t *p, size_t n, uint32_t sum)
{
    while (n > 1u) { sum += read16(p); p += 2; n -= 2; }
    if (n) sum += (uint32_t)*p << 8u;
    return sum;
}
static uint16_t finish(uint32_t sum)
{
    while (sum >> 16u) sum = (sum & 65535u) + (sum >> 16u);
    return (uint16_t)~sum;
}
uint16_t solaris_ip_checksum(const uint8_t *bytes, size_t length)
{ return finish(sum_bytes(bytes, length, 0)); }
static uint16_t transport_checksum(const uint8_t *p, const solaris_ip_packet_t *ip)
{
    uint32_t sum = 0;
    if (ip->protocol != SOLARIS_IP_ICMP) {
        if (ip->source.family == SOLARIS_ADDRESS_IPV4) sum = sum_bytes(p + 12, 8, 0);
        else sum = sum_bytes(p + 8, 32, 0);
        sum += (uint32_t)ip->transport_length + ip->protocol;
    }
    return finish(sum_bytes(p + ip->transport_offset, ip->transport_length, sum));
}
solaris_status_t solaris_ip_parse(const uint8_t *p, size_t n, int verify, solaris_ip_packet_t *out)
{
    if (!p || !out || n < 1u) return SOLARIS_EINVAL;
    memset(out, 0, sizeof(*out));
    solaris_ip_packet_t ip; memset(&ip, 0, sizeof(ip));
    size_t offset;
    if ((p[0] >> 4u) == 4u) {
        if (n < 20u) return SOLARIS_EINVAL;
        offset = (p[0] & 15u) * 4u;
        if (offset < 20u || offset > n || read16(p + 2) != n || (p[6] & 128u)) return SOLARIS_EINVAL;
        if (read16(p + 6) & 0x3fffu) return SOLARIS_ENOTSUP;
        if (verify && solaris_ip_checksum(p, offset)) return SOLARIS_EINVAL;
        for (size_t i = 20; i < offset;) {
            const uint8_t kind = p[i];
            if (kind == 0) break;
            if (kind == 1) { ++i; continue; }
            if (i + 2u > offset || p[i + 1] < 2u || p[i + 1] > offset - i) return SOLARIS_EINVAL;
            if (kind == 131u || kind == 137u) return SOLARIS_ENOTSUP;
            i += p[i + 1];
        }
        ip.source.family = ip.destination.family = SOLARIS_ADDRESS_IPV4;
        memcpy(ip.source.ip, p + 12, 4); memcpy(ip.destination.ip, p + 16, 4);
        ip.protocol = p[9]; ip.hop_limit = p[8];
    } else if ((p[0] >> 4u) == 6u) {
        if (n < 40u || n - 40u != read16(p + 4) || read16(p + 4) == 0u) return SOLARIS_EINVAL;
        ip.source.family = ip.destination.family = SOLARIS_ADDRESS_IPV6;
        memcpy(ip.source.ip, p + 8, 16); memcpy(ip.destination.ip, p + 24, 16);
        ip.protocol = p[6]; ip.hop_limit = p[7]; offset = 40u;
        unsigned count = 0;
        while (ip.protocol == 0u || ip.protocol == 60u) {
            if (++count > 8u || offset + 2u > n || (ip.protocol == 0u && offset != 40u)) return SOLARIS_EINVAL;
            size_t size = ((size_t)p[offset + 1] + 1u) * 8u;
            if (size > n - offset) return SOLARIS_EINVAL;
            for (size_t i = offset + 2; i < offset + size;) {
                uint8_t kind = p[i];
                if (kind == 0u) { ++i; continue; }
                if (i + 2u > offset + size || (size_t)p[i + 1] + 2u > offset + size - i) return SOLARIS_EINVAL;
                /* Unknown options that require discard are never forwarded. */
                if (kind & 0xc0u) return SOLARIS_ENOTSUP;
                i += (size_t)p[i + 1] + 2u;
            }
            ip.protocol = p[offset]; offset += size;
        }
        if (ip.protocol == 43u || ip.protocol == 44u || ip.protocol == 50u || ip.protocol == 51u)
            return SOLARIS_ENOTSUP;
    } else return SOLARIS_EINVAL;
    if (offset > n) return SOLARIS_EINVAL;
    ip.length = n; ip.transport_offset = offset; ip.transport_length = n - offset;
    const uint8_t *t = p + offset;
    size_t header;
    if (ip.protocol == SOLARIS_IP_TCP) {
        if (ip.transport_length < 20u) return SOLARIS_EINVAL;
        header = (size_t)(t[12] >> 4u) * 4u;
        if (header < 20u || header > ip.transport_length) return SOLARIS_EINVAL;
        ip.tcp_flags = t[13];
    } else if (ip.protocol == SOLARIS_IP_UDP) {
        header = 8u;
        if (ip.transport_length < header || read16(t + 4) != ip.transport_length) return SOLARIS_EINVAL;
        if (ip.source.family == SOLARIS_ADDRESS_IPV6 && !read16(t + 6)) return SOLARIS_EINVAL;
    } else if ((ip.protocol == SOLARIS_IP_ICMP && ip.source.family == SOLARIS_ADDRESS_IPV4) ||
               (ip.protocol == SOLARIS_IP_ICMP6 && ip.source.family == SOLARIS_ADDRESS_IPV6)) {
        header = 8u;
        if (ip.transport_length < header) return SOLARIS_EINVAL;
    } else return SOLARIS_ENOTSUP;
    if (verify && !(ip.protocol == SOLARIS_IP_UDP && ip.source.family == SOLARIS_ADDRESS_IPV4 && !read16(t + 6)) &&
        transport_checksum(p, &ip)) return SOLARIS_EINVAL;
    if (ip.protocol == SOLARIS_IP_TCP || ip.protocol == SOLARIS_IP_UDP) {
        ip.source.port = read16(t); ip.destination.port = read16(t + 2);
    }
    ip.payload_offset = offset + header; ip.payload_length = n - ip.payload_offset;
    *out = ip; return SOLARIS_OK;
}
solaris_status_t solaris_ip_rewrite(uint8_t *p, size_t n,
                                    const solaris_address_t *source, const solaris_address_t *destination)
{
    solaris_ip_packet_t ip;
    solaris_status_t rc = solaris_ip_parse(p, n, 0, &ip);
    if (rc != SOLARIS_OK) return rc;
    if (!source || !destination || source->family != ip.source.family || destination->family != source->family)
        return SOLARIS_EINVAL;
    if (source->family == SOLARIS_ADDRESS_IPV4) {
        memcpy(p + 12, source->ip, 4); memcpy(p + 16, destination->ip, 4);
        p[10] = p[11] = 0;
        write16(p + 10, solaris_ip_checksum(p, ip.transport_offset));
    } else {
        memcpy(p + 8, source->ip, 16); memcpy(p + 24, destination->ip, 16);
    }
    uint8_t *t = p + ip.transport_offset;
    size_t checksum_offset;
    if (ip.protocol == SOLARIS_IP_TCP || ip.protocol == SOLARIS_IP_UDP) {
        write16(t, source->port); write16(t + 2, destination->port);
        checksum_offset = ip.protocol == SOLARIS_IP_TCP ? 16u : 6u;
    } else checksum_offset = 2u;
    write16(t + checksum_offset, 0);
    uint16_t checksum = transport_checksum(p, &ip);
    if (!checksum && ip.protocol == SOLARIS_IP_UDP) checksum = 65535u;
    write16(t + checksum_offset, checksum);
    return SOLARIS_OK;
}
solaris_status_t solaris_ip_udp(solaris_budget_t *budget, const solaris_address_t *source,
                                const solaris_address_t *destination, const uint8_t *payload,
                                size_t n, solaris_buffer_t **out)
{
    if (!out) return SOLARIS_EINVAL;
    *out = NULL;
    if (!source || !destination || (!payload && n) || source->family != destination->family ||
        (source->family != SOLARIS_ADDRESS_IPV4 && source->family != SOLARIS_ADDRESS_IPV6)) return SOLARIS_EINVAL;
    size_t header = source->family == SOLARIS_ADDRESS_IPV4 ? 20u : 40u;
    if (n > 65535u - (header == 20u ? 28u : 8u)) return SOLARIS_EMSGSIZE;
    solaris_buffer_t *b;
    solaris_status_t rc = solaris_buffer_allocate(budget, header + 8u + n, &b);
    if (rc != SOLARIS_OK) return rc;
    uint8_t *p = solaris_buffer_mutable_data(b);
    memset(p, 0, header + 8u);
    if (header == 20u) {
        p[0] = 0x45; write16(p + 2, (uint16_t)(header + 8u + n)); p[8] = 64; p[9] = SOLARIS_IP_UDP;
    } else {
        p[0] = 0x60; write16(p + 4, (uint16_t)(8u + n)); p[6] = SOLARIS_IP_UDP; p[7] = 64;
    }
    write16(p + header + 4, (uint16_t)(n + 8u));
    /* A temporary nonzero checksum allows IPv6 structural validation. */
    write16(p + header + 6, 65535u);
    if (n) memcpy(p + header + 8u, payload, n);
    rc = solaris_ip_rewrite(p, header + 8u + n, source, destination);
    if (rc != SOLARIS_OK) { solaris_buffer_release(b); return rc; }
    (void)solaris_buffer_set_length(b, header + 8u + n);
    solaris_buffer_publish(b); *out = b; return SOLARIS_OK;
}
