#include "md5.h"

#include <stdlib.h>
#include <string.h>

#define ANYTLS_MD5_LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32u - (c))))

static uint32_t load32_le(const uint8_t *p)
{
    return ((uint32_t)p[0]) |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static void store32_le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

void anytls_md5(const uint8_t *data, size_t len, uint8_t out[16])
{
    static const uint32_t s[64] = {
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
    };
    static const uint32_t k[64] = {
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
    };

    uint32_t a0 = 0x67452301;
    uint32_t b0 = 0xefcdab89;
    uint32_t c0 = 0x98badcfe;
    uint32_t d0 = 0x10325476;

    size_t new_len = len + 1u;
    while ((new_len % 64u) != 56u) {
        new_len++;
    }

    uint8_t *msg = (uint8_t *)calloc(new_len + 8u, 1u);
    if (msg == NULL) {
        memset(out, 0, 16u);
        return;
    }
    if (len > 0u && data != NULL) {
        memcpy(msg, data, len);
    }
    msg[len] = 0x80u;

    const uint64_t bits = (uint64_t)len * 8u;
    for (size_t i = 0; i < 8u; i++) {
        msg[new_len + i] = (uint8_t)(bits >> (8u * i));
    }

    for (size_t offset = 0; offset < new_len; offset += 64u) {
        uint32_t m[16];
        for (size_t i = 0; i < 16u; i++) {
            m[i] = load32_le(msg + offset + (i * 4u));
        }

        uint32_t a = a0;
        uint32_t b = b0;
        uint32_t c = c0;
        uint32_t d = d0;

        for (uint32_t i = 0; i < 64u; i++) {
            uint32_t f;
            uint32_t g;

            if (i < 16u) {
                f = (b & c) | ((~b) & d);
                g = i;
            } else if (i < 32u) {
                f = (d & b) | ((~d) & c);
                g = (5u * i + 1u) % 16u;
            } else if (i < 48u) {
                f = b ^ c ^ d;
                g = (3u * i + 5u) % 16u;
            } else {
                f = c ^ (b | (~d));
                g = (7u * i) % 16u;
            }

            const uint32_t temp = d;
            d = c;
            c = b;
            b = b + ANYTLS_MD5_LEFTROTATE(a + f + k[i] + m[g], s[i]);
            a = temp;
        }

        a0 += a;
        b0 += b;
        c0 += c;
        d0 += d;
    }

    free(msg);

    store32_le(out, a0);
    store32_le(out + 4, b0);
    store32_le(out + 8, c0);
    store32_le(out + 12, d0);
}

void anytls_md5_hex(const uint8_t digest[16], char out[33])
{
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < 16u; i++) {
        out[i * 2u] = hex[digest[i] >> 4];
        out[i * 2u + 1u] = hex[digest[i] & 0x0fu];
    }
    out[32] = '\0';
}
