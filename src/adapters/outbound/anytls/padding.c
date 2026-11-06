#include "adapters/outbound/anytls/internal.h"
#include <openssl/md5.h>
#include <openssl/rand.h>
#include <string.h>

static const char default_policy[] =
    "stop=8\n0=30-30\n1=100-400\n2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n"
    "3=9-9,500-1000\n4=500-1000\n5=500-1000\n6=500-1000\n7=500-1000";
static int number(const uint8_t **p, const uint8_t *end, uint32_t *out)
{
    const uint8_t *begin = *p; uint32_t n = 0u;
    while (*p != end && **p >= '0' && **p <= '9') {
        if (n > 65535u) return 0;
        n = n * 10u + (uint32_t)(*(*p)++ - '0');
    }
    *out = n; return *p != begin && n <= 65535u;
}
solaris_status_t solaris_anytls_policy_parse(const uint8_t *text, size_t length, solaris_anytls_policy_t *out)
{
    if (text == NULL || out == NULL || length == 0u || length > 4096u) return SOLARIS_EINVAL;
    solaris_anytls_policy_t policy = {0}; int have_stop = 0;
    const uint8_t *p = text, *end = text + length;
    while (p < end) {
        if ((size_t)(end - p) >= 5u && memcmp(p, "stop=", 5u) == 0) {
            p += 5u;
            if (have_stop || !number(&p, end, &policy.stop) || policy.stop > SOLARIS_ANYTLS_POLICY_ROWS) return SOLARIS_EINVAL;
            have_stop = 1;
        } else {
            uint32_t row;
            if (!number(&p, end, &row) || row >= SOLARIS_ANYTLS_POLICY_ROWS || p == end || *p++ != '=' || policy.counts[row] != 0u) return SOLARIS_EINVAL;
            for (;;) {
                uint8_t n = policy.counts[row];
                if (n == SOLARIS_ANYTLS_POLICY_PARTS || p == end) return SOLARIS_EINVAL;
                solaris_anytls_range_t *range = &policy.rows[row][n];
                if (*p == 'c') { p++; range->check = 1; if (row == 0u) return SOLARIS_EINVAL; }
                else {
                    uint32_t a, b;
                    if (!number(&p, end, &a) || p == end || *p++ != '-' || !number(&p, end, &b) || a == 0u || b == 0u) return SOLARIS_EINVAL;
                    range->low = (uint16_t)(a < b ? a : b); range->high = (uint16_t)(a > b ? a : b);
                }
                policy.counts[row]++;
                if (p == end || *p != ',') break;
                p++;
            }
        }
        if (p != end && *p++ != '\n') return SOLARIS_EINVAL;
    }
    if (!have_stop || policy.counts[0] > 1u) return SOLARIS_EINVAL;
    uint8_t digest[MD5_DIGEST_LENGTH]; MD5(text, length, digest);
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0u; i < sizeof(digest); ++i) { policy.md5[2u*i] = hex[digest[i] >> 4]; policy.md5[2u*i+1u] = hex[digest[i] & 15u]; }
    *out = policy; return SOLARIS_OK;
}
solaris_status_t solaris_anytls_policy_default(solaris_anytls_policy_t *out)
{ return solaris_anytls_policy_parse((const uint8_t *)default_policy, sizeof(default_policy) - 1u, out); }
static solaris_status_t draw(const solaris_anytls_parameters_t *parameters, const solaris_anytls_range_t *range, size_t *out)
{
    uint32_t value, width = (uint32_t)range->high - range->low;
    if (width == 0u) { *out = range->low; return SOLARIS_OK; }
    /* Rejection sampling matches the upstream half-open random range. */
    uint32_t threshold = (uint32_t)(0u - width) % width;
    unsigned int attempts = 0u;
    do {
        if (attempts++ == 16u) return SOLARIS_EIO;
        solaris_status_t rc = parameters->crypto.random != NULL ?
            parameters->crypto.random(parameters->crypto.context, (uint8_t *)&value, sizeof(value)) :
            (RAND_bytes((uint8_t *)&value, sizeof(value)) == 1 ? SOLARIS_OK : SOLARIS_EIO);
        if (rc != SOLARIS_OK) return rc;
    } while (value < threshold);
    *out = range->low + value % width; return SOLARIS_OK;
}
solaris_status_t solaris_anytls_padding0(const solaris_anytls_parameters_t *parameters, const solaris_anytls_policy_t *policy, size_t *length)
{
    *length = 0u;
    return policy->counts[0] == 0u ? SOLARIS_OK : draw(parameters, &policy->rows[0][0], length);
}
static solaris_status_t append(solaris_budget_t *budget, const uint8_t *data, size_t length,
    size_t waste, int has_waste, solaris_session_batch_t *out)
{
    if (out->count == SOLARIS_SESSION_BATCH_MAX) return SOLARIS_EMSGSIZE;
    solaris_buffer_t *b;
    solaris_status_t rc = solaris_buffer_allocate(budget, length + (has_waste ? 7u + waste : 0u), &b);
    if (rc != SOLARIS_OK) return rc;
    uint8_t *p = solaris_buffer_mutable_data(b);
    if (length != 0u) memcpy(p, data, length);
    if (has_waste) { memset(p + length, 0, 7u + waste); p[length + 5u] = (uint8_t)(waste >> 8); p[length + 6u] = (uint8_t)waste; }
    (void)solaris_buffer_set_length(b, length + (has_waste ? 7u + waste : 0u)); out->buffers[out->count++] = b;
    return SOLARIS_OK;
}
solaris_status_t solaris_anytls_pad(const solaris_anytls_parameters_t *parameters,
    const solaris_anytls_policy_t *policy, uint32_t packet, solaris_budget_t *budget,
    const uint8_t *data, size_t length, solaris_session_batch_t *out)
{
    size_t remain = length;
    if (packet < policy->stop && packet < SOLARIS_ANYTLS_POLICY_ROWS) {
        for (size_t i = 0u; i < policy->counts[packet]; ++i) {
            const solaris_anytls_range_t *range = &policy->rows[packet][i];
            if (range->check) { if (remain == 0u) break; else continue; }
            size_t target; solaris_status_t rc = draw(parameters, range, &target); if (rc != SOLARIS_OK) return rc;
            size_t n = remain > target ? target : remain;
            size_t padding = n == 0u ? target : (target > n + 7u ? target - n - 7u : 0u);
            rc = append(budget, data, n, padding, n == 0u || padding != 0u, out);
            if (rc != SOLARIS_OK) return rc;
            data += n; remain -= n;
        }
    }
    if (remain != 0u || out->count == 0u) return append(budget, data, remain, 0u, 0, out);
    return SOLARIS_OK;
}
