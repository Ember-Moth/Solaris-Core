#include "policy/route/internal.h"
#include <stdio.h>
#include <string.h>

static solaris_status_t invalid(solaris_error_t *error, solaris_status_t code, const char *message)
{
    if (error) {
        memset(error, 0, sizeof(*error));
        error->code = code;
        (void)snprintf(error->message, sizeof(error->message), "%s", message);
    }
    return code;
}
static int space(unsigned char value) { return value == ' ' || value == '\t' || value == '\r' || value == '\n'; }
static void trim(const char **text, size_t *length)
{
    while (*length && space((unsigned char)**text)) { ++*text; --*length; }
    while (*length && space((unsigned char)(*text)[*length - 1])) --*length;
}
solaris_status_t solaris_route_normalize_domain(const char *text, size_t length, int suffix, int keyword,
    char out[256])
{
    if (suffix && length && text[0] == '.') { ++text; --length; }
    if (!keyword && length && text[length - 1] == '.') --length;
    if (!length || length > 255) return SOLARIS_EINVAL;
    for (size_t i = 0; i < length; ++i) {
        unsigned char value = (unsigned char)text[i];
        if (!((value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') ||
            (value >= '0' && value <= '9') || value == '-' || value == '_' || value == '.')) return SOLARIS_EINVAL;
        if (!keyword && value == '.' && (!i || i + 1 == length || text[i - 1] == '.')) return SOLARIS_EINVAL;
        out[i] = value >= 'A' && value <= 'Z' ? (char)(value + ('a' - 'A')) : (char)value;
    }
    out[length] = 0;
    return SOLARIS_OK;
}
static int number(const char *text, size_t length, unsigned limit, unsigned *out)
{
    if (!length) return 0;
    unsigned value = 0;
    for (size_t i = 0; i < length; ++i) {
        if (text[i] < '0' || text[i] > '9') return 0;
        unsigned digit = (unsigned)(text[i] - '0');
        if (value > (limit - digit) / 10) return 0;
        value = value * 10 + digit;
    }
    *out = value; return 1;
}
solaris_status_t solaris_route_rule_compile(const char *kind, const char *value, int no_resolve,
    uint64_t target, solaris_route_rule_t *out, solaris_error_t *error)
{
    if (out) memset(out, 0, sizeof(*out));
    if (error) memset(error, 0, sizeof(*error));
    if (!out || !kind || !target || (no_resolve != 0 && no_resolve != 1))
        return invalid(error, SOLARIS_EINVAL, "Invalid route rule arguments");
    static const char *const names[] = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR", "IP-CIDR6",
        "SRC-IP-CIDR", "SRC-PORT", "DST-PORT", "NETWORK", "FINAL"};
    solaris_route_rule_t rule = {0};
    for (size_t i = 0; i < sizeof(names) / sizeof(*names); ++i)
        if (!strcmp(kind, names[i])) { rule.kind = (uint32_t)i + 1; break; }
    if (!rule.kind) return invalid(error, SOLARIS_ENOTSUP, "Unsupported route rule kind");
    int cidr = rule.kind >= SOLARIS_ROUTE_IP_CIDR && rule.kind <= SOLARIS_ROUTE_SRC_IP_CIDR;
    if (no_resolve && !cidr) return invalid(error, SOLARIS_EINVAL, "no-resolve is only valid for CIDR rules");
    rule.target_id = target; rule.no_resolve = (uint32_t)no_resolve;
    if (!value) value = "";
    size_t length = strlen(value); trim(&value, &length);
    if (rule.kind == SOLARIS_ROUTE_FINAL) {
        if (length) return invalid(error, SOLARIS_EINVAL, "FINAL has no matcher value");
    } else if (rule.kind <= SOLARIS_ROUTE_DOMAIN_KEYWORD) {
        if (solaris_route_normalize_domain(value, length, rule.kind == SOLARIS_ROUTE_DOMAIN_SUFFIX,
            rule.kind == SOLARIS_ROUTE_DOMAIN_KEYWORD, rule.domain) != SOLARIS_OK)
            return invalid(error, SOLARIS_EINVAL, "Invalid ASCII domain matcher");
    } else if (cidr) {
        const char *slash = memchr(value, '/', length);
        if (!slash || slash == value || (size_t)(slash - value) >= sizeof(rule.address.host))
            return invalid(error, SOLARIS_EINVAL, "CIDR requires a numeric address and prefix");
        char host[256]; size_t host_length = (size_t)(slash - value);
        memcpy(host, value, host_length); host[host_length] = 0;
        if (solaris_address_parse(host, 0, &rule.address) != SOLARIS_OK ||
            (rule.address.family != SOLARIS_ADDRESS_IPV4 && rule.address.family != SOLARIS_ADDRESS_IPV6) ||
            (rule.kind == SOLARIS_ROUTE_IP_CIDR && rule.address.family != SOLARIS_ADDRESS_IPV4) ||
            (rule.kind == SOLARIS_ROUTE_IP_CIDR6 && rule.address.family != SOLARIS_ADDRESS_IPV6))
            return invalid(error, SOLARIS_EINVAL, "CIDR address family does not match the rule");
        unsigned prefix, bits = rule.address.family == SOLARIS_ADDRESS_IPV4 ? 32 : 128;
        if (!number(slash + 1, length - host_length - 1, bits, &prefix))
            return invalid(error, SOLARIS_EINVAL, "Invalid CIDR prefix length");
        rule.prefix_length = prefix;
        for (unsigned i = 0; i < bits / 8; ++i) {
            unsigned offset = i * 8;
            if (offset >= prefix) rule.address.ip[i] = 0;
            else if (offset + 8 > prefix) rule.address.ip[i] &= (uint8_t)(255u << (8 - (prefix - offset)));
        }
    } else if (rule.kind == SOLARIS_ROUTE_SRC_PORT || rule.kind == SOLARIS_ROUTE_DST_PORT) {
        const char *dash = memchr(value, '-', length); unsigned first;
        size_t first_length = dash ? (size_t)(dash - value) : length;
        if (!number(value, first_length, 65535, &first))
            return invalid(error, SOLARIS_EINVAL, "Invalid port or inclusive port range");
        unsigned last = first;
        if (dash && !number(dash + 1, length - first_length - 1, 65535, &last))
            return invalid(error, SOLARIS_EINVAL, "Invalid port or inclusive port range");
        if (first > last) return invalid(error, SOLARIS_EINVAL, "Port range is reversed");
        rule.port_first = (uint16_t)first; rule.port_last = (uint16_t)last;
    } else {
        if (length == 3 && (!memcmp(value, "tcp", 3) || !memcmp(value, "TCP", 3))) rule.network = SOLARIS_NETWORK_TCP;
        else if (length == 3 && (!memcmp(value, "udp", 3) || !memcmp(value, "UDP", 3))) rule.network = SOLARIS_NETWORK_UDP;
        else return invalid(error, SOLARIS_EINVAL, "NETWORK must be tcp or udp");
    }
    *out = rule; return SOLARIS_OK;
}
