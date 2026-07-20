#include "aproxy/geoip.h"

#include <stdlib.h>
#include <string.h>

#include "aproxy/filemap.h"

#define APROXY_GEOIP_MAX_FILE_SIZE (64u * 1024u * 1024u)

#if defined(_MSC_VER)
#define APROXY_ALWAYS_INLINE __forceinline
#elif defined(__GNUC__) || defined(__clang__)
#define APROXY_ALWAYS_INLINE inline __attribute__((always_inline))
#else
#define APROXY_ALWAYS_INLINE inline
#endif

typedef struct ipv4_entry {
    uint32_t network;
    uint8_t prefix_len;
} ipv4_entry_t;

typedef struct ipv6_entry {
    uint8_t network[16];
    uint8_t prefix_len;
} ipv6_entry_t;

/* Store IPv6 keys as two host-order integers after loading. This preserves
 * bytewise network ordering while avoiding a 16-byte memcmp in every binary
 * search iteration. */
typedef struct ipv6_key {
    uint64_t high;
    uint64_t low;
} ipv6_key_t;

typedef struct geoip_ref {
    const uint8_t *code;
    size_t code_len;
    const uint8_t *data;
    size_t len;
} geoip_ref_t;

typedef struct cidr_builder {
    ipv4_entry_t *ipv4;
    size_t ipv4_len;
    size_t ipv4_cap;
    ipv6_entry_t *ipv6;
    size_t ipv6_len;
    size_t ipv6_cap;
} cidr_builder_t;

struct aproxy_geoip_db {
    aproxy_filemap_t map;
    geoip_ref_t *entries;
    size_t entry_count;
    size_t entry_cap;
};

struct aproxy_geoip_set {
    char *code;
    uint32_t *ipv4_networks;
    uint32_t ipv4_offsets[34];
    size_t ipv4_count;
    uint8_t ipv4_prefixes[33];
    uint8_t ipv4_prefix_count;
    ipv6_key_t *ipv6_networks;
    uint32_t ipv6_offsets[130];
    size_t ipv6_count;
    uint8_t ipv6_prefixes[129];
    uint8_t ipv6_prefix_count;
};

static char *copy_string_n(const char *s, size_t len)
{
    char *copy = (char *)malloc(len + 1u);
    if (copy == NULL) {
        return NULL;
    }
    memcpy(copy, s, len);
    copy[len] = '\0';
    return copy;
}

static int ascii_lower(int c)
{
    return c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c;
}

static int code_compare(const uint8_t *a,
                        size_t a_len,
                        const uint8_t *b,
                        size_t b_len)
{
    const size_t common = a_len < b_len ? a_len : b_len;
    for (size_t i = 0u; i < common; i++) {
        const int left = ascii_lower(a[i]);
        const int right = ascii_lower(b[i]);
        if (left != right) {
            return left < right ? -1 : 1;
        }
    }
    if (a_len == b_len) {
        return 0;
    }
    return a_len < b_len ? -1 : 1;
}

static uint32_t load_ipv4_be(const uint8_t ip[4])
{
    return ((uint32_t)ip[0] << 24u) | ((uint32_t)ip[1] << 16u) |
           ((uint32_t)ip[2] << 8u) | (uint32_t)ip[3];
}

static APROXY_ALWAYS_INLINE uint64_t load_u64_be(const uint8_t value[8])
{
    return ((uint64_t)value[0] << 56u) |
           ((uint64_t)value[1] << 48u) |
           ((uint64_t)value[2] << 40u) |
           ((uint64_t)value[3] << 32u) |
           ((uint64_t)value[4] << 24u) |
           ((uint64_t)value[5] << 16u) |
           ((uint64_t)value[6] << 8u) | (uint64_t)value[7];
}

static APROXY_ALWAYS_INLINE ipv6_key_t
ipv6_key_from_bytes(const uint8_t value[16])
{
    ipv6_key_t key;
    key.high = load_u64_be(value);
    key.low = load_u64_be(value + 8u);
    return key;
}

static APROXY_ALWAYS_INLINE uint64_t ipv6_u64_mask(uint8_t bits)
{
    if (bits == 0u) {
        return 0u;
    }
    if (bits >= 64u) {
        return UINT64_MAX;
    }
    return UINT64_MAX << (64u - bits);
}

static APROXY_ALWAYS_INLINE ipv6_key_t
ipv6_key_mask(ipv6_key_t address, uint8_t prefix_len)
{
    ipv6_key_t network;
    if (prefix_len <= 64u) {
        network.high = address.high & ipv6_u64_mask(prefix_len);
        network.low = 0u;
    } else {
        network.high = address.high;
        network.low =
            address.low & ipv6_u64_mask((uint8_t)(prefix_len - 64u));
    }
    return network;
}

static uint32_t ipv4_mask(uint8_t prefix_len)
{
    if (prefix_len == 0u) {
        return 0u;
    }
    if (prefix_len >= 32u) {
        return UINT32_MAX;
    }
    return UINT32_MAX << (32u - prefix_len);
}

static void mask_ipv6_in_place(uint8_t address[16], uint8_t prefix_len)
{
    const size_t full_bytes = prefix_len / 8u;
    const uint8_t rem_bits = (uint8_t)(prefix_len % 8u);
    if (full_bytes < 16u) {
        if (rem_bits == 0u) {
            memset(address + full_bytes, 0, 16u - full_bytes);
        } else {
            address[full_bytes] = (uint8_t)(
                address[full_bytes] &
                (uint8_t)(0xffu << (8u - rem_bits)));
            if (full_bytes + 1u < 16u) {
                memset(address + full_bytes + 1u, 0,
                       16u - full_bytes - 1u);
            }
        }
    }
}

static void mask_ipv6(const uint8_t ip[16],
                      uint8_t prefix_len,
                      uint8_t out[16])
{
    memcpy(out, ip, 16u);
    mask_ipv6_in_place(out, prefix_len);
}

static int reserve_ipv4(cidr_builder_t *builder, size_t need)
{
    if (need <= builder->ipv4_cap) {
        return APROXY_OK;
    }
    size_t cap = builder->ipv4_cap == 0u ? 64u : builder->ipv4_cap;
    while (cap < need) {
        cap *= 2u;
    }
    ipv4_entry_t *entries =
        (ipv4_entry_t *)realloc(builder->ipv4, cap * sizeof(*entries));
    if (entries == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    builder->ipv4 = entries;
    builder->ipv4_cap = cap;
    return APROXY_OK;
}

static int reserve_ipv6(cidr_builder_t *builder, size_t need)
{
    if (need <= builder->ipv6_cap) {
        return APROXY_OK;
    }
    size_t cap = builder->ipv6_cap == 0u ? 64u : builder->ipv6_cap;
    while (cap < need) {
        cap *= 2u;
    }
    ipv6_entry_t *entries =
        (ipv6_entry_t *)realloc(builder->ipv6, cap * sizeof(*entries));
    if (entries == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    builder->ipv6 = entries;
    builder->ipv6_cap = cap;
    return APROXY_OK;
}

static int builder_add_cidr(cidr_builder_t *builder,
                            const uint8_t *ip,
                            size_t ip_len,
                            uint8_t prefix_len)
{
    if (builder == NULL || ip == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    if (ip_len == 4u) {
        if (prefix_len > 32u) {
            return APROXY_ERR_PARSE;
        }
        int rc = reserve_ipv4(builder, builder->ipv4_len + 1u);
        if (rc != APROXY_OK) {
            return rc;
        }
        builder->ipv4[builder->ipv4_len].prefix_len = prefix_len;
        builder->ipv4[builder->ipv4_len].network =
            load_ipv4_be(ip) & ipv4_mask(prefix_len);
        builder->ipv4_len++;
        return APROXY_OK;
    }
    if (ip_len == 16u) {
        if (prefix_len > 128u) {
            return APROXY_ERR_PARSE;
        }
        int rc = reserve_ipv6(builder, builder->ipv6_len + 1u);
        if (rc != APROXY_OK) {
            return rc;
        }
        builder->ipv6[builder->ipv6_len].prefix_len = prefix_len;
        mask_ipv6(ip, prefix_len, builder->ipv6[builder->ipv6_len].network);
        builder->ipv6_len++;
        return APROXY_OK;
    }
    return APROXY_ERR_PARSE;
}

static void builder_free(cidr_builder_t *builder)
{
    if (builder == NULL) {
        return;
    }
    free(builder->ipv4);
    free(builder->ipv6);
    memset(builder, 0, sizeof(*builder));
}

static int pb_read_varint(const uint8_t *data,
                          size_t len,
                          size_t *pos,
                          uint64_t *out)
{
    if (data == NULL || pos == NULL || out == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    uint64_t value = 0u;
    for (unsigned int shift = 0u; shift < 64u; shift += 7u) {
        if (*pos >= len) {
            return APROXY_ERR_BUFFER_TOO_SMALL;
        }
        const uint8_t byte = data[(*pos)++];
        value |= (uint64_t)(byte & 0x7fu) << shift;
        if ((byte & 0x80u) == 0u) {
            *out = value;
            return APROXY_OK;
        }
    }
    return APROXY_ERR_PARSE;
}

static int pb_read_len(const uint8_t *data,
                       size_t len,
                       size_t *pos,
                       const uint8_t **out_data,
                       size_t *out_len)
{
    uint64_t field_len = 0u;
    int rc = pb_read_varint(data, len, pos, &field_len);
    if (rc != APROXY_OK) {
        return rc;
    }
    if (field_len > (uint64_t)(len - *pos)) {
        return APROXY_ERR_BUFFER_TOO_SMALL;
    }
    *out_data = data + *pos;
    *out_len = (size_t)field_len;
    *pos += (size_t)field_len;
    return APROXY_OK;
}

static int pb_skip_field(const uint8_t *data,
                         size_t len,
                         size_t *pos,
                         uint32_t wire_type)
{
    uint64_t ignored = 0u;
    switch (wire_type) {
    case 0:
        return pb_read_varint(data, len, pos, &ignored);
    case 1:
        if (len - *pos < 8u) {
            return APROXY_ERR_BUFFER_TOO_SMALL;
        }
        *pos += 8u;
        return APROXY_OK;
    case 2: {
        const uint8_t *field_data = NULL;
        size_t field_len = 0u;
        return pb_read_len(data, len, pos, &field_data, &field_len);
    }
    case 5:
        if (len - *pos < 4u) {
            return APROXY_ERR_BUFFER_TOO_SMALL;
        }
        *pos += 4u;
        return APROXY_OK;
    default:
        return APROXY_ERR_PARSE;
    }
}

static int parse_cidr_message(const uint8_t *data,
                              size_t len,
                              cidr_builder_t *builder)
{
    size_t pos = 0u;
    const uint8_t *ip = NULL;
    size_t ip_len = 0u;
    uint64_t prefix = 0u;
    int has_prefix = 0;

    while (pos < len) {
        uint64_t key = 0u;
        int rc = pb_read_varint(data, len, &pos, &key);
        if (rc != APROXY_OK) {
            return rc;
        }
        const uint32_t field = (uint32_t)(key >> 3u);
        const uint32_t wire_type = (uint32_t)(key & 0x07u);

        if (field == 1u && wire_type == 2u) {
            rc = pb_read_len(data, len, &pos, &ip, &ip_len);
            if (rc != APROXY_OK) {
                return rc;
            }
        } else if (field == 2u && wire_type == 0u) {
            rc = pb_read_varint(data, len, &pos, &prefix);
            if (rc != APROXY_OK) {
                return rc;
            }
            has_prefix = 1;
        } else {
            rc = pb_skip_field(data, len, &pos, wire_type);
            if (rc != APROXY_OK) {
                return rc;
            }
        }
    }

    if (ip == NULL || !has_prefix || prefix > 128u) {
        return APROXY_ERR_PARSE;
    }
    return builder_add_cidr(builder, ip, ip_len, (uint8_t)prefix);
}

static int geoip_entry_code(const uint8_t *data,
                            size_t len,
                            const uint8_t **out_code,
                            size_t *out_code_len)
{
    size_t pos = 0u;
    *out_code = NULL;
    *out_code_len = 0u;

    while (pos < len) {
        uint64_t key = 0u;
        int rc = pb_read_varint(data, len, &pos, &key);
        if (rc != APROXY_OK) {
            return rc;
        }
        const uint32_t field = (uint32_t)(key >> 3u);
        const uint32_t wire_type = (uint32_t)(key & 0x07u);
        if (field == 1u && wire_type == 2u) {
            rc = pb_read_len(data, len, &pos, out_code, out_code_len);
            if (rc != APROXY_OK) {
                return rc;
            }
        } else {
            rc = pb_skip_field(data, len, &pos, wire_type);
            if (rc != APROXY_OK) {
                return rc;
            }
        }
    }
    return *out_code == NULL || *out_code_len == 0u ? APROXY_ERR_PARSE
                                                    : APROXY_OK;
}

static int parse_geoip_entry_cidrs(const uint8_t *data,
                                   size_t len,
                                   cidr_builder_t *builder)
{
    size_t pos = 0u;
    while (pos < len) {
        uint64_t key = 0u;
        int rc = pb_read_varint(data, len, &pos, &key);
        if (rc != APROXY_OK) {
            return rc;
        }
        const uint32_t field = (uint32_t)(key >> 3u);
        const uint32_t wire_type = (uint32_t)(key & 0x07u);
        if (field == 2u && wire_type == 2u) {
            const uint8_t *cidr_data = NULL;
            size_t cidr_len = 0u;
            rc = pb_read_len(data, len, &pos, &cidr_data, &cidr_len);
            if (rc != APROXY_OK) {
                return rc;
            }
            rc = parse_cidr_message(cidr_data, cidr_len, builder);
            if (rc != APROXY_OK) {
                return rc;
            }
        } else {
            rc = pb_skip_field(data, len, &pos, wire_type);
            if (rc != APROXY_OK) {
                return rc;
            }
        }
    }
    return APROXY_OK;
}

static int cmp_ipv4_entry(const void *a, const void *b)
{
    const ipv4_entry_t *ea = (const ipv4_entry_t *)a;
    const ipv4_entry_t *eb = (const ipv4_entry_t *)b;
    if (ea->prefix_len != eb->prefix_len) {
        return (int)ea->prefix_len - (int)eb->prefix_len;
    }
    if (ea->network < eb->network) {
        return -1;
    }
    return ea->network > eb->network ? 1 : 0;
}

static int cmp_ipv6_entry(const void *a, const void *b)
{
    const ipv6_entry_t *ea = (const ipv6_entry_t *)a;
    const ipv6_entry_t *eb = (const ipv6_entry_t *)b;
    if (ea->prefix_len != eb->prefix_len) {
        return (int)ea->prefix_len - (int)eb->prefix_len;
    }
    return memcmp(ea->network, eb->network, 16u);
}

static size_t dedup_ipv4(ipv4_entry_t *entries, size_t count)
{
    if (count == 0u) {
        return 0u;
    }
    size_t out = 1u;
    for (size_t i = 1u; i < count; i++) {
        if (entries[i].prefix_len != entries[out - 1u].prefix_len ||
            entries[i].network != entries[out - 1u].network) {
            entries[out++] = entries[i];
        }
    }
    return out;
}

static size_t dedup_ipv6(ipv6_entry_t *entries, size_t count)
{
    if (count == 0u) {
        return 0u;
    }
    size_t out = 1u;
    for (size_t i = 1u; i < count; i++) {
        if (entries[i].prefix_len != entries[out - 1u].prefix_len ||
            memcmp(entries[i].network, entries[out - 1u].network, 16u) != 0) {
            entries[out++] = entries[i];
        }
    }
    return out;
}

static int compile_set(aproxy_geoip_set_t *set, cidr_builder_t *builder)
{
    if (builder->ipv4_len > UINT32_MAX ||
        builder->ipv6_len > UINT32_MAX) {
        return APROXY_ERR_FRAME_TOO_LARGE;
    }
    if (builder->ipv4_len > 0u) {
        qsort(builder->ipv4, builder->ipv4_len, sizeof(builder->ipv4[0]),
              cmp_ipv4_entry);
        builder->ipv4_len = dedup_ipv4(builder->ipv4, builder->ipv4_len);
        for (size_t i = 0u; i < builder->ipv4_len; i++) {
            set->ipv4_offsets[builder->ipv4[i].prefix_len + 1u]++;
        }
        for (size_t i = 1u; i < 34u; i++) {
            set->ipv4_offsets[i] += set->ipv4_offsets[i - 1u];
        }
        /* The result is narrower than the builder entry, so compact it in
         * place before transferring allocation ownership to the set. */
        for (size_t i = 0u; i < builder->ipv4_len; i++) {
            const uint32_t network = builder->ipv4[i].network;
            memcpy((uint8_t *)builder->ipv4 + i * sizeof(network),
                   &network, sizeof(network));
        }
        for (int prefix = 32; prefix >= 0; prefix--) {
            if (set->ipv4_offsets[prefix] !=
                set->ipv4_offsets[prefix + 1]) {
                set->ipv4_prefixes[set->ipv4_prefix_count++] =
                    (uint8_t)prefix;
            }
        }
        set->ipv4_count = builder->ipv4_len;
        void *ipv4_storage = builder->ipv4;
        void *shrunk = realloc(
            ipv4_storage, builder->ipv4_len * sizeof(uint32_t));
        set->ipv4_networks = (uint32_t *)(shrunk == NULL
                                              ? ipv4_storage
                                              : shrunk);
        builder->ipv4 = NULL;
        builder->ipv4_len = 0u;
        builder->ipv4_cap = 0u;
    }

    if (builder->ipv6_len > 0u) {
        qsort(builder->ipv6, builder->ipv6_len, sizeof(builder->ipv6[0]),
              cmp_ipv6_entry);
        builder->ipv6_len = dedup_ipv6(builder->ipv6, builder->ipv6_len);
        for (size_t i = 0u; i < builder->ipv6_len; i++) {
            set->ipv6_offsets[builder->ipv6[i].prefix_len + 1u]++;
        }
        for (size_t i = 1u; i < 130u; i++) {
            set->ipv6_offsets[i] += set->ipv6_offsets[i - 1u];
        }
        /* Read each 17-byte builder entry before overwriting its leading
         * bytes with the narrower runtime representation. */
        for (size_t i = 0u; i < builder->ipv6_len; i++) {
            const ipv6_key_t key =
                ipv6_key_from_bytes(builder->ipv6[i].network);
            memcpy((uint8_t *)builder->ipv6 + i * sizeof(key), &key,
                   sizeof(key));
        }
        for (int prefix = 128; prefix >= 0; prefix--) {
            if (set->ipv6_offsets[prefix] !=
                set->ipv6_offsets[prefix + 1]) {
                set->ipv6_prefixes[set->ipv6_prefix_count++] =
                    (uint8_t)prefix;
            }
        }
        set->ipv6_count = builder->ipv6_len;
        void *ipv6_storage = builder->ipv6;
        void *shrunk = realloc(
            ipv6_storage, builder->ipv6_len * sizeof(ipv6_key_t));
        set->ipv6_networks = (ipv6_key_t *)(shrunk == NULL
                                                ? ipv6_storage
                                                : shrunk);
        builder->ipv6 = NULL;
        builder->ipv6_len = 0u;
        builder->ipv6_cap = 0u;
    }
    return APROXY_OK;
}

static int db_reserve(aproxy_geoip_db_t *db, size_t need)
{
    if (need <= db->entry_cap) {
        return APROXY_OK;
    }
    size_t cap = db->entry_cap == 0u ? 64u : db->entry_cap;
    while (cap < need) {
        if (cap > SIZE_MAX / 2u) {
            cap = need;
            break;
        }
        cap *= 2u;
    }
    if (cap > SIZE_MAX / sizeof(*db->entries)) {
        return APROXY_ERR_NO_MEMORY;
    }
    geoip_ref_t *entries =
        (geoip_ref_t *)realloc(db->entries, cap * sizeof(*entries));
    if (entries == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    db->entries = entries;
    db->entry_cap = cap;
    return APROXY_OK;
}

static int db_add_entry(aproxy_geoip_db_t *db,
                        const uint8_t *entry,
                        size_t entry_len)
{
    const uint8_t *code = NULL;
    size_t code_len = 0u;
    int rc = geoip_entry_code(entry, entry_len, &code, &code_len);
    if (rc != APROXY_OK) {
        return rc;
    }
    rc = db_reserve(db, db->entry_count + 1u);
    if (rc != APROXY_OK) {
        return rc;
    }
    geoip_ref_t *ref = &db->entries[db->entry_count++];
    ref->code = code;
    ref->code_len = code_len;
    ref->data = entry;
    ref->len = entry_len;
    return APROXY_OK;
}

static int ref_compare(const void *a, const void *b)
{
    const geoip_ref_t *left = (const geoip_ref_t *)a;
    const geoip_ref_t *right = (const geoip_ref_t *)b;
    return code_compare(left->code, left->code_len, right->code,
                        right->code_len);
}

static int parse_db_index(aproxy_geoip_db_t *db)
{
    size_t pos = 0u;

    while (pos < db->map.len) {
        uint64_t key = 0u;
        int rc = pb_read_varint(db->map.data, db->map.len, &pos, &key);
        if (rc != APROXY_OK) {
            return rc;
        }
        const uint32_t field = (uint32_t)(key >> 3u);
        const uint32_t wire_type = (uint32_t)(key & 0x07u);
        if (field == 1u && wire_type == 2u) {
            const uint8_t *entry_data = NULL;
            size_t entry_len = 0u;
            rc = pb_read_len(db->map.data, db->map.len, &pos, &entry_data,
                             &entry_len);
            if (rc == APROXY_OK) {
                rc = db_add_entry(db, entry_data, entry_len);
            }
        } else {
            rc = pb_skip_field(db->map.data, db->map.len, &pos, wire_type);
        }
        if (rc != APROXY_OK) {
            return rc;
        }
    }
    if (db->entry_count == 0u) {
        return APROXY_ERR_PARSE;
    }
    qsort(db->entries, db->entry_count, sizeof(db->entries[0]), ref_compare);
    geoip_ref_t *entries = (geoip_ref_t *)realloc(
        db->entries, db->entry_count * sizeof(*db->entries));
    if (entries != NULL) {
        db->entries = entries;
        db->entry_cap = db->entry_count;
    }
    return APROXY_OK;
}

static size_t db_find_first(const aproxy_geoip_db_t *db,
                            const uint8_t *code,
                            size_t code_len)
{
    size_t left = 0u;
    size_t right = db->entry_count;
    while (left < right) {
        const size_t mid = left + (right - left) / 2u;
        if (code_compare(db->entries[mid].code, db->entries[mid].code_len,
                         code, code_len) < 0) {
            left = mid + 1u;
        } else {
            right = mid;
        }
    }
    return left < db->entry_count &&
                   code_compare(db->entries[left].code,
                                db->entries[left].code_len, code,
                                code_len) == 0
               ? left
               : SIZE_MAX;
}

int aproxy_geoip_db_open_v2ray_dat(const char *path,
                                   aproxy_geoip_db_t **out)
{
    if (path == NULL || out == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    *out = NULL;
    aproxy_geoip_db_t *db =
        (aproxy_geoip_db_t *)calloc(1u, sizeof(*db));
    if (db == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    db->map.fd = -1;
    int rc = aproxy_filemap_open_ro(path, APROXY_GEOIP_MAX_FILE_SIZE,
                                    &db->map);
    if (rc == APROXY_OK) {
        rc = parse_db_index(db);
    }
    if (rc == APROXY_OK) {
        aproxy_filemap_advise_normal(&db->map);
    }
    if (rc != APROXY_OK) {
        aproxy_geoip_db_free(db);
        return rc;
    }
    *out = db;
    return APROXY_OK;
}

void aproxy_geoip_db_free(aproxy_geoip_db_t *db)
{
    if (db == NULL) {
        return;
    }
    free(db->entries);
    aproxy_filemap_close(&db->map);
    free(db);
}

static int ipv4_binary_search(const uint32_t *values,
                              size_t start,
                              size_t end,
                              uint32_t needle)
{
    while (start < end) {
        const size_t mid = start + (end - start) / 2u;
        if (values[mid] == needle) {
            return 1;
        }
        if (values[mid] < needle) {
            start = mid + 1u;
        } else {
            end = mid;
        }
    }
    return 0;
}

static APROXY_ALWAYS_INLINE int
ipv6_binary_search(const ipv6_key_t *values,
                   size_t start,
                   size_t end,
                   ipv6_key_t needle)
{
    while (start < end) {
        const size_t mid = start + (end - start) / 2u;
        const ipv6_key_t value = values[mid];
        if (value.high == needle.high && value.low == needle.low) {
            return 1;
        }
        if (value.high < needle.high ||
            (value.high == needle.high && value.low < needle.low)) {
            start = mid + 1u;
        } else {
            end = mid;
        }
    }
    return 0;
}

int aproxy_geoip_db_load(const aproxy_geoip_db_t *db,
                         const char *country_code,
                         aproxy_geoip_set_t **out)
{
    if (db == NULL || country_code == NULL || country_code[0] == '\0' ||
        out == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    *out = NULL;

    const size_t code_len = strlen(country_code);
    const size_t first = db_find_first(
        db, (const uint8_t *)country_code, code_len);
    if (first == SIZE_MAX) {
        return APROXY_ERR_PARSE;
    }

    cidr_builder_t builder;
    memset(&builder, 0, sizeof(builder));
    int rc = APROXY_OK;
    for (size_t i = first;
         i < db->entry_count &&
         code_compare(db->entries[i].code, db->entries[i].code_len,
                      (const uint8_t *)country_code, code_len) == 0;
         i++) {
        rc = parse_geoip_entry_cidrs(db->entries[i].data, db->entries[i].len,
                                     &builder);
        if (rc != APROXY_OK) {
            break;
        }
    }
    if (rc != APROXY_OK) {
        builder_free(&builder);
        return rc;
    }
    if (builder.ipv4_len == 0u && builder.ipv6_len == 0u) {
        builder_free(&builder);
        return APROXY_ERR_PARSE;
    }

    aproxy_geoip_set_t *set =
        (aproxy_geoip_set_t *)calloc(1u, sizeof(*set));
    if (set == NULL) {
        builder_free(&builder);
        return APROXY_ERR_NO_MEMORY;
    }
    set->code = copy_string_n(country_code, strlen(country_code));
    if (set->code == NULL) {
        builder_free(&builder);
        free(set);
        return APROXY_ERR_NO_MEMORY;
    }

    rc = compile_set(set, &builder);
    builder_free(&builder);
    if (rc != APROXY_OK) {
        aproxy_geoip_set_free(set);
        return rc;
    }

    *out = set;
    return APROXY_OK;
}

int aproxy_geoip_set_load_v2ray_dat(const char *path,
                                    const char *country_code,
                                    aproxy_geoip_set_t **out)
{
    if (path == NULL || country_code == NULL || country_code[0] == '\0' ||
        out == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    *out = NULL;
    aproxy_geoip_db_t *db = NULL;
    int rc = aproxy_geoip_db_open_v2ray_dat(path, &db);
    if (rc == APROXY_OK) {
        rc = aproxy_geoip_db_load(db, country_code, out);
    }
    aproxy_geoip_db_free(db);
    return rc;
}

void aproxy_geoip_set_free(aproxy_geoip_set_t *set)
{
    if (set == NULL) {
        return;
    }
    free(set->code);
    free(set->ipv4_networks);
    free(set->ipv6_networks);
    free(set);
}

const char *aproxy_geoip_set_code(const aproxy_geoip_set_t *set)
{
    return set == NULL ? NULL : set->code;
}

void aproxy_geoip_set_stats(const aproxy_geoip_set_t *set,
                            aproxy_geoip_stats_t *out)
{
    if (out == NULL) {
        return;
    }
    memset(out, 0, sizeof(*out));
    if (set == NULL) {
        return;
    }
    out->ipv4_count = set->ipv4_count;
    out->ipv6_count = set->ipv6_count;
}

int aproxy_geoip_set_match(const aproxy_geoip_set_t *set,
                           const aproxy_addr_t *addr)
{
    if (set == NULL || addr == NULL) {
        return 0;
    }
    if (addr->family == APROXY_ADDR_IPV4 && set->ipv4_networks != NULL) {
        const uint32_t ip = load_ipv4_be(addr->addr);
        for (size_t i = 0u; i < set->ipv4_prefix_count; i++) {
            const uint8_t prefix = set->ipv4_prefixes[i];
            const size_t start = set->ipv4_offsets[prefix];
            const size_t end = set->ipv4_offsets[prefix + 1];
            const uint32_t network = ip & ipv4_mask(prefix);
            if (ipv4_binary_search(set->ipv4_networks, start, end, network)) {
                return 1;
            }
        }
        return 0;
    }
    if (addr->family == APROXY_ADDR_IPV6 && set->ipv6_networks != NULL) {
        const ipv6_key_t address = ipv6_key_from_bytes(addr->addr);
        for (size_t i = 0u; i < set->ipv6_prefix_count; i++) {
            const uint8_t prefix = set->ipv6_prefixes[i];
            const size_t start = set->ipv6_offsets[prefix];
            const size_t end = set->ipv6_offsets[prefix + 1];
            const ipv6_key_t key = ipv6_key_mask(address, prefix);
            if (ipv6_binary_search(set->ipv6_networks, start, end, key)) {
                return 1;
            }
        }
    }
    return 0;
}
