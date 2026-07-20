#define PCRE2_CODE_UNIT_WIDTH 8

#include "aproxy/geosite.h"

#include <pcre2.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "aproxy/filemap.h"

#define APROXY_GEOSITE_MAX_FILE_SIZE (128u * 1024u * 1024u)

#if defined(_MSC_VER)
#define APROXY_ALWAYS_INLINE __forceinline
#elif defined(__GNUC__) || defined(__clang__)
#define APROXY_ALWAYS_INLINE inline __attribute__((always_inline))
#else
#define APROXY_ALWAYS_INLINE inline
#endif

typedef struct geosite_ref {
    const uint8_t *code;
    size_t code_len;
    const uint8_t *data;
    size_t len;
} geosite_ref_t;

typedef struct string_builder {
    char **items;
    size_t len;
    size_t cap;
} string_builder_t;

typedef struct string_table {
    char *arena;
    uint32_t *offsets;
    size_t count;
    size_t bytes;
} string_table_t;

typedef struct keyword_edge {
    uint8_t value;
    uint32_t next;
} keyword_edge_t;

typedef struct keyword_build_node {
    keyword_edge_t *edges;
    size_t edge_count;
    size_t edge_capacity;
    uint32_t failure;
    int terminal;
} keyword_build_node_t;

typedef struct keyword_builder {
    keyword_build_node_t *nodes;
    size_t count;
    size_t capacity;
} keyword_builder_t;

typedef struct keyword_node {
    uint32_t edge_offset;
    uint32_t failure;
    /* A byte-keyed trie node has at most 256 distinct outgoing edges. */
    uint16_t edge_count;
    uint8_t terminal;
} keyword_node_t;

typedef struct keyword_matcher {
    keyword_node_t *nodes;
    uint8_t *edge_values;
    uint32_t *edge_next;
    size_t count;
    size_t edge_count;
} keyword_matcher_t;

struct aproxy_geosite_db {
    aproxy_filemap_t map;
    geosite_ref_t *entries;
    size_t entry_count;
    size_t entry_cap;
};

struct aproxy_geosite_set {
    char *selector;
    string_table_t exact;
    string_table_t suffix;
    string_table_t keyword;
    keyword_matcher_t keyword_matcher;
    size_t keyword_count;
    size_t keyword_bytes;
    pcre2_code **regex_codes;
    pcre2_match_data **regex_matches;
    size_t regex_count;
};

static int keyword_builder_reserve(keyword_builder_t *builder, size_t need)
{
    if (need <= builder->capacity) {
        return APROXY_OK;
    }
    size_t capacity = builder->capacity == 0u ? 64u : builder->capacity;
    while (capacity < need) {
        if (capacity > SIZE_MAX / 2u) {
            return APROXY_ERR_NO_MEMORY;
        }
        capacity *= 2u;
    }
    if (capacity > UINT32_MAX ||
        capacity > SIZE_MAX / sizeof(*builder->nodes)) {
        return APROXY_ERR_NO_MEMORY;
    }
    keyword_build_node_t *nodes = (keyword_build_node_t *)realloc(
        builder->nodes, capacity * sizeof(*builder->nodes));
    if (nodes == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    builder->nodes = nodes;
    builder->capacity = capacity;
    return APROXY_OK;
}

static int keyword_builder_add_node(keyword_builder_t *builder, uint32_t *out)
{
    const int rc = keyword_builder_reserve(builder, builder->count + 1u);
    if (rc != APROXY_OK) {
        return rc;
    }
    keyword_build_node_t *node = &builder->nodes[builder->count];
    memset(node, 0, sizeof(*node));
    *out = (uint32_t)builder->count++;
    return APROXY_OK;
}

static uint32_t keyword_build_node_find(const keyword_build_node_t *node,
                                        uint8_t value)
{
    for (size_t i = 0u; i < node->edge_count; i++) {
        if (node->edges[i].value == value) {
            return node->edges[i].next;
        }
    }
    return UINT32_MAX;
}

static int keyword_build_node_add_edge(keyword_build_node_t *node,
                                       uint8_t value,
                                       uint32_t next)
{
    if (node->edge_count == node->edge_capacity) {
        size_t capacity =
            node->edge_capacity == 0u ? 4u : node->edge_capacity * 2u;
        if (capacity < node->edge_capacity ||
            capacity > SIZE_MAX / sizeof(*node->edges)) {
            return APROXY_ERR_NO_MEMORY;
        }
        keyword_edge_t *edges = (keyword_edge_t *)realloc(
            node->edges, capacity * sizeof(*node->edges));
        if (edges == NULL) {
            return APROXY_ERR_NO_MEMORY;
        }
        node->edges = edges;
        node->edge_capacity = capacity;
    }
    node->edges[node->edge_count++] =
        (keyword_edge_t){.value = value, .next = next};
    return APROXY_OK;
}

static void keyword_builder_free(keyword_builder_t *builder)
{
    if (builder == NULL) {
        return;
    }
    for (size_t i = 0u; i < builder->count; i++) {
        free(builder->nodes[i].edges);
    }
    free(builder->nodes);
    memset(builder, 0, sizeof(*builder));
}

static int keyword_edge_compare(const void *a, const void *b)
{
    return (int)((const keyword_edge_t *)a)->value -
           (int)((const keyword_edge_t *)b)->value;
}

static int keyword_matcher_pack(keyword_matcher_t *matcher,
                                keyword_builder_t *builder)
{
    size_t edge_count = 0u;
    for (size_t i = 0u; i < builder->count; i++) {
        const size_t node_edges = builder->nodes[i].edge_count;
        if (node_edges > UINT16_MAX || edge_count > UINT32_MAX - node_edges) {
            return APROXY_ERR_NO_MEMORY;
        }
        edge_count += node_edges;
    }
    if (builder->count > SIZE_MAX / sizeof(*matcher->nodes) ||
        edge_count > SIZE_MAX / sizeof(*matcher->edge_next)) {
        return APROXY_ERR_NO_MEMORY;
    }

    uint8_t *edge_values = edge_count == 0u
                               ? NULL
                               : (uint8_t *)malloc(edge_count);
    uint32_t *edge_next = edge_count == 0u
                              ? NULL
                              : (uint32_t *)malloc(
                                    edge_count * sizeof(*edge_next));
    if (edge_count != 0u &&
        (edge_values == NULL || edge_next == NULL)) {
        free(edge_values);
        free(edge_next);
        return APROXY_ERR_NO_MEMORY;
    }

    size_t offset = 0u;
    for (size_t i = 0u; i < builder->count; i++) {
        keyword_build_node_t source;
        memcpy(&source, &builder->nodes[i], sizeof(source));
        if (source.edge_count > 1u) {
            qsort(source.edges, source.edge_count, sizeof(source.edges[0]),
                  keyword_edge_compare);
        }
        keyword_node_t packed = {
            .edge_offset = (uint32_t)offset,
            .failure = source.failure,
            .edge_count = (uint16_t)source.edge_count,
            .terminal = source.terminal != 0,
        };
        for (size_t j = 0u; j < source.edge_count; j++) {
            edge_values[offset] = source.edges[j].value;
            edge_next[offset] = source.edges[j].next;
            offset++;
        }
        free(source.edges);
        memcpy((uint8_t *)builder->nodes + i * sizeof(packed),
               &packed, sizeof(packed));
    }

    void *node_storage = builder->nodes;
    const size_t node_bytes = builder->count * sizeof(keyword_node_t);
    void *shrunk = realloc(node_storage, node_bytes);
    if (shrunk != NULL) {
        node_storage = shrunk;
    }

    matcher->nodes = (keyword_node_t *)node_storage;
    matcher->edge_values = edge_values;
    matcher->edge_next = edge_next;
    matcher->count = builder->count;
    matcher->edge_count = edge_count;
    builder->nodes = NULL;
    builder->count = 0u;
    builder->capacity = 0u;
    return APROXY_OK;
}

static int keyword_matcher_build(keyword_matcher_t *matcher,
                                 const string_table_t *table)
{
    if (table->count == 0u) {
        return APROXY_OK;
    }
    keyword_builder_t builder;
    memset(&builder, 0, sizeof(builder));
    uint32_t root = 0u;
    int rc = keyword_builder_add_node(&builder, &root);
    for (size_t i = 0u; i < table->count && rc == APROXY_OK; i++) {
        const uint8_t *keyword =
            (const uint8_t *)(table->arena + table->offsets[i]);
        uint32_t state = 0u;
        for (size_t position = 0u; keyword[position] != 0u; position++) {
            uint32_t next = keyword_build_node_find(
                &builder.nodes[state], keyword[position]);
            if (next == UINT32_MAX) {
                rc = keyword_builder_add_node(&builder, &next);
                if (rc != APROXY_OK) {
                    break;
                }
                rc = keyword_build_node_add_edge(
                    &builder.nodes[state], keyword[position], next);
                if (rc != APROXY_OK) {
                    break;
                }
            }
            state = next;
        }
        if (rc == APROXY_OK) {
            builder.nodes[state].terminal = 1;
        }
    }

    uint32_t *queue = NULL;
    if (rc == APROXY_OK) {
        queue = (uint32_t *)malloc(builder.count * sizeof(*queue));
        if (queue == NULL) {
            rc = APROXY_ERR_NO_MEMORY;
        }
    }
    size_t head = 0u;
    size_t tail = 0u;
    if (rc == APROXY_OK) {
        keyword_build_node_t *root_node = &builder.nodes[0];
        for (size_t i = 0u; i < root_node->edge_count; i++) {
            queue[tail++] = root_node->edges[i].next;
        }
    }
    while (rc == APROXY_OK && head < tail) {
        const uint32_t state = queue[head++];
        keyword_build_node_t *node = &builder.nodes[state];
        for (size_t i = 0u; i < node->edge_count; i++) {
            const uint8_t value = node->edges[i].value;
            const uint32_t next = node->edges[i].next;
            uint32_t failure = node->failure;
            uint32_t candidate = keyword_build_node_find(
                &builder.nodes[failure], value);
            while (candidate == UINT32_MAX && failure != 0u) {
                failure = builder.nodes[failure].failure;
                candidate = keyword_build_node_find(
                    &builder.nodes[failure], value);
            }
            builder.nodes[next].failure =
                candidate == UINT32_MAX ? 0u : candidate;
            builder.nodes[next].terminal |=
                builder.nodes[builder.nodes[next].failure].terminal;
            queue[tail++] = next;
        }
    }
    free(queue);
    if (rc == APROXY_OK) {
        rc = keyword_matcher_pack(matcher, &builder);
    }
    keyword_builder_free(&builder);
    return rc;
}

static uint32_t keyword_matcher_find(const keyword_matcher_t *matcher,
                                     uint32_t state,
                                     uint8_t value)
{
    const keyword_node_t *node = &matcher->nodes[state];
    if (node->edge_count == 0u) {
        return UINT32_MAX;
    }
    const uint8_t *values = matcher->edge_values + node->edge_offset;
    const uint32_t *next = matcher->edge_next + node->edge_offset;
    if (node->edge_count <= 4u) {
        for (uint16_t i = 0u; i < node->edge_count; i++) {
            if (values[i] == value) {
                return next[i];
            }
        }
        return UINT32_MAX;
    }

    uint32_t left = 0u;
    uint32_t right = node->edge_count;
    while (left < right) {
        const uint32_t mid = left + (right - left) / 2u;
        if (values[mid] == value) {
            return next[mid];
        }
        if (values[mid] < value) {
            left = mid + 1u;
        } else {
            right = mid;
        }
    }
    return UINT32_MAX;
}

static int keyword_matcher_match(const keyword_matcher_t *matcher,
                                 const uint8_t *value,
                                 size_t len)
{
    if (matcher->count == 0u) {
        return 0;
    }
    uint32_t state = 0u;
    for (size_t i = 0u; i < len; i++) {
        uint32_t next = keyword_matcher_find(matcher, state, value[i]);
        while (next == UINT32_MAX && state != 0u) {
            state = matcher->nodes[state].failure;
            next = keyword_matcher_find(matcher, state, value[i]);
        }
        state = next == UINT32_MAX ? 0u : next;
        if (matcher->nodes[state].terminal) {
            return 1;
        }
    }
    return 0;
}

static void keyword_matcher_free(keyword_matcher_t *matcher)
{
    free(matcher->nodes);
    free(matcher->edge_values);
    free(matcher->edge_next);
    memset(matcher, 0, sizeof(*matcher));
}

static int ascii_lower(int c)
{
    return c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c;
}

static int ascii_compare_fold(const uint8_t *a,
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

static char *copy_normalized(const uint8_t *value,
                             size_t len,
                             int lower,
                             int trim_dot)
{
    if (value == NULL) {
        return NULL;
    }
    while (trim_dot && len > 0u && value[len - 1u] == '.') {
        len--;
    }
    if (len == 0u) {
        return NULL;
    }
    char *copy = (char *)malloc(len + 1u);
    if (copy == NULL) {
        return NULL;
    }
    for (size_t i = 0u; i < len; i++) {
        copy[i] = lower ? (char)ascii_lower(value[i]) : (char)value[i];
    }
    copy[len] = '\0';
    return copy;
}

static int ascii_equal_fold(const char *a,
                            const uint8_t *b,
                            size_t b_len)
{
    if (a == NULL || b == NULL || strlen(a) != b_len) {
        return 0;
    }
    for (size_t i = 0u; i < b_len; i++) {
        if (ascii_lower((unsigned char)a[i]) !=
            ascii_lower((unsigned char)b[i])) {
            return 0;
        }
    }
    return 1;
}

static int pb_read_varint(const uint8_t *data,
                          size_t len,
                          size_t *pos,
                          uint64_t *out)
{
    uint64_t value = 0u;
    if (data == NULL || pos == NULL || out == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    for (unsigned shift = 0u; shift < 64u; shift += 7u) {
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
    *pos += *out_len;
    return APROXY_OK;
}

static int pb_skip(const uint8_t *data,
                   size_t len,
                   size_t *pos,
                   uint32_t wire_type)
{
    uint64_t ignored = 0u;
    const uint8_t *bytes = NULL;
    size_t bytes_len = 0u;
    switch (wire_type) {
    case 0u:
        return pb_read_varint(data, len, pos, &ignored);
    case 1u:
        if (len - *pos < 8u) {
            return APROXY_ERR_BUFFER_TOO_SMALL;
        }
        *pos += 8u;
        return APROXY_OK;
    case 2u:
        return pb_read_len(data, len, pos, &bytes, &bytes_len);
    case 5u:
        if (len - *pos < 4u) {
            return APROXY_ERR_BUFFER_TOO_SMALL;
        }
        *pos += 4u;
        return APROXY_OK;
    default:
        return APROXY_ERR_PARSE;
    }
}

static int message_string_field(const uint8_t *data,
                                size_t len,
                                uint32_t wanted,
                                const uint8_t **out,
                                size_t *out_len)
{
    size_t pos = 0u;
    *out = NULL;
    *out_len = 0u;
    while (pos < len) {
        uint64_t key = 0u;
        int rc = pb_read_varint(data, len, &pos, &key);
        if (rc != APROXY_OK) {
            return rc;
        }
        const uint32_t field = (uint32_t)(key >> 3u);
        const uint32_t wire = (uint32_t)(key & 7u);
        if (field == wanted && wire == 2u) {
            return pb_read_len(data, len, &pos, out, out_len);
        }
        rc = pb_skip(data, len, &pos, wire);
        if (rc != APROXY_OK) {
            return rc;
        }
    }
    return APROXY_OK;
}

static int db_reserve(aproxy_geosite_db_t *db, size_t need)
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
    geosite_ref_t *entries =
        (geosite_ref_t *)realloc(db->entries, cap * sizeof(*entries));
    if (entries == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    db->entries = entries;
    db->entry_cap = cap;
    return APROXY_OK;
}

static int db_add_entry(aproxy_geosite_db_t *db,
                        const uint8_t *entry,
                        size_t entry_len)
{
    const uint8_t *code = NULL;
    size_t code_len = 0u;
    int rc = message_string_field(entry, entry_len, 1u, &code, &code_len);
    if (rc != APROXY_OK || code == NULL || code_len == 0u) {
        return rc == APROXY_OK ? APROXY_ERR_PARSE : rc;
    }
    rc = db_reserve(db, db->entry_count + 1u);
    if (rc != APROXY_OK) {
        return rc;
    }
    geosite_ref_t *ref = &db->entries[db->entry_count++];
    ref->code = code;
    ref->code_len = code_len;
    ref->data = entry;
    ref->len = entry_len;
    return APROXY_OK;
}

static int ref_compare(const void *a, const void *b)
{
    const geosite_ref_t *left = (const geosite_ref_t *)a;
    const geosite_ref_t *right = (const geosite_ref_t *)b;
    return ascii_compare_fold(left->code, left->code_len, right->code,
                              right->code_len);
}

static int parse_db_index(aproxy_geosite_db_t *db)
{
    size_t pos = 0u;
    while (pos < db->map.len) {
        uint64_t key = 0u;
        int rc = pb_read_varint(db->map.data, db->map.len, &pos, &key);
        if (rc != APROXY_OK) {
            return rc;
        }
        const uint32_t field = (uint32_t)(key >> 3u);
        const uint32_t wire = (uint32_t)(key & 7u);
        if (field == 1u && wire == 2u) {
            const uint8_t *entry = NULL;
            size_t entry_len = 0u;
            rc = pb_read_len(db->map.data, db->map.len, &pos, &entry,
                             &entry_len);
            if (rc == APROXY_OK) {
                rc = db_add_entry(db, entry, entry_len);
            }
        } else {
            rc = pb_skip(db->map.data, db->map.len, &pos, wire);
        }
        if (rc != APROXY_OK) {
            return rc;
        }
    }
    if (db->entry_count == 0u) {
        return APROXY_ERR_PARSE;
    }
    qsort(db->entries, db->entry_count, sizeof(db->entries[0]),
          ref_compare);
    geosite_ref_t *entries = (geosite_ref_t *)realloc(
        db->entries, db->entry_count * sizeof(*db->entries));
    if (entries != NULL) {
        db->entries = entries;
        db->entry_cap = db->entry_count;
    }
    return APROXY_OK;
}

int aproxy_geosite_db_open_v2ray_dat(const char *path,
                                     aproxy_geosite_db_t **out)
{
    if (path == NULL || out == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    *out = NULL;
    aproxy_geosite_db_t *db =
        (aproxy_geosite_db_t *)calloc(1u, sizeof(*db));
    if (db == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    db->map.fd = -1;
    int rc = aproxy_filemap_open_ro(path, APROXY_GEOSITE_MAX_FILE_SIZE,
                                    &db->map);
    if (rc == APROXY_OK) {
        rc = parse_db_index(db);
    }
    if (rc == APROXY_OK) {
        aproxy_filemap_advise_normal(&db->map);
    }
    if (rc != APROXY_OK) {
        aproxy_geosite_db_free(db);
        return rc;
    }
    *out = db;
    return APROXY_OK;
}

void aproxy_geosite_db_free(aproxy_geosite_db_t *db)
{
    if (db == NULL) {
        return;
    }
    free(db->entries);
    aproxy_filemap_close(&db->map);
    free(db);
}

static const geosite_ref_t *db_find(const aproxy_geosite_db_t *db,
                                    const uint8_t *code,
                                    size_t code_len)
{
    size_t left = 0u;
    size_t right = db->entry_count;
    while (left < right) {
        const size_t mid = left + (right - left) / 2u;
        const int cmp = ascii_compare_fold(
            db->entries[mid].code, db->entries[mid].code_len, code,
            code_len);
        if (cmp == 0) {
            return &db->entries[mid];
        }
        if (cmp < 0) {
            left = mid + 1u;
        } else {
            right = mid;
        }
    }
    return NULL;
}

static int builder_add(string_builder_t *builder, char *value)
{
    if (value == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    if (builder->len == builder->cap) {
        size_t cap = builder->cap == 0u ? 64u : builder->cap * 2u;
        char **items =
            (char **)realloc(builder->items, cap * sizeof(*items));
        if (items == NULL) {
            free(value);
            return APROXY_ERR_NO_MEMORY;
        }
        builder->items = items;
        builder->cap = cap;
    }
    builder->items[builder->len++] = value;
    return APROXY_OK;
}

static void builder_free(string_builder_t *builder)
{
    if (builder == NULL) {
        return;
    }
    for (size_t i = 0u; i < builder->len; i++) {
        free(builder->items[i]);
    }
    free(builder->items);
    memset(builder, 0, sizeof(*builder));
}

static int string_ptr_compare(const void *a, const void *b)
{
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

static int compile_table(string_builder_t *builder, string_table_t *table)
{
    if (builder->len == 0u) {
        return APROXY_OK;
    }
    qsort(builder->items, builder->len, sizeof(builder->items[0]),
          string_ptr_compare);
    size_t unique = 0u;
    size_t bytes = 0u;
    for (size_t i = 0u; i < builder->len; i++) {
        char *item = builder->items[i];
        if (unique > 0u &&
            strcmp(item, builder->items[unique - 1u]) == 0) {
            free(item);
            builder->items[i] = NULL;
            continue;
        }
        builder->items[unique] = item;
        if (unique != i) {
            builder->items[i] = NULL;
        }
        unique++;
        const size_t len = strlen(item) + 1u;
        if (bytes > UINT32_MAX - len) {
            return APROXY_ERR_FRAME_TOO_LARGE;
        }
        bytes += len;
    }
    table->arena = (char *)malloc(bytes);
    table->offsets = (uint32_t *)malloc(unique * sizeof(uint32_t));
    if (table->arena == NULL || table->offsets == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    size_t offset = 0u;
    for (size_t i = 0u; i < unique; i++) {
        const size_t len = strlen(builder->items[i]) + 1u;
        table->offsets[i] = (uint32_t)offset;
        memcpy(table->arena + offset, builder->items[i], len);
        offset += len;
    }
    table->count = unique;
    table->bytes = bytes;
    return APROXY_OK;
}

static int attribute_matches(const uint8_t *domain,
                             size_t domain_len,
                             const char *wanted)
{
    if (wanted == NULL) {
        return 1;
    }
    size_t pos = 0u;
    while (pos < domain_len) {
        uint64_t key = 0u;
        int rc = pb_read_varint(domain, domain_len, &pos, &key);
        if (rc != APROXY_OK) {
            return 0;
        }
        const uint32_t field = (uint32_t)(key >> 3u);
        const uint32_t wire = (uint32_t)(key & 7u);
        if (field == 3u && wire == 2u) {
            const uint8_t *attribute = NULL;
            size_t attribute_len = 0u;
            rc = pb_read_len(domain, domain_len, &pos, &attribute,
                             &attribute_len);
            if (rc != APROXY_OK) {
                return 0;
            }
            const uint8_t *name = NULL;
            size_t name_len = 0u;
            rc = message_string_field(attribute, attribute_len, 1u, &name,
                                      &name_len);
            if (rc == APROXY_OK && name != NULL &&
                ascii_equal_fold(wanted, name, name_len)) {
                return 1;
            }
        } else if (pb_skip(domain, domain_len, &pos, wire) != APROXY_OK) {
            return 0;
        }
    }
    return 0;
}

static int parse_domain(const uint8_t *domain,
                        size_t domain_len,
                        const char *attribute,
                        string_builder_t builders[4])
{
    if (!attribute_matches(domain, domain_len, attribute)) {
        return APROXY_OK;
    }
    size_t pos = 0u;
    uint64_t type = 0u;
    const uint8_t *value = NULL;
    size_t value_len = 0u;
    while (pos < domain_len) {
        uint64_t key = 0u;
        int rc = pb_read_varint(domain, domain_len, &pos, &key);
        if (rc != APROXY_OK) {
            return rc;
        }
        const uint32_t field = (uint32_t)(key >> 3u);
        const uint32_t wire = (uint32_t)(key & 7u);
        if (field == 1u && wire == 0u) {
            rc = pb_read_varint(domain, domain_len, &pos, &type);
        } else if (field == 2u && wire == 2u) {
            rc = pb_read_len(domain, domain_len, &pos, &value, &value_len);
        } else {
            rc = pb_skip(domain, domain_len, &pos, wire);
        }
        if (rc != APROXY_OK) {
            return rc;
        }
    }
    if (value == NULL || value_len == 0u || type > 3u) {
        return value == NULL ? APROXY_ERR_PARSE : APROXY_OK;
    }
    const int is_regex = type == 1u;
    char *copy = copy_normalized(value, value_len, !is_regex, !is_regex);
    return builder_add(&builders[type], copy);
}

static int compile_regexes(string_builder_t *builder,
                           aproxy_geosite_set_t *set)
{
    if (builder->len == 0u) {
        return APROXY_OK;
    }
    set->regex_codes =
        (pcre2_code **)calloc(builder->len, sizeof(*set->regex_codes));
    set->regex_matches = (pcre2_match_data **)calloc(
        builder->len, sizeof(*set->regex_matches));
    if (set->regex_codes == NULL || set->regex_matches == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    for (size_t i = 0u; i < builder->len; i++) {
        int error = 0;
        PCRE2_SIZE offset = 0u;
        pcre2_code *code = pcre2_compile(
            (PCRE2_SPTR)builder->items[i], PCRE2_ZERO_TERMINATED,
            PCRE2_CASELESS | PCRE2_NO_AUTO_CAPTURE, &error, &offset, NULL);
        if (code == NULL) {
            (void)error;
            (void)offset;
            return APROXY_ERR_PARSE;
        }
        (void)pcre2_jit_compile(code, PCRE2_JIT_COMPLETE);
        pcre2_match_data *match = pcre2_match_data_create(1u, NULL);
        if (match == NULL) {
            pcre2_code_free(code);
            return APROXY_ERR_NO_MEMORY;
        }
        set->regex_codes[set->regex_count] = code;
        set->regex_matches[set->regex_count] = match;
        set->regex_count++;
        free(builder->items[i]);
        builder->items[i] = NULL;
    }
    return APROXY_OK;
}

static int parse_entry(const geosite_ref_t *ref,
                       const char *attribute,
                       aproxy_geosite_set_t *set)
{
    string_builder_t builders[4];
    memset(builders, 0, sizeof(builders));
    size_t pos = 0u;
    int rc = APROXY_OK;
    while (pos < ref->len) {
        uint64_t key = 0u;
        rc = pb_read_varint(ref->data, ref->len, &pos, &key);
        if (rc != APROXY_OK) {
            break;
        }
        const uint32_t field = (uint32_t)(key >> 3u);
        const uint32_t wire = (uint32_t)(key & 7u);
        if (field == 2u && wire == 2u) {
            const uint8_t *domain = NULL;
            size_t domain_len = 0u;
            rc = pb_read_len(ref->data, ref->len, &pos, &domain,
                             &domain_len);
            if (rc == APROXY_OK) {
                rc = parse_domain(domain, domain_len, attribute, builders);
            }
        } else {
            rc = pb_skip(ref->data, ref->len, &pos, wire);
        }
        if (rc != APROXY_OK) {
            break;
        }
    }
    const size_t count = builders[0].len + builders[1].len +
                         builders[2].len + builders[3].len;
    if (rc == APROXY_OK) {
        rc = compile_table(&builders[3], &set->exact);
        builder_free(&builders[3]);
    }
    if (rc == APROXY_OK) {
        rc = compile_table(&builders[2], &set->suffix);
        builder_free(&builders[2]);
    }
    if (rc == APROXY_OK) {
        rc = compile_table(&builders[0], &set->keyword);
        builder_free(&builders[0]);
    }
    if (rc == APROXY_OK) {
        rc = keyword_matcher_build(&set->keyword_matcher, &set->keyword);
    }
    if (rc == APROXY_OK) {
        set->keyword_count = set->keyword.count;
        set->keyword_bytes = set->keyword.bytes;
        free(set->keyword.arena);
        free(set->keyword.offsets);
        memset(&set->keyword, 0, sizeof(set->keyword));
    }
    if (rc == APROXY_OK) {
        rc = compile_regexes(&builders[1], set);
        builder_free(&builders[1]);
    }
    for (size_t i = 0u; i < 4u; i++) {
        builder_free(&builders[i]);
    }
    if (rc == APROXY_OK && count == 0u) {
        rc = APROXY_ERR_PARSE;
    }
    return rc;
}

int aproxy_geosite_db_load(const aproxy_geosite_db_t *db,
                           const char *selector,
                           aproxy_geosite_set_t **out)
{
    if (db == NULL || selector == NULL || selector[0] == '\0' ||
        out == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    *out = NULL;
    const char *at = strchr(selector, '@');
    const size_t code_len = at == NULL ? strlen(selector)
                                       : (size_t)(at - selector);
    if (code_len == 0u || (at != NULL && at[1] == '\0')) {
        return APROXY_ERR_PARSE;
    }
    const geosite_ref_t *ref = db_find(
        db, (const uint8_t *)selector, code_len);
    if (ref == NULL) {
        return APROXY_ERR_PARSE;
    }

    aproxy_geosite_set_t *set =
        (aproxy_geosite_set_t *)calloc(1u, sizeof(*set));
    if (set == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    set->selector = copy_normalized((const uint8_t *)selector,
                                    strlen(selector), 1, 0);
    if (set->selector == NULL) {
        aproxy_geosite_set_free(set);
        return APROXY_ERR_NO_MEMORY;
    }
    int rc = parse_entry(ref, at == NULL ? NULL : at + 1u, set);
    if (rc != APROXY_OK) {
        aproxy_geosite_set_free(set);
        return rc;
    }
    *out = set;
    return APROXY_OK;
}

int aproxy_geosite_set_load_v2ray_dat(const char *path,
                                      const char *selector,
                                      aproxy_geosite_set_t **out)
{
    aproxy_geosite_db_t *db = NULL;
    int rc = aproxy_geosite_db_open_v2ray_dat(path, &db);
    if (rc == APROXY_OK) {
        rc = aproxy_geosite_db_load(db, selector, out);
    }
    aproxy_geosite_db_free(db);
    return rc;
}

void aproxy_geosite_set_free(aproxy_geosite_set_t *set)
{
    if (set == NULL) {
        return;
    }
    free(set->selector);
    free(set->exact.arena);
    free(set->exact.offsets);
    free(set->suffix.arena);
    free(set->suffix.offsets);
    free(set->keyword.arena);
    free(set->keyword.offsets);
    keyword_matcher_free(&set->keyword_matcher);
    for (size_t i = 0u; i < set->regex_count; i++) {
        pcre2_match_data_free(set->regex_matches[i]);
        pcre2_code_free(set->regex_codes[i]);
    }
    free(set->regex_matches);
    free(set->regex_codes);
    free(set);
}

const char *aproxy_geosite_set_selector(const aproxy_geosite_set_t *set)
{
    return set == NULL ? NULL : set->selector;
}

void aproxy_geosite_set_stats(const aproxy_geosite_set_t *set,
                              aproxy_geosite_stats_t *out)
{
    if (out == NULL) {
        return;
    }
    memset(out, 0, sizeof(*out));
    if (set == NULL) {
        return;
    }
    out->exact_count = set->exact.count;
    out->suffix_count = set->suffix.count;
    out->keyword_count = set->keyword_count;
    out->regex_count = set->regex_count;
    out->string_bytes = set->exact.bytes + set->suffix.bytes +
                        set->keyword_bytes;
}

static int table_contains(const string_table_t *table, const char *value)
{
    size_t left = 0u;
    size_t right = table->count;
    while (left < right) {
        const size_t mid = left + (right - left) / 2u;
        const int cmp = strcmp(table->arena + table->offsets[mid], value);
        if (cmp == 0) {
            return 1;
        }
        if (cmp < 0) {
            left = mid + 1u;
        } else {
            right = mid;
        }
    }
    return 0;
}

/* This is the ordinary CN lookup hot path. Keep it in the two public entry
 * points so the lower-case router path does not pay an extra call per set. */
static APROXY_ALWAYS_INLINE int
match_normalized_domain(const aproxy_geosite_set_t *set,
                        const char *normalized,
                        size_t domain_len)
{
    if (table_contains(&set->exact, normalized)) {
        return 1;
    }
    const char *suffix = normalized;
    for (;;) {
        if (table_contains(&set->suffix, suffix)) {
            return 1;
        }
        const char *dot = strchr(suffix, '.');
        if (dot == NULL) {
            break;
        }
        suffix = dot + 1u;
    }
    if (keyword_matcher_match(&set->keyword_matcher,
                              (const uint8_t *)normalized, domain_len)) {
        return 1;
    }
    for (size_t i = 0u; i < set->regex_count; i++) {
        if (pcre2_match(set->regex_codes[i], (PCRE2_SPTR)normalized,
                        domain_len, 0u, 0u, set->regex_matches[i], NULL) >=
            0) {
            return 1;
        }
    }
    return 0;
}

int aproxy_geosite_set_match_domain_lower(const aproxy_geosite_set_t *set,
                                          const char *lower_domain,
                                          size_t domain_len)
{
    if (set == NULL || lower_domain == NULL || domain_len == 0u ||
        domain_len > APROXY_ADDR_MAX_FQDN) {
        return 0;
    }
    const size_t original_len = domain_len;
    while (domain_len > 0u && lower_domain[domain_len - 1u] == '.') {
        domain_len--;
    }
    if (domain_len == 0u) {
        return 0;
    }
    if (domain_len == original_len) {
        return match_normalized_domain(set, lower_domain, domain_len);
    }

    /* The router's shared lowercase buffer must retain its original length
     * for ordinary domain rules. Only the uncommon trailing-dot form needs
     * a per-set terminated copy. */
    char trimmed[APROXY_ADDR_MAX_FQDN + 1u];
    memcpy(trimmed, lower_domain, domain_len);
    trimmed[domain_len] = '\0';
    return match_normalized_domain(set, trimmed, domain_len);
}

int aproxy_geosite_set_match_domain(const aproxy_geosite_set_t *set,
                                    const char *domain,
                                    size_t domain_len)
{
    if (set == NULL || domain == NULL || domain_len == 0u ||
        domain_len > APROXY_ADDR_MAX_FQDN) {
        return 0;
    }
    while (domain_len > 0u && domain[domain_len - 1u] == '.') {
        domain_len--;
    }
    if (domain_len == 0u) {
        return 0;
    }
    char normalized[APROXY_ADDR_MAX_FQDN + 1u];
    for (size_t i = 0u; i < domain_len; i++) {
        normalized[i] = (char)ascii_lower((unsigned char)domain[i]);
    }
    normalized[domain_len] = '\0';
    return match_normalized_domain(set, normalized, domain_len);
}

int aproxy_geosite_set_match(const aproxy_geosite_set_t *set,
                             const aproxy_addr_t *addr)
{
    return addr != NULL && addr->family == APROXY_ADDR_FQDN &&
           aproxy_geosite_set_match_domain(set, addr->fqdn,
                                           addr->fqdn_len);
}
