#include "anytls/padding.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "md5.h"

const uint8_t anytls_default_padding_scheme[] =
    "stop=8\n"
    "0=30-30\n"
    "1=100-400\n"
    "2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n"
    "3=9-9,500-1000\n"
    "4=500-1000\n"
    "5=500-1000\n"
    "6=500-1000\n"
    "7=500-1000";

const size_t anytls_default_padding_scheme_len =
    sizeof(anytls_default_padding_scheme) - 1u;

typedef struct anytls_padding_step {
    int is_check;
    int minimum;
    int maximum;
} anytls_padding_step_t;

typedef struct anytls_padding_packet {
    uint32_t packet;
    size_t step_count;
    anytls_padding_step_t steps[ANYTLS_PADDING_MAX_RANGES_PER_PACKET];
} anytls_padding_packet_t;

struct anytls_padding_factory {
    uint8_t *raw;
    size_t raw_len;
    char md5_hex[33];
    uint32_t stop;
    anytls_padding_packet_t *packets;
    size_t packet_count;
};

struct anytls_padding_store {
    anytls_padding_factory_t *current;
};

static void free_line_copy(char *copy)
{
    free(copy);
}

static int copy_bytes(uint8_t **out, const uint8_t *src, size_t len)
{
    uint8_t *copy = NULL;
    if (len > 0u) {
        copy = (uint8_t *)malloc(len);
        if (copy == NULL) {
            return ANYTLS_ERR_NO_MEMORY;
        }
        memcpy(copy, src, len);
    }
    *out = copy;
    return ANYTLS_OK;
}

static char *copy_string_span(const uint8_t *src, size_t len)
{
    char *copy = (char *)malloc(len + 1u);
    if (copy == NULL) {
        return NULL;
    }
    if (len > 0u) {
        memcpy(copy, src, len);
    }
    copy[len] = '\0';
    return copy;
}

static int parse_int64_strict(const char *s, long long *out)
{
    char *end = NULL;
    errno = 0;
    const long long value = strtoll(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0') {
        return ANYTLS_ERR_PARSE;
    }
    *out = value;
    return ANYTLS_OK;
}

static int parse_u32_strict(const char *s, uint32_t *out)
{
    char *end = NULL;
    errno = 0;
    const unsigned long value = strtoul(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0' || value > UINT32_MAX) {
        return ANYTLS_ERR_PARSE;
    }
    *out = (uint32_t)value;
    return ANYTLS_OK;
}

static int append_packet(anytls_padding_factory_t *factory,
                         anytls_padding_packet_t *packet)
{
    for (size_t i = 0; i < factory->packet_count; i++) {
        if (factory->packets[i].packet == packet->packet) {
            factory->packets[i] = *packet;
            return ANYTLS_OK;
        }
    }

    const size_t new_count = factory->packet_count + 1u;
    anytls_padding_packet_t *new_packets =
        (anytls_padding_packet_t *)realloc(factory->packets,
                                           new_count * sizeof(*new_packets));
    if (new_packets == NULL) {
        return ANYTLS_ERR_NO_MEMORY;
    }
    factory->packets = new_packets;
    factory->packets[factory->packet_count] = *packet;
    factory->packet_count = new_count;
    return ANYTLS_OK;
}

static int parse_packet_steps(char *value, anytls_padding_packet_t *packet)
{
    char *cursor = value;
    while (cursor != NULL) {
        char *token = cursor;
        char *comma = strchr(cursor, ',');
        if (comma != NULL) {
            *comma = '\0';
            cursor = comma + 1;
        } else {
            cursor = NULL;
        }

        if (packet->step_count >= ANYTLS_PADDING_MAX_RANGES_PER_PACKET) {
            return ANYTLS_ERR_PARSE;
        }

        anytls_padding_step_t *step = &packet->steps[packet->step_count];
        if (strcmp(token, "c") == 0) {
            step->is_check = 1;
            step->minimum = 0;
            step->maximum = 0;
            packet->step_count++;
            continue;
        }

        char *dash = strchr(token, '-');
        if (dash == NULL) {
            return ANYTLS_ERR_PARSE;
        }
        *dash = '\0';

        long long minimum = 0;
        long long maximum = 0;
        if (parse_int64_strict(token, &minimum) != ANYTLS_OK ||
            parse_int64_strict(dash + 1, &maximum) != ANYTLS_OK) {
            return ANYTLS_ERR_PARSE;
        }
        if (minimum <= 0 || maximum <= 0 || minimum > UINT16_MAX ||
            maximum > UINT16_MAX) {
            return ANYTLS_ERR_PARSE;
        }

        step->is_check = 0;
        step->minimum = (int)minimum;
        step->maximum = (int)maximum;
        packet->step_count++;
    }
    return ANYTLS_OK;
}

static int parse_line(anytls_padding_factory_t *factory,
                      char *line,
                      int *saw_stop)
{
    if (*line == '\0') {
        return ANYTLS_OK;
    }

    char *equal = strchr(line, '=');
    if (equal == NULL) {
        return ANYTLS_OK;
    }
    *equal = '\0';
    const char *key = line;
    char *value = equal + 1;

    if (strcmp(key, "stop") == 0) {
        long long stop = 0;
        if (parse_int64_strict(value, &stop) != ANYTLS_OK || stop < 0 ||
            stop > UINT32_MAX) {
            return ANYTLS_ERR_PARSE;
        }
        factory->stop = (uint32_t)stop;
        *saw_stop = 1;
        return ANYTLS_OK;
    }

    uint32_t packet_number = 0;
    if (parse_u32_strict(key, &packet_number) != ANYTLS_OK) {
        return ANYTLS_ERR_PARSE;
    }

    anytls_padding_packet_t packet;
    memset(&packet, 0, sizeof(packet));
    packet.packet = packet_number;

    const int parsed = parse_packet_steps(value, &packet);
    if (parsed != ANYTLS_OK) {
        return parsed;
    }
    return append_packet(factory, &packet);
}

static int validate_packets(const anytls_padding_factory_t *factory)
{
    for (size_t i = 0; i < factory->packet_count; i++) {
        if (factory->packets[i].packet >= factory->stop) {
            return ANYTLS_ERR_PARSE;
        }
    }
    return ANYTLS_OK;
}

static const anytls_padding_packet_t *find_packet(
    const anytls_padding_factory_t *factory,
    uint32_t packet)
{
    for (size_t i = 0; i < factory->packet_count; i++) {
        if (factory->packets[i].packet == packet) {
            return &factory->packets[i];
        }
    }
    return NULL;
}

static uint32_t random_u32(void)
{
    uint32_t value = 0;
    FILE *f = fopen("/dev/urandom", "rb");
    if (f != NULL) {
        const size_t n = fread(&value, 1u, sizeof(value), f);
        fclose(f);
        if (n == sizeof(value)) {
            return value;
        }
    }
    return (uint32_t)rand();
}

int anytls_padding_factory_new(const uint8_t *raw,
                               size_t raw_len,
                               anytls_padding_factory_t **out)
{
    if (out == NULL || (raw == NULL && raw_len > 0u)) {
        return ANYTLS_ERR_INVALID_ARGUMENT;
    }
    *out = NULL;
    if (raw_len == 0u) {
        return ANYTLS_ERR_PARSE;
    }

    anytls_padding_factory_t *factory =
        (anytls_padding_factory_t *)calloc(1u, sizeof(*factory));
    if (factory == NULL) {
        return ANYTLS_ERR_NO_MEMORY;
    }

    int rc = copy_bytes(&factory->raw, raw, raw_len);
    if (rc != ANYTLS_OK) {
        anytls_padding_factory_free(factory);
        return rc;
    }
    factory->raw_len = raw_len;

    uint8_t digest[16];
    anytls_md5(raw, raw_len, digest);
    anytls_md5_hex(digest, factory->md5_hex);

    char *copy = copy_string_span(raw, raw_len);
    if (copy == NULL) {
        anytls_padding_factory_free(factory);
        return ANYTLS_ERR_NO_MEMORY;
    }

    int saw_stop = 0;
    char *cursor = copy;
    while (cursor != NULL) {
        char *line = cursor;
        char *newline = strchr(cursor, '\n');
        if (newline != NULL) {
            *newline = '\0';
            cursor = newline + 1;
        } else {
            cursor = NULL;
        }
        rc = parse_line(factory, line, &saw_stop);
        if (rc != ANYTLS_OK) {
            free_line_copy(copy);
            anytls_padding_factory_free(factory);
            return rc;
        }
    }
    free_line_copy(copy);

    if (!saw_stop || validate_packets(factory) != ANYTLS_OK) {
        anytls_padding_factory_free(factory);
        return ANYTLS_ERR_PARSE;
    }

    *out = factory;
    return ANYTLS_OK;
}

void anytls_padding_factory_free(anytls_padding_factory_t *factory)
{
    if (factory == NULL) {
        return;
    }
    free(factory->raw);
    free(factory->packets);
    free(factory);
}

uint32_t anytls_padding_stop(const anytls_padding_factory_t *factory)
{
    return factory == NULL ? 0u : factory->stop;
}

const char *anytls_padding_md5_hex(const anytls_padding_factory_t *factory)
{
    return factory == NULL ? NULL : factory->md5_hex;
}

const uint8_t *anytls_padding_raw(const anytls_padding_factory_t *factory,
                                  size_t *len)
{
    if (factory == NULL) {
        if (len != NULL) {
            *len = 0u;
        }
        return NULL;
    }
    if (len != NULL) {
        *len = factory->raw_len;
    }
    return factory->raw;
}

int anytls_padding_generate_record_payload_sizes(
    const anytls_padding_factory_t *factory,
    uint32_t packet,
    int *out_sizes,
    size_t out_capacity,
    size_t *out_count)
{
    if (factory == NULL || out_count == NULL) {
        return ANYTLS_ERR_INVALID_ARGUMENT;
    }
    *out_count = 0u;

    const anytls_padding_packet_t *definition = find_packet(factory, packet);
    if (definition == NULL) {
        return ANYTLS_OK;
    }

    if (out_capacity < definition->step_count ||
        (definition->step_count > 0u && out_sizes == NULL)) {
        return ANYTLS_ERR_BUFFER_TOO_SMALL;
    }

    for (size_t i = 0; i < definition->step_count; i++) {
        const anytls_padding_step_t *step = &definition->steps[i];
        if (step->is_check) {
            out_sizes[i] = ANYTLS_PADDING_CHECK_MARK;
            continue;
        }

        int minimum = step->minimum;
        int maximum = step->maximum;
        if (minimum > maximum) {
            const int tmp = minimum;
            minimum = maximum;
            maximum = tmp;
        }

        if (minimum == maximum) {
            out_sizes[i] = minimum;
        } else {
            const uint32_t span = (uint32_t)(maximum - minimum);
            out_sizes[i] = minimum + (int)(random_u32() % span);
        }
    }

    *out_count = definition->step_count;
    return ANYTLS_OK;
}

int anytls_padding_auth_length(const anytls_padding_factory_t *factory,
                               uint16_t *out_len)
{
    if (factory == NULL || out_len == NULL) {
        return ANYTLS_ERR_INVALID_ARGUMENT;
    }

    int sizes[ANYTLS_PADDING_MAX_RANGES_PER_PACKET];
    size_t count = 0u;
    const int rc = anytls_padding_generate_record_payload_sizes(
        factory, 0u, sizes, ANYTLS_PADDING_MAX_RANGES_PER_PACKET, &count);
    if (rc != ANYTLS_OK) {
        return rc;
    }

    for (size_t i = 0; i < count; i++) {
        if (sizes[i] >= 0) {
            *out_len = (uint16_t)sizes[i];
            return ANYTLS_OK;
        }
    }
    *out_len = 0u;
    return ANYTLS_OK;
}

int anytls_padding_store_new_default(anytls_padding_store_t **out)
{
    if (out == NULL) {
        return ANYTLS_ERR_INVALID_ARGUMENT;
    }
    *out = NULL;
    anytls_padding_store_t *store =
        (anytls_padding_store_t *)calloc(1u, sizeof(*store));
    if (store == NULL) {
        return ANYTLS_ERR_NO_MEMORY;
    }
    const int rc = anytls_padding_factory_new(
        anytls_default_padding_scheme, anytls_default_padding_scheme_len,
        &store->current);
    if (rc != ANYTLS_OK) {
        anytls_padding_store_free(store);
        return rc;
    }
    *out = store;
    return ANYTLS_OK;
}

void anytls_padding_store_free(anytls_padding_store_t *store)
{
    if (store == NULL) {
        return;
    }
    anytls_padding_factory_free(store->current);
    free(store);
}

const anytls_padding_factory_t *anytls_padding_store_get(
    const anytls_padding_store_t *store)
{
    return store == NULL ? NULL : store->current;
}

int anytls_padding_store_update(anytls_padding_store_t *store,
                                const uint8_t *raw,
                                size_t raw_len)
{
    if (store == NULL || (raw == NULL && raw_len > 0u)) {
        return ANYTLS_ERR_INVALID_ARGUMENT;
    }
    anytls_padding_factory_t *updated = NULL;
    const int rc = anytls_padding_factory_new(raw, raw_len, &updated);
    if (rc != ANYTLS_OK) {
        return rc;
    }
    anytls_padding_factory_free(store->current);
    store->current = updated;
    return ANYTLS_OK;
}
