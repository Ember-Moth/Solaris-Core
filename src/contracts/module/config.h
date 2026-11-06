#ifndef SOLARIS_CONFIG_VIEW_H
#define SOLARIS_CONFIG_VIEW_H

#include <stddef.h>
#include <stdint.h>
#include <solaris/error.h>

/* Borrowed, immutable prepare-time input. No parser/library types escape into
 * modules; compiled configurations must copy every value they keep. */
typedef struct solaris_config_view solaris_config_view_t;
typedef struct solaris_config_field solaris_config_field_t;
typedef enum solaris_config_kind {
    SOLARIS_CONFIG_NULL, SOLARIS_CONFIG_BOOL, SOLARIS_CONFIG_INTEGER,
    SOLARIS_CONFIG_STRING, SOLARIS_CONFIG_MAP, SOLARIS_CONFIG_SEQUENCE
} solaris_config_kind_t;

struct solaris_config_view {
    solaris_config_kind_t kind;
    uint32_t line, column;
    union {
        int boolean;
        int64_t integer;
        struct { const char *data; size_t length; } string;
        struct { const solaris_config_field_t *fields; size_t count; } map;
        struct { const solaris_config_view_t *items; size_t count; } sequence;
    } value;
};
struct solaris_config_field {
    const char *name;
    solaris_config_view_t value;
};

solaris_status_t solaris_config_error(const solaris_config_view_t *view, const char *field,
                                      const char *message, solaris_error_t *error);
/* Rejects duplicate and unknown fields before a module consumes the view. */
solaris_status_t solaris_config_check_fields(const solaris_config_view_t *view,
                                             const char *const *allowed, size_t count,
                                             solaris_error_t *error);
const solaris_config_view_t *solaris_config_get(const solaris_config_view_t *map, const char *name);
solaris_status_t solaris_config_uint(const solaris_config_view_t *map, const char *name,
                                     uint64_t fallback, uint64_t minimum, uint64_t maximum,
                                     uint64_t *out, solaris_error_t *error);
solaris_status_t solaris_config_string(const solaris_config_view_t *map, const char *name,
                                       int required, char *out, size_t capacity,
                                       solaris_error_t *error);

#endif
