#include "contracts/module/config.h"
#include "api/common/error.h"
#include <stdio.h>
#include <string.h>

solaris_status_t solaris_config_error(const solaris_config_view_t *view, const char *field,
                                      const char *message, solaris_error_t *error)
{
    char text[SOLARIS_ERROR_MESSAGE_CAPACITY];
    (void)snprintf(text, sizeof(text), "%s at %u:%u: %s", field == NULL ? "config" : field,
                   view == NULL ? 0u : view->line, view == NULL ? 0u : view->column, message);
    return solaris_error_set(error, SOLARIS_EINVAL, 0, text);
}

solaris_status_t solaris_config_check_fields(const solaris_config_view_t *view,
                                             const char *const *allowed, size_t count,
                                             solaris_error_t *error)
{
    if (view == NULL || view->kind != SOLARIS_CONFIG_MAP ||
        (view->value.map.count != 0u && view->value.map.fields == NULL) ||
        (count != 0u && allowed == NULL))
        return solaris_config_error(view, NULL, "expected a map", error);
    for (size_t i = 0; i < view->value.map.count; ++i) {
        const solaris_config_field_t *field = &view->value.map.fields[i];
        if (field->name == NULL || field->name[0] == '\0')
            return solaris_config_error(&field->value, NULL, "empty field name", error);
        for (size_t j = 0; j < i; ++j)
            if (strcmp(field->name, view->value.map.fields[j].name) == 0)
                return solaris_config_error(&field->value, field->name, "duplicate field", error);
        size_t j = 0;
        for (; j < count; ++j) if (allowed[j] != NULL && strcmp(field->name, allowed[j]) == 0) break;
        if (j == count)
            return solaris_config_error(&field->value, field->name, "unknown field", error);
    }
    return solaris_error_set(error, SOLARIS_OK, 0, NULL);
}

const solaris_config_view_t *solaris_config_get(const solaris_config_view_t *map, const char *name)
{
    if (map == NULL || name == NULL || map->kind != SOLARIS_CONFIG_MAP || map->value.map.fields == NULL)
        return NULL;
    for (size_t i = 0; i < map->value.map.count; ++i)
        if (map->value.map.fields[i].name != NULL && strcmp(map->value.map.fields[i].name, name) == 0)
            return &map->value.map.fields[i].value;
    return NULL;
}

solaris_status_t solaris_config_uint(const solaris_config_view_t *map, const char *name,
                                     uint64_t fallback, uint64_t minimum, uint64_t maximum,
                                     uint64_t *out, solaris_error_t *error)
{
    if (out == NULL || minimum > maximum || fallback < minimum || fallback > maximum)
        return solaris_config_error(map, name, "invalid numeric helper bounds", error);
    const solaris_config_view_t *value = solaris_config_get(map, name);
    if (value == NULL) { *out = fallback; return SOLARIS_OK; }
    if (value->kind != SOLARIS_CONFIG_INTEGER || value->value.integer < 0 ||
        (uint64_t)value->value.integer < minimum || (uint64_t)value->value.integer > maximum)
        return solaris_config_error(value, name, "expected an integer in range", error);
    *out = (uint64_t)value->value.integer;
    return SOLARIS_OK;
}

solaris_status_t solaris_config_string(const solaris_config_view_t *map, const char *name,
                                       int required, char *out, size_t capacity,
                                       solaris_error_t *error)
{
    if (out == NULL || capacity == 0u) return SOLARIS_EINVAL;
    out[0] = '\0';
    const solaris_config_view_t *value = solaris_config_get(map, name);
    if (value == NULL) return required ? solaris_config_error(map, name, "required field is missing", error) : SOLARIS_OK;
    if (value->kind != SOLARIS_CONFIG_STRING || value->value.string.data == NULL ||
        value->value.string.length == 0u || value->value.string.length >= capacity ||
        memchr(value->value.string.data, '\0', value->value.string.length) != NULL)
        return solaris_config_error(value, name, "expected a nonempty bounded string without NUL", error);
    memcpy(out, value->value.string.data, value->value.string.length);
    out[value->value.string.length] = '\0';
    return SOLARIS_OK;
}
