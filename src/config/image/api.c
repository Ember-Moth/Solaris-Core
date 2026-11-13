#include "api/common/error.h"
#include "config/image/internal.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>

void solaris_config_options_init(solaris_config_options_t *o) {
    if (!o)
        return;
    memset(o, 0, sizeof(*o));
    o->input_limit_bytes = 1048576;
    o->memory_limit_bytes = 16777216;
    o->string_limit_bytes = 65536;
    o->line_limit_bytes = 65536;
    o->node_limit = 65536;
    o->entry_limit = 16384;
    o->diagnostic_limit = 64;
}
static solaris_status_t initialize(cfg_context_t *c, const solaris_config_options_t *input,
                                   const solaris_runtime_services_t *services, solaris_error_t *error) {
    memset(c, 0, sizeof(*c));
    solaris_config_options_init(&c->options);
    if (input) {
        c->options.base_directory = input->base_directory;
        c->options.source_name = input->source_name;
#define OPTION(field)                                                                                                  \
    if (input->field)                                                                                                  \
    c->options.field = input->field
        OPTION(input_limit_bytes);
        OPTION(memory_limit_bytes);
        OPTION(string_limit_bytes);
        OPTION(line_limit_bytes);
        OPTION(node_limit);
        OPTION(entry_limit);
        OPTION(diagnostic_limit);
#undef OPTION
    }
    if (c->options.input_limit_bytes > 67108864 || c->options.string_limit_bytes > 67108864 ||
        c->options.line_limit_bytes > 67108864 || c->options.node_limit > 1048576 || c->options.entry_limit > 1048576 ||
        c->options.diagnostic_limit > 1024 || (c->options.source_name && strlen(c->options.source_name) > 511) ||
        (c->options.base_directory && strlen(c->options.base_directory) > 4095))
        return solaris_error_set(error, SOLARIS_EINVAL, 0, "configuration limits or source metadata are invalid");
    solaris_status_t rc = solaris_budget_create(c->options.memory_limit_bytes, services, &c->budget);
    if (rc != SOLARIS_OK)
        return solaris_error_set(error, rc, 0, NULL);
    c->ast.budget = c->budget;
    size_t bytes = sizeof(*c->diagnostics) + c->options.diagnostic_limit * sizeof(solaris_config_diagnostic_t);
    c->diagnostics = solaris_memory_allocate(c->budget, bytes);
    if (!c->diagnostics)
        return solaris_error_set(error, SOLARIS_ENOMEM, 0, "configuration memory budget exhausted");
    memset(c->diagnostics, 0, bytes);
    atomic_init(&c->diagnostics->references, 1);
    c->diagnostics->capacity = c->options.diagnostic_limit;
    c->image = solaris_memory_allocate(c->budget, sizeof(*c->image));
    if (!c->image) {
        cfg_fail(c, NULL, "$", SOLARIS_ENOMEM, "configuration memory budget exhausted");
        return SOLARIS_ENOMEM;
    }
    memset(c->image, 0, sizeof(*c->image));
    atomic_init(&c->image->references, 1);
    c->image->arena.budget = c->budget;
    const char *source = c->options.source_name ? c->options.source_name : "<bytes>";
    c->image->source_name = cfg_string(&c->image->arena, source, strlen(source));
    if (!c->image->source_name) {
        cfg_fail(c, NULL, "$", SOLARIS_ENOMEM, "configuration memory budget exhausted");
        return SOLARIS_ENOMEM;
    }
    if (c->options.base_directory) {
        c->image->base_directory =
            cfg_string(&c->image->arena, c->options.base_directory, strlen(c->options.base_directory));
        if (!c->image->base_directory) {
            cfg_fail(c, NULL, "$", SOLARIS_ENOMEM, "configuration memory budget exhausted");
            return SOLARIS_ENOMEM;
        }
    }
    return SOLARIS_OK;
}
static solaris_status_t compile(cfg_context_t *c, const void *bytes, size_t length) {
    if (length > c->options.input_limit_bytes) {
        cfg_fail(c, NULL, "$", SOLARIS_EOVERFLOW, "configuration input limit exceeded");
        return c->status;
    }
    cfg_node_t *root = cfg_conf_parse(c, bytes ? bytes : "", length);
    if (root && !c->errors)
        cfg_image_compile(c, root);
    if (!root && !c->errors)
        cfg_fail(c, NULL, "$", SOLARIS_EINVAL, "invalid Solaris Conf configuration");
    return c->errors ? c->status : SOLARIS_OK;
}
static solaris_status_t finish(cfg_context_t *c, solaris_status_t rc, solaris_config_t **out,
                               solaris_diagnostics_t **diagnostics, solaris_error_t *error) {
    cfg_arena_clear(&c->ast);
    if (rc == SOLARIS_OK) {
        *out = c->image;
        c->image = NULL;
        solaris_error_set(error, SOLARIS_OK, 0, NULL);
    } else {
        const char *message = "configuration compilation failed";
        if (c->diagnostics)
            for (size_t i = 0; i < c->diagnostics->count; ++i)
                if (c->diagnostics->entries[i].severity == SOLARIS_DIAGNOSTIC_ERROR) {
                    message = c->diagnostics->entries[i].message;
                    break;
                }
        solaris_error_set(error, rc, 0, message);
    }
    solaris_config_release(c->image);
    if (diagnostics)
        *diagnostics = c->diagnostics;
    else
        solaris_diagnostics_release(c->diagnostics);
    solaris_budget_release(c->budget);
    return rc;
}
solaris_status_t solaris_config_compile_bytes_services(const void *bytes, size_t length,
                                                       const solaris_config_options_t *options,
                                                       const solaris_runtime_services_t *services,
                                                       solaris_config_t **out, solaris_diagnostics_t **diagnostics,
                                                       solaris_error_t *error) {
    if (diagnostics)
        *diagnostics = NULL;
    if (out)
        *out = NULL;
    if (!out || (!bytes && length))
        return solaris_error_set(error, SOLARIS_EINVAL, 0, "configuration input/output is required");
    cfg_context_t c;
    solaris_status_t rc = initialize(&c, options, services, error);
    if (rc == SOLARIS_OK)
        rc = compile(&c, bytes, length);
    return finish(&c, rc, out, diagnostics, error);
}
solaris_status_t solaris_config_compile_bytes(const void *bytes, size_t length, const solaris_config_options_t *options,
                                              solaris_config_t **out, solaris_diagnostics_t **diagnostics,
                                              solaris_error_t *error) {
    return solaris_config_compile_bytes_services(bytes, length, options, NULL, out, diagnostics, error);
}
solaris_status_t solaris_config_compile_file(const char *path, const solaris_config_options_t *options,
                                             solaris_config_t **out, solaris_diagnostics_t **diagnostics,
                                             solaris_error_t *error) {
    if (out)
        *out = NULL;
    if (diagnostics)
        *diagnostics = NULL;
    if (!path || !out || !*path || strlen(path) > 4095)
        return solaris_error_set(error, SOLARIS_EINVAL, 0, "configuration file path/output is required");
    solaris_config_options_t selected;
    if (options)
        selected = *options;
    else
        solaris_config_options_init(&selected);
    char parent[4096];
    if (!selected.base_directory) {
        const char *last = strrchr(path, '/');
#ifdef _WIN32
        const char *back = strrchr(path, '\\');
        if (back && (!last || back > last))
            last = back;
#endif
        if (!last) {
            parent[0] = '.';
            parent[1] = 0;
        } else {
            size_t n = (size_t)(last - path);
            if (!n)
                n = 1;
#ifdef _WIN32
            if (n == 2 && path[1] == ':')
                n = 3;
#endif
            memcpy(parent, path, n);
            parent[n] = 0;
        }
        selected.base_directory = parent;
    }
    if (!selected.source_name)
        selected.source_name = path;
    cfg_context_t c;
    solaris_status_t rc = initialize(&c, &selected, NULL, error);
    FILE *file = NULL;
    unsigned char *bytes = NULL;
    size_t length = 0;
    if (rc != SOLARIS_OK)
        goto done;
#ifdef _MSC_VER
    (void)fopen_s(&file, path, "rb");
#else
    file = fopen(path, "rb");
#endif
    if (!file) {
        cfg_fail(&c, NULL, "$", SOLARIS_EIO, "configuration file could not be opened");
        rc = SOLARIS_EIO;
        goto done;
    }
    if (fseek(file, 0, SEEK_END)) {
        cfg_fail(&c, NULL, "$", SOLARIS_EIO, "configuration file must be seekable");
        rc = SOLARIS_EIO;
        goto done;
    }
    long size = ftell(file);
    if (size < 0 || fseek(file, 0, SEEK_SET)) {
        cfg_fail(&c, NULL, "$", SOLARIS_EIO, "configuration file size could not be read");
        rc = SOLARIS_EIO;
        goto done;
    }
    if ((uint64_t)size > c.options.input_limit_bytes) {
        cfg_fail(&c, NULL, "$", SOLARIS_EOVERFLOW, "configuration input limit exceeded");
        rc = SOLARIS_EOVERFLOW;
        goto done;
    }
    length = (size_t)size;
    bytes = solaris_memory_allocate(c.budget, length ? length : 1);
    if (!bytes) {
        cfg_fail(&c, NULL, "$", SOLARIS_ENOMEM, "configuration memory budget exhausted");
        rc = SOLARIS_ENOMEM;
        goto done;
    }
    if (fread(bytes, 1, length, file) != length || fgetc(file) != EOF || ferror(file)) {
        cfg_fail(&c, NULL, "$", SOLARIS_EIO, "configuration file changed or failed during bounded read");
        rc = SOLARIS_EIO;
        goto done;
    }
    rc = compile(&c, bytes, length);
done:
    if (file)
        fclose(file);
    if (bytes) {
        for (size_t i = 0; i < length; ++i)
            ((volatile unsigned char *)bytes)[i] = 0;
        solaris_memory_free(bytes);
    }
    return finish(&c, rc, out, diagnostics, error);
}
