#include <solaris/config.h>
#include <assert.h>
#include <stdint.h>
#include <string.h>

/* Offline compile only: no filesystem, DNS, sockets, engines or callbacks.
 * Exercise public snapshot ownership after releasing diagnostics and retaining
 * the image independently. Limits also bound line, token, entry and AST allocation growth. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    solaris_config_options_t options;
    solaris_config_options_init(&options);
    options.input_limit_bytes = 65536;
    options.memory_limit_bytes = 1024 * 1024;
    options.string_limit_bytes = 65536;
    options.line_limit_bytes = 65536;
    options.node_limit = 2048;
    options.entry_limit = 128;
    options.diagnostic_limit = 8;
    solaris_config_t *config = NULL;
    solaris_diagnostics_t *diagnostics = NULL;
    solaris_error_t error;
    solaris_status_t status = solaris_config_compile_bytes(data, size, &options,
        &config, &diagnostics, &error);
    assert((status == SOLARIS_OK) == (config != NULL));
    size_t count = solaris_diagnostics_count(diagnostics);
    assert(count <= options.diagnostic_limit);
    for (size_t i = 0; i < count; ++i) {
        solaris_config_diagnostic_t item;
        assert(solaris_diagnostics_get(diagnostics, i, &item) == SOLARIS_OK);
        assert(memchr(item.message, 0, sizeof(item.message)));
        assert(memchr(item.path, 0, sizeof(item.path)));
    }
    solaris_diagnostics_release(diagnostics);
    if (config) {
        solaris_config_snapshot_t before, after;
        assert(solaris_config_get_snapshot(config, &before) == SOLARIS_OK);
        solaris_config_retain(config);
        solaris_config_release(config);
        assert(solaris_config_get_snapshot(config, &after) == SOLARIS_OK);
        assert(before.fingerprint == after.fingerprint && before.node_count == after.node_count);
        for (size_t i = 0; i < after.node_count; ++i) {
            solaris_config_node_info_t node;
            assert(solaris_config_get_node(config, i, &node) == SOLARIS_OK);
            assert(node.id && memchr(node.name, 0, sizeof(node.name)) && memchr(node.type, 0, sizeof(node.type)));
        }
        solaris_config_release(config);
    }
    return 0;
}
