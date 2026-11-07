#include <solaris/core.h>
#include <type_traits>

static_assert(std::is_standard_layout<solaris_engine_snapshot_t>::value,
              "SDK snapshot must be a plain C value");
static_assert(std::is_standard_layout<solaris_connection_info_t>::value &&
              std::is_standard_layout<solaris_probe_result_t>::value &&
              std::is_standard_layout<solaris_control_result_t>::value,
              "Control and observation results must be plain C values");

int main()
{
    solaris_engine_t *engine = nullptr;
    if (solaris_version_string()[0] == '\0') return 1;
    if (solaris_engine_create(nullptr, nullptr, &engine, nullptr) != SOLARIS_OK) return 1;
    return solaris_engine_destroy(engine, nullptr) == SOLARIS_OK ? 0 : 1;
}
