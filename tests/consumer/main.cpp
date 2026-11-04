#include <solaris/core.h>
#include <type_traits>

static_assert(std::is_standard_layout<solaris_engine_snapshot_t>::value,
              "SDK snapshot must be a plain C value");

int main()
{
    solaris_engine_t *engine = nullptr;
    if (solaris_version_string()[0] == '\0') return 1;
    if (solaris_engine_create(nullptr, nullptr, &engine, nullptr) != SOLARIS_OK) return 1;
    return solaris_engine_destroy(engine, nullptr) == SOLARIS_OK ? 0 : 1;
}
