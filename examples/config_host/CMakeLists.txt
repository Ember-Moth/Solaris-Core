cmake_minimum_required(VERSION 3.24)
project(SolarisConfigHost LANGUAGES C)
find_package(Solaris CONFIG REQUIRED)
# The SDK installs config_host.c beside this file. No source-tree fallback,
# private headers, extra runtime libraries or test framework are used.
add_executable(solaris_config_host config_host.c)
set_target_properties(solaris_config_host PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
target_link_libraries(solaris_config_host PRIVATE Solaris::core)
if(MSVC AND CMAKE_C_COMPILER_ID STREQUAL "MSVC")
    target_compile_options(solaris_config_host PRIVATE /experimental:c11atomics)
endif()
