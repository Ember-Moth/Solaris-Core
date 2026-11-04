cmake_minimum_required(VERSION 3.24)
project(Solaris VERSION 0.1.0 LANGUAGES C)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
include(CTest)

option(BUILD_SHARED_LIBS "Build Solaris as a shared library" ON)
option(SOLARIS_BUILD_TESTS "Build Solaris SDK and lifecycle tests" ${PROJECT_IS_TOP_LEVEL})
option(SOLARIS_BUILD_EXAMPLES "Build the minimal C host" ${PROJECT_IS_TOP_LEVEL})
set(SOLARIS_SANITIZER "none" CACHE STRING "none, address, or thread")
set_property(CACHE SOLARIS_SANITIZER PROPERTY STRINGS none address thread)
if(NOT SOLARIS_SANITIZER MATCHES "^(none|address|thread)$")
    message(FATAL_ERROR "Unknown SOLARIS_SANITIZER=${SOLARIS_SANITIZER}")
endif()
if(NOT SOLARIS_SANITIZER STREQUAL "none" AND MSVC)
    message(FATAL_ERROR "This sanitizer preset requires Clang or GCC")
endif()

include(cmake/SolarisModules.cmake)
include(cmake/SolarisDependencies.cmake)
configure_file(cmake/solaris_build_config.h.in generated/solaris_build_config.h @ONLY)

function(solaris_configure_target target)
    set_target_properties(${target} PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /WX)
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra -Werror -Wpedantic)
        target_compile_definitions(${target} PRIVATE _POSIX_C_SOURCE=200809L)
    endif()
    if(SOLARIS_SANITIZER STREQUAL "address")
        target_compile_options(${target} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
        target_link_options(${target} PRIVATE -fsanitize=address,undefined)
    elseif(SOLARIS_SANITIZER STREQUAL "thread")
        target_compile_options(${target} PRIVATE -fsanitize=thread -fno-omit-frame-pointer)
        target_link_options(${target} PRIVATE -fsanitize=thread)
    endif()
endfunction()

add_library(solaris_core ${SOLARIS_SOURCES})
add_library(Solaris::core ALIAS solaris_core)
solaris_configure_target(solaris_core)
target_include_directories(solaris_core
    PUBLIC $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    PRIVATE src "${PROJECT_BINARY_DIR}/generated")
target_compile_definitions(solaris_core PRIVATE SOLARIS_BUILDING_CORE)
target_link_libraries(solaris_core PRIVATE uv_a)
set_target_properties(solaris_core PROPERTIES
    OUTPUT_NAME solaris EXPORT_NAME core
    C_VISIBILITY_PRESET hidden POSITION_INDEPENDENT_CODE ON
    WINDOWS_EXPORT_ALL_SYMBOLS OFF)

if(BUILD_SHARED_LIBS)
    target_compile_definitions(solaris_core PUBLIC SOLARIS_SHARED)
    if(WIN32)
        target_sources(solaris_core PRIVATE "${PROJECT_BINARY_DIR}/generated/solaris.def")
        set_property(TARGET solaris_core APPEND PROPERTY LINK_DEPENDS "${PROJECT_BINARY_DIR}/generated/solaris.def")
    elseif(APPLE)
        target_link_options(solaris_core PRIVATE
            "LINKER:-exported_symbols_list,${PROJECT_BINARY_DIR}/generated/solaris.exports")
        set_property(TARGET solaris_core APPEND PROPERTY LINK_DEPENDS "${PROJECT_BINARY_DIR}/generated/solaris.exports")
    else()
        target_link_options(solaris_core PRIVATE
            "LINKER:--version-script=${PROJECT_BINARY_DIR}/generated/solaris.map"
            "LINKER:--no-undefined")
        set_property(TARGET solaris_core APPEND PROPERTY LINK_DEPENDS "${PROJECT_BINARY_DIR}/generated/solaris.map")
    endif()
    if(ANDROID)
        target_link_options(solaris_core PRIVATE "LINKER:-z,max-page-size=16384")
    endif()
endif()
if(NOT SOLARIS_SANITIZER STREQUAL "none")
    if(SOLARIS_SANITIZER STREQUAL "address")
        target_link_options(solaris_core INTERFACE -fsanitize=address,undefined)
    else()
        target_link_options(solaris_core INTERFACE -fsanitize=thread)
    endif()
endif()

if(SOLARIS_BUILD_EXAMPLES)
    add_executable(solaris_minimal_host examples/minimal_host.c)
    solaris_configure_target(solaris_minimal_host)
    target_link_libraries(solaris_minimal_host PRIVATE Solaris::core)
endif()

if(SOLARIS_BUILD_TESTS AND BUILD_TESTING AND NOT CMAKE_CROSSCOMPILING)
    find_package(Python3 3.9 REQUIRED COMPONENTS Interpreter)
    add_executable(solaris_sdk_smoke tests/sdk_smoke.c)
    solaris_configure_target(solaris_sdk_smoke)
    target_link_libraries(solaris_sdk_smoke PRIVATE Solaris::core)
    add_test(NAME sdk_smoke COMMAND solaris_sdk_smoke)

    # Internal services are tested without adding test hooks to the shared ABI.
    add_library(solaris_test_core STATIC ${SOLARIS_SOURCES})
    solaris_configure_target(solaris_test_core)
    target_include_directories(solaris_test_core PUBLIC include PRIVATE src "${PROJECT_BINARY_DIR}/generated")
    target_link_libraries(solaris_test_core PUBLIC uv_a)
    add_executable(solaris_lifecycle_tests tests/contracts/lifecycle.c)
    solaris_configure_target(solaris_lifecycle_tests)
    target_include_directories(solaris_lifecycle_tests PRIVATE src)
    target_link_libraries(solaris_lifecycle_tests PRIVATE solaris_test_core)
    add_test(NAME lifecycle_contract COMMAND solaris_lifecycle_tests)
    set_tests_properties(sdk_smoke lifecycle_contract PROPERTIES TIMEOUT 30)

    if(BUILD_SHARED_LIBS)
        add_test(NAME sdk_exports COMMAND "${Python3_EXECUTABLE}"
            "${PROJECT_SOURCE_DIR}/scripts/verify_exports.py"
            --library "$<TARGET_FILE:solaris_core>"
            --expected "${PROJECT_BINARY_DIR}/generated/exports.txt"
            --nm "${CMAKE_NM}" --linker "${CMAKE_LINKER}")
    endif()
    add_test(NAME installed_consumer COMMAND "${Python3_EXECUTABLE}"
        "${PROJECT_SOURCE_DIR}/scripts/verify_install.py"
        --build "${PROJECT_BINARY_DIR}" --source "${PROJECT_SOURCE_DIR}/tests/consumer"
        --config "$<CONFIG>" --cmake "${CMAKE_COMMAND}" --compiler "${CMAKE_C_COMPILER}")
    set_tests_properties(installed_consumer PROPERTIES TIMEOUT 120 RUN_SERIAL TRUE)
endif()

install(TARGETS solaris_core EXPORT SolarisTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
if(NOT BUILD_SHARED_LIBS)
    install(TARGETS uv_a EXPORT SolarisTargets ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif()
install(EXPORT SolarisTargets NAMESPACE Solaris:: DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Solaris)
install(FILES ${SOLARIS_PUBLIC_HEADERS} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/solaris)
configure_package_config_file(cmake/SolarisConfig.cmake.in
    "${PROJECT_BINARY_DIR}/SolarisConfig.cmake"
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Solaris)
write_basic_package_version_file("${PROJECT_BINARY_DIR}/SolarisConfigVersion.cmake"
    VERSION ${PROJECT_VERSION} COMPATIBILITY ExactVersion)
install(FILES "${PROJECT_BINARY_DIR}/SolarisConfig.cmake"
    "${PROJECT_BINARY_DIR}/SolarisConfigVersion.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Solaris)
install(FILES "${solaris_uv_SOURCE_DIR}/LICENSE" "${solaris_uv_SOURCE_DIR}/LICENSE-extra"
    DESTINATION ${CMAKE_INSTALL_DATADIR}/Solaris/licenses/libuv)
install(FILES THIRD_PARTY_NOTICES.md dependencies/lock.json
    DESTINATION ${CMAKE_INSTALL_DATADIR}/Solaris)
