cmake_minimum_required(VERSION 3.24)
project(Solaris VERSION 0.1.0 LANGUAGES C)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
include(CTest)

option(BUILD_SHARED_LIBS "Build Solaris as a shared library" ON)
option(SOLARIS_BUILD_TESTS "Build Solaris SDK and lifecycle tests" ${PROJECT_IS_TOP_LEVEL})
option(SOLARIS_BUILD_EXAMPLES "Build the minimal C host" ${PROJECT_IS_TOP_LEVEL})
option(SOLARIS_BUILD_FUZZERS "Build coverage-guided parser targets with libFuzzer/ASan/UBSan" OFF)
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
        if(CMAKE_C_COMPILER_ID STREQUAL "MSVC")
            target_compile_options(${target} PRIVATE /experimental:c11atomics)
        endif()
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
target_link_libraries(solaris_core PRIVATE ${SOLARIS_PRIVATE_LIBRARIES})
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
    add_executable(solaris_config_host examples/config_host.c)
    solaris_configure_target(solaris_config_host)
    target_link_libraries(solaris_config_host PRIVATE Solaris::core)
endif()

if(SOLARIS_BUILD_TESTS AND BUILD_TESTING AND NOT CMAKE_CROSSCOMPILING)
    find_package(Python3 3.9 REQUIRED COMPONENTS Interpreter)
    add_executable(solaris_sdk_smoke tests/sdk/smoke.c)
    solaris_configure_target(solaris_sdk_smoke)
    target_link_libraries(solaris_sdk_smoke PRIVATE Solaris::core)
    add_test(NAME sdk_smoke COMMAND solaris_sdk_smoke)
    add_executable(solaris_config_sdk_tests tests/sdk/config.c)
    solaris_configure_target(solaris_config_sdk_tests)
    target_include_directories(solaris_config_sdk_tests PRIVATE "${PROJECT_BINARY_DIR}/generated")
    target_link_libraries(solaris_config_sdk_tests PRIVATE Solaris::core)
    add_test(NAME config_sdk_contract COMMAND solaris_config_sdk_tests)
    set_tests_properties(config_sdk_contract PROPERTIES TIMEOUT 30)

    # Internal services are tested without adding test hooks to the shared ABI.
    add_library(solaris_test_core STATIC ${SOLARIS_SOURCES})
    solaris_configure_target(solaris_test_core)
    target_include_directories(solaris_test_core PUBLIC include PRIVATE src "${PROJECT_BINARY_DIR}/generated")
    target_link_libraries(solaris_test_core PUBLIC ${SOLARIS_PRIVATE_LIBRARIES})
    add_executable(solaris_lifecycle_tests tests/contracts/runtime/lifecycle.c)
    solaris_configure_target(solaris_lifecycle_tests)
    target_include_directories(solaris_lifecycle_tests PRIVATE src)
    target_link_libraries(solaris_lifecycle_tests PRIVATE solaris_test_core)
    add_test(NAME lifecycle_contract COMMAND solaris_lifecycle_tests)
    set_tests_properties(sdk_smoke lifecycle_contract PROPERTIES TIMEOUT 30)
    add_executable(solaris_executor_tests tests/contracts/runtime/executor.c)
    solaris_configure_target(solaris_executor_tests)
    target_include_directories(solaris_executor_tests PRIVATE src tests)
    target_link_libraries(solaris_executor_tests PRIVATE solaris_test_core)
    add_test(NAME executor_contract COMMAND solaris_executor_tests)
    set_tests_properties(executor_contract PROPERTIES TIMEOUT 30)
    add_executable(solaris_m2_foundation_tests tests/contracts/runtime/m2_foundation.c)
    solaris_configure_target(solaris_m2_foundation_tests)
    target_include_directories(solaris_m2_foundation_tests PRIVATE src tests)
    target_link_libraries(solaris_m2_foundation_tests PRIVATE solaris_test_core)
    add_test(NAME m2_foundation_contract COMMAND solaris_m2_foundation_tests)
    set_tests_properties(m2_foundation_contract PROPERTIES TIMEOUT 30)
    add_executable(solaris_config_slots_tests tests/contracts/runtime/config_slots.c)
    solaris_configure_target(solaris_config_slots_tests)
    target_include_directories(solaris_config_slots_tests PRIVATE src tests)
    target_link_libraries(solaris_config_slots_tests PRIVATE solaris_test_core)
    add_test(NAME config_slots_contract COMMAND solaris_config_slots_tests)
    set_tests_properties(config_slots_contract PROPERTIES TIMEOUT 30)
    add_executable(solaris_engine_hooks_tests tests/contracts/runtime/engine_hooks.c)
    solaris_configure_target(solaris_engine_hooks_tests)
    target_include_directories(solaris_engine_hooks_tests PRIVATE src tests)
    target_link_libraries(solaris_engine_hooks_tests PRIVATE solaris_test_core)
    add_test(NAME engine_hooks_contract COMMAND solaris_engine_hooks_tests)
    set_tests_properties(engine_hooks_contract PROPERTIES TIMEOUT 30)
    if(SOLARIS_ENABLE_DIRECT AND SOLARIS_ENABLE_BLOCK)
        add_executable(solaris_config_bounds_tests tests/contracts/config/bounds.c)
        solaris_configure_target(solaris_config_bounds_tests)
        target_link_libraries(solaris_config_bounds_tests PRIVATE Solaris::core)
        add_test(NAME config_bounds_contract COMMAND solaris_config_bounds_tests)
        set_tests_properties(config_bounds_contract PROPERTIES TIMEOUT 30)
        add_executable(solaris_config_control_tests tests/contracts/runtime/config_control.c)
        solaris_configure_target(solaris_config_control_tests)
        target_include_directories(solaris_config_control_tests PRIVATE src tests)
        target_link_libraries(solaris_config_control_tests PRIVATE solaris_test_core)
        add_test(NAME config_control_contract COMMAND solaris_config_control_tests)
        set_tests_properties(config_control_contract PROPERTIES TIMEOUT 60)
        add_executable(solaris_config_modules_tests tests/contracts/runtime/config_modules.c)
        solaris_configure_target(solaris_config_modules_tests)
        target_include_directories(solaris_config_modules_tests PRIVATE src tests "${PROJECT_BINARY_DIR}/generated")
        target_link_libraries(solaris_config_modules_tests PRIVATE solaris_test_core)
        add_test(NAME config_modules_contract COMMAND solaris_config_modules_tests)
        set_tests_properties(config_modules_contract PROPERTIES TIMEOUT 30)
    endif()
    add_executable(solaris_route_tests tests/contracts/policy/route.c)
    solaris_configure_target(solaris_route_tests)
    target_include_directories(solaris_route_tests PRIVATE src tests)
    target_link_libraries(solaris_route_tests PRIVATE solaris_test_core)
    add_test(NAME route_contract COMMAND solaris_route_tests)
    set_tests_properties(route_contract PROPERTIES TIMEOUT 30)
    add_executable(solaris_operation_tests tests/contracts/runtime/operations.c)
    solaris_configure_target(solaris_operation_tests)
    target_include_directories(solaris_operation_tests PRIVATE src tests)
    target_link_libraries(solaris_operation_tests PRIVATE solaris_test_core)
    add_test(NAME operation_contract COMMAND solaris_operation_tests)
    set_tests_properties(operation_contract PROPERTIES TIMEOUT 30)
    if(TARGET solaris_yaml)
        add_test(NAME yaml_private_symbols COMMAND "${Python3_EXECUTABLE}"
            "${PROJECT_SOURCE_DIR}/scripts/verify/private_symbols.py"
            --nm "${CMAKE_NM}" --prefix solaris_private_yaml "$<TARGET_FILE:solaris_yaml>")
        set_tests_properties(yaml_private_symbols PROPERTIES TIMEOUT 30)
    endif()
    if("direct" IN_LIST solaris_enabled_modules AND "block" IN_LIST solaris_enabled_modules AND "socks5" IN_LIST solaris_enabled_modules)
        add_executable(solaris_config_compile_tests tests/contracts/config/compile.c)
        solaris_configure_target(solaris_config_compile_tests)
        target_include_directories(solaris_config_compile_tests PRIVATE src tests "${PROJECT_BINARY_DIR}/generated")
        target_link_libraries(solaris_config_compile_tests PRIVATE solaris_test_core)
        add_test(NAME config_compile_contract COMMAND solaris_config_compile_tests
            "${PROJECT_SOURCE_DIR}/tests/support/config/valid.yaml")
        set_tests_properties(config_compile_contract PROPERTIES TIMEOUT 30)
        find_program(GO_EXECUTABLE go REQUIRED)
        set(solaris_yaml_reference "${PROJECT_BINARY_DIR}/reference-tools/yaml-reference${CMAKE_EXECUTABLE_SUFFIX}")
        add_custom_command(OUTPUT "${solaris_yaml_reference}"
            COMMAND "${CMAKE_COMMAND}" -E make_directory "${PROJECT_BINARY_DIR}/reference-tools"
            COMMAND "${GO_EXECUTABLE}" build -mod=readonly -trimpath -o "${solaris_yaml_reference}" .
            WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/support/config/reference"
            DEPENDS tests/support/config/reference/go.mod tests/support/config/reference/go.sum
                tests/support/config/reference/main.go VERBATIM)
        add_custom_target(solaris_yaml_reference ALL DEPENDS "${solaris_yaml_reference}")
        add_test(NAME config_differential_contract COMMAND "${Python3_EXECUTABLE}"
            "${PROJECT_SOURCE_DIR}/tests/support/config/differential.py"
            "$<TARGET_FILE:solaris_config_compile_tests>" "${solaris_yaml_reference}")
        set_tests_properties(config_differential_contract PROPERTIES TIMEOUT 30)
        add_executable(solaris_config_dump_tests tests/contracts/config/dump.c)
        solaris_configure_target(solaris_config_dump_tests)
        target_include_directories(solaris_config_dump_tests PRIVATE src tests "${PROJECT_BINARY_DIR}/generated")
        target_link_libraries(solaris_config_dump_tests PRIVATE solaris_test_core)
        set(solaris_full_reference "${PROJECT_BINARY_DIR}/reference-tools/mihomo-full-reference${CMAKE_EXECUTABLE_SUFFIX}")
        set(solaris_full_reference_source "${PROJECT_SOURCE_DIR}/tests/support/config/reference/full")
        add_custom_command(OUTPUT "${solaris_full_reference}"
            COMMAND "${Python3_EXECUTABLE}" "${solaris_full_reference_source}/build.py"
                "${solaris_full_reference}" --go "${GO_EXECUTABLE}"
            DEPENDS "${solaris_full_reference_source}/build.py" "${solaris_full_reference_source}/main.go"
                "${solaris_full_reference_source}/go.mod" "${solaris_full_reference_source}/go.sum"
                "${solaris_full_reference_source}/overlay/manifest.json"
                "${solaris_full_reference_source}/overlay/observer.go.txt"
                "${solaris_full_reference_source}/overlay/listener.go.txt"
                "${solaris_full_reference_source}/overlay/tunnel.go.txt"
                "${solaris_full_reference_source}/overlay/inbound.go.txt"
            BYPRODUCTS "${solaris_full_reference}-evidence.json" VERBATIM)
        add_custom_target(solaris_full_config_reference ALL DEPENDS "${solaris_full_reference}")
        add_test(NAME config_full_differential_contract COMMAND "${Python3_EXECUTABLE}"
            "${PROJECT_SOURCE_DIR}/tests/support/config/full_differential.py"
            "$<TARGET_FILE:solaris_config_dump_tests>" "${solaris_full_reference}"
            --report "${PROJECT_BINARY_DIR}/config-full-differential.json")
        set_tests_properties(config_full_differential_contract PROPERTIES TIMEOUT 120)
        add_executable(solaris_config_routing_tests tests/contracts/config/routing.c)
        solaris_configure_target(solaris_config_routing_tests)
        target_include_directories(solaris_config_routing_tests PRIVATE src tests)
        target_link_libraries(solaris_config_routing_tests PRIVATE solaris_test_core)
        add_test(NAME config_routing_contract COMMAND solaris_config_routing_tests)
        set_tests_properties(config_routing_contract PROPERTIES TIMEOUT 30)
    endif()
    add_executable(solaris_module_tests tests/contracts/module/registry.c)
    solaris_configure_target(solaris_module_tests)
    target_include_directories(solaris_module_tests PRIVATE src tests "${PROJECT_BINARY_DIR}/generated")
    target_link_libraries(solaris_module_tests PRIVATE solaris_test_core)
    add_test(NAME module_contract COMMAND solaris_module_tests)
    set_tests_properties(module_contract PROPERTIES TIMEOUT 30)
    add_executable(solaris_udp_lifecycle_tests tests/contracts/flow/udp/lifecycle.c)
    solaris_configure_target(solaris_udp_lifecycle_tests)
    target_include_directories(solaris_udp_lifecycle_tests PRIVATE src tests)
    target_link_libraries(solaris_udp_lifecycle_tests PRIVATE solaris_test_core)
    add_test(NAME udp_lifecycle_contract COMMAND solaris_udp_lifecycle_tests)
    set_tests_properties(udp_lifecycle_contract PROPERTIES TIMEOUT 30)
    add_executable(solaris_uot_codec_tests tests/contracts/transport/uot_codec.c)
    solaris_configure_target(solaris_uot_codec_tests)
    target_include_directories(solaris_uot_codec_tests PRIVATE src tests)
    target_link_libraries(solaris_uot_codec_tests PRIVATE solaris_test_core)
    add_test(NAME uot_codec_contract COMMAND "${Python3_EXECUTABLE}"
        "${PROJECT_SOURCE_DIR}/tests/support/transport/uot_codec.py" "$<TARGET_FILE:solaris_uot_codec_tests>")
    set_tests_properties(uot_codec_contract PROPERTIES TIMEOUT 30)
    add_executable(solaris_xudp_codec_tests tests/contracts/transport/xudp_codec.c)
    solaris_configure_target(solaris_xudp_codec_tests)
    target_include_directories(solaris_xudp_codec_tests PRIVATE src tests)
    target_link_libraries(solaris_xudp_codec_tests PRIVATE solaris_test_core)
    add_test(NAME xudp_codec_contract COMMAND "${Python3_EXECUTABLE}"
        "${PROJECT_SOURCE_DIR}/tests/support/transport/xudp_codec.py" "$<TARGET_FILE:solaris_xudp_codec_tests>")
    set_tests_properties(xudp_codec_contract PROPERTIES TIMEOUT 30)
    add_executable(solaris_datagram_stream_tests tests/contracts/transport/datagram_stream.c)
    solaris_configure_target(solaris_datagram_stream_tests)
    target_include_directories(solaris_datagram_stream_tests PRIVATE src tests)
    target_link_libraries(solaris_datagram_stream_tests PRIVATE solaris_test_core)
    add_test(NAME datagram_stream_contract COMMAND "${Python3_EXECUTABLE}"
        "${PROJECT_SOURCE_DIR}/tests/support/transport/uot_codec.py" "$<TARGET_FILE:solaris_datagram_stream_tests>")
    set_tests_properties(datagram_stream_contract PROPERTIES TIMEOUT 30)
    add_test(NAME xudp_stream_contract COMMAND "${Python3_EXECUTABLE}"
        "${PROJECT_SOURCE_DIR}/tests/support/transport/xudp_codec.py" "$<TARGET_FILE:solaris_datagram_stream_tests>" xudp)
    set_tests_properties(xudp_stream_contract PROPERTIES TIMEOUT 30)
    add_executable(solaris_stream_filter_tests tests/contracts/transport/stream_filter.c)
    solaris_configure_target(solaris_stream_filter_tests)
    target_include_directories(solaris_stream_filter_tests PRIVATE src tests)
    target_link_libraries(solaris_stream_filter_tests PRIVATE solaris_test_core)
    add_test(NAME stream_filter_contract COMMAND solaris_stream_filter_tests)
    set_tests_properties(stream_filter_contract PROPERTIES TIMEOUT 30)
    add_executable(solaris_select_tests tests/contracts/flow/select.c)
    solaris_configure_target(solaris_select_tests)
    target_include_directories(solaris_select_tests PRIVATE src tests)
    target_link_libraries(solaris_select_tests PRIVATE solaris_test_core)
    add_test(NAME select_contract COMMAND solaris_select_tests)
    set_tests_properties(select_contract PROPERTIES TIMEOUT 30)
    add_executable(solaris_observation_tests tests/contracts/flow/observation.c)
    solaris_configure_target(solaris_observation_tests)
    target_include_directories(solaris_observation_tests PRIVATE src tests)
    target_link_libraries(solaris_observation_tests PRIVATE solaris_test_core)
    add_test(NAME observation_contract COMMAND solaris_observation_tests)
    set_tests_properties(observation_contract PROPERTIES TIMEOUT 30)
    add_executable(solaris_observation_admission_tests tests/contracts/flow/observation_admission.c)
    solaris_configure_target(solaris_observation_admission_tests)
    target_include_directories(solaris_observation_admission_tests PRIVATE src tests)
    target_link_libraries(solaris_observation_admission_tests PRIVATE solaris_test_core)
    add_test(NAME observation_admission_contract COMMAND solaris_observation_admission_tests)
    set_tests_properties(observation_admission_contract PROPERTIES TIMEOUT 30)
    add_executable(solaris_probe_tests tests/contracts/flow/probe.c)
    solaris_configure_target(solaris_probe_tests)
    target_include_directories(solaris_probe_tests PRIVATE src tests)
    target_link_libraries(solaris_probe_tests PRIVATE solaris_test_core)
    add_test(NAME probe_contract COMMAND solaris_probe_tests)
    set_tests_properties(probe_contract PROPERTIES TIMEOUT 30)
    add_executable(solaris_log_tests tests/contracts/observe/log.c)
    solaris_configure_target(solaris_log_tests)
    target_include_directories(solaris_log_tests PRIVATE src tests)
    target_link_libraries(solaris_log_tests PRIVATE solaris_test_core)
    add_test(NAME log_contract COMMAND solaris_log_tests)
    set_tests_properties(log_contract PROPERTIES TIMEOUT 30)
    add_executable(solaris_sdk_observe_tests tests/contracts/runtime/observe.c)
    solaris_configure_target(solaris_sdk_observe_tests)
    target_include_directories(solaris_sdk_observe_tests PRIVATE src tests)
    target_link_libraries(solaris_sdk_observe_tests PRIVATE solaris_test_core)
    add_test(NAME sdk_observe_contract COMMAND solaris_sdk_observe_tests)
    set_tests_properties(sdk_observe_contract PROPERTIES TIMEOUT 30)
    if(SOLARIS_ENABLE_DIRECT AND SOLARIS_ENABLE_BLOCK)
        add_executable(solaris_sdk_probe_tests tests/contracts/flow/sdk_probe.c)
        solaris_configure_target(solaris_sdk_probe_tests)
        target_include_directories(solaris_sdk_probe_tests PRIVATE src tests)
        target_link_libraries(solaris_sdk_probe_tests PRIVATE solaris_test_core)
        add_test(NAME sdk_probe_contract COMMAND solaris_sdk_probe_tests)
        set_tests_properties(sdk_probe_contract PROPERTIES TIMEOUT 60)
        if("tls" IN_LIST solaris_enabled_modules)
            add_test(NAME sdk_probe_https_contract COMMAND "${Python3_EXECUTABLE}"
                "${PROJECT_SOURCE_DIR}/tests/support/flow/sdk_probe_https.py" "$<TARGET_FILE:solaris_sdk_probe_tests>")
            set_tests_properties(sdk_probe_https_contract PROPERTIES TIMEOUT 60 SKIP_RETURN_CODE 77)
        endif()
    endif()
    add_executable(solaris_session_tests tests/contracts/transport/session.c)
    solaris_configure_target(solaris_session_tests)
    target_include_directories(solaris_session_tests PRIVATE src tests)
    target_link_libraries(solaris_session_tests PRIVATE solaris_test_core)
    add_test(NAME session_contract COMMAND solaris_session_tests)
    set_tests_properties(session_contract PROPERTIES TIMEOUT 30)
    add_executable(solaris_tcp_relay_tests tests/contracts/flow/tcp.c)
    solaris_configure_target(solaris_tcp_relay_tests)
    target_include_directories(solaris_tcp_relay_tests PRIVATE src tests)
    target_link_libraries(solaris_tcp_relay_tests PRIVATE solaris_test_core)
    add_test(NAME tcp_relay_contract COMMAND solaris_tcp_relay_tests)
    set_tests_properties(tcp_relay_contract PROPERTIES TIMEOUT 30)
    if(SOLARIS_ENABLE_PROXY_INBOUND)
        add_executable(solaris_http_proxy_codec_tests tests/contracts/inbound/proxy/http.c)
        solaris_configure_target(solaris_http_proxy_codec_tests)
        target_include_directories(solaris_http_proxy_codec_tests PRIVATE src tests)
        target_link_libraries(solaris_http_proxy_codec_tests PRIVATE solaris_test_core)
        add_test(NAME http_proxy_codec_contract COMMAND solaris_http_proxy_codec_tests)
        set_tests_properties(http_proxy_codec_contract PROPERTIES TIMEOUT 30)
        if(SOLARIS_ENABLE_DIRECT)
            if(SOLARIS_ENABLE_BLOCK)
                add_executable(solaris_config_transactions_tests tests/contracts/runtime/config_transactions.c)
                solaris_configure_target(solaris_config_transactions_tests)
                target_include_directories(solaris_config_transactions_tests PRIVATE src tests)
                target_link_libraries(solaris_config_transactions_tests PRIVATE solaris_test_core)
                add_test(NAME config_transactions_contract COMMAND solaris_config_transactions_tests)
                set_tests_properties(config_transactions_contract PROPERTIES TIMEOUT 90)
                add_executable(solaris_routed_inbound_tests tests/contracts/inbound/routed.c)
                solaris_configure_target(solaris_routed_inbound_tests)
                target_include_directories(solaris_routed_inbound_tests PRIVATE src tests)
                target_link_libraries(solaris_routed_inbound_tests PRIVATE solaris_test_core)
                add_test(NAME routed_inbound_contract COMMAND "${Python3_EXECUTABLE}"
                    "${PROJECT_SOURCE_DIR}/tests/support/inbound/routed.py" "$<TARGET_FILE:solaris_routed_inbound_tests>")
                set_tests_properties(routed_inbound_contract PROPERTIES TIMEOUT 90)
                add_executable(solaris_runtime_proxy_tests tests/sdk/runtime_proxy.c)
                solaris_configure_target(solaris_runtime_proxy_tests)
                target_link_libraries(solaris_runtime_proxy_tests PRIVATE Solaris::core)
                add_test(NAME runtime_proxy_contract COMMAND "${Python3_EXECUTABLE}"
                    "${PROJECT_SOURCE_DIR}/tests/support/config/runtime_proxy.py" "$<TARGET_FILE:solaris_runtime_proxy_tests>")
                set_tests_properties(runtime_proxy_contract PROPERTIES TIMEOUT 90)
                add_test(NAME runtime_control_contract COMMAND "${Python3_EXECUTABLE}"
                    "${PROJECT_SOURCE_DIR}/tests/support/config/runtime_control.py" "$<TARGET_FILE:solaris_runtime_proxy_tests>")
                set_tests_properties(runtime_control_contract PROPERTIES TIMEOUT 120)
                set(solaris_acceptance_args)
                if(NOT SOLARIS_ENABLE_SOCKS5)
                    list(APPEND solaris_acceptance_args --without-socks)
                endif()
                add_test(NAME runtime_acceptance_contract COMMAND "${Python3_EXECUTABLE}"
                    "${PROJECT_SOURCE_DIR}/tests/support/config/runtime_acceptance.py"
                    "$<TARGET_FILE:solaris_runtime_proxy_tests>" ${solaris_acceptance_args})
                set_tests_properties(runtime_acceptance_contract PROPERTIES TIMEOUT 120)
                add_executable(solaris_route_acceptance_tests tests/contracts/runtime/route_acceptance.c)
                solaris_configure_target(solaris_route_acceptance_tests)
                target_include_directories(solaris_route_acceptance_tests PRIVATE src tests)
                target_link_libraries(solaris_route_acceptance_tests PRIVATE solaris_test_core)
                add_test(NAME route_acceptance_contract COMMAND "${Python3_EXECUTABLE}"
                    "${PROJECT_SOURCE_DIR}/tests/support/config/route_acceptance.py"
                    "$<TARGET_FILE:solaris_route_acceptance_tests>")
                set_tests_properties(route_acceptance_contract PROPERTIES TIMEOUT 180)
                if(TARGET solaris_config_host)
                    add_test(NAME config_host_contract COMMAND "${Python3_EXECUTABLE}"
                        "${PROJECT_SOURCE_DIR}/tests/support/config/config_host.py"
                        "$<TARGET_FILE:solaris_config_host>"
                        "${PROJECT_SOURCE_DIR}/examples/config_host.yaml"
                        "${PROJECT_SOURCE_DIR}/examples/config_host_reload.yaml")
                    set_tests_properties(config_host_contract PROPERTIES TIMEOUT 90)
                endif()
            endif()
            add_executable(solaris_proxy_inbound_tests tests/contracts/inbound/proxy/inbound.c)
            solaris_configure_target(solaris_proxy_inbound_tests)
            target_include_directories(solaris_proxy_inbound_tests PRIVATE src tests)
            target_link_libraries(solaris_proxy_inbound_tests PRIVATE solaris_test_core)
            add_test(NAME proxy_inbound_contract COMMAND "${Python3_EXECUTABLE}"
                "${PROJECT_SOURCE_DIR}/tests/support/inbound/proxy/inbound.py" "$<TARGET_FILE:solaris_proxy_inbound_tests>")
            set_tests_properties(proxy_inbound_contract PROPERTIES TIMEOUT 90)
            add_test(NAME websocket_inbound_contract COMMAND "${Python3_EXECUTABLE}"
                "${PROJECT_SOURCE_DIR}/tests/support/inbound/proxy/websocket.py" "$<TARGET_FILE:solaris_proxy_inbound_tests>")
            set_tests_properties(websocket_inbound_contract PROPERTIES TIMEOUT 90 SKIP_RETURN_CODE 77)
        endif()
        add_test(NAME llhttp_private_symbols COMMAND "${Python3_EXECUTABLE}"
            "${PROJECT_SOURCE_DIR}/scripts/verify/private_symbols.py"
            --nm "${CMAKE_NM}" "$<TARGET_FILE:solaris_llhttp>" --prefix solaris_llhttp)
    endif()
    add_executable(solaris_ip_packet_tests tests/contracts/inbound/tun/ip.c)
    solaris_configure_target(solaris_ip_packet_tests)
    target_include_directories(solaris_ip_packet_tests PRIVATE src tests)
    target_link_libraries(solaris_ip_packet_tests PRIVATE solaris_test_core)
    add_test(NAME ip_packet_contract COMMAND "${Python3_EXECUTABLE}"
        "${PROJECT_SOURCE_DIR}/tests/support/inbound/tun/ip.py" "$<TARGET_FILE:solaris_ip_packet_tests>")
    set_tests_properties(ip_packet_contract PROPERTIES TIMEOUT 30)
    if("tun" IN_LIST solaris_enabled_modules)
        if("tun_system" IN_LIST solaris_enabled_modules)
            add_executable(solaris_tun_system_tests tests/contracts/inbound/tun/system.c)
            solaris_configure_target(solaris_tun_system_tests)
            target_include_directories(solaris_tun_system_tests PRIVATE src tests)
            target_link_libraries(solaris_tun_system_tests PRIVATE solaris_test_core)
            add_test(NAME tun_system_contract COMMAND solaris_tun_system_tests)
            set_tests_properties(tun_system_contract PROPERTIES TIMEOUT 60)
        endif()
        add_executable(solaris_tun_wintun_tests tests/contracts/inbound/tun/device_wintun.c)
        solaris_configure_target(solaris_tun_wintun_tests)
        target_include_directories(solaris_tun_wintun_tests PRIVATE src tests)
        target_link_libraries(solaris_tun_wintun_tests PRIVATE solaris_test_core)
        add_test(NAME tun_wintun_contract COMMAND solaris_tun_wintun_tests)
        set_tests_properties(tun_wintun_contract PROPERTIES TIMEOUT 30)
        if(UNIX)
            add_executable(solaris_tun_fd_tests tests/contracts/inbound/tun/device_fd.c)
            solaris_configure_target(solaris_tun_fd_tests)
            target_include_directories(solaris_tun_fd_tests PRIVATE src tests)
            target_link_libraries(solaris_tun_fd_tests PRIVATE solaris_test_core)
            add_test(NAME tun_fd_contract COMMAND solaris_tun_fd_tests)
            set_tests_properties(tun_fd_contract PROPERTIES TIMEOUT 30)
        endif()
    endif()
    if("tun_lwip" IN_LIST solaris_enabled_modules)
        if(NOT MSVC)
            add_test(NAME lwip_private_symbols COMMAND "${Python3_EXECUTABLE}"
                "${PROJECT_SOURCE_DIR}/scripts/verify/private_symbols.py"
                --nm "${CMAKE_NM}" --prefix solaris_lwip "$<TARGET_FILE:solaris_lwip>")
        endif()
        if("direct" IN_LIST solaris_enabled_modules)
            add_executable(solaris_tun_inbound_tests tests/contracts/inbound/tun/inbound.c)
            solaris_configure_target(solaris_tun_inbound_tests)
            target_include_directories(solaris_tun_inbound_tests PRIVATE src tests)
            target_link_libraries(solaris_tun_inbound_tests PRIVATE solaris_test_core)
            add_test(NAME tun_inbound_contract COMMAND "${Python3_EXECUTABLE}"
                "${PROJECT_SOURCE_DIR}/tests/support/inbound/tun/inbound.py" "$<TARGET_FILE:solaris_tun_inbound_tests>")
            set_tests_properties(tun_inbound_contract PROPERTIES TIMEOUT 60)
        endif()
        add_executable(solaris_tun_lwip_tests tests/contracts/inbound/tun/lwip.c)
        solaris_configure_target(solaris_tun_lwip_tests)
        target_include_directories(solaris_tun_lwip_tests PRIVATE src tests)
        target_link_libraries(solaris_tun_lwip_tests PRIVATE solaris_test_core)
        add_test(NAME tun_lwip_contract COMMAND "${Python3_EXECUTABLE}"
            "${PROJECT_SOURCE_DIR}/tests/support/inbound/tun/lwip.py" "$<TARGET_FILE:solaris_tun_lwip_tests>")
        set_tests_properties(tun_lwip_contract PROPERTIES TIMEOUT 60)
    endif()
    if("tls" IN_LIST solaris_enabled_modules)
        add_executable(solaris_tls_patch_tests tests/contracts/transport/tls_patch.c)
        solaris_configure_target(solaris_tls_patch_tests)
        target_link_libraries(solaris_tls_patch_tests PRIVATE ssl crypto)
        add_test(NAME tls_patch_contract COMMAND "${Python3_EXECUTABLE}"
            "${PROJECT_SOURCE_DIR}/tests/support/transport/tls_patch.py" "$<TARGET_FILE:solaris_tls_patch_tests>")
        set_tests_properties(tls_patch_contract PROPERTIES TIMEOUT 30)
        add_executable(solaris_tls_record_patch_tests tests/contracts/transport/tls_record_patch.c)
        solaris_configure_target(solaris_tls_record_patch_tests)
        target_include_directories(solaris_tls_record_patch_tests PRIVATE tests)
        target_link_libraries(solaris_tls_record_patch_tests PRIVATE ssl crypto)
        add_test(NAME tls_record_patch_contract COMMAND "${Python3_EXECUTABLE}"
            "${PROJECT_SOURCE_DIR}/tests/support/transport/tls_patch.py" "$<TARGET_FILE:solaris_tls_record_patch_tests>")
        set_tests_properties(tls_record_patch_contract PROPERTIES TIMEOUT 30)
        add_executable(solaris_tls_key_patch_tests tests/contracts/transport/tls_key_patch.c)
        solaris_configure_target(solaris_tls_key_patch_tests)
        target_include_directories(solaris_tls_key_patch_tests PRIVATE tests)
        target_link_libraries(solaris_tls_key_patch_tests PRIVATE ssl crypto)
        add_test(NAME tls_key_patch_contract COMMAND "${Python3_EXECUTABLE}"
            "${PROJECT_SOURCE_DIR}/tests/support/transport/tls_patch.py" "$<TARGET_FILE:solaris_tls_key_patch_tests>")
        set_tests_properties(tls_key_patch_contract PROPERTIES TIMEOUT 30)
        add_executable(solaris_tls_resumption_patch_tests tests/contracts/transport/tls_resumption_patch.c)
        solaris_configure_target(solaris_tls_resumption_patch_tests)
        target_include_directories(solaris_tls_resumption_patch_tests PRIVATE tests)
        target_link_libraries(solaris_tls_resumption_patch_tests PRIVATE ssl crypto)
        add_test(NAME tls_resumption_patch_contract COMMAND "${Python3_EXECUTABLE}"
            "${PROJECT_SOURCE_DIR}/tests/support/transport/tls_patch.py" "$<TARGET_FILE:solaris_tls_resumption_patch_tests>")
        set_tests_properties(tls_resumption_patch_contract PROPERTIES TIMEOUT 30)
        add_executable(solaris_tls_policy_patch_tests tests/contracts/transport/tls_policy_patch.c)
        solaris_configure_target(solaris_tls_policy_patch_tests)
        target_link_libraries(solaris_tls_policy_patch_tests PRIVATE ssl crypto)
        add_test(NAME tls_policy_patch_contract COMMAND solaris_tls_policy_patch_tests)
        set_tests_properties(tls_policy_patch_contract PROPERTIES TIMEOUT 30)
        # The protocol algorithms here are test consumers of the private TLS
        # seams. They do not add unimplemented outbound/configuration entries.
        add_library(solaris_tls_fixture_blake3 STATIC
            third_party/blake3/blake3.c third_party/blake3/blake3_dispatch.c third_party/blake3/blake3_portable.c)
        set_target_properties(solaris_tls_fixture_blake3 PROPERTIES POSITION_INDEPENDENT_CODE ON)
        target_include_directories(solaris_tls_fixture_blake3 PUBLIC third_party/blake3)
        target_compile_definitions(solaris_tls_fixture_blake3 PRIVATE
            BLAKE3_NO_SSE2 BLAKE3_NO_SSE41 BLAKE3_NO_AVX2 BLAKE3_NO_AVX512 BLAKE3_USE_NEON=0)
        add_executable(solaris_tls_profiles_tests tests/contracts/transport/tls_profiles.c
            tests/support/transport/tls_profiles/profile.c tests/support/transport/tls_profiles/records.c)
        solaris_configure_target(solaris_tls_profiles_tests)
        target_include_directories(solaris_tls_profiles_tests PRIVATE tests)
        target_link_libraries(solaris_tls_profiles_tests PRIVATE ssl crypto uv_a solaris_tls_fixture_blake3)
        find_program(GO_EXECUTABLE go REQUIRED)
        set(solaris_tls_profiles_peer "${PROJECT_BINARY_DIR}/reference-tools/tls-profiles-peer${CMAKE_EXECUTABLE_SUFFIX}")
        add_custom_command(OUTPUT "${solaris_tls_profiles_peer}"
            COMMAND "${CMAKE_COMMAND}" -E make_directory "${PROJECT_BINARY_DIR}/reference-tools"
            COMMAND "${GO_EXECUTABLE}" build -mod=readonly -trimpath -o "${solaris_tls_profiles_peer}" .
            WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/support/transport/tls_profiles_peer"
            DEPENDS tests/support/transport/tls_profiles_peer/go.mod tests/support/transport/tls_profiles_peer/go.sum
                tests/support/transport/tls_profiles_peer/main.go VERBATIM)
        add_custom_target(solaris_tls_profiles_peer ALL DEPENDS "${solaris_tls_profiles_peer}")
        add_test(NAME tls_profiles_interop_contract COMMAND "${Python3_EXECUTABLE}"
            "${PROJECT_SOURCE_DIR}/tests/support/transport/tls_profiles.py" "$<TARGET_FILE:solaris_tls_profiles_tests>"
            --peer "${solaris_tls_profiles_peer}")
        set_tests_properties(tls_profiles_interop_contract PROPERTIES TIMEOUT 180)
        add_test(NAME tls_recipe_contract COMMAND "${Python3_EXECUTABLE}"
            "${PROJECT_SOURCE_DIR}/tests/contracts/transport/tls_recipe.py")
        set_tests_properties(tls_recipe_contract PROPERTIES TIMEOUT 30)
        add_executable(solaris_tls_tests tests/contracts/transport/tls.c)
        solaris_configure_target(solaris_tls_tests)
        target_include_directories(solaris_tls_tests PRIVATE src tests)
        target_link_libraries(solaris_tls_tests PRIVATE solaris_test_core)
        add_test(NAME tls_contract COMMAND "${Python3_EXECUTABLE}"
            "${PROJECT_SOURCE_DIR}/tests/support/transport/tls_peers.py" "$<TARGET_FILE:solaris_tls_tests>")
        set_tests_properties(tls_contract PROPERTIES TIMEOUT 30)
        add_executable(solaris_tls_raw_tests tests/contracts/transport/tls_raw.c)
        solaris_configure_target(solaris_tls_raw_tests)
        target_include_directories(solaris_tls_raw_tests PRIVATE src tests)
        target_link_libraries(solaris_tls_raw_tests PRIVATE solaris_test_core)
        add_test(NAME tls_raw_contract COMMAND "${Python3_EXECUTABLE}"
            "${PROJECT_SOURCE_DIR}/tests/support/transport/tls_raw.py" "$<TARGET_FILE:solaris_tls_raw_tests>")
        set_tests_properties(tls_raw_contract PROPERTIES TIMEOUT 45)
        add_test(NAME crypto_symbols COMMAND "${Python3_EXECUTABLE}"
            "${PROJECT_SOURCE_DIR}/scripts/verify/crypto_symbols.py"
            --go "${GO_EXECUTABLE}" --source "${solaris_bssl_SOURCE_DIR}"
            "$<TARGET_FILE:ssl>" "$<TARGET_FILE:crypto>")
        set_tests_properties(crypto_symbols PROPERTIES TIMEOUT 60)
    endif()
    if("vless" IN_LIST solaris_enabled_modules OR "shadowsocks" IN_LIST solaris_enabled_modules OR "anytls" IN_LIST solaris_enabled_modules OR "socks5" IN_LIST solaris_enabled_modules)
        string(JSON solaris_peer_version GET "${solaris_dependency_lock}" reference_sing_box version)
        set(SOLARIS_REFERENCE_PEER "" CACHE FILEPATH "Existing pinned sing-box test peer; empty builds the pinned source")
        if(NOT SOLARIS_REFERENCE_PEER)
            find_program(GO_EXECUTABLE go REQUIRED)
            set(solaris_peer "${PROJECT_BINARY_DIR}/reference-tools/sing-box${CMAKE_EXECUTABLE_SUFFIX}")
            add_custom_command(OUTPUT "${solaris_peer}"
                COMMAND "${CMAKE_COMMAND}" -E make_directory "${PROJECT_BINARY_DIR}/reference-tools"
                COMMAND "${CMAKE_COMMAND}" -E env "GOBIN=${PROJECT_BINARY_DIR}/reference-tools"
                    "${GO_EXECUTABLE}" install -trimpath
                    "-ldflags=-X github.com/sagernet/sing-box/constant.Version=${solaris_peer_version}"
                    "github.com/sagernet/sing-box/cmd/sing-box@${solaris_peer_version}"
                DEPENDS "${PROJECT_SOURCE_DIR}/dependencies/lock.json" VERBATIM)
            add_custom_target(solaris_reference_peer ALL DEPENDS "${solaris_peer}")
        else()
            set(solaris_peer "${SOLARIS_REFERENCE_PEER}")
        endif()
        if(TARGET solaris_runtime_proxy_tests AND SOLARIS_ENABLE_VLESS AND
           SOLARIS_ENABLE_SHADOWSOCKS AND SOLARIS_ENABLE_ANYTLS AND SOLARIS_ENABLE_SOCKS5)
            add_test(NAME runtime_protocol_contract COMMAND "${Python3_EXECUTABLE}"
                "${PROJECT_SOURCE_DIR}/tests/support/config/runtime_protocol.py"
                "$<TARGET_FILE:solaris_runtime_proxy_tests>"
                --peer "${solaris_peer}" --version "${solaris_peer_version}")
            set_tests_properties(runtime_protocol_contract PROPERTIES TIMEOUT 150)
        endif()
        add_executable(solaris_proxy_tests tests/contracts/outbound/stream.c)
        solaris_configure_target(solaris_proxy_tests)
        target_include_directories(solaris_proxy_tests PRIVATE src tests "${PROJECT_BINARY_DIR}/generated")
        target_link_libraries(solaris_proxy_tests PRIVATE solaris_test_core)
        add_executable(solaris_proxy_udp_tests tests/contracts/outbound/datagram.c)
        solaris_configure_target(solaris_proxy_udp_tests)
        target_include_directories(solaris_proxy_udp_tests PRIVATE src tests)
        target_link_libraries(solaris_proxy_udp_tests PRIVATE solaris_test_core)
        add_executable(solaris_proxy_association_tests tests/contracts/flow/udp/proxy.c)
        solaris_configure_target(solaris_proxy_association_tests)
        target_include_directories(solaris_proxy_association_tests PRIVATE src tests)
        target_link_libraries(solaris_proxy_association_tests PRIVATE solaris_test_core)
        if("socks5" IN_LIST solaris_enabled_modules)
            add_executable(solaris_socks5_codec_tests tests/contracts/outbound/socks5/codec.c)
            solaris_configure_target(solaris_socks5_codec_tests)
            target_include_directories(solaris_socks5_codec_tests PRIVATE src tests)
            target_link_libraries(solaris_socks5_codec_tests PRIVATE solaris_test_core)
            add_test(NAME socks5_codec_contract COMMAND "${Python3_EXECUTABLE}"
                "${PROJECT_SOURCE_DIR}/tests/support/outbound/socks5/codec.py" "$<TARGET_FILE:solaris_socks5_codec_tests>")
            set_tests_properties(socks5_codec_contract PROPERTIES TIMEOUT 30)
            add_executable(solaris_socks5_stream_tests tests/contracts/outbound/socks5/stream.c)
            solaris_configure_target(solaris_socks5_stream_tests)
            target_include_directories(solaris_socks5_stream_tests PRIVATE src tests)
            target_link_libraries(solaris_socks5_stream_tests PRIVATE solaris_test_core)
            add_test(NAME socks5_stream_contract COMMAND solaris_socks5_stream_tests)
            set_tests_properties(socks5_stream_contract PROPERTIES TIMEOUT 30)
            add_executable(solaris_socks5_udp_tests tests/contracts/outbound/socks5/udp.c)
            solaris_configure_target(solaris_socks5_udp_tests)
            target_include_directories(solaris_socks5_udp_tests PRIVATE src tests)
            target_link_libraries(solaris_socks5_udp_tests PRIVATE solaris_test_core)
            add_test(NAME socks5_udp_contract COMMAND solaris_socks5_udp_tests)
            set_tests_properties(socks5_udp_contract PROPERTIES TIMEOUT 30)
            add_test(NAME socks5_interop_contract COMMAND "${Python3_EXECUTABLE}"
                "${PROJECT_SOURCE_DIR}/tests/support/outbound/socks5/peers.py" "$<TARGET_FILE:solaris_proxy_tests>"
                --udp-client "$<TARGET_FILE:solaris_proxy_udp_tests>" --association-client "$<TARGET_FILE:solaris_proxy_association_tests>"
                --peer "${solaris_peer}" --version "${solaris_peer_version}")
            set_tests_properties(socks5_interop_contract PROPERTIES TIMEOUT 120)
        endif()
        if("vless" IN_LIST solaris_enabled_modules)
            string(JSON solaris_xray_version GET "${solaris_dependency_lock}" reference_xray version)
            string(JSON solaris_xray_module_version GET "${solaris_dependency_lock}" reference_xray module_version)
            string(JSON solaris_xray_revision GET "${solaris_dependency_lock}" reference_xray revision)
            set(SOLARIS_XRAY_REFERENCE_PEER "" CACHE FILEPATH "Existing pinned Xray test peer; empty builds pinned source")
            find_program(GO_EXECUTABLE go REQUIRED)
            if(NOT SOLARIS_XRAY_REFERENCE_PEER)
                set(solaris_xray_peer "${PROJECT_BINARY_DIR}/reference-tools/main${CMAKE_EXECUTABLE_SUFFIX}")
                add_custom_command(OUTPUT "${solaris_xray_peer}"
                    COMMAND "${CMAKE_COMMAND}" -E make_directory "${PROJECT_BINARY_DIR}/reference-tools"
                    COMMAND "${CMAKE_COMMAND}" -E env "GOBIN=${PROJECT_BINARY_DIR}/reference-tools"
                        "${GO_EXECUTABLE}" install -trimpath
                        "-ldflags=-X github.com/xtls/xray-core/core.build=${solaris_xray_revision}"
                        "github.com/xtls/xray-core/main@${solaris_xray_module_version}"
                    DEPENDS "${PROJECT_SOURCE_DIR}/dependencies/lock.json" VERBATIM)
                add_custom_target(solaris_xray_reference_peer ALL DEPENDS "${solaris_xray_peer}")
            else()
                set(solaris_xray_peer "${SOLARIS_XRAY_REFERENCE_PEER}")
            endif()
            set(solaris_vless_control "${PROJECT_BINARY_DIR}/reference-tools/vless-control${CMAKE_EXECUTABLE_SUFFIX}")
            add_custom_command(OUTPUT "${solaris_vless_control}"
                COMMAND "${CMAKE_COMMAND}" -E make_directory "${PROJECT_BINARY_DIR}/reference-tools"
                COMMAND "${GO_EXECUTABLE}" build -mod=readonly -trimpath -o "${solaris_vless_control}" .
                WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/support/outbound/vless/control"
                DEPENDS tests/support/outbound/vless/control/go.mod tests/support/outbound/vless/control/go.sum
                    tests/support/outbound/vless/control/main.go VERBATIM)
            add_custom_target(solaris_vless_control_peer ALL DEPENDS "${solaris_vless_control}")
            add_test(NAME proxy_interop_contract COMMAND "${Python3_EXECUTABLE}"
                "${PROJECT_SOURCE_DIR}/tests/support/outbound/vless_peers.py" "$<TARGET_FILE:solaris_proxy_tests>"
                --peer "${solaris_peer}" --version "${solaris_peer_version}")
            set_tests_properties(proxy_interop_contract PROPERTIES TIMEOUT 120)
            add_test(NAME xudp_interop_contract COMMAND "${Python3_EXECUTABLE}"
                "${PROJECT_SOURCE_DIR}/tests/support/outbound/vless/xudp.py" "$<TARGET_FILE:solaris_proxy_udp_tests>"
                --peer "${solaris_peer}" --version "${solaris_peer_version}" --xray "${solaris_xray_peer}"
                --xray-version "${solaris_xray_version}" --control "${solaris_vless_control}"
                --association-client "$<TARGET_FILE:solaris_proxy_association_tests>")
            set_tests_properties(xudp_interop_contract PROPERTIES TIMEOUT 120)
            foreach(kind recovery lifecycle)
                add_executable(solaris_vless_xudp_${kind}_tests tests/contracts/outbound/vless/xudp_${kind}.c)
                solaris_configure_target(solaris_vless_xudp_${kind}_tests)
                target_include_directories(solaris_vless_xudp_${kind}_tests PRIVATE src tests)
                target_link_libraries(solaris_vless_xudp_${kind}_tests PRIVATE solaris_test_core)
            endforeach()
            add_test(NAME xudp_recovery_contract COMMAND "${Python3_EXECUTABLE}"
                "${PROJECT_SOURCE_DIR}/tests/support/outbound/vless/xudp_recovery.py"
                "$<TARGET_FILE:solaris_vless_xudp_recovery_tests>" --xray "${solaris_xray_peer}"
                --xray-version "${solaris_xray_version}")
            add_test(NAME xudp_recovery_lifecycle_contract COMMAND solaris_vless_xudp_lifecycle_tests)
            set_tests_properties(xudp_recovery_contract PROPERTIES TIMEOUT 120)
            set_tests_properties(xudp_recovery_lifecycle_contract PROPERTIES TIMEOUT 30)
            set(solaris_encryption_control "${PROJECT_BINARY_DIR}/reference-tools/encryption-control${CMAKE_EXECUTABLE_SUFFIX}")
            add_test(NAME vless_encryption_interop_contract COMMAND "${Python3_EXECUTABLE}"
                "${PROJECT_SOURCE_DIR}/tests/support/outbound/vless/encryption.py" "$<TARGET_FILE:solaris_proxy_tests>"
                --peer "${solaris_xray_peer}" --version "${solaris_xray_version}"
                --udp-client "$<TARGET_FILE:solaris_proxy_udp_tests>" --association-client "$<TARGET_FILE:solaris_proxy_association_tests>"
                --control "${solaris_encryption_control}")
            set_tests_properties(vless_encryption_interop_contract PROPERTIES TIMEOUT 180)
            add_custom_command(OUTPUT "${solaris_encryption_control}"
                COMMAND "${CMAKE_COMMAND}" -E make_directory "${PROJECT_BINARY_DIR}/reference-tools"
                COMMAND "${GO_EXECUTABLE}" build -mod=readonly -trimpath -o "${solaris_encryption_control}" .
                WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/support/outbound/vless/encryption_control"
                DEPENDS tests/support/outbound/vless/encryption_control/go.mod tests/support/outbound/vless/encryption_control/go.sum
                    tests/support/outbound/vless/encryption_control/main.go tests/support/outbound/vless/encryption_control/probe.go
                    tests/support/outbound/vless/encryption_control/short.go VERBATIM)
            add_custom_target(solaris_encryption_control_peer ALL DEPENDS "${solaris_encryption_control}")
            add_executable(solaris_vless_encryption_tests tests/contracts/outbound/vless/encryption.c)
            solaris_configure_target(solaris_vless_encryption_tests)
            target_include_directories(solaris_vless_encryption_tests PRIVATE src tests)
            target_link_libraries(solaris_vless_encryption_tests PRIVATE solaris_test_core)
            add_test(NAME vless_encryption_codec_contract COMMAND "${Python3_EXECUTABLE}"
                "${PROJECT_SOURCE_DIR}/tests/support/outbound/vless/encryption_codec.py" "$<TARGET_FILE:solaris_vless_encryption_tests>"
                --control "${solaris_encryption_control}")
            set_tests_properties(vless_encryption_codec_contract PROPERTIES TIMEOUT 60)
            add_test(NAME vless_vision_interop_contract COMMAND "${Python3_EXECUTABLE}"
                "${PROJECT_SOURCE_DIR}/tests/support/outbound/vless/vision.py" "$<TARGET_FILE:solaris_proxy_tests>"
                --peer "${solaris_xray_peer}" --version "${solaris_xray_version}"
                --udp-client "$<TARGET_FILE:solaris_proxy_udp_tests>" --association-client "$<TARGET_FILE:solaris_proxy_association_tests>")
            set_tests_properties(vless_vision_interop_contract PROPERTIES TIMEOUT 120)
            add_executable(solaris_vless_vision_tests tests/contracts/outbound/vless/vision.c)
            solaris_configure_target(solaris_vless_vision_tests)
            target_include_directories(solaris_vless_vision_tests PRIVATE src tests)
            target_link_libraries(solaris_vless_vision_tests PRIVATE solaris_test_core)
            add_test(NAME vless_vision_codec_contract COMMAND "${Python3_EXECUTABLE}"
                "${PROJECT_SOURCE_DIR}/tests/support/outbound/vless/vision_codec.py" "$<TARGET_FILE:solaris_vless_vision_tests>")
            set_tests_properties(vless_vision_codec_contract PROPERTIES TIMEOUT 30)
        endif()
        if("anytls" IN_LIST solaris_enabled_modules)
            add_executable(solaris_anytls_codec_tests tests/contracts/outbound/anytls/codec.c)
            solaris_configure_target(solaris_anytls_codec_tests)
            target_include_directories(solaris_anytls_codec_tests PRIVATE src tests)
            target_link_libraries(solaris_anytls_codec_tests PRIVATE solaris_test_core)
            add_test(NAME anytls_codec_contract COMMAND "${Python3_EXECUTABLE}"
                "${PROJECT_SOURCE_DIR}/tests/support/outbound/anytls/codec.py" "$<TARGET_FILE:solaris_anytls_codec_tests>")
            set_tests_properties(anytls_codec_contract PROPERTIES TIMEOUT 30)
            add_test(NAME anytls_interop_contract COMMAND "${Python3_EXECUTABLE}"
                "${PROJECT_SOURCE_DIR}/tests/support/outbound/anytls/peers.py" "$<TARGET_FILE:solaris_proxy_tests>"
                --udp-client "$<TARGET_FILE:solaris_proxy_udp_tests>" --peer "${solaris_peer}" --version "${solaris_peer_version}"
                --association-client "$<TARGET_FILE:solaris_proxy_association_tests>")
            set_tests_properties(anytls_interop_contract PROPERTIES TIMEOUT 120)
        endif()
        if("shadowsocks" IN_LIST solaris_enabled_modules)
            add_test(NAME blake3_symbols COMMAND "${Python3_EXECUTABLE}"
                "${PROJECT_SOURCE_DIR}/scripts/verify/crypto_symbols.py"
                --go "${GO_EXECUTABLE}" --source "${solaris_bssl_SOURCE_DIR}" --prefix solaris_blake3
                "$<TARGET_FILE:solaris_blake3>")
            set_tests_properties(blake3_symbols PROPERTIES TIMEOUT 60)
            set(solaris_ss_control "${PROJECT_BINARY_DIR}/reference-tools/ss-control${CMAKE_EXECUTABLE_SUFFIX}")
            add_custom_command(OUTPUT "${solaris_ss_control}"
                COMMAND "${CMAKE_COMMAND}" -E make_directory "${PROJECT_BINARY_DIR}/reference-tools"
                COMMAND "${GO_EXECUTABLE}" build -mod=readonly -trimpath -o "${solaris_ss_control}" .
                WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/support/outbound/shadowsocks/control"
                DEPENDS tests/support/outbound/shadowsocks/control/go.mod tests/support/outbound/shadowsocks/control/go.sum tests/support/outbound/shadowsocks/control/main.go tests/support/outbound/shadowsocks/control/fixtures.go
                VERBATIM)
            add_custom_target(solaris_ss_control_peer ALL DEPENDS "${solaris_ss_control}")
            add_executable(solaris_ss_codec_tests tests/contracts/outbound/shadowsocks/codec.c)
            solaris_configure_target(solaris_ss_codec_tests)
            target_include_directories(solaris_ss_codec_tests PRIVATE src tests)
            target_link_libraries(solaris_ss_codec_tests PRIVATE solaris_test_core)
            add_test(NAME shadowsocks_codec_contract COMMAND "${Python3_EXECUTABLE}"
                "${PROJECT_SOURCE_DIR}/tests/support/outbound/shadowsocks/codec.py" "${solaris_ss_control}" "$<TARGET_FILE:solaris_ss_codec_tests>")
            set_tests_properties(shadowsocks_codec_contract PROPERTIES TIMEOUT 30)
            add_test(NAME shadowsocks_interop_contract COMMAND "${Python3_EXECUTABLE}"
                "${PROJECT_SOURCE_DIR}/tests/support/outbound/shadowsocks/peers.py" "$<TARGET_FILE:solaris_proxy_tests>"
                --udp-client "$<TARGET_FILE:solaris_proxy_udp_tests>" --control "${solaris_ss_control}"
                --peer "${solaris_peer}" --version "${solaris_peer_version}"
                --association-client "$<TARGET_FILE:solaris_proxy_association_tests>")
            set_tests_properties(shadowsocks_interop_contract PROPERTIES TIMEOUT 120)
        endif()
    endif()
    if(TARGET solaris_runtime_proxy_tests AND SOLARIS_ENABLE_VLESS AND SOLARIS_ENABLE_SHADOWSOCKS AND SOLARIS_ENABLE_TLS)
        add_test(NAME runtime_advanced_contract COMMAND "${Python3_EXECUTABLE}"
            "${PROJECT_SOURCE_DIR}/tests/support/config/runtime_advanced.py" "$<TARGET_FILE:solaris_runtime_proxy_tests>"
            --xray "${solaris_xray_peer}" --xray-version "${solaris_xray_version}"
            --peer "${solaris_peer}" --version "${solaris_peer_version}" --control "${solaris_vless_control}"
            --encryption-control "${solaris_encryption_control}")
        set_tests_properties(runtime_advanced_contract PROPERTIES TIMEOUT 300)
    endif()
    if("tls" IN_LIST solaris_enabled_modules AND solaris_outbound_count GREATER 0)
        add_executable(solaris_proxy_probe_tests tests/contracts/flow/proxy_probe.c)
        solaris_configure_target(solaris_proxy_probe_tests)
        target_include_directories(solaris_proxy_probe_tests PRIVATE src tests)
        target_link_libraries(solaris_proxy_probe_tests PRIVATE solaris_test_core)
        set(solaris_probe_peers)
        if(DEFINED solaris_peer)
            list(APPEND solaris_probe_peers --peer "${solaris_peer}" --version "${solaris_peer_version}")
        endif()
        if(DEFINED solaris_xray_peer)
            list(APPEND solaris_probe_peers --xray "${solaris_xray_peer}" --xray-version "${solaris_xray_version}")
        endif()
        add_test(NAME proxy_probe_contract COMMAND "${Python3_EXECUTABLE}"
            "${PROJECT_SOURCE_DIR}/tests/support/flow/probe_peers.py" "$<TARGET_FILE:solaris_proxy_probe_tests>"
            ${solaris_probe_peers} --types ${solaris_enabled_modules})
        set_tests_properties(proxy_probe_contract PROPERTIES TIMEOUT 120)
    endif()
    if(NOT BUILD_SHARED_LIBS AND NOT MSVC)
        add_test(NAME module_symbols COMMAND "${Python3_EXECUTABLE}"
            "${PROJECT_SOURCE_DIR}/scripts/verify/modules.py"
            --library "$<TARGET_FILE:solaris_core>" --manifest "${PROJECT_SOURCE_DIR}/modules/builtin.json"
            --nm "${CMAKE_NM}" --enabled ${solaris_enabled_modules})
    endif()
    if(NOT MSVC)
        add_test(NAME module_linked_symbols COMMAND "${Python3_EXECUTABLE}"
            "${PROJECT_SOURCE_DIR}/scripts/verify/modules.py"
            --library "$<TARGET_FILE:solaris_module_tests>" --manifest "${PROJECT_SOURCE_DIR}/modules/builtin.json"
            --nm "${CMAKE_NM}" --enabled ${solaris_enabled_modules})
    endif()

    if("direct" IN_LIST solaris_enabled_modules AND "block" IN_LIST solaris_enabled_modules)
    add_executable(solaris_io_tests tests/contracts/io/channel.c)
    solaris_configure_target(solaris_io_tests)
    target_include_directories(solaris_io_tests PRIVATE src tests)
    target_link_libraries(solaris_io_tests PRIVATE solaris_test_core)
    add_test(NAME io_contract COMMAND "${Python3_EXECUTABLE}"
        "${PROJECT_SOURCE_DIR}/tests/support/io/peers.py" "$<TARGET_FILE:solaris_io_tests>")
    set_tests_properties(io_contract PROPERTIES TIMEOUT 45)
    endif()
    if("direct" IN_LIST solaris_enabled_modules)
        add_executable(solaris_udp_association_tests tests/contracts/flow/udp/association.c)
        solaris_configure_target(solaris_udp_association_tests)
        target_include_directories(solaris_udp_association_tests PRIVATE src tests)
        target_link_libraries(solaris_udp_association_tests PRIVATE solaris_test_core)
        add_test(NAME udp_association_contract COMMAND "${Python3_EXECUTABLE}"
            "${PROJECT_SOURCE_DIR}/tests/support/flow/udp_peers.py" "$<TARGET_FILE:solaris_udp_association_tests>")
        set_tests_properties(udp_association_contract PROPERTIES TIMEOUT 45)
    endif()

    if(BUILD_SHARED_LIBS)
        add_test(NAME sdk_exports COMMAND "${Python3_EXECUTABLE}"
            "${PROJECT_SOURCE_DIR}/scripts/verify/exports.py"
            --library "$<TARGET_FILE:solaris_core>"
            --expected "${PROJECT_BINARY_DIR}/generated/exports.txt"
            --nm "${CMAKE_NM}" --linker "${CMAKE_LINKER}")
    endif()
    set(solaris_consumer_extra)
    if(SOLARIS_ENABLE_PROXY_INBOUND AND SOLARIS_ENABLE_DIRECT AND SOLARIS_ENABLE_BLOCK)
        list(APPEND solaris_consumer_extra --runtime-proxy)
    endif()
    if(TEST runtime_protocol_contract OR TEST runtime_advanced_contract)
        list(APPEND solaris_consumer_extra --peer "${solaris_peer}" --peer-version "${solaris_peer_version}")
    endif()
    if(TEST runtime_protocol_contract)
        list(APPEND solaris_consumer_extra --runtime-protocols)
    endif()
    if(TEST runtime_advanced_contract)
        list(APPEND solaris_consumer_extra --runtime-advanced --xray "${solaris_xray_peer}" --xray-version "${solaris_xray_version}"
            --vless-control "${solaris_vless_control}" --encryption-control "${solaris_encryption_control}")
    endif()
    add_test(NAME installed_consumer COMMAND "${Python3_EXECUTABLE}"
        "${PROJECT_SOURCE_DIR}/scripts/verify/install.py"
        --build "${PROJECT_BINARY_DIR}" --source "${PROJECT_SOURCE_DIR}/tests/consumer"
        --config "$<CONFIG>" --cmake "${CMAKE_COMMAND}" --compiler "${CMAKE_C_COMPILER}" ${solaris_consumer_extra})
    set_tests_properties(installed_consumer PROPERTIES TIMEOUT 600 RUN_SERIAL TRUE)
    include(cmake/SolarisAcceptance.cmake)
endif()

if(SOLARIS_BUILD_FUZZERS)
    if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang" OR CMAKE_CROSSCOMPILING OR SOLARIS_SANITIZER STREQUAL "thread")
        message(FATAL_ERROR "Fuzz targets require a native Clang toolchain with libFuzzer and no ThreadSanitizer")
    endif()
    add_library(solaris_fuzz_core STATIC ${SOLARIS_SOURCES})
    solaris_configure_target(solaris_fuzz_core)
    target_include_directories(solaris_fuzz_core PUBLIC include PRIVATE src "${PROJECT_BINARY_DIR}/generated")
    target_compile_options(solaris_fuzz_core PRIVATE -fsanitize=fuzzer-no-link,address,undefined -fno-omit-frame-pointer)
    set(solaris_fuzz_libraries ${SOLARIS_PRIVATE_LIBRARIES})
    if(TARGET solaris_yaml)
        solaris_add_yaml_library(solaris_fuzz_yaml)
        target_compile_options(solaris_fuzz_yaml PRIVATE
            -fsanitize=fuzzer-no-link,address,undefined -fno-omit-frame-pointer)
        list(REMOVE_ITEM solaris_fuzz_libraries solaris_yaml)
        list(APPEND solaris_fuzz_libraries solaris_fuzz_yaml)
    endif()
    if(TARGET solaris_llhttp)
        get_target_property(solaris_llhttp_sources solaris_llhttp SOURCES)
        add_library(solaris_fuzz_llhttp STATIC ${solaris_llhttp_sources})
        target_include_directories(solaris_fuzz_llhttp PUBLIC
            "${solaris_llhttp_include_dir}" "${PROJECT_SOURCE_DIR}/third_party/llhttp")
        target_compile_options(solaris_fuzz_llhttp PRIVATE
            -include "${PROJECT_SOURCE_DIR}/third_party/llhttp/solaris_llhttp_symbols.h"
            -fsanitize=fuzzer-no-link,address,undefined -fno-omit-frame-pointer)
        list(REMOVE_ITEM solaris_fuzz_libraries solaris_llhttp)
        list(APPEND solaris_fuzz_libraries solaris_fuzz_llhttp)
    endif()
    target_link_libraries(solaris_fuzz_core PUBLIC ${solaris_fuzz_libraries})
    add_executable(solaris_parser_fuzz tests/fuzz/parsers.c)
    solaris_configure_target(solaris_parser_fuzz)
    target_include_directories(solaris_parser_fuzz PRIVATE src "${PROJECT_BINARY_DIR}/generated")
    target_compile_options(solaris_parser_fuzz PRIVATE -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer)
    target_link_options(solaris_parser_fuzz PRIVATE -fsanitize=fuzzer,address,undefined)
    target_link_libraries(solaris_parser_fuzz PRIVATE solaris_fuzz_core)
    add_executable(solaris_config_fuzz tests/fuzz/config.c)
    solaris_configure_target(solaris_config_fuzz)
    target_compile_options(solaris_config_fuzz PRIVATE -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer)
    target_link_options(solaris_config_fuzz PRIVATE -fsanitize=fuzzer,address,undefined)
    target_link_libraries(solaris_config_fuzz PRIVATE solaris_fuzz_core)
endif()

install(TARGETS solaris_core EXPORT SolarisTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
if(NOT BUILD_SHARED_LIBS)
    install(TARGETS ${SOLARIS_PRIVATE_LIBRARIES} EXPORT SolarisTargets ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
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
if("boringssl" IN_LIST SOLARIS_DEPENDENCIES)
    install(FILES "${solaris_bssl_SOURCE_DIR}/LICENSE"
        DESTINATION ${CMAKE_INSTALL_DATADIR}/Solaris/licenses/boringssl)
endif()
install(FILES THIRD_PARTY_NOTICES.md dependencies/lock.json
    DESTINATION ${CMAKE_INSTALL_DATADIR}/Solaris)
install(FILES examples/config_host.c examples/config_host.yaml examples/config_host_reload.yaml
    examples/config_host/CMakeLists.txt examples/config_host/README.md
    DESTINATION ${CMAKE_INSTALL_DATADIR}/Solaris/examples/config-host)

if("lwip" IN_LIST SOLARIS_DEPENDENCIES)
    install(FILES "${solaris_lwip_SOURCE_DIR}/COPYING"
        DESTINATION ${CMAKE_INSTALL_DATADIR}/Solaris/licenses/lwip)
endif()

if("blake3" IN_LIST SOLARIS_DEPENDENCIES)
    install(FILES third_party/blake3/LICENSE_A2 third_party/blake3/LICENSE_CC0
        DESTINATION ${CMAKE_INSTALL_DATADIR}/Solaris/licenses/blake3)
endif()

if(TARGET solaris_llhttp)
    install(FILES "${solaris_llhttp_SOURCE_DIR}/LICENSE-MIT" DESTINATION "${CMAKE_INSTALL_DATADIR}/Solaris/licenses/llhttp")
endif()
if(TARGET solaris_yaml)
    install(FILES "${solaris_yaml_SOURCE_DIR}/License" DESTINATION "${CMAKE_INSTALL_DATADIR}/Solaris/licenses/libyaml")
endif()
