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
endif()

if(SOLARIS_BUILD_TESTS AND BUILD_TESTING AND NOT CMAKE_CROSSCOMPILING)
    find_package(Python3 3.9 REQUIRED COMPONENTS Interpreter)
    add_executable(solaris_sdk_smoke tests/sdk/smoke.c)
    solaris_configure_target(solaris_sdk_smoke)
    target_link_libraries(solaris_sdk_smoke PRIVATE Solaris::core)
    add_test(NAME sdk_smoke COMMAND solaris_sdk_smoke)

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
    add_executable(solaris_probe_tests tests/contracts/flow/probe.c)
    solaris_configure_target(solaris_probe_tests)
    target_include_directories(solaris_probe_tests PRIVATE src tests)
    target_link_libraries(solaris_probe_tests PRIVATE solaris_test_core)
    add_test(NAME probe_contract COMMAND solaris_probe_tests)
    set_tests_properties(probe_contract PROPERTIES TIMEOUT 30)
    add_executable(solaris_session_tests tests/contracts/transport/session.c)
    solaris_configure_target(solaris_session_tests)
    target_include_directories(solaris_session_tests PRIVATE src tests)
    target_link_libraries(solaris_session_tests PRIVATE solaris_test_core)
    add_test(NAME session_contract COMMAND solaris_session_tests)
    set_tests_properties(session_contract PROPERTIES TIMEOUT 30)
    if("tls" IN_LIST solaris_enabled_modules)
        add_executable(solaris_tls_patch_tests tests/contracts/transport/tls_patch.c)
        solaris_configure_target(solaris_tls_patch_tests)
        target_link_libraries(solaris_tls_patch_tests PRIVATE ssl crypto)
        add_test(NAME tls_patch_contract COMMAND "${Python3_EXECUTABLE}"
            "${PROJECT_SOURCE_DIR}/tests/support/transport/tls_patch.py" "$<TARGET_FILE:solaris_tls_patch_tests>")
        set_tests_properties(tls_patch_contract PROPERTIES TIMEOUT 30)
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
                    tests/support/outbound/vless/encryption_control/main.go tests/support/outbound/vless/encryption_control/probe.go VERBATIM)
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
    add_test(NAME installed_consumer COMMAND "${Python3_EXECUTABLE}"
        "${PROJECT_SOURCE_DIR}/scripts/verify/install.py"
        --build "${PROJECT_BINARY_DIR}" --source "${PROJECT_SOURCE_DIR}/tests/consumer"
        --config "$<CONFIG>" --cmake "${CMAKE_COMMAND}" --compiler "${CMAKE_C_COMPILER}")
    set_tests_properties(installed_consumer PROPERTIES TIMEOUT 120 RUN_SERIAL TRUE)
endif()

if(SOLARIS_BUILD_FUZZERS)
    if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang" OR CMAKE_CROSSCOMPILING OR SOLARIS_SANITIZER STREQUAL "thread")
        message(FATAL_ERROR "Fuzz targets require a native Clang toolchain with libFuzzer and no ThreadSanitizer")
    endif()
    add_library(solaris_fuzz_core STATIC ${SOLARIS_SOURCES})
    solaris_configure_target(solaris_fuzz_core)
    target_include_directories(solaris_fuzz_core PUBLIC include PRIVATE src "${PROJECT_BINARY_DIR}/generated")
    target_compile_options(solaris_fuzz_core PRIVATE -fsanitize=fuzzer-no-link,address,undefined -fno-omit-frame-pointer)
    target_link_libraries(solaris_fuzz_core PUBLIC ${SOLARIS_PRIVATE_LIBRARIES})
    add_executable(solaris_parser_fuzz tests/fuzz/parsers.c)
    solaris_configure_target(solaris_parser_fuzz)
    target_include_directories(solaris_parser_fuzz PRIVATE src "${PROJECT_BINARY_DIR}/generated")
    target_compile_options(solaris_parser_fuzz PRIVATE -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer)
    target_link_options(solaris_parser_fuzz PRIVATE -fsanitize=fuzzer,address,undefined)
    target_link_libraries(solaris_parser_fuzz PRIVATE solaris_fuzz_core)
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

if("blake3" IN_LIST SOLARIS_DEPENDENCIES)
    install(FILES third_party/blake3/LICENSE_A2 third_party/blake3/LICENSE_CC0
        DESTINATION ${CMAKE_INSTALL_DATADIR}/Solaris/licenses/blake3)
endif()
