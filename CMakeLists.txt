cmake_minimum_required(VERSION 3.20)

project(solaris_core VERSION 0.1.0 LANGUAGES C CXX ASM)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
if(NOT WIN32)
    add_compile_definitions(_POSIX_C_SOURCE=200809L _DEFAULT_SOURCE)
endif()

if(MSVC)
    set(APROXY_WARNING_OPTIONS /W4 /WX)
else()
    set(APROXY_WARNING_OPTIONS -Wall -Wextra -Werror -pedantic)
endif()

option(APROXY_BLAKE3_SIMD "Enable official BLAKE3 SIMD backends" ON)
option(APROXY_ENABLE_REALITY
    "Enable REALITY client support (requires the bundled BoringSSL patch)" ON)
option(APROXY_ENABLE_TUN "Build the lwIP-based TUN inbound" ON)
option(APROXY_FETCH_ANDROID_DEPS
    "Fetch pinned static dependencies when cross-compiling for Android"
    ${ANDROID})
option(APROXY_FETCH_APPLE_DEPS
    "Fetch pinned static dependencies when cross-compiling for Apple"
    ${APPLE})
option(APROXY_FETCH_WINDOWS_DEPS
    "Fetch pinned static dependencies when building for Windows"
    ${WIN32})
set(APROXY_BORINGSSL_ROOT "$ENV{APROXY_BORINGSSL_ROOT}" CACHE PATH
    "BoringSSL installation root")

if(NOT APROXY_BORINGSSL_ROOT)
    message(FATAL_ERROR
        "APROXY_BORINGSSL_ROOT is required; pass -DAPROXY_BORINGSSL_ROOT=/path/to/boringssl")
endif()
if((ANDROID AND APROXY_FETCH_ANDROID_DEPS) OR
   (APPLE AND APROXY_FETCH_APPLE_DEPS) OR
   (WIN32 AND APROXY_FETCH_WINDOWS_DEPS))
    include(cmake/MobileDependencies.cmake)
    aproxy_configure_mobile_dependencies()
    set(APROXY_LIBUV_TARGET uv_a)
    set(APROXY_PCRE2_TARGET pcre2-8-static)
    set(APROXY_NGHTTP2_TARGET nghttp2_static)
    set(APROXY_LLHTTP_TARGET llhttp_static)
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(LIBUV REQUIRED IMPORTED_TARGET libuv>=1.50.0)
    pkg_check_modules(PCRE2 REQUIRED IMPORTED_TARGET libpcre2-8)
    pkg_check_modules(NGHTTP2 REQUIRED IMPORTED_TARGET libnghttp2)
    pkg_check_modules(LLHTTP REQUIRED IMPORTED_TARGET libllhttp)
    set(APROXY_LIBUV_TARGET PkgConfig::LIBUV)
    set(APROXY_PCRE2_TARGET PkgConfig::PCRE2)
    set(APROXY_NGHTTP2_TARGET PkgConfig::NGHTTP2)
    set(APROXY_LLHTTP_TARGET PkgConfig::LLHTTP)
    if(APROXY_ENABLE_TUN)
        pkg_check_modules(LWIP REQUIRED IMPORTED_TARGET lwip)
        set(APROXY_LWIP_TARGET PkgConfig::LWIP)
    endif()
endif()
find_package(Threads REQUIRED)

if(APROXY_ENABLE_REALITY)
    include(CheckCSourceCompiles)
    set(CMAKE_REQUIRED_INCLUDES "${APROXY_BORINGSSL_ROOT}/include")
    check_c_source_compiles(
        "#include <openssl/ssl.h>\n#ifndef BORINGSSL_HAS_REALITY_CLIENT\n#error missing aproxy-core REALITY patch\n#endif\nint main(void) { return 0; }"
        APROXY_BORINGSSL_HAS_REALITY_CLIENT)
    unset(CMAKE_REQUIRED_INCLUDES)
    if(NOT APROXY_BORINGSSL_HAS_REALITY_CLIENT)
        message(FATAL_ERROR
            "REALITY requires the patched BoringSSL built by the mobile scripts; otherwise configure -DAPROXY_ENABLE_REALITY=OFF")
    endif()
endif()

if(WIN32)
    set(APROXY_BORINGSSL_CRYPTO_LIBRARY
        "${APROXY_BORINGSSL_ROOT}/lib/crypto.lib")
    set(APROXY_BORINGSSL_SSL_LIBRARY
        "${APROXY_BORINGSSL_ROOT}/lib/ssl.lib")
else()
    set(APROXY_BORINGSSL_CRYPTO_LIBRARY
        "${APROXY_BORINGSSL_ROOT}/lib/libcrypto.a")
    set(APROXY_BORINGSSL_SSL_LIBRARY
        "${APROXY_BORINGSSL_ROOT}/lib/libssl.a")
endif()

add_library(BoringSSL::crypto STATIC IMPORTED)
set_target_properties(BoringSSL::crypto PROPERTIES
    IMPORTED_LOCATION "${APROXY_BORINGSSL_CRYPTO_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${APROXY_BORINGSSL_ROOT}/include")

add_library(BoringSSL::ssl STATIC IMPORTED)
set_target_properties(BoringSSL::ssl PROPERTIES
    IMPORTED_LOCATION "${APROXY_BORINGSSL_SSL_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${APROXY_BORINGSSL_ROOT}/include"
    INTERFACE_LINK_LIBRARIES BoringSSL::crypto)

set(APROXY_CORE_SOURCES
    src/address.c
    src/buffer.c
    src/bufpool.c
    src/filemap.c
    src/framework/memory.c
    src/framework/packet_flow.c
    src/framework/packet_session.c
    src/framework/packet_udp_relay.c
    src/ring.c
    src/uot.c
    src/vmess_addr.c
    src/xudp.c
    src/framework/direct_outbound.c
    src/framework/block_outbound.c
    src/framework/dns.c
    src/framework/geoip.c
    src/framework/geosite.c
    src/framework/inbound.c
    src/framework/outbound.c
    src/framework/outbound_group.c
    src/framework/protocol.c
    src/framework/router.c
    src/framework/sniffer.c
    src/framework/socket_protect.c
    src/framework/stream.c
    src/framework/transport.c
    src/inbound/socks5.c)
if(APROXY_ENABLE_TUN)
    list(APPEND APROXY_CORE_SOURCES
        src/framework/packet_tcp_relay.c
        src/inbound/tun.c)
endif()
add_library(aproxy_core STATIC ${APROXY_CORE_SOURCES})
target_include_directories(aproxy_core PUBLIC include PRIVATE src src/framework)
target_compile_options(aproxy_core PRIVATE ${APROXY_WARNING_OPTIONS})
target_link_libraries(aproxy_core PUBLIC
    ${APROXY_LIBUV_TARGET}
    ${APROXY_PCRE2_TARGET}
    BoringSSL::crypto
    Threads::Threads)
if(APROXY_ENABLE_TUN)
    target_compile_definitions(aproxy_core PUBLIC APROXY_ENABLE_TUN=1)
    target_link_libraries(aproxy_core PUBLIC ${APROXY_LWIP_TARGET})
endif()

add_library(anytls_protocol STATIC
    src/frame.c
    src/md5.c
    src/padding.c)
target_include_directories(anytls_protocol PUBLIC include)
target_compile_options(anytls_protocol PRIVATE ${APROXY_WARNING_OPTIONS})

add_library(vless_protocol STATIC
    src/vless_protocol.c
    src/vless_encryption.c
    src/vless_vision.c)
target_include_directories(vless_protocol PUBLIC include PRIVATE src)
target_compile_options(vless_protocol PRIVATE ${APROXY_WARNING_OPTIONS})
target_link_libraries(vless_protocol
    PUBLIC aproxy_core BoringSSL::crypto blake3)

add_library(aproxy_tls STATIC src/tls_uv.c src/reality.c)
target_include_directories(aproxy_tls PUBLIC include PRIVATE src)
target_compile_options(aproxy_tls PRIVATE ${APROXY_WARNING_OPTIONS})
target_link_libraries(aproxy_tls
    PUBLIC aproxy_core BoringSSL::ssl BoringSSL::crypto Threads::Threads
           ${CMAKE_DL_LIBS})
set_target_properties(aproxy_tls PROPERTIES LINKER_LANGUAGE CXX)

add_library(aproxy_xhttp STATIC
    src/xhttp_config.c
    src/xhttp_client.c
    src/xhttp_h1.c
    src/xhttp_request.c)
target_include_directories(aproxy_xhttp PUBLIC include PRIVATE src src/framework)
target_compile_options(aproxy_xhttp PRIVATE ${APROXY_WARNING_OPTIONS})
target_link_libraries(aproxy_xhttp
    PUBLIC aproxy_core aproxy_tls ${APROXY_NGHTTP2_TARGET}
           ${APROXY_LLHTTP_TARGET}
           BoringSSL::crypto)
set_target_properties(aproxy_xhttp PROPERTIES LINKER_LANGUAGE CXX)

add_library(anytls_client STATIC
    src/anytls_outbound.c
    src/client.c)
target_include_directories(anytls_client PUBLIC include PRIVATE src src/framework)
target_compile_options(anytls_client PRIVATE ${APROXY_WARNING_OPTIONS})
target_link_libraries(anytls_client
    PUBLIC
        aproxy_core
        aproxy_tls
        anytls_protocol
        BoringSSL::ssl
        BoringSSL::crypto
        Threads::Threads
        ${CMAKE_DL_LIBS})
set_target_properties(anytls_client PROPERTIES LINKER_LANGUAGE CXX)

add_library(vless_client STATIC src/vless_outbound.c)
target_include_directories(vless_client PUBLIC include PRIVATE src src/framework)
target_compile_options(vless_client PRIVATE ${APROXY_WARNING_OPTIONS})
target_link_libraries(vless_client
    PUBLIC aproxy_core aproxy_tls aproxy_xhttp vless_protocol
           BoringSSL::crypto)
set_target_properties(vless_client PROPERTIES LINKER_LANGUAGE CXX)

set(APROXY_BLAKE3_SOURCES
    third_party/blake3/blake3.c
    third_party/blake3/blake3_dispatch.c
    third_party/blake3/blake3_portable.c)
set(APROXY_BLAKE3_DEFINITIONS)
set(APROXY_BLAKE3_ARCH "${CMAKE_SYSTEM_PROCESSOR}")
if(ANDROID)
    if(ANDROID_ABI STREQUAL "arm64-v8a")
        set(APROXY_BLAKE3_ARCH "arm64")
    elseif(ANDROID_ABI STREQUAL "armeabi-v7a")
        set(APROXY_BLAKE3_ARCH "armv7")
    elseif(ANDROID_ABI STREQUAL "x86")
        set(APROXY_BLAKE3_ARCH "x86")
    elseif(ANDROID_ABI STREQUAL "x86_64")
        set(APROXY_BLAKE3_ARCH "x86_64")
    else()
        message(FATAL_ERROR "Unsupported Android ABI for BLAKE3: ${ANDROID_ABI}")
    endif()
elseif(APPLE AND CMAKE_OSX_ARCHITECTURES)
    list(LENGTH CMAKE_OSX_ARCHITECTURES APROXY_APPLE_ARCH_COUNT)
    if(NOT APROXY_APPLE_ARCH_COUNT EQUAL 1)
        message(FATAL_ERROR
            "Build each Apple architecture separately before creating a universal library")
    endif()
    set(APROXY_BLAKE3_ARCH "${CMAKE_OSX_ARCHITECTURES}")
endif()
string(TOLOWER "${APROXY_BLAKE3_ARCH}" APROXY_BLAKE3_ARCH)

set(APROXY_BLAKE3_BACKEND "portable")
if(APROXY_BLAKE3_SIMD AND UNIX AND
   APROXY_BLAKE3_ARCH MATCHES "^(x86_64|amd64)$")
    list(APPEND APROXY_BLAKE3_SOURCES
        third_party/blake3/blake3_sse2_x86-64_unix.S
        third_party/blake3/blake3_sse41_x86-64_unix.S
        third_party/blake3/blake3_avx2_x86-64_unix.S
        third_party/blake3/blake3_avx512_x86-64_unix.S)
    list(APPEND APROXY_BLAKE3_DEFINITIONS BLAKE3_USE_NEON=0)
    set(APROXY_BLAKE3_BACKEND "x86_64 assembly")
elseif(APROXY_BLAKE3_SIMD AND
       (APROXY_BLAKE3_ARCH MATCHES "^(x86|i[3-6]86)$" OR
        (NOT UNIX AND APROXY_BLAKE3_ARCH MATCHES "^(x86_64|amd64)$")))
    list(APPEND APROXY_BLAKE3_SOURCES
        third_party/blake3/blake3_sse2.c
        third_party/blake3/blake3_sse41.c
        third_party/blake3/blake3_avx2.c
        third_party/blake3/blake3_avx512.c)
    if(MSVC)
        set_property(SOURCE third_party/blake3/blake3_avx2.c APPEND PROPERTY
            COMPILE_OPTIONS /arch:AVX2)
        set_property(SOURCE third_party/blake3/blake3_avx512.c APPEND PROPERTY
            COMPILE_OPTIONS /arch:AVX512)
    else()
        set_property(SOURCE third_party/blake3/blake3_sse2.c APPEND PROPERTY
            COMPILE_OPTIONS -msse2)
        set_property(SOURCE third_party/blake3/blake3_sse41.c APPEND PROPERTY
            COMPILE_OPTIONS -msse4.1)
        set_property(SOURCE third_party/blake3/blake3_avx2.c APPEND PROPERTY
            COMPILE_OPTIONS -mavx2)
        set_property(SOURCE third_party/blake3/blake3_avx512.c APPEND PROPERTY
            COMPILE_OPTIONS -mavx512f -mavx512vl)
    endif()
    list(APPEND APROXY_BLAKE3_DEFINITIONS BLAKE3_USE_NEON=0)
    set(APROXY_BLAKE3_BACKEND "x86 intrinsics")
elseif(APROXY_BLAKE3_SIMD AND
       APROXY_BLAKE3_ARCH MATCHES "^(aarch64|arm64)$")
    list(APPEND APROXY_BLAKE3_SOURCES third_party/blake3/blake3_neon.c)
    list(APPEND APROXY_BLAKE3_DEFINITIONS
        BLAKE3_USE_NEON=1
        BLAKE3_NO_SSE2
        BLAKE3_NO_SSE41
        BLAKE3_NO_AVX2
        BLAKE3_NO_AVX512)
    set(APROXY_BLAKE3_BACKEND "NEON intrinsics")
elseif(APROXY_BLAKE3_SIMD AND APROXY_BLAKE3_ARCH MATCHES "^armv7")
    list(APPEND APROXY_BLAKE3_SOURCES third_party/blake3/blake3_neon.c)
    set_property(SOURCE third_party/blake3/blake3_neon.c APPEND PROPERTY
        COMPILE_OPTIONS -mfpu=neon)
    list(APPEND APROXY_BLAKE3_DEFINITIONS
        BLAKE3_USE_NEON=1
        BLAKE3_NEON_RUNTIME=1
        BLAKE3_NO_SSE2
        BLAKE3_NO_SSE41
        BLAKE3_NO_AVX2
        BLAKE3_NO_AVX512)
    set(APROXY_BLAKE3_BACKEND "ARMv7 runtime-dispatched NEON intrinsics")
else()
    list(APPEND APROXY_BLAKE3_DEFINITIONS
        BLAKE3_USE_NEON=0
        BLAKE3_NO_SSE2
        BLAKE3_NO_SSE41
        BLAKE3_NO_AVX2
        BLAKE3_NO_AVX512)
endif()
message(STATUS
    "BLAKE3 backend for ${APROXY_BLAKE3_ARCH}: ${APROXY_BLAKE3_BACKEND}")

add_library(blake3 STATIC ${APROXY_BLAKE3_SOURCES})
target_include_directories(blake3 PUBLIC third_party/blake3)
target_compile_definitions(blake3 PRIVATE ${APROXY_BLAKE3_DEFINITIONS})

add_library(shadowsocks_client STATIC
    src/shadowsocks_aead.c
    src/shadowsocks_outbound.c)
target_include_directories(shadowsocks_client PUBLIC include PRIVATE src src/framework)
target_compile_options(shadowsocks_client PRIVATE ${APROXY_WARNING_OPTIONS})
target_link_libraries(shadowsocks_client
    PUBLIC
        aproxy_core
        BoringSSL::crypto
        blake3)

if(APPLE)
    # Network Extension embeds one fixed core archive. Include all internal
    # sources here so the final Apple archive only has external dependencies.
    add_library(aproxy STATIC
        src/library.c
        src/engine.c
        ${APROXY_CORE_SOURCES}
        src/frame.c
        src/md5.c
        src/padding.c
        src/vless_protocol.c
        src/vless_encryption.c
        src/vless_vision.c
        src/tls_uv.c
        src/reality.c
        src/xhttp_config.c
        src/xhttp_client.c
        src/xhttp_h1.c
        src/xhttp_request.c
        src/anytls_outbound.c
        src/client.c
        src/vless_outbound.c
        src/shadowsocks_aead.c
        src/shadowsocks_outbound.c
        ${APROXY_BLAKE3_SOURCES})
else()
    add_library(aproxy SHARED src/library.c src/engine.c ${APROXY_CORE_SOURCES})
endif()
add_library(Solaris::core ALIAS aproxy)
target_compile_definitions(aproxy PRIVATE
    APROXY_BUILDING_ENGINE
    APROXY_BUILDING_LIBRARY
    APROXY_HIDE_LIBRARY_EXPORTS)
target_compile_options(aproxy PRIVATE ${APROXY_WARNING_OPTIONS})
target_include_directories(aproxy PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
    PRIVATE src src/framework third_party/blake3)
if(WIN32 AND NOT APPLE)
    target_sources(aproxy PRIVATE src/core.def)
endif()
if(APPLE)
    target_compile_definitions(aproxy PRIVATE ${APROXY_BLAKE3_DEFINITIONS})
    target_link_libraries(aproxy PRIVATE
        ${APROXY_LIBUV_TARGET}
        ${APROXY_PCRE2_TARGET}
        ${APROXY_NGHTTP2_TARGET}
        ${APROXY_LLHTTP_TARGET}
        BoringSSL::ssl
        BoringSSL::crypto
        Threads::Threads)
    if(APROXY_ENABLE_TUN)
        target_compile_definitions(aproxy PUBLIC APROXY_ENABLE_TUN=1)
        target_link_libraries(aproxy PRIVATE ${APROXY_LWIP_TARGET})
    endif()

    find_program(APROXY_APPLE_LIBTOOL NAMES libtool REQUIRED)
    set(APROXY_APPLE_ARCHIVE
        "${CMAKE_CURRENT_BINARY_DIR}/libcore_ios.a")
    set(APROXY_APPLE_ARCHIVE_INPUTS
        $<TARGET_FILE:aproxy>
        $<TARGET_FILE:${APROXY_LIBUV_TARGET}>
        $<TARGET_FILE:${APROXY_PCRE2_TARGET}>
        $<TARGET_FILE:${APROXY_NGHTTP2_TARGET}>
        $<TARGET_FILE:${APROXY_LLHTTP_TARGET}>
        $<TARGET_FILE:BoringSSL::ssl>
        $<TARGET_FILE:BoringSSL::crypto>)
    if(APROXY_ENABLE_TUN)
        list(APPEND APROXY_APPLE_ARCHIVE_INPUTS
            $<TARGET_FILE:${APROXY_LWIP_TARGET}>)
    endif()
    add_custom_command(
        OUTPUT "${APROXY_APPLE_ARCHIVE}"
        COMMAND "${APROXY_APPLE_LIBTOOL}" -static
            -o "${APROXY_APPLE_ARCHIVE}"
            ${APROXY_APPLE_ARCHIVE_INPUTS}
        DEPENDS aproxy
            ${APROXY_LIBUV_TARGET}
            ${APROXY_PCRE2_TARGET}
            ${APROXY_NGHTTP2_TARGET}
            ${APROXY_LLHTTP_TARGET}
            ${APROXY_LWIP_TARGET}
        VERBATIM)
    add_custom_target(aproxy_ios_archive DEPENDS "${APROXY_APPLE_ARCHIVE}")
else()
    target_link_libraries(aproxy PRIVATE
        anytls_client shadowsocks_client vless_client)
endif()
if(WIN32)
    target_link_libraries(aproxy PRIVATE psapi ws2_32)
endif()
set_target_properties(aproxy PROPERTIES
    C_VISIBILITY_PRESET hidden
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN YES
    EXPORT_NAME core
    OUTPUT_NAME core
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    WINDOWS_EXPORT_ALL_SYMBOLS OFF
    LINKER_LANGUAGE CXX)
if(UNIX AND NOT APPLE)
    target_link_options(aproxy PRIVATE
        "LINKER:--version-script=${CMAKE_CURRENT_SOURCE_DIR}/cmake/solaris-core.map"
        "LINKER:--no-undefined")
endif()
if(ANDROID)
    # Every PT_LOAD segment must be compatible with Android devices using a
    # 16 KiB kernel page size. NDK r28+ also applies this by default, but keep
    # the contract explicit so custom toolchains cannot silently regress it.
    target_link_options(aproxy PRIVATE "LINKER:-z,max-page-size=16384")
endif()

option(SOLARIS_BUILD_TESTS "Build Solaris Core ABI smoke tests"
    ${PROJECT_IS_TOP_LEVEL})
if(SOLARIS_BUILD_TESTS)
    include(CTest)
    if(BUILD_TESTING AND NOT CMAKE_CROSSCOMPILING)
        add_executable(solaris_abi_smoke tests/abi_smoke.c)
        target_link_libraries(solaris_abi_smoke PRIVATE Solaris::core)
        add_test(NAME solaris_abi_smoke COMMAND solaris_abi_smoke)
        if(UNIX AND NOT APPLE)
            add_test(NAME solaris_core_exports
                COMMAND ${CMAKE_COMMAND}
                    -DCORE_LIBRARY=$<TARGET_FILE:aproxy>
                    -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/VerifyCoreExports.cmake")
        endif()
    endif()
endif()

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

set(SOLARIS_CMAKE_INSTALL_DIR
    "${CMAKE_INSTALL_LIBDIR}/cmake/Solaris")
set(SOLARIS_CORE_INSTALLED_LIBRARY "libcore.a")
configure_package_config_file(
    cmake/SolarisConfig.cmake.in
    "${CMAKE_CURRENT_BINARY_DIR}/SolarisConfig.cmake"
    INSTALL_DESTINATION "${SOLARIS_CMAKE_INSTALL_DIR}")
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/SolarisConfigVersion.cmake"
    VERSION "${PROJECT_VERSION}"
    COMPATIBILITY SameMajorVersion)

if(APPLE)
    install(FILES "${APROXY_APPLE_ARCHIVE}"
        DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RENAME libcore.a)
else()
    install(TARGETS aproxy
        EXPORT SolarisTargets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
    install(EXPORT SolarisTargets
        FILE SolarisTargets.cmake
        NAMESPACE Solaris::
        DESTINATION "${SOLARIS_CMAKE_INSTALL_DIR}")
endif()
install(FILES include/solaris/core.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/solaris)
install(FILES include/aproxy/engine.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/aproxy)
install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/SolarisConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/SolarisConfigVersion.cmake"
    DESTINATION "${SOLARIS_CMAKE_INSTALL_DIR}")
