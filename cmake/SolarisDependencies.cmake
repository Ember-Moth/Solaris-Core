include(FetchContent)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    "${PROJECT_SOURCE_DIR}/dependencies/lock.json")
file(READ "${PROJECT_SOURCE_DIR}/dependencies/lock.json" solaris_dependency_lock)
foreach(dependency IN LISTS SOLARIS_DEPENDENCIES)
    if(NOT dependency MATCHES "^(libuv|boringssl|blake3|lwip|llhttp)$")
        message(FATAL_ERROR "No build recipe for declared dependency: ${dependency}")
    endif()
endforeach()
string(JSON solaris_uv_url GET "${solaris_dependency_lock}" libuv url)
string(JSON solaris_uv_hash GET "${solaris_dependency_lock}" libuv sha256)

# Populate separately so vendor install rules do not become part of our SDK.
FetchContent_Declare(solaris_uv
    URL "${solaris_uv_url}"
    URL_HASH "SHA256=${solaris_uv_hash}"
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    SOURCE_SUBDIR solaris-populate-only)
FetchContent_MakeAvailable(solaris_uv)
set(LIBUV_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(LIBUV_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(LIBUV_BUILD_BENCH OFF CACHE BOOL "" FORCE)
set(ENABLE_CLANG_TIDY OFF CACHE BOOL "" FORCE)
function(solaris_add_private_libuv)
    # libuv's alias selection also consults BUILD_SHARED_LIBS. Keep its static
    # choice scoped to this dependency without changing the Solaris library.
    set(BUILD_SHARED_LIBS OFF)
    add_subdirectory("${solaris_uv_SOURCE_DIR}" "${solaris_uv_BINARY_DIR}" EXCLUDE_FROM_ALL)
endfunction()
solaris_add_private_libuv()
set_target_properties(uv_a PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    OUTPUT_NAME solaris_uv
    EXPORT_NAME private_uv)
if(ANDROID)
    target_compile_definitions(uv_a PRIVATE LLONG_MAX=__LONG_LONG_MAX__)
endif()

set(SOLARIS_PRIVATE_LIBRARIES uv_a)
set(SOLARIS_PACKAGE_NEEDS_THREADS OFF)
if("llhttp" IN_LIST SOLARIS_DEPENDENCIES)
    string(JSON solaris_llhttp_url GET "${solaris_dependency_lock}" llhttp url)
    string(JSON solaris_llhttp_hash GET "${solaris_dependency_lock}" llhttp sha256)
    FetchContent_Declare(solaris_llhttp URL "${solaris_llhttp_url}"
        URL_HASH "SHA256=${solaris_llhttp_hash}" DOWNLOAD_EXTRACT_TIMESTAMP TRUE
        SOURCE_SUBDIR solaris-populate-only)
    FetchContent_MakeAvailable(solaris_llhttp)
    add_library(solaris_llhttp STATIC "${solaris_llhttp_SOURCE_DIR}/src/llhttp.c"
        "${solaris_llhttp_SOURCE_DIR}/src/api.c" "${solaris_llhttp_SOURCE_DIR}/src/http.c")
    set_target_properties(solaris_llhttp PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON
        POSITION_INDEPENDENT_CODE ON C_VISIBILITY_PRESET hidden EXPORT_NAME private_llhttp)
    target_include_directories(solaris_llhttp PUBLIC
        "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/third_party/llhttp>"
        "$<BUILD_INTERFACE:${solaris_llhttp_SOURCE_DIR}/include>")
    if(MSVC)
        target_compile_options(solaris_llhttp PRIVATE "/FI${PROJECT_SOURCE_DIR}/third_party/llhttp/solaris_llhttp_symbols.h")
    else()
        target_compile_options(solaris_llhttp PRIVATE -include "${PROJECT_SOURCE_DIR}/third_party/llhttp/solaris_llhttp_symbols.h")
    endif()
    if(SOLARIS_SANITIZER STREQUAL "address")
        target_compile_options(solaris_llhttp PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    elseif(SOLARIS_SANITIZER STREQUAL "thread")
        target_compile_options(solaris_llhttp PRIVATE -fsanitize=thread -fno-omit-frame-pointer)
    endif()
    list(APPEND SOLARIS_PRIVATE_LIBRARIES solaris_llhttp)
endif()
if("lwip" IN_LIST SOLARIS_DEPENDENCIES)
    string(JSON solaris_lwip_url GET "${solaris_dependency_lock}" lwip url)
    string(JSON solaris_lwip_hash GET "${solaris_dependency_lock}" lwip sha256)
    FetchContent_Declare(solaris_lwip
        URL "${solaris_lwip_url}" URL_HASH "SHA256=${solaris_lwip_hash}"
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE SOURCE_SUBDIR solaris-populate-only)
    FetchContent_MakeAvailable(solaris_lwip)
    set(solaris_lwip_files)
    foreach(file init inet_chksum ip mem memp netif pbuf stats sys tcp tcp_in tcp_out)
        list(APPEND solaris_lwip_files "${solaris_lwip_SOURCE_DIR}/src/core/${file}.c")
    endforeach()
    foreach(file ip4 ip4_addr icmp)
        list(APPEND solaris_lwip_files "${solaris_lwip_SOURCE_DIR}/src/core/ipv4/${file}.c")
    endforeach()
    foreach(file ip6 ip6_addr icmp6 nd6)
        list(APPEND solaris_lwip_files "${solaris_lwip_SOURCE_DIR}/src/core/ipv6/${file}.c")
    endforeach()
    add_library(solaris_lwip STATIC ${solaris_lwip_files})
    set_target_properties(solaris_lwip PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON
        POSITION_INDEPENDENT_CODE ON C_VISIBILITY_PRESET hidden EXPORT_NAME private_lwip)
    target_include_directories(solaris_lwip PUBLIC
        "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/third_party/lwip>"
        "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src/stack/tun/lwip/port>"
        "$<BUILD_INTERFACE:${solaris_lwip_SOURCE_DIR}/src/include>")
    if(SOLARIS_SANITIZER STREQUAL "address")
        target_compile_options(solaris_lwip PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    elseif(SOLARIS_SANITIZER STREQUAL "thread")
        target_compile_options(solaris_lwip PRIVATE -fsanitize=thread -fno-omit-frame-pointer)
    endif()
    list(APPEND SOLARIS_PRIVATE_LIBRARIES solaris_lwip)
endif()
if("boringssl" IN_LIST SOLARIS_DEPENDENCIES)
    enable_language(CXX)
    string(JSON solaris_bssl_url GET "${solaris_dependency_lock}" boringssl url)
    string(JSON solaris_bssl_hash GET "${solaris_dependency_lock}" boringssl sha256)
    FetchContent_Declare(solaris_bssl
        URL "${solaris_bssl_url}" URL_HASH "SHA256=${solaris_bssl_hash}"
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE SOURCE_SUBDIR solaris-populate-only)
    FetchContent_MakeAvailable(solaris_bssl)
    # Keep upstream immutable. Every configure verifies the pristine source,
    # ordered patch checksums, and the resulting build-local source tree.
    find_package(Python3 3.9 REQUIRED COMPONENTS Interpreter)
    find_package(Git REQUIRED)
    file(GLOB solaris_bssl_patches CONFIGURE_DEPENDS
        "${PROJECT_SOURCE_DIR}/third_party/boringssl/patches/*.patch")
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
        ${solaris_bssl_patches} "${PROJECT_SOURCE_DIR}/scripts/dependencies/boringssl.py")
    set(solaris_bssl_pristine_SOURCE_DIR "${solaris_bssl_SOURCE_DIR}")
    set(solaris_bssl_SOURCE_DIR "${PROJECT_BINARY_DIR}/_deps/solaris_bssl-patched")
    execute_process(COMMAND "${Python3_EXECUTABLE}"
        "${PROJECT_SOURCE_DIR}/scripts/dependencies/boringssl.py"
        --project "${PROJECT_SOURCE_DIR}" --source "${solaris_bssl_pristine_SOURCE_DIR}"
        --output "${solaris_bssl_SOURCE_DIR}"
        COMMAND_ERROR_IS_FATAL ANY)
    function(solaris_add_private_boringssl)
        set(BUILD_SHARED_LIBS OFF)
        set(BUILD_TESTING OFF)
        set(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT FALSE)
        set(CMAKE_POSITION_INDEPENDENT_CODE ON)
        set(BORINGSSL_PREFIX solaris_bssl)
        # The Visual Studio generator cannot build BoringSSL's NASM sources.
        # Keep the portable backend for MSVC; other targets retain assembly.
        if(MSVC)
            set(OPENSSL_NO_ASM ON)
        endif()
        add_subdirectory("${solaris_bssl_SOURCE_DIR}" "${solaris_bssl_BINARY_DIR}" EXCLUDE_FROM_ALL)
    endfunction()
    solaris_add_private_boringssl()
    # The private handshake patch must be instrumented too, not only its
    # Solaris callers. Keep production builds and upstream crypto flags intact.
    if(SOLARIS_SANITIZER STREQUAL "address")
        target_compile_options(ssl PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    elseif(SOLARIS_SANITIZER STREQUAL "thread")
        target_compile_options(ssl PRIVATE -fsanitize=thread -fno-omit-frame-pointer)
    endif()
    set_target_properties(ssl PROPERTIES OUTPUT_NAME solaris_ssl EXPORT_NAME private_ssl)
    set_target_properties(crypto PROPERTIES OUTPUT_NAME solaris_crypto EXPORT_NAME private_crypto
        INTERFACE_INCLUDE_DIRECTORIES "$<BUILD_INTERFACE:${solaris_bssl_SOURCE_DIR}/include>")
    # This pinned upstream prefix table omits the out-of-line SSL_SESSION
    # destructor's struct tag. Rename it consistently in library and consumers
    # so a statically linked host can also embed an independent BoringSSL.
    target_compile_definitions(crypto PRIVATE ssl_session_st=solaris_bssl_ssl_session_st)
    target_compile_definitions(crypto INTERFACE
        "$<BUILD_INTERFACE:BORINGSSL_PREFIX=solaris_bssl>"
        "$<BUILD_INTERFACE:ssl_session_st=solaris_bssl_ssl_session_st>")
    # A C-only installed consumer has no C++ compiler metadata from which
    # CMake could infer these libraries. Preserve the selected toolchain's
    # C++ runtime dependency without exposing private crypto headers.
    foreach(runtime IN LISTS CMAKE_CXX_IMPLICIT_LINK_LIBRARIES)
        if(runtime MATCHES "^(stdc\\+\\+|c\\+\\+|c\\+\\+abi)$")
            target_link_libraries(ssl "${runtime}")
        endif()
    endforeach()
    list(APPEND SOLARIS_PRIVATE_LIBRARIES ssl crypto)
    # Imported targets created in the vendor subdirectory need not be visible
    # here, but the exported crypto link interface still references them.
    get_target_property(solaris_crypto_links crypto INTERFACE_LINK_LIBRARIES)
    if(solaris_crypto_links MATCHES "Threads::Threads")
        set(SOLARIS_PACKAGE_NEEDS_THREADS ON)
    endif()
endif()

if("blake3" IN_LIST SOLARIS_DEPENDENCIES)
    add_library(solaris_blake3 STATIC
        third_party/blake3/blake3.c third_party/blake3/blake3_dispatch.c third_party/blake3/blake3_portable.c)
    set_target_properties(solaris_blake3 PROPERTIES POSITION_INDEPENDENT_CODE ON
        C_VISIBILITY_PRESET hidden EXPORT_NAME private_blake3)
    target_include_directories(solaris_blake3 INTERFACE "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/third_party/blake3>")
    target_compile_definitions(solaris_blake3 PRIVATE BLAKE3_NO_SSE2 BLAKE3_NO_SSE41 BLAKE3_NO_AVX2 BLAKE3_NO_AVX512 BLAKE3_USE_NEON=0)
    foreach(symbol version hasher_init hasher_init_keyed hasher_init_derive_key hasher_init_derive_key_raw
        hasher_update hasher_finalize hasher_finalize_seek hasher_reset compress_in_place compress_xof xof_many
        hash_many simd_degree compress_in_place_portable compress_xof_portable hash_many_portable compress_subtree_wide)
        target_compile_definitions(solaris_blake3 PRIVATE "blake3_${symbol}=solaris_blake3_${symbol}")
        target_compile_definitions(solaris_blake3 INTERFACE "$<BUILD_INTERFACE:blake3_${symbol}=solaris_blake3_${symbol}>")
    endforeach()
    list(APPEND SOLARIS_PRIVATE_LIBRARIES solaris_blake3)
endif()
