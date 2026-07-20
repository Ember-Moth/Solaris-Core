include(FetchContent)

function(aproxy_configure_mobile_dependencies)
    if(NOT ANDROID AND NOT APPLE AND NOT WIN32)
        message(FATAL_ERROR
            "MobileDependencies.cmake requires Android, Apple or Windows")
    endif()

    set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
    set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
    set(BUILD_STATIC_LIBS ON CACHE BOOL "" FORCE)

    set(LIBUV_BUILD_SHARED OFF CACHE BOOL "" FORCE)
    set(LIBUV_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(LIBUV_BUILD_BENCH OFF CACHE BOOL "" FORCE)

    set(PCRE2_BUILD_PCRE2_8 ON CACHE BOOL "" FORCE)
    set(PCRE2_BUILD_PCRE2_16 OFF CACHE BOOL "" FORCE)
    set(PCRE2_BUILD_PCRE2_32 OFF CACHE BOOL "" FORCE)
    set(PCRE2_BUILD_PCRE2GREP OFF CACHE BOOL "" FORCE)
    set(PCRE2_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(PCRE2_STATIC_PIC ON CACHE BOOL "" FORCE)
    set(PCRE2_SUPPORT_LIBBZ2 OFF CACHE BOOL "" FORCE)
    set(PCRE2_SUPPORT_LIBZ OFF CACHE BOOL "" FORCE)
    set(PCRE2_SUPPORT_LIBREADLINE OFF CACHE BOOL "" FORCE)

    set(ENABLE_LIB_ONLY ON CACHE BOOL "" FORCE)
    set(ENABLE_APP OFF CACHE BOOL "" FORCE)
    set(ENABLE_EXAMPLES OFF CACHE BOOL "" FORCE)
    set(ENABLE_HPACK_TOOLS OFF CACHE BOOL "" FORCE)
    set(ENABLE_PYTHON_BINDINGS OFF CACHE BOOL "" FORCE)

    FetchContent_Declare(aproxy_libuv
        GIT_REPOSITORY https://github.com/libuv/libuv.git
        GIT_TAG 8fb9cb919489a48880680a56efecff6a7dfb4504
        GIT_SHALLOW TRUE)
    FetchContent_Declare(aproxy_pcre2
        GIT_REPOSITORY https://github.com/PCRE2Project/pcre2.git
        GIT_TAG b2bd4254b379b9d7dc9a3dda060a7e27009ccdff
        GIT_SHALLOW TRUE)
    FetchContent_Declare(aproxy_nghttp2
        GIT_REPOSITORY https://github.com/nghttp2/nghttp2.git
        GIT_TAG 526ff38e0249acbcc4d0e8958c12cdeae9960cfe
        GIT_SHALLOW TRUE)
    FetchContent_Declare(aproxy_llhttp
        GIT_REPOSITORY https://github.com/nodejs/llhttp.git
        GIT_TAG 610a87d755f6bae466cd871c2ba97574ccac5483
        GIT_SHALLOW TRUE)

    if(APROXY_ENABLE_TUN)
        FetchContent_Declare(aproxy_lwip
            GIT_REPOSITORY https://github.com/lwip-tcpip/lwip.git
            GIT_TAG 77dcd25a72509eb83f72b033d219b1d40cd8eb95
            GIT_SHALLOW TRUE)
        FetchContent_GetProperties(aproxy_lwip)
        if(NOT aproxy_lwip_POPULATED)
            if(POLICY CMP0169)
                cmake_policy(PUSH)
                cmake_policy(SET CMP0169 OLD)
            endif()
            FetchContent_Populate(aproxy_lwip)
            if(POLICY CMP0169)
                cmake_policy(POP)
            endif()
        endif()
        set(LWIP_DIR "${aproxy_lwip_SOURCE_DIR}")
        include("${LWIP_DIR}/src/Filelists.cmake")
        add_library(aproxy_lwip STATIC
            ${lwipcore_SRCS}
            ${lwipcore4_SRCS}
            ${lwipcore6_SRCS}
            "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/mobile/lwip/sys_arch.c")
        target_include_directories(aproxy_lwip PUBLIC
            "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/mobile/lwip"
            "${LWIP_DIR}/src/include")
        set(APROXY_LWIP_TARGET aproxy_lwip PARENT_SCOPE)
    endif()

    FetchContent_MakeAvailable(
        aproxy_libuv
        aproxy_pcre2
        aproxy_nghttp2
        aproxy_llhttp)

    if(APROXY_ENABLE_TUN)
        target_link_libraries(aproxy_lwip PUBLIC uv_a)
    endif()

    if(ANDROID)
        # libuv 1.50 uses gnu90; strict NDK headers hide LLONG_MAX.
        target_compile_definitions(uv_a PRIVATE LLONG_MAX=__LONG_LONG_MAX__)
    endif()
endfunction()
