include(FetchContent)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    "${PROJECT_SOURCE_DIR}/dependencies/lock.json")
file(READ "${PROJECT_SOURCE_DIR}/dependencies/lock.json" solaris_dependency_lock)
foreach(dependency IN LISTS SOLARIS_DEPENDENCIES)
    if(NOT dependency STREQUAL "libuv")
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
