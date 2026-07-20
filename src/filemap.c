#include "aproxy/filemap.h"

#include <stdlib.h>
#include <string.h>
#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#if defined(_WIN32)
static wchar_t *utf8_path(const char *path)
{
    const int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                           path, -1, NULL, 0);
    if (length <= 0) {
        return NULL;
    }
    wchar_t *wide = (wchar_t *)malloc((size_t)length * sizeof(*wide));
    if (wide == NULL ||
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, wide,
                            length) != length) {
        free(wide);
        return NULL;
    }
    return wide;
}
#endif

int aproxy_filemap_open_ro(const char *path,
                           size_t max_size,
                           aproxy_filemap_t *out)
{
    if (path == NULL || out == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    memset(out, 0, sizeof(*out));
    out->fd = -1;

#if defined(_WIN32)
    wchar_t *wide_path = utf8_path(path);
    if (wide_path == NULL) {
        return APROXY_ERR_PARSE;
    }
    HANDLE file = CreateFileW(wide_path, GENERIC_READ, FILE_SHARE_READ,
                              NULL, OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                              NULL);
    free(wide_path);
    if (file == INVALID_HANDLE_VALUE) {
        return APROXY_ERR_PARSE;
    }
    LARGE_INTEGER size;
    if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 ||
        (uint64_t)size.QuadPart > (uint64_t)SIZE_MAX ||
        (max_size != 0u && (uint64_t)size.QuadPart > (uint64_t)max_size)) {
        CloseHandle(file);
        return APROXY_ERR_PARSE;
    }
    HANDLE section = CreateFileMappingW(file, NULL, PAGE_READONLY, 0, 0, NULL);
    CloseHandle(file);
    if (section == NULL) {
        return APROXY_ERR_PARSE;
    }
    void *mapping = MapViewOfFile(section, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(section);
    if (mapping == NULL) {
        return APROXY_ERR_PARSE;
    }
    out->data = (const uint8_t *)mapping;
    out->len = (size_t)size.QuadPart;
    out->mapping = mapping;
    return APROXY_OK;
#else
    const int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return APROXY_ERR_PARSE;
    }

    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size <= 0) {
        close(fd);
        return APROXY_ERR_PARSE;
    }
    if (max_size != 0u && (uint64_t)st.st_size > (uint64_t)max_size) {
        close(fd);
        return APROXY_ERR_PARSE;
    }

    void *mapping = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd,
                         0);
    if (mapping == MAP_FAILED) {
        close(fd);
        return APROXY_ERR_PARSE;
    }

#if defined(MADV_SEQUENTIAL)
    /* Geo databases are indexed with one forward scan during startup. */
    (void)madvise(mapping, (size_t)st.st_size, MADV_SEQUENTIAL);
#endif

    out->data = (const uint8_t *)mapping;
    out->len = (size_t)st.st_size;
    out->mapping = mapping;
    /* The mapping retains the file reference; no descriptor is needed while
     * Geo entries are compiled. */
    (void)close(fd);
    out->fd = -1;
    return APROXY_OK;
#endif
}

void aproxy_filemap_advise_normal(aproxy_filemap_t *map)
{
#if defined(_WIN32)
    (void)map;
#elif defined(MADV_NORMAL)
    if (map != NULL && map->mapping != NULL && map->len > 0u) {
        (void)madvise(map->mapping, map->len, MADV_NORMAL);
    }
#else
    (void)map;
#endif
}

void aproxy_filemap_close(aproxy_filemap_t *map)
{
    if (map == NULL) {
        return;
    }
    if (map->mapping != NULL && map->len > 0u) {
#if defined(_WIN32)
        (void)UnmapViewOfFile(map->mapping);
#else
        (void)munmap(map->mapping, map->len);
#endif
    }
#if !defined(_WIN32)
    if (map->fd >= 0) {
        (void)close(map->fd);
    }
#endif
    memset(map, 0, sizeof(*map));
    map->fd = -1;
}
