#include "aproxy/memory.h"

#include <stdatomic.h>
#include <string.h>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <psapi.h>
#elif defined(__APPLE__)
#include <mach/mach.h>
#elif defined(__linux__)
#include <fcntl.h>
#include <limits.h>
#include <unistd.h>
#endif

static atomic_size_t dynamic_current_bytes;
static atomic_size_t dynamic_peak_bytes;
static atomic_size_t dynamic_limit_bytes;
static atomic_uint_fast64_t rejected_reservations;

void aproxy_memory_set_dynamic_limit(size_t limit_bytes)
{
    atomic_store_explicit(&dynamic_limit_bytes, limit_bytes,
                          memory_order_release);
}

static int reject_reservation(void)
{
    (void)atomic_fetch_add_explicit(&rejected_reservations, 1u,
                                    memory_order_relaxed);
    return APROXY_ERR_NO_MEMORY;
}

int aproxy_memory_try_reserve(size_t bytes)
{
    if (bytes == 0u) {
        return APROXY_OK;
    }

    size_t current = atomic_load_explicit(&dynamic_current_bytes,
                                          memory_order_relaxed);
    for (;;) {
        if (bytes > SIZE_MAX - current) {
            return reject_reservation();
        }
        const size_t limit = atomic_load_explicit(&dynamic_limit_bytes,
                                                  memory_order_acquire);
        if (limit != 0u && (current >= limit || bytes > limit - current)) {
            return reject_reservation();
        }
        const size_t next = current + bytes;
        if (atomic_compare_exchange_weak_explicit(
                &dynamic_current_bytes, &current, next,
                memory_order_acq_rel, memory_order_relaxed)) {
            size_t peak = atomic_load_explicit(&dynamic_peak_bytes,
                                               memory_order_relaxed);
            while (peak < next &&
                   !atomic_compare_exchange_weak_explicit(
                       &dynamic_peak_bytes, &peak, next,
                       memory_order_relaxed, memory_order_relaxed)) {
            }
            return APROXY_OK;
        }
    }
}

void aproxy_memory_release(size_t bytes)
{
    if (bytes == 0u) {
        return;
    }
    size_t current = atomic_load_explicit(&dynamic_current_bytes,
                                          memory_order_relaxed);
    for (;;) {
        const size_t next = bytes < current ? current - bytes : 0u;
        if (atomic_compare_exchange_weak_explicit(
                &dynamic_current_bytes, &current, next,
                memory_order_release, memory_order_relaxed)) {
            return;
        }
    }
}

void aproxy_memory_get_stats(aproxy_memory_stats_t *stats)
{
    if (stats == NULL) {
        return;
    }
    stats->dynamic_current_bytes = atomic_load_explicit(
        &dynamic_current_bytes, memory_order_acquire);
    stats->dynamic_peak_bytes = atomic_load_explicit(
        &dynamic_peak_bytes, memory_order_relaxed);
    stats->dynamic_limit_bytes = atomic_load_explicit(
        &dynamic_limit_bytes, memory_order_acquire);
    stats->rejected_reservations = atomic_load_explicit(
        &rejected_reservations, memory_order_relaxed);
}

#if defined(_WIN32)
int aproxy_process_memory_bytes(size_t *bytes)
{
    if (bytes == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    PROCESS_MEMORY_COUNTERS_EX counters;
    memset(&counters, 0, sizeof(counters));
    counters.cb = sizeof(counters);
    if (!GetProcessMemoryInfo(
            GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS *)&counters,
            sizeof(counters))) {
        return APROXY_ERR_UNSUPPORTED;
    }
    *bytes = (size_t)counters.WorkingSetSize;
    return APROXY_OK;
}
#elif defined(__APPLE__)
int aproxy_process_memory_bytes(size_t *bytes)
{
    if (bytes == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    task_vm_info_data_t info;
    mach_msg_type_number_t count = TASK_VM_INFO_COUNT;
    const kern_return_t rc = task_info(
        mach_task_self(), TASK_VM_INFO, (task_info_t)&info, &count);
    if (rc != KERN_SUCCESS) {
        return APROXY_ERR_UNSUPPORTED;
    }
    *bytes = (size_t)info.phys_footprint;
    return APROXY_OK;
}
#elif defined(__linux__)
static int parse_resident_pages(const char *text,
                                size_t len,
                                size_t *pages)
{
    size_t offset = 0u;
    while (offset < len && text[offset] >= '0' && text[offset] <= '9') {
        offset++;
    }
    while (offset < len && (text[offset] == ' ' || text[offset] == '\t')) {
        offset++;
    }
    if (offset == len || text[offset] < '0' || text[offset] > '9') {
        return APROXY_ERR_PARSE;
    }
    size_t value = 0u;
    while (offset < len && text[offset] >= '0' && text[offset] <= '9') {
        const size_t digit = (size_t)(text[offset] - '0');
        if (value > (SIZE_MAX - digit) / 10u) {
            return APROXY_ERR_PARSE;
        }
        value = value * 10u + digit;
        offset++;
    }
    *pages = value;
    return APROXY_OK;
}

int aproxy_process_memory_bytes(size_t *bytes)
{
    if (bytes == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    const int fd = open("/proc/self/statm", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return APROXY_ERR_UNSUPPORTED;
    }
    char statm[128];
    const ssize_t length = read(fd, statm, sizeof(statm));
    (void)close(fd);
    if (length <= 0) {
        return APROXY_ERR_PARSE;
    }
    size_t pages = 0u;
    int rc = parse_resident_pages(statm, (size_t)length, &pages);
    if (rc != APROXY_OK) {
        return rc;
    }
    const long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0 || pages > SIZE_MAX / (size_t)page_size) {
        return APROXY_ERR_PARSE;
    }
    *bytes = pages * (size_t)page_size;
    return APROXY_OK;
}
#else
int aproxy_process_memory_bytes(size_t *bytes)
{
    (void)bytes;
    return APROXY_ERR_UNSUPPORTED;
}
#endif
