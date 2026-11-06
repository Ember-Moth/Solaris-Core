#include "platform/tun/internal.h"
#ifdef _WIN32
#include <windows.h>
#include <string.h>

typedef void *wintun_adapter_t;
typedef void *wintun_session_t;
typedef wintun_adapter_t (WINAPI *open_adapter_fn)(LPCWSTR);
typedef wintun_adapter_t (WINAPI *create_adapter_fn)(LPCWSTR, LPCWSTR, const GUID *);
typedef void (WINAPI *close_adapter_fn)(wintun_adapter_t);
typedef wintun_session_t (WINAPI *start_session_fn)(wintun_adapter_t, DWORD);
typedef void (WINAPI *end_session_fn)(wintun_session_t);
typedef HANDLE (WINAPI *read_event_fn)(wintun_session_t);
typedef BYTE *(WINAPI *receive_fn)(wintun_session_t, DWORD *);
typedef void (WINAPI *release_fn)(wintun_session_t, const BYTE *);
typedef BYTE *(WINAPI *allocate_fn)(wintun_session_t, DWORD);
typedef void (WINAPI *send_fn)(wintun_session_t, const BYTE *);
typedef struct wintun_driver {
    HMODULE library;
    wintun_adapter_t adapter;
    wintun_session_t session;
    HANDLE read_event, stop_event;
    open_adapter_fn open_adapter;
    create_adapter_fn create_adapter;
    close_adapter_fn close_adapter;
    start_session_fn start_session;
    end_session_fn end_session;
    read_event_fn get_read_event;
    receive_fn receive;
    release_fn release;
    allocate_fn allocate;
    send_fn send;
} wintun_driver_t;
static solaris_status_t win_status(DWORD error)
{
    switch (error) {
    case ERROR_NO_MORE_ITEMS: case ERROR_BUFFER_OVERFLOW: return SOLARIS_EAGAIN;
    case ERROR_ACCESS_DENIED: case ERROR_PRIVILEGE_NOT_HELD: return SOLARIS_EACCESS;
    case ERROR_NOT_ENOUGH_MEMORY: case ERROR_OUTOFMEMORY: return SOLARIS_ENOMEM;
    case ERROR_HANDLE_EOF: case ERROR_INVALID_HANDLE: return SOLARIS_ECLOSED;
    case ERROR_INVALID_PARAMETER: return SOLARIS_EINVAL;
    default: return SOLARIS_EIO;
    }
}
static uint8_t *receive(void *context, size_t *length, solaris_status_t *status)
{
    wintun_driver_t *d = context; DWORD size = 0u;
    BYTE *packet = d->receive(d->session, &size);
    if (packet == NULL) *status = win_status(GetLastError()); else *length = size;
    return packet;
}
static void release(void *context, uint8_t *packet)
{ wintun_driver_t *d = context; d->release(d->session, packet); }
static uint8_t *allocate(void *context, size_t length, solaris_status_t *status)
{
    wintun_driver_t *d = context; BYTE *packet = d->allocate(d->session, (DWORD)length);
    if (packet == NULL) *status = win_status(GetLastError());
    return packet;
}
static void driver_send(void *context, uint8_t *packet)
{ wintun_driver_t *d = context; d->send(d->session, packet); }
static solaris_status_t wait_readable(void *context)
{
    wintun_driver_t *d = context; HANDLE events[2] = {d->stop_event, d->read_event};
    DWORD result = WaitForMultipleObjects(2u, events, FALSE, INFINITE);
    if (result == WAIT_OBJECT_0) return SOLARIS_ECANCELLED;
    if (result == WAIT_OBJECT_0 + 1u) return SOLARIS_OK;
    return SOLARIS_EIO;
}
static void interrupt(void *context) { wintun_driver_t *d = context; if (d->stop_event != NULL) (void)SetEvent(d->stop_event); }
static void close_driver(void *context)
{
    wintun_driver_t *d = context;
    if (d->session != NULL) d->end_session(d->session);
    if (d->stop_event != NULL) CloseHandle(d->stop_event);
    if (d->adapter != NULL) d->close_adapter(d->adapter);
    if (d->library != NULL) FreeLibrary(d->library);
    solaris_memory_free(d);
}
static int absolute_path(const char *path)
{
    if (path == NULL || strlen(path) < 3u || strlen(path) > 32767u) return 0;
    if ((path[0] == '\\' && path[1] == '\\') || (path[0] == '/' && path[1] == '/')) return 1;
    return ((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) &&
        path[1] == ':' && (path[2] == '\\' || path[2] == '/');
}
static solaris_status_t wide(solaris_budget_t *budget, const char *text, wchar_t **out)
{
    int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, -1, NULL, 0);
    if (length <= 0) return SOLARIS_EINVAL;
    *out = solaris_memory_allocate(budget, (size_t)length * sizeof(**out));
    if (*out == NULL) return SOLARIS_ENOMEM;
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, -1, *out, length) != length) {
        solaris_memory_free(*out); *out = NULL; return SOLARIS_EINVAL;
    }
    return SOLARIS_OK;
}
solaris_status_t solaris_tun_wintun_open(const solaris_tun_device_options_t *options, solaris_tun_device_t **out)
{
    if (!absolute_path(options->wintun_library)) return SOLARIS_EINVAL;
    solaris_budget_t *budget = solaris_executor_budget(options->owner);
    wchar_t *path = NULL, *name = NULL;
    solaris_status_t rc = wide(budget, options->wintun_library, &path);
    if (rc == SOLARIS_OK) rc = wide(budget, options->name == NULL || options->name[0] == '\0' ? "Solaris" : options->name, &name);
    if (rc != SOLARIS_OK) { solaris_memory_free(path); solaris_memory_free(name); return rc; }
    wintun_driver_t *d = solaris_memory_allocate(budget, sizeof(*d));
    if (d == NULL) { solaris_memory_free(path); solaris_memory_free(name); return SOLARIS_ENOMEM; }
    memset(d, 0, sizeof(*d));
    d->library = LoadLibraryExW(path, NULL, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    rc = d->library == NULL ? win_status(GetLastError()) : SOLARIS_OK;
    solaris_memory_free(path);
#define LOAD(member, type, symbol) do { if (rc == SOLARIS_OK) { \
    FARPROC address = GetProcAddress(d->library, symbol); \
    _Static_assert(sizeof(address) == sizeof(type), "Windows function pointer ABI"); \
    memcpy(&d->member, &address, sizeof(d->member)); \
    if (d->member == NULL) rc = SOLARIS_ENOTSUP; \
} } while (0)
    LOAD(open_adapter, open_adapter_fn, "WintunOpenAdapter");
    LOAD(create_adapter, create_adapter_fn, "WintunCreateAdapter");
    LOAD(close_adapter, close_adapter_fn, "WintunCloseAdapter");
    LOAD(start_session, start_session_fn, "WintunStartSession");
    LOAD(end_session, end_session_fn, "WintunEndSession");
    LOAD(get_read_event, read_event_fn, "WintunGetReadWaitEvent");
    LOAD(receive, receive_fn, "WintunReceivePacket");
    LOAD(release, release_fn, "WintunReleaseReceivePacket");
    LOAD(allocate, allocate_fn, "WintunAllocateSendPacket");
    LOAD(send, send_fn, "WintunSendPacket");
#undef LOAD
    if (rc == SOLARIS_OK) {
        d->adapter = d->open_adapter(name);
        if (d->adapter == NULL) {
            DWORD error = GetLastError();
            if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND || error == ERROR_NOT_FOUND)
                d->adapter = d->create_adapter(name, L"Solaris", NULL);
            if (d->adapter == NULL) rc = win_status(GetLastError());
        }
    }
    solaris_memory_free(name);
    if (rc == SOLARIS_OK) {
        DWORD capacity = 0x20000u;
        while (capacity < options->queue_byte_limit && capacity < 0x4000000u) capacity <<= 1u;
        d->session = d->start_session(d->adapter, capacity);
        if (d->session == NULL) rc = win_status(GetLastError());
    }
    if (rc == SOLARIS_OK) {
        d->read_event = d->get_read_event(d->session);
        if (d->read_event == NULL) rc = win_status(GetLastError());
    }
    if (rc == SOLARIS_OK) {
        d->stop_event = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (d->stop_event == NULL) rc = win_status(GetLastError());
    }
    if (rc != SOLARIS_OK) { close_driver(d); return rc; }
    solaris_wintun_api_t api = {d, receive, release, allocate, driver_send, wait_readable, interrupt, close_driver};
    return solaris_tun_wintun_open_api(options, &api, out);
}
#else
solaris_status_t solaris_tun_wintun_open(const solaris_tun_device_options_t *options, solaris_tun_device_t **out)
{ (void)options; (void)out; return SOLARIS_ENOTSUP; }
#endif
