#include "platform/tun/internal.h"
#include "support/runtime/event.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)
enum { RING_ECHO, CLOSE_QUEUE, STOP_QUEUE, STOP_WAIT, CLOSE_READ, FLOOD, WAIT_ERROR, RECEIVE_ERROR, SEND_ERROR, IMMEDIATE_CLOSE, ALLOCATE_ERROR };
typedef struct environment {
    solaris_executor_t *owner;
    solaris_budget_t *budget;
    solaris_tun_device_t *device;
    solaris_runtime_services_t services;
    solaris_test_event_t ready, done, entered, blocked, received, writable;
    uv_mutex_t mutex;
    uv_cond_t condition;
    int mode, full, stopped, wait_active, borrowed, reserved, fail_allocate;
    unsigned int input_count, input_index, waits, interrupts, driver_closes, closes, packets, releases, sends, writable_count;
    uint8_t packet[40], input[64][40], output[40];
    solaris_status_t status, submitted;
} environment_t;
static void *allocate_memory(void *context, size_t size)
{ environment_t *e = context; if (e->fail_allocate) { e->fail_allocate = 0; return NULL; } return malloc(size); }
static uint8_t *receive(void *context, size_t *length, solaris_status_t *status)
{
    environment_t *e = context; CHECK(solaris_executor_is_owner(e->owner));
    uv_mutex_lock(&e->mutex);
    if (e->mode == RECEIVE_ERROR) { *status = SOLARIS_EIO; uv_mutex_unlock(&e->mutex); return NULL; }
    if (e->input_count == 0u) { *status = SOLARIS_EAGAIN; uv_mutex_unlock(&e->mutex); return NULL; }
    CHECK(!e->borrowed); e->borrowed = 1; *length = sizeof(e->packet);
    uint8_t *result = e->input[e->input_index]; uv_mutex_unlock(&e->mutex); return result;
}
static void release(void *context, uint8_t *data)
{
    environment_t *e = context; CHECK(solaris_executor_is_owner(e->owner)); uv_mutex_lock(&e->mutex);
    CHECK(e->borrowed && data == e->input[e->input_index]); e->borrowed = 0; e->input_count--; e->input_index++; e->releases++;
    uv_mutex_unlock(&e->mutex);
}
static uint8_t *allocate_packet(void *context, size_t length, solaris_status_t *status)
{
    environment_t *e = context; CHECK(solaris_executor_is_owner(e->owner) && length == sizeof(e->packet));
    uv_mutex_lock(&e->mutex);
    if (e->mode == SEND_ERROR) { *status = SOLARIS_EIO; uv_mutex_unlock(&e->mutex); return NULL; }
    if (e->full) { *status = SOLARIS_EAGAIN; uv_mutex_unlock(&e->mutex); solaris_test_event_signal(&e->blocked); return NULL; }
    CHECK(!e->reserved); e->reserved = 1; uv_mutex_unlock(&e->mutex); return e->output;
}
static void send_packet(void *context, uint8_t *data)
{
    environment_t *e = context; CHECK(solaris_executor_is_owner(e->owner)); uv_mutex_lock(&e->mutex);
    CHECK(e->reserved && data == e->output && memcmp(data, e->packet, sizeof(e->packet)) == 0);
    e->reserved = 0; e->sends++;
    CHECK(e->input_count + e->input_index < 64u);
    memcpy(e->input[e->input_index + e->input_count], data, sizeof(e->packet)); e->input_count++;
    uv_cond_signal(&e->condition); uv_mutex_unlock(&e->mutex);
}
static solaris_status_t wait_packet(void *context)
{
    environment_t *e = context; CHECK(!solaris_executor_is_owner(e->owner)); uv_mutex_lock(&e->mutex);
    e->wait_active = 1; e->waits++; solaris_test_event_signal(&e->entered);
    while (!e->stopped && e->input_count == 0u && e->mode != WAIT_ERROR && e->mode != RECEIVE_ERROR)
        uv_cond_wait(&e->condition, &e->mutex);
    e->wait_active = 0;
    solaris_status_t status = e->stopped ? SOLARIS_ECANCELLED : e->mode == WAIT_ERROR ? SOLARIS_EIO : SOLARIS_OK;
    uv_mutex_unlock(&e->mutex); return status;
}
static void interrupt(void *context)
{
    environment_t *e = context; CHECK(solaris_executor_is_owner(e->owner)); uv_mutex_lock(&e->mutex);
    e->stopped = 1; e->interrupts++; uv_cond_signal(&e->condition); uv_mutex_unlock(&e->mutex);
}
static void close_driver(void *context)
{
    environment_t *e = context; CHECK(solaris_executor_is_owner(e->owner)); uv_mutex_lock(&e->mutex);
    CHECK(!e->wait_active && !e->borrowed && !e->reserved && e->closes == 0u && ++e->driver_closes == 1u);
    uv_mutex_unlock(&e->mutex);
}
static void writable(void *context)
{ environment_t *e = context; CHECK(e->closes == 0u); e->writable_count++; solaris_test_event_signal(&e->writable); }
static void packet(void *context, const uint8_t *data, size_t length)
{
    environment_t *e = context;
    CHECK(solaris_executor_is_owner(e->owner) && e->closes == 0u && length == sizeof(e->packet) && memcmp(data, e->packet, length) == 0);
    e->packets++;
    if (e->mode == CLOSE_READ) solaris_tun_device_close(e->device);
    if (e->mode != FLOOD || e->packets == 64u) solaris_test_event_signal(&e->received);
}
static void closed(void *context, solaris_status_t status)
{
    environment_t *e = context; CHECK(e->driver_closes == 1u && ++e->closes == 1u);
    e->status = status; e->device = NULL; solaris_test_event_signal(&e->done);
}
static void start(void *context, solaris_status_t status)
{
    environment_t *e = context; CHECK(status == SOLARIS_OK);
    solaris_tun_device_options_t options = {.owner = e->owner, .kind = SOLARIS_TUN_DEVICE_WINTUN, .mtu = 1500u,
        .queue_packet_limit = 1u, .queue_byte_limit = 1500u, .context = e, .on_packet = packet, .on_writable = writable, .on_close = closed};
    solaris_wintun_api_t api = {e, receive, release, allocate_packet, send_packet, wait_packet, interrupt, close_driver};
    e->fail_allocate = e->mode == ALLOCATE_ERROR;
    e->submitted = solaris_tun_wintun_open_api(&options, &api, &e->device);
    if (e->mode == ALLOCATE_ERROR) { CHECK(e->submitted == SOLARIS_ENOMEM && e->device == NULL); solaris_test_event_signal(&e->done); }
    else {
        CHECK(e->submitted == SOLARIS_OK && strcmp(solaris_tun_device_name(e->device), "Solaris") == 0);
        if (e->mode == IMMEDIATE_CLOSE) solaris_tun_device_close(e->device);
        if (e->mode == RING_ECHO || e->mode == CLOSE_QUEUE || e->mode == STOP_QUEUE || e->mode == SEND_ERROR) {
            CHECK(solaris_tun_device_write(e->device, e->packet, sizeof(e->packet)) == SOLARIS_OK);
            CHECK(solaris_tun_device_write(e->device, e->packet, sizeof(e->packet)) == SOLARIS_EAGAIN);
        }
    }
    solaris_test_event_signal(&e->ready);
}
static void finish(void *context, solaris_status_t status)
{ environment_t *e = context; CHECK(status == SOLARIS_OK); solaris_tun_device_close(e->device); }
static void run(int mode)
{
    environment_t e; memset(&e, 0, sizeof(e)); e.mode = mode;
    e.full = mode == RING_ECHO || mode == CLOSE_QUEUE || mode == STOP_QUEUE;
    e.packet[0] = 0x60u; for (size_t i = 1u; i < sizeof(e.packet); ++i) e.packet[i] = (uint8_t)i;
    if (mode == CLOSE_READ || mode == FLOOD) {
        e.input_count = 64u; for (size_t i = 0u; i < 64u; ++i) memcpy(e.input[i], e.packet, sizeof(e.packet));
    }
    CHECK(uv_mutex_init(&e.mutex) == 0 && uv_cond_init(&e.condition) == 0);
    CHECK(solaris_test_event_init(&e.ready, 0u) == 0 && solaris_test_event_init(&e.done, 0u) == 0 &&
        solaris_test_event_init(&e.entered, 0u) == 0 && solaris_test_event_init(&e.blocked, 0u) == 0 &&
        solaris_test_event_init(&e.received, 0u) == 0 && solaris_test_event_init(&e.writable, 0u) == 0);
    solaris_runtime_services_init(&e.services); e.services.context = &e; e.services.allocate = allocate_memory;
    CHECK(solaris_budget_create(4u * 1024u * 1024u, &e.services, &e.budget) == SOLARIS_OK);
    solaris_executor_options_t options = {.budget = e.budget, .services = &e.services, .queue_capacity = 8u, .resource_limit = 64u};
    CHECK(solaris_executor_create(&options, &e.owner) == SOLARIS_OK && solaris_executor_activate(e.owner, 1u) == SOLARIS_OK);
    CHECK(solaris_executor_post(e.owner, start, &e) == SOLARIS_OK); solaris_test_event_wait(&e.ready);
    if (mode == RING_ECHO || mode == CLOSE_QUEUE || mode == STOP_QUEUE) {
        solaris_test_event_wait(&e.blocked);
        if (mode == RING_ECHO) {
            uv_mutex_lock(&e.mutex); e.full = 0; uv_mutex_unlock(&e.mutex);
            solaris_test_event_wait(&e.received); solaris_test_event_wait(&e.writable);
            CHECK(solaris_executor_post(e.owner, finish, &e) == SOLARIS_OK);
        } else if (mode == CLOSE_QUEUE) CHECK(solaris_executor_post(e.owner, finish, &e) == SOLARIS_OK);
        else CHECK(solaris_executor_begin_quiesce(e.owner) == SOLARIS_OK);
    } else if (mode == STOP_WAIT) {
        solaris_test_event_wait(&e.entered); CHECK(solaris_executor_begin_quiesce(e.owner) == SOLARIS_OK);
    } else if (mode == FLOOD) {
        solaris_test_event_wait(&e.received); CHECK(solaris_executor_post(e.owner, finish, &e) == SOLARIS_OK);
    }
    solaris_test_event_wait(&e.done);
    CHECK(solaris_executor_quiesce(e.owner) == SOLARIS_OK && solaris_executor_destroy(e.owner) == SOLARIS_OK);
    CHECK(e.driver_closes == 1u && !e.wait_active && !e.borrowed);
    if (mode == ALLOCATE_ERROR) CHECK(e.closes == 0u && e.interrupts == 0u);
    else {
        CHECK(e.closes == 1u && e.interrupts == 1u);
        CHECK(e.status == (mode == STOP_QUEUE || mode == STOP_WAIT ? SOLARIS_ECANCELLED : mode == WAIT_ERROR || mode == RECEIVE_ERROR || mode == SEND_ERROR ? SOLARIS_EIO : SOLARIS_OK));
        CHECK(e.packets == (mode == FLOOD ? 64u : mode == RING_ECHO || mode == CLOSE_READ ? 1u : 0u) && e.releases == e.packets);
        CHECK(e.sends == (mode == RING_ECHO ? 1u : 0u) && e.writable_count == (mode == RING_ECHO ? 1u : 0u));
    }
    CHECK(solaris_budget_used(e.budget) == 0u); solaris_budget_release(e.budget);
    solaris_test_event_destroy(&e.ready); solaris_test_event_destroy(&e.done); solaris_test_event_destroy(&e.entered);
    solaris_test_event_destroy(&e.blocked); solaris_test_event_destroy(&e.received); solaris_test_event_destroy(&e.writable);
    uv_cond_destroy(&e.condition); uv_mutex_destroy(&e.mutex);
}
int main(void)
{
    for (int mode = RING_ECHO; mode <= ALLOCATE_ERROR; ++mode) run(mode);
    /* Cancellation may win before the worker enters its native wait, or
     * overlap its final async wake. Both paths must precede handle release. */
    for (unsigned int i = 0u; i < 32u; ++i) run(IMMEDIATE_CLOSE);
    puts("Wintun ring: bounded retry/backpressure, wait thread wake, owner delivery, release-before-close, stop and injected failures passed"); return 0;
}
