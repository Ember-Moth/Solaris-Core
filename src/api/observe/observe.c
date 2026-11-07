#include "api/common/error.h"
#include "runtime/config/manager.h"
#include "runtime/operation/request.h"
#include <solaris/observe.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>

struct solaris_connection_list {
  atomic_size_t references;
  size_t count;
  solaris_connection_info_t entries[];
};

static void endpoint(const solaris_address_t *source, solaris_endpoint_t *out) {
  memset(out, 0, sizeof(*out));
  if (source->family == SOLARIS_ADDRESS_DOMAIN) {
    memcpy(out->host, source->host, sizeof(out->host) - 1);
  } else if (source->family == SOLARIS_ADDRESS_IPV4 ||
             source->family == SOLARIS_ADDRESS_IPV6) {
    int family = source->family == SOLARIS_ADDRESS_IPV4 ? AF_INET : AF_INET6;
    if (uv_inet_ntop(family, source->ip, out->host, sizeof(out->host)))
      return;
    if (source->family == SOLARIS_ADDRESS_IPV6 && source->scope_id) {
      size_t used = strlen(out->host);
      (void)snprintf(out->host + used, sizeof(out->host) - used, "%%%u",
                     (unsigned)source->scope_id);
    }
  } else
    return;
  out->port = source->port;
}
static void connection(const solaris_connection_snapshot_t *source,
                       solaris_connection_info_t *out) {
  memset(out, 0, sizeof(*out));
  out->key = (solaris_connection_id_t){source->generation, source->id};
#define COPY(field) out->field = source->field
  COPY(config_revision);
  COPY(selection_revision);
  COPY(inbound_id);
  COPY(rule_index);
  COPY(node_id);
  COPY(worker_id);
  COPY(kind);
  COPY(purpose);
  COPY(state);
  COPY(created_ns);
  COPY(opened_ns);
  COPY(closed_ns);
  COPY(bytes_read);
  COPY(bytes_written);
  COPY(packets_read);
  COPY(packets_written);
  COPY(accepted_writes);
  COPY(write_failures);
  COPY(rejections);
  COPY(pending_bytes);
  COPY(pending_requests);
  COPY(active_channels);
  COPY(status);
#undef COPY
  endpoint(&source->source, &out->source);
  endpoint(&source->target, &out->logical_target);
  endpoint(&source->dial_target, &out->dial_target);
  endpoint(&source->last_destination, &out->last_destination);
  endpoint(&source->last_peer, &out->last_peer);
}
solaris_status_t solaris_engine_get_connections(solaris_engine_t *engine,
                                                int include_closed,
                                                solaris_connection_list_t **out,
                                                solaris_error_t *error) {
  if (out)
    *out = NULL;
  if (!engine || !out || (include_closed != 0 && include_closed != 1))
    return solaris_error_set(error, SOLARIS_EINVAL, 0, NULL);
  solaris_config_manager_t *manager = solaris_config_manager_find(engine);
  solaris_tracker_t *tracker =
      manager ? solaris_config_manager_tracker(manager) : NULL;
  solaris_connection_snapshot_t *copy = NULL;
  size_t count = 0;
  solaris_status_t rc =
      tracker ? solaris_tracker_capture(tracker, include_closed, &copy, &count)
              : SOLARIS_OK;
  if (rc != SOLARIS_OK)
    return solaris_error_set(error, rc, 0, NULL);
  if (count > (SIZE_MAX - sizeof(solaris_connection_list_t)) /
                  sizeof(solaris_connection_info_t)) {
    solaris_tracker_capture_free(copy);
    return solaris_error_set(error, SOLARIS_EOVERFLOW, 0, NULL);
  }
  /* Public snapshots must outlive the engine's injected allocator context. */
  solaris_connection_list_t *list =
      calloc(1, sizeof(*list) + count * sizeof(*list->entries));
  if (!list) {
    solaris_tracker_capture_free(copy);
    return solaris_error_set(error, SOLARIS_ENOMEM, 0, NULL);
  }
  atomic_init(&list->references, 1);
  list->count = count;
  for (size_t i = 0; i < count; ++i)
    connection(&copy[i], &list->entries[i]);
  solaris_tracker_capture_free(copy);
  *out = list;
  return solaris_error_set(error, SOLARIS_OK, 0, NULL);
}
void solaris_connection_list_retain(solaris_connection_list_t *list) {
  if (list)
    atomic_fetch_add_explicit(&list->references, 1, memory_order_relaxed);
}
void solaris_connection_list_release(solaris_connection_list_t *list) {
  if (list && atomic_fetch_sub_explicit(&list->references, 1,
                                        memory_order_acq_rel) == 1)
    free(list);
}
size_t solaris_connection_list_count(const solaris_connection_list_t *list) {
  return list ? list->count : 0;
}
solaris_status_t
solaris_connection_list_get(const solaris_connection_list_t *list, size_t index,
                            solaris_connection_info_t *out) {
  if (!list || !out || index >= list->count)
    return SOLARIS_EINVAL;
  *out = list->entries[index];
  return SOLARIS_OK;
}
solaris_status_t solaris_engine_get_connection(
    solaris_engine_t *engine, const solaris_connection_id_t *id,
    solaris_connection_info_t *out, solaris_error_t *error) {
  if (out)
    memset(out, 0, sizeof(*out));
  if (!engine || !id || !id->generation || !id->id || !out)
    return solaris_error_set(error, SOLARIS_EINVAL, 0, NULL);
  solaris_config_manager_t *manager = solaris_config_manager_find(engine);
  solaris_tracker_t *tracker =
      manager ? solaris_config_manager_tracker(manager) : NULL;
  solaris_connection_snapshot_t copy;
  solaris_status_t rc = tracker
                            ? solaris_tracker_snapshot_key(tracker, id, &copy)
                            : SOLARIS_ECLOSED;
  if (rc == SOLARIS_OK)
    connection(&copy, out);
  return solaris_error_set(error, rc, 0, NULL);
}
solaris_status_t solaris_engine_get_traffic(solaris_engine_t *engine,
                                            solaris_traffic_info_t *out,
                                            solaris_error_t *error) {
  if (out)
    memset(out, 0, sizeof(*out));
  if (!engine || !out)
    return solaris_error_set(error, SOLARIS_EINVAL, 0, NULL);
  solaris_config_manager_t *manager = solaris_config_manager_find(engine);
  if (manager) {
    solaris_tracker_t *tracker = solaris_config_manager_tracker(manager);
    for (uint32_t i = 0; i < SOLARIS_FLOW_PURPOSE_COUNT; ++i) {
      solaris_tracker_totals_t source;
      solaris_status_t rc = solaris_tracker_totals(tracker, i, &source);
      if (rc != SOLARIS_OK)
        return solaris_error_set(error, rc, 0, NULL);
#define COPY(field) out->logical[i].field = source.field
      COPY(created);
      COPY(opened);
      COPY(closed);
      COPY(active);
      COPY(open_failures);
      COPY(bytes_read);
      COPY(bytes_written);
      COPY(packets_read);
      COPY(packets_written);
      COPY(accepted_writes);
      COPY(write_failures);
      COPY(rejections);
#undef COPY
    }
    solaris_traffic_snapshot_t source;
    solaris_status_t rc = solaris_traffic_counter_snapshot(
        solaris_config_manager_traffic(manager), &source);
    if (rc != SOLARIS_OK)
      return solaris_error_set(error, rc, 0, NULL);
#define COPY(field) out->physical.field = source.field
    COPY(stream_read);
    COPY(stream_written);
    COPY(datagram_read);
    COPY(datagram_written);
    COPY(packets_read);
    COPY(packets_written);
    COPY(saturated);
#undef COPY
  }
  out->sampled_ns = uv_hrtime();
  return solaris_error_set(error, SOLARIS_OK, 0, NULL);
}

typedef struct close_request {
  solaris_runtime_operation_t *operation;
  solaris_connection_id_t key;
  solaris_connections_close_callback_t callback;
  void *context;
  uint64_t matched;
  int single;
} close_request_t;
static void closed(void *context, solaris_status_t status, uint64_t matched) {
  close_request_t *request = context;
  request->matched = matched;
  /* Complete only after the captured records drain. A cancellation can change
   * the reported status, but cannot undo closes; matched still reports them. */
  solaris_runtime_operation_complete(request->operation, status, 0);
}
static solaris_status_t close_start(void *context, solaris_engine_t *engine,
                                    solaris_runtime_operation_t *operation) {
  close_request_t *request = context;
  request->operation = operation;
  if (solaris_runtime_operation_cancelled(operation))
    return SOLARIS_ECANCELLED;
  solaris_config_manager_t *manager = solaris_config_manager_find(engine);
  solaris_tracker_t *tracker =
      manager ? solaris_config_manager_tracker(manager) : NULL;
  if (!tracker) {
    if (request->single)
      return SOLARIS_ECLOSED;
    closed(request, SOLARIS_OK, 0);
    return SOLARIS_OK;
  }
  return solaris_tracker_close_current(
      tracker, request->single ? &request->key : NULL, closed, request);
}
static void close_complete(void *context, solaris_status_t status,
                           uint64_t revision) {
  close_request_t *request = context;
  (void)revision;
  solaris_error_t error;
  (void)solaris_error_set(&error, status, 0, NULL);
  if (request->callback)
    request->callback(request->context, status, request->matched, &error);
}
static void close_dispose(void *context) { solaris_memory_free(context); }
static solaris_status_t
close_submit(solaris_engine_t *engine, const solaris_connection_id_t *id,
             solaris_connections_close_callback_t callback, void *context,
             uint64_t *operation_id, solaris_error_t *error) {
  if (operation_id)
    *operation_id = 0;
  if (!engine || !operation_id || (id && (!id->generation || !id->id)))
    return solaris_error_set(error, SOLARIS_EINVAL, 0, NULL);
  close_request_t *request =
      solaris_memory_allocate(solaris_runtime_budget(engine), sizeof(*request));
  if (!request)
    return solaris_error_set(error, SOLARIS_ENOMEM, 0, NULL);
  memset(request, 0, sizeof(*request));
  request->callback = callback;
  request->context = context;
  if (id) {
    request->single = 1;
    request->key = *id;
  }
  solaris_runtime_request_t operation = {
      .operation = SOLARIS_OPERATION_CLOSE_CONNECTIONS,
      .requires_running = 1,
      .context = request,
      .start = close_start,
      .complete = close_complete,
      .dispose = close_dispose};
  solaris_status_t rc =
      solaris_runtime_request_submit(engine, &operation, operation_id, error);
  if (rc != SOLARIS_OK)
    close_dispose(request);
  return rc;
}
solaris_status_t solaris_engine_close_connection(
    solaris_engine_t *engine, const solaris_connection_id_t *id,
    solaris_connections_close_callback_t callback, void *context,
    uint64_t *operation_id, solaris_error_t *error) {
  if (!id) {
    if (operation_id)
      *operation_id = 0;
    return solaris_error_set(error, SOLARIS_EINVAL, 0, NULL);
  }
  return close_submit(engine, id, callback, context, operation_id, error);
}
solaris_status_t solaris_engine_close_connections(
    solaris_engine_t *engine, solaris_connections_close_callback_t callback,
    void *context, uint64_t *operation_id, solaris_error_t *error) {
  return close_submit(engine, NULL, callback, context, operation_id, error);
}
