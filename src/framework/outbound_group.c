#include "aproxy/outbound_group.h"

#include <stdlib.h>
#include <string.h>

typedef struct outbound_group_impl {
    char *tag;
    aproxy_outbound_t **members;
    size_t member_count;
    size_t next_member;
    aproxy_outbound_group_mode_t mode;
} outbound_group_impl_t;

static char *copy_string(const char *s)
{
    if (s == NULL) {
        return NULL;
    }
    const size_t len = strlen(s);
    char *copy = (char *)malloc(len + 1u);
    if (copy == NULL) {
        return NULL;
    }
    memcpy(copy, s, len + 1u);
    return copy;
}

static int group_connect(void *impl_ptr)
{
    outbound_group_impl_t *impl = (outbound_group_impl_t *)impl_ptr;
    if (impl == NULL || impl->member_count == 0u) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }

    int first_error = APROXY_OK;
    for (size_t i = 0u; i < impl->member_count; i++) {
        const int rc = aproxy_outbound_connect(impl->members[i]);
        if (rc != APROXY_OK && first_error == APROXY_OK) {
            first_error = rc;
        }
    }
    return first_error;
}

static int group_open_stream(void *impl_ptr,
                             const aproxy_addr_t *destination,
                             aproxy_stream_data_cb on_data,
                             aproxy_stream_event_cb on_open,
                             aproxy_stream_event_cb on_close,
                             void *user_data,
                             aproxy_stream_t **out)
{
    outbound_group_impl_t *impl = (outbound_group_impl_t *)impl_ptr;
    if (impl == NULL || destination == NULL || out == NULL ||
        impl->member_count == 0u) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }

    *out = NULL;
    int first_error = APROXY_ERR_INVALID_ARGUMENT;
    int have_error = 0;
    const size_t start = impl->next_member % impl->member_count;
    for (size_t attempt = 0u; attempt < impl->member_count; attempt++) {
        const size_t index = (start + attempt) % impl->member_count;
        aproxy_stream_t *stream = NULL;
        const int rc = aproxy_outbound_open_stream(
            impl->members[index], destination, on_data, on_open, on_close,
            user_data, &stream);
        if (rc == APROXY_OK) {
            impl->next_member = (index + 1u) % impl->member_count;
            *out = stream;
            return APROXY_OK;
        }
        if (stream != NULL) {
            aproxy_stream_free(stream);
        }
        if (!have_error) {
            first_error = rc;
            have_error = 1;
        }
    }
    return first_error;
}

static int group_open_packet(void *impl_ptr,
                             const aproxy_addr_t *initial_destination,
                             aproxy_packet_flow_data_cb on_data,
                             aproxy_packet_flow_event_cb on_open,
                             aproxy_packet_flow_event_cb on_close,
                             void *user_data,
                             aproxy_packet_flow_t **out)
{
    outbound_group_impl_t *impl = (outbound_group_impl_t *)impl_ptr;
    if (impl == NULL || initial_destination == NULL || out == NULL ||
        impl->member_count == 0u) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }

    *out = NULL;
    int first_error = APROXY_ERR_INVALID_ARGUMENT;
    int have_error = 0;
    const size_t start = impl->next_member % impl->member_count;
    for (size_t attempt = 0u; attempt < impl->member_count; attempt++) {
        const size_t index = (start + attempt) % impl->member_count;
        aproxy_packet_flow_t *flow = NULL;
        const int rc = aproxy_outbound_open_packet(
            impl->members[index], initial_destination, on_data, on_open,
            on_close, user_data, &flow);
        if (rc == APROXY_OK) {
            impl->next_member = (index + 1u) % impl->member_count;
            *out = flow;
            return APROXY_OK;
        }
        if (flow != NULL) {
            aproxy_packet_flow_free(flow);
        }
        if (!have_error) {
            first_error = rc;
            have_error = 1;
        }
    }
    return first_error;
}

static void group_close(void *impl_ptr)
{
    outbound_group_impl_t *impl = (outbound_group_impl_t *)impl_ptr;
    if (impl == NULL) {
        return;
    }
    for (size_t i = 0u; i < impl->member_count; i++) {
        aproxy_outbound_close(impl->members[i]);
    }
}

static void group_free(void *impl_ptr)
{
    outbound_group_impl_t *impl = (outbound_group_impl_t *)impl_ptr;
    if (impl == NULL) {
        return;
    }
    free(impl->members);
    free(impl->tag);
    free(impl);
}

static const aproxy_outbound_vtable_t outbound_group_vtable = {
    .connect = group_connect,
    .open_stream = group_open_stream,
    .open_packet = group_open_packet,
    .close = group_close,
    .free = group_free,
};

int aproxy_outbound_group_new(const aproxy_outbound_group_config_t *config,
                              aproxy_outbound_t **out)
{
    if (config == NULL || out == NULL || config->members == NULL ||
        config->member_count == 0u ||
        config->mode != APROXY_OUTBOUND_GROUP_ROUND_ROBIN) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    *out = NULL;

    for (size_t i = 0u; i < config->member_count; i++) {
        if (config->members[i] == NULL ||
            config->members[i]->udp_transport !=
                config->members[0]->udp_transport ||
            (config->members[i]->udp_transport == APROXY_OUTBOUND_UDP_UOT &&
             config->members[i]->uot_version !=
                 config->members[0]->uot_version)) {
            return APROXY_ERR_INVALID_ARGUMENT;
        }
    }

    aproxy_outbound_t *outbound =
        (aproxy_outbound_t *)calloc(1u, sizeof(*outbound));
    if (outbound == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }

    outbound_group_impl_t *impl =
        (outbound_group_impl_t *)calloc(1u, sizeof(*impl));
    if (impl == NULL) {
        free(outbound);
        return APROXY_ERR_NO_MEMORY;
    }
    impl->members =
        (aproxy_outbound_t **)malloc(sizeof(*impl->members) *
                                     config->member_count);
    if (impl->members == NULL) {
        free(impl);
        free(outbound);
        return APROXY_ERR_NO_MEMORY;
    }
    memcpy(impl->members, config->members,
           sizeof(*impl->members) * config->member_count);
    impl->member_count = config->member_count;
    impl->mode = config->mode;
    impl->tag = copy_string(config->tag != NULL ? config->tag : "group");
    if (impl->tag == NULL) {
        free(impl->members);
        free(impl);
        free(outbound);
        return APROXY_ERR_NO_MEMORY;
    }

    outbound->tag = impl->tag;
    outbound->vtable = &outbound_group_vtable;
    outbound->impl = impl;
    outbound->udp_transport = config->members[0]->udp_transport;
    outbound->uot_version = config->members[0]->uot_version;
    *out = outbound;
    return APROXY_OK;
}
