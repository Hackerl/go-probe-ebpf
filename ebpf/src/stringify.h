#ifndef GO_PROBE_EBPF_STRINGIFY_H
#define GO_PROBE_EBPF_STRINGIFY_H

#include "type.h"
#include "event.h"
#include "macro.h"
#include <bpf/bpf_helpers.h>

#define SLICE_MAX_COUNT 10

static __always_inline int stringify_string(string *str, char *buffer, size_t size) {
    if (!str->data || str->length <= 0)
        return 0;

    __u32 length;
    __u32 remain = size - 1;

    if (str->length > remain)
        length = remain;
    else
        length = str->length;

    if (bpf_probe_read_user(buffer, BOUND(length, ARG_LENGTH), str->data) < 0)
        return -1;

    buffer[BOUND(length, ARG_LENGTH)] = 0;

    return (int) length;
}

static __always_inline int stringify_string_slice(slice *s, char *buffer, size_t size) {
    if (!s->data || !s->count)
        return 0;

    size_t length = 0;

#pragma unroll
    for (int i = 0; i < SLICE_MAX_COUNT * 2 - 1; i++) {
        if (i >= s->count * 2 - 1 || length >= size - 1)
            break;

        if (i % 2) {
            buffer[BOUND(length++, ARG_LENGTH)] = ' ';
            continue;
        }

        string str;

        if (bpf_probe_read_user(&str, sizeof(string), (string *) s->data + i/2) < 0)
            return -1;

        int n = stringify_string(&str, buffer + BOUND(length, ARG_LENGTH), size - BOUND(length, ARG_LENGTH));

        if (n < 0)
            break;

        length += n;
    }

    buffer[BOUND(length, ARG_LENGTH)] = 0;

    return (int) length;
}

#endif //GO_PROBE_EBPF_STRINGIFY_H
