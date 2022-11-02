#ifndef GO_PROBE_EBPF_STRINGIFY_H
#define GO_PROBE_EBPF_STRINGIFY_H

#include "type.h"
#include "event.h"
#include <bpf/bpf_helpers.h>

#define SLICE_MAX_COUNT 10

static int stringify_string(string *str, char *buffer, size_t size) {
    if (!str->data || str->length <= 0)
        return 0;

    size_t length = MAX_LENGTH(str->length, ARG_LENGTH);
    length = length < size - 1 ? length : size - 1;

    if (bpf_probe_read_user(buffer, length, str->data) < 0)
        return -1;

    return (int) length;
}

static int stringify_string_slice(slice *s, char *buffer, size_t size) {
    if (!s->data || !s->count)
        return 0;

    size_t length = 0;

#pragma unroll
    for (int i = 0; i < SLICE_MAX_COUNT * 2 - 1; i++) {
        if (i >= s->count * 2 - 1 || length >= size - 1)
            break;

        if (i % 2) {
            buffer[length++] = ' ';
            continue;
        }

        string str;

        if (bpf_probe_read_user(&str, sizeof(string), (string *) s->data + i/2) < 0)
            return -1;

        int n = stringify_string(&str, buffer + length, size - length);

        if (n < 0)
            break;

        length += n;
    }

    return (int) length;
}

#endif //GO_PROBE_EBPF_STRINGIFY_H
