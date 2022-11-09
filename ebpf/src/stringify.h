#ifndef GO_PROBE_EBPF_STRINGIFY_H
#define GO_PROBE_EBPF_STRINGIFY_H

#include "type.h"
#include "event.h"
#include "macro.h"
#include <bpf/bpf_helpers.h>
#include <sys/param.h>

#define SLICE_MAX_COUNT 10
#define INT64_STR_MAX_LENGTH 19
#define UINT64_STR_MAX_LENGTH 20

static __always_inline int stringify_go_uint64(go_uint64 num, char *buffer, size_t size) {
    size_t length = 0;
    go_uint64 n = num;

#pragma unroll
    for (int i = 0; i < UINT64_STR_MAX_LENGTH; i++) {
        length++;
        n /= 10;

        if (n == 0)
            break;
    }

    if (length >= size)
        return 0;

    n = num;

#pragma unroll
    for (int i = 0; i < UINT64_STR_MAX_LENGTH; i++) {
        buffer[BOUND(length - i - 1, ARG_LENGTH)] = n % 10 + '0';
        n /= 10;

        if (n == 0)
            break;
    }

    buffer[BOUND(length, ARG_LENGTH)] = 0;

    return (int) length;
}

static __always_inline int stringify_go_int64(go_int64 num, char *buffer, size_t size) {
    size_t length = 0;

    if (num < 0) {
        num = -num;
        buffer[BOUND(length++, ARG_LENGTH)] = '-';
    }

    go_int64 n = num;

#pragma unroll
    for (int i = 0; i < INT64_STR_MAX_LENGTH; i++) {
        length++;
        n /= 10;

        if (n == 0)
            break;
    }

    if (length >= size)
        return 0;

    n = num;

#pragma unroll
    for (int i = 0; i < INT64_STR_MAX_LENGTH; i++) {
        buffer[BOUND(length - i - 1, ARG_LENGTH)] = n % 10 + '0';
        n /= 10;

        if (n == 0)
            break;
    }

    buffer[BOUND(length, ARG_LENGTH)] = 0;

    return (int) length;
}

static __always_inline int stringify_string(string *str, char *buffer, size_t size) {
    if (!str->data || str->length == 0)
        return 0;

    volatile __u32 length = MIN(str->length, size - 1);

    if (bpf_probe_read_user(buffer, BOUND(length, ARG_LENGTH), str->data) < 0)
        return -1;

    buffer[BOUND(length, ARG_LENGTH)] = 0;

    return (int) length;
}

static __always_inline int stringify_string_slice(slice *s, char *buffer, size_t size) {
    if (!s->data || !s->count)
        return 0;

    volatile size_t length = 0;

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

static __always_inline int stringify_ip(slice *ip, char *buffer, size_t size) {
    if (ip->count != 4)
        return 0;

    unsigned char bytes[4];

    if (bpf_probe_read_user(&bytes, sizeof(bytes), ip->data) < 0)
        return -1;

    size_t length = 0;

#pragma unroll
    for (int i = 0; i < 4 * 2 - 1; i++) {
        if (length >= size - 1) {
            buffer[0] = 0;
            return 0;
        }

        if (i % 2) {
            buffer[BOUND(length++, ARG_LENGTH)] = '.';
            continue;
        }

        int n = stringify_go_uint64(bytes[i/2], buffer + BOUND(length, ARG_LENGTH), size - BOUND(length, ARG_LENGTH));

        if (n < 0)
            return -1;

        length += n;
    }

    buffer[BOUND(length, ARG_LENGTH)] = 0;

    return (int) length;
}

static __always_inline int stringify_tcp_address(tcp_address *address, char *buffer, size_t size) {
    size_t length = 0;

    int n = stringify_ip(&address->ip, buffer, size);

    if (n < 0)
        return -1;

    length += n;

    if (n >= size - 1) {
        buffer[BOUND(length, ARG_LENGTH)] = 0;
        return (int) length;
    }

    buffer[BOUND(length++, ARG_LENGTH)] = ':';

    n = stringify_go_uint64(address->port, buffer + BOUND(length, ARG_LENGTH), size - BOUND(length, ARG_LENGTH));

    if (n < 0)
        return -1;

    length += n;

    buffer[BOUND(length, ARG_LENGTH)] = 0;

    return (int) length;
}

static __always_inline int stringify_ip_address(ip_address *address, char *buffer, size_t size) {
    return stringify_ip(&address->ip, buffer, size);
}

static __always_inline int stringify_udp_address(udp_address *address, char *buffer, size_t size) {
    return stringify_tcp_address(address, buffer, size);
}

static __always_inline int stringify_unix_address(unix_address *address, char *buffer, size_t size) {
    size_t length = 0;

    int n = stringify_string(&address->name, buffer, size);

    if (n < 0)
        return -1;

    length += n;

    if (n >= size - 1 || !address->net.data || !address->net.length) {
        buffer[BOUND(length, ARG_LENGTH)] = 0;
        return (int) length;
    }

    buffer[BOUND(length++, ARG_LENGTH)] = ':';

    n = stringify_string(&address->net, buffer + BOUND(length, ARG_LENGTH), size - BOUND(length, ARG_LENGTH));

    if (n < 0)
        return -1;

    length += n;

    buffer[BOUND(length, ARG_LENGTH)] = 0;

    return (int) length;
}

#endif //GO_PROBE_EBPF_STRINGIFY_H
