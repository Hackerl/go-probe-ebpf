#ifndef GO_PROBE_EBPF_TYPE_H
#define GO_PROBE_EBPF_TYPE_H

#include <stddef.h>

typedef signed char go_int8;
typedef unsigned char go_uint8;
typedef short go_int16;
typedef unsigned short go_uint16;
typedef int go_int32;
typedef unsigned int go_uint32;
typedef long long go_int64;
typedef unsigned long long go_uint64;
typedef go_int64 go_int;
typedef go_uint64 go_uint;
typedef __SIZE_TYPE__ go_uintptr;
typedef float go_float32;
typedef double go_float64;
typedef float _Complex go_complex64;
typedef double _Complex go_complex128;

typedef struct {
    void *t;
    void *v;
} interface;

typedef struct {
    void *data;
    go_int count;
    go_int capacity;
} slice;

typedef struct {
    const char *data;
    size_t length;
} string;

typedef struct {
    string path;
    slice args;
} os_exec_cmd;

#endif //GO_PROBE_EBPF_TYPE_H
