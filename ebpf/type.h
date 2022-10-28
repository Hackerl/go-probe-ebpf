#ifndef GO_PROBE_EBPF_TYPE_H
#define GO_PROBE_EBPF_TYPE_H

#include <linux/types.h>

typedef signed char GoInt8;
typedef unsigned char GoUint8;
typedef short GoInt16;
typedef unsigned short GoUint16;
typedef int GoInt32;
typedef unsigned int GoUint32;
typedef long long GoInt64;
typedef unsigned long long GoUint64;
typedef GoInt64 GoInt;
typedef GoUint64 GoUint;
typedef __SIZE_TYPE__ GoUintptr;
typedef float GoFloat32;
typedef double GoFloat64;
typedef float _Complex GoComplex64;
typedef double _Complex GoComplex128;

typedef struct {
    void *t;
    void *v;
} GoInterface;

typedef struct {
    void *data;
    GoInt len;
    GoInt cap;
} GoSlice;

typedef struct {
    const char *p;
    ptrdiff_t n;
} GoString;

typedef struct {
    GoString path;
    GoSlice args;
} GoExecCmd;

#endif //GO_PROBE_EBPF_TYPE_H
