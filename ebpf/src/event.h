#ifndef GO_PROBE_EBPF_EVENT_H
#define GO_PROBE_EBPF_EVENT_H

#include <stdint.h>

#define ARG_COUNT 4
#define ARG_LENGTH 256
#define SHORT_ARG_LENGTH 32
#define TRACE_COUNT 20
#define HEADER_COUNT 8

typedef struct {
    char method[SHORT_ARG_LENGTH];
    char uri[ARG_LENGTH];
    char host[SHORT_ARG_LENGTH];
    char remote[SHORT_ARG_LENGTH];
    char headers[HEADER_COUNT][2][SHORT_ARG_LENGTH];
} go_probe_request;

typedef struct {
    int pid;
    int count;
    int class_id;
    int method_id;
    char args[ARG_COUNT][ARG_LENGTH];
    uintptr_t stack_trace[TRACE_COUNT];
#ifdef ENABLE_HTTP
    go_probe_request request;
#endif
} go_probe_event;

#endif //GO_PROBE_EBPF_EVENT_H
