#ifndef GO_PROBE_EBPF_EVENT_H
#define GO_PROBE_EBPF_EVENT_H

#include <stdint.h>

#define ARG_COUNT 16
#define ARG_LENGTH 256
#define TRACE_COUNT 20

struct go_probe_event {
    int pid;
    int count;
    int class_id;
    int method_id;
    char args[ARG_COUNT][ARG_LENGTH];
    uintptr_t stack_trace[TRACE_COUNT];
};

#endif //GO_PROBE_EBPF_EVENT_H
