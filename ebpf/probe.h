#ifndef PROBE_H
#define PROBE_H

#define ARG_COUNT 16
#define ARG_LENGTH 256
#define TRACE_COUNT 20
#define MAX_LENGTH(length, limit) (length < limit ? (length & (limit - 1)) : limit)

struct event {
    int pid;
    int count;
    int class_id;
    int method_id;
    char args[ARG_COUNT][ARG_LENGTH];
    unsigned long stack_trace[TRACE_COUNT];
};

#endif //PROBE_H
