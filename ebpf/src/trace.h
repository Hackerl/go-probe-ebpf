#ifndef GO_PROBE_EBPF_TRACE_H
#define GO_PROBE_EBPF_TRACE_H

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include "event.h"
#include "macro.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, uintptr_t);
    __type(value, int);
} frame_map SEC(".maps");

#ifdef USE_RING_BUFFER
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");
#else
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, go_probe_event);
    __uint(max_entries, 1);
} cache SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");
#endif

static __always_inline int traceback(go_probe_event *event, uintptr_t sp) {
    uintptr_t pc;
    int frame_size = 0;

    UNROLL_LOOP
    for (int i = 0; i < TRACE_COUNT; i++) {
        if (bpf_probe_read_user(&pc, sizeof(uintptr_t), (void *) (sp + frame_size)) < 0)
            return -1;

        event->stack_trace[i] = pc;

        int *v = bpf_map_lookup_elem(&frame_map, &pc);

        if (!v) {
            if (i == TRACE_COUNT - 1)
                break;

            event->stack_trace[i + 1] = 0;
            break;
        }

        frame_size += *v + (int) sizeof(uintptr_t);
    }

    return 0;
}

static __always_inline go_probe_event *new_event(int class_id, int method_id, int count) {
#ifdef USE_RING_BUFFER
    go_probe_event *event = bpf_ringbuf_reserve(&events, sizeof(go_probe_event), 0);
#else
    __u32 index = 0;
    go_probe_event *event = bpf_map_lookup_elem(&cache, &index);
#endif
    if (!event)
        return NULL;

    event->pid = (int) (bpf_get_current_pid_tgid() >> 32);
    event->class_id = class_id;
    event->method_id = method_id;
    event->count = count;

    UNROLL_LOOP
    for (int i = 0; i < count; i++)
        event->args[i][0] = 0;

    return event;
}

static __always_inline void free_event(go_probe_event *event) {
#ifdef USE_RING_BUFFER
    bpf_ringbuf_discard(event, 0);
#endif
}

static __always_inline void submit_event(struct pt_regs *ctx, go_probe_event *event) {
    if (traceback(event, PT_REGS_RET(ctx)) < 0) {
        free_event(event);
        return;
    }

#ifdef USE_RING_BUFFER
    bpf_ringbuf_submit(event, 0);
#else
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(go_probe_event));
#endif
}

#endif //GO_PROBE_EBPF_TRACE_H
