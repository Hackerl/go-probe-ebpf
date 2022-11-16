#ifndef GO_PROBE_EBPF_TRACE_H
#define GO_PROBE_EBPF_TRACE_H

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include "event.h"
#include "macro.h"

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

static __always_inline int traceback(struct pt_regs *ctx, go_probe_event *event) {
    if (bpf_probe_read_user(event->stack_trace, sizeof(uintptr_t), (void *) PT_REGS_RET(ctx)) < 0)
        return -1;

    uintptr_t fp = PT_REGS_FP(ctx);

    UNROLL_LOOP
    for (int i = 1; i < TRACE_COUNT; i++) {
        if (!fp)
            break;

        if (bpf_probe_read_user(event->stack_trace + i, sizeof(uintptr_t), (void *) fp + sizeof(uintptr_t)) < 0)
            break;

        if (!event->stack_trace[i])
            break;

        if (bpf_probe_read_user(&fp, sizeof(uintptr_t), (void *) fp) < 0)
            break;
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
    if (traceback(ctx, event) < 0) {
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
