#ifndef GO_PROBE_EBPF_TRACE_H
#define GO_PROBE_EBPF_TRACE_H

#if __KERNEL__
#include <linux/bpf.h>
#include <linux/ptrace.h>
#endif

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
    __type(key, u32);
    __type(value, struct go_probe_event);
    __uint(max_entries, 1);
} cache SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");
#endif

static int traceback(struct go_probe_event *event, uintptr_t sp) {
    uintptr_t pc;
    int frame_size = 0;

#pragma unroll
    for (int i = 0; i < TRACE_COUNT; i++) {
        if (bpf_probe_read_user(&pc, sizeof(uintptr_t), (void *) (sp + frame_size)) < 0)
            return -1;

        event->stack_trace[i] = pc;

        int *v = bpf_map_lookup_elem(&frame_map, &pc);

        if (!v)
            break;

        frame_size += *v + (int) sizeof(uintptr_t);
    }

    return 0;
}

static struct go_probe_event *new_event() {
#ifdef USE_RING_BUFFER
    struct go_probe_event *event = bpf_ringbuf_reserve(&events, sizeof(struct go_probe_event), 0);
#else
    u32 index = 0;
    struct go_probe_event* event = bpf_map_lookup_elem(&cache, &index);
#endif
    if (!event)
        return NULL;

    event->pid = (int) (bpf_get_current_pid_tgid() >> 32);
    event->count = 0;

    return event;
}

static void free_event(struct go_probe_event *event) {
#ifdef USE_RING_BUFFER
    bpf_ringbuf_discard(event, 0);
#endif
}

static void submit_event(struct pt_regs *ctx, struct go_probe_event *event) {
    __builtin_memset(event->stack_trace, 0, sizeof(event->stack_trace));

    if (traceback(event, PT_REGS_RET(ctx)) < 0) {
        free_event(event);
        return;
    }

#ifdef USE_RING_BUFFER
    bpf_ringbuf_submit(event, 0);
#else
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(struct go_probe_event));
#endif
}

#endif //GO_PROBE_EBPF_TRACE_H
