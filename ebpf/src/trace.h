#ifndef GO_PROBE_EBPF_TRACE_H
#define GO_PROBE_EBPF_TRACE_H

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include "event.h"
#include "macro.h"
#include "config.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, uintptr_t);
    __type(value, int);
} frame_map SEC(".maps");

#ifdef ENABLE_HTTP
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, uintptr_t);
    __type(value, go_probe_request);
} request_map SEC(".maps");
#endif

#if ENABLE_HTTP || !USE_RING_BUFFER
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __uint(value_size, 4096);
    __uint(max_entries, 1);
} cache SEC(".maps");
#endif

#ifdef USE_RING_BUFFER
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");
#else
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");
#endif

static __always_inline uintptr_t get_g(struct pt_regs *ctx) {
    uintptr_t g = GO_REGS_ABI_0_G(ctx);

    if (is_register_based())
        g = GO_REGS_G(ctx);

    return g;
}

static __always_inline void *get_cache() {
    __u32 index = 0;
    return bpf_map_lookup_elem(&cache, &index);
}

static __always_inline int traceback_with_fp(struct pt_regs *ctx, go_probe_event *event) {
    if (bpf_probe_read_user(event->stack_trace, sizeof(uintptr_t), (void *) PT_REGS_RET(ctx)) < 0)
        return -1;

    uintptr_t fp = PT_REGS_FP(ctx);

    UNROLL_LOOP
    for (int i = 1; i < TRACE_COUNT; i++) {
        if (!fp) {
            event->stack_trace[i] = 0;
            break;
        }

        if (bpf_probe_read_user(event->stack_trace + i, sizeof(uintptr_t), (void *) fp + sizeof(uintptr_t)) < 0)
            break;

        if (!event->stack_trace[i])
            break;

        if (bpf_probe_read_user(&fp, sizeof(uintptr_t), (void *) fp) < 0)
            break;
    }

    return 0;
}

static __always_inline int traceback(struct pt_regs *ctx, go_probe_event *event) {
    uintptr_t pc;
    uintptr_t sp = PT_REGS_RET(ctx);

    UNROLL_LOOP
    for (int i = 0; i < TRACE_COUNT; i++) {
        if (bpf_probe_read_user(&pc, sizeof(uintptr_t), (void *) sp) < 0)
            break;

        event->stack_trace[i] = pc;

        int *v = bpf_map_lookup_elem(&frame_map, &pc);

        if (!v) {
            if (i != TRACE_COUNT - 1)
                event->stack_trace[i + 1] = 0;

            break;
        }

        sp += *v + (int) sizeof(uintptr_t);
    }

    return 0;
}

static __always_inline go_probe_event *new_event(int class_id, int method_id, int count) {
#ifdef USE_RING_BUFFER
    go_probe_event *event = bpf_ringbuf_reserve(&events, sizeof(go_probe_event), 0);
#else
    go_probe_event *event = get_cache();
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

#ifdef ENABLE_HTTP
    event->request.method[0] = 0;
    event->request.uri[0] = 0;
    event->request.host[0] = 0;
    event->request.remote[0] = 0;
    event->request.headers[0][0][0] = 0;
#endif

    return event;
}

static __always_inline void free_event(go_probe_event *event) {
#ifdef USE_RING_BUFFER
    bpf_ringbuf_discard(event, 0);
#endif
}

static __always_inline void submit_event(struct pt_regs *ctx, go_probe_event *event) {
    if ((has_frame_pointer() ? traceback_with_fp(ctx, event) : traceback(ctx, event)) < 0) {
        free_event(event);
        return;
    }

#ifdef ENABLE_HTTP
    uintptr_t g = get_g(ctx);

    go_probe_request *request = bpf_map_lookup_elem(&request_map, &g);

    if (request)
        __builtin_memcpy(&event->request, request, sizeof(go_probe_request));

    event->g = g;
#endif

#ifdef USE_RING_BUFFER
    bpf_ringbuf_submit(event, 0);
#else
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(go_probe_event));
#endif
}

#endif //GO_PROBE_EBPF_TRACE_H
