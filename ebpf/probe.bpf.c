#include "type.h"
#include "probe.h"
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_LENGTH(length, limit) (length < limit ? (length & (limit - 1)) : limit)

#ifdef BPF_NO_GLOBAL_DATA
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, int);
} config_map SEC(".maps");
#else
bool register_based = false;
#endif

static bool is_register_based() {
#ifdef BPF_NO_GLOBAL_DATA
    u32 index = 0;
    int *config = bpf_map_lookup_elem(&config_map, &index);

    if (!config)
        return false;

    return *config;
#else
    return register_based;
#endif
}

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

static char *next_slot(struct go_probe_event *event) {
    int index = event->count++;
    char *p = event->args[MAX_LENGTH(index, ARG_COUNT)];

    __builtin_memset(p, 0, ARG_LENGTH);

    return p;
}

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

SEC("uprobe/cmd_start")
int cmd_start(struct pt_regs *ctx) {
    struct GoExecCmd *receiver;

    if (is_register_based()) {
        receiver = (struct GoExecCmd *) PT_REGS_RC(ctx);
    } else {
        if (bpf_probe_read_user(&receiver, sizeof(struct cmd *), (void *) (PT_REGS_SP(ctx) + sizeof(long))) < 0)
            return 0;
    }

    GoExecCmd cmd;

    if (bpf_probe_read_user(&cmd, sizeof(GoExecCmd), (void *)receiver) < 0)
        return 0;

    if (!cmd.path.p || !cmd.path.n)
        return 0;

    struct go_probe_event *event = new_event();

    if (!event)
        return 0;

    event->class_id = 0;
    event->method_id = 0;

    if (bpf_probe_read_user(next_slot(event), MAX_LENGTH(cmd.path.n, ARG_LENGTH), cmd.path.p) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, event);

    return 0;
}
