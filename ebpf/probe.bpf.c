#include "probe.h"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, uintptr_t);
    __type(value, int);
} map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

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
typedef double _Complex go_Complex128;

struct go_string {
    const char *data;
    ptrdiff_t length;
} ;

struct go_slice {
    void *values;
    go_int count;
    go_int capacity;
};

struct cmd {
    struct go_string path;
    struct go_slice args;
};

static char *next(struct event *e) {
    int index = e->count++;
    char *p = e->args[MAX_LENGTH(index, ARG_COUNT)];

    __builtin_memset(p, 0, ARG_LENGTH);

    return p;
}

static int traceback(struct event *e, uintptr_t sp) {
    int frame_size = 0;

    for (int i = 0; i < TRACE_COUNT; i++) {
        if (bpf_probe_read_user(&e->stack_trace[i], sizeof(uintptr_t), (void *) (sp + frame_size)) < 0)
            return -1;

        int *v = bpf_map_lookup_elem(&map, &e->stack_trace[i]);

        if (!v)
            break;

        frame_size += *v + (int)sizeof(uintptr_t);
    }

    return 0;
}

bool register_based = false;

SEC("uprobe/cmd_start")
int cmd_start(struct pt_regs *ctx) {
    struct cmd *receiver;

    if (register_based) {
        receiver = (struct cmd *) PT_REGS_RC(ctx);
    } else {
        if (bpf_probe_read_user(&receiver, sizeof(struct cmd *), (void *) (PT_REGS_SP(ctx) + sizeof(long))) < 0)
            return 0;
    }

    struct cmd c;

    if (bpf_probe_read_user(&c, sizeof(struct cmd), (void *)receiver) < 0)
        return 0;

    if (!c.path.data || !c.path.length)
        return 0;

    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);

    if (!e)
        return 0;

    e->pid = (int) (bpf_get_current_pid_tgid() >> 32);
    e->count = 0;
    e->class_id = 0;
    e->method_id = 0;

    if (bpf_probe_read_user(next(e), MAX_LENGTH(c.path.length, ARG_LENGTH), c.path.data) < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    __builtin_memset(e->stack_trace, 0, sizeof(e->stack_trace));

    if (traceback(e, PT_REGS_RET(ctx)) < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    bpf_ringbuf_submit(e, 0);

    return 0;
}
