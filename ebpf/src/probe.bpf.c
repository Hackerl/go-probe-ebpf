#include "trace.h"
#include "stringify.h"
#include "config.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("uprobe/os_exec_command")
int os_exec_command(struct pt_regs *ctx) {
    string path;
    slice args;

    if (is_register_based()) {
        path.data = (const char *) GO_REGS_PARM1(ctx);
        path.length = (size_t) GO_REGS_PARM2(ctx);

        args.data = (void *) GO_REGS_PARM3(ctx);
        args.count = (go_int) GO_REGS_PARM4(ctx);
        args.capacity = (go_int) GO_REGS_PARM5(ctx);
    } else {
        if (bpf_probe_read_user(&path, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;

        if (bpf_probe_read_user(&args, sizeof(slice), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t) + sizeof(string))) < 0)
            return 0;
    }

    go_probe_event *event = new_event(0, 0, 2);

    if (!event)
        return 0;

    if (stringify_string(&path, event->args[0], ARG_LENGTH) < 0)
        return -1;

    if (stringify_string_slice(&args, event->args[1], ARG_LENGTH) < 0)
        return -1;

    submit_event(ctx, event);

    return 0;
}

SEC("uprobe/os_exec_cmd_start")
int os_exec_cmd_start(struct pt_regs *ctx) {
    os_exec_cmd *receiver;

    if (is_register_based()) {
        receiver = (os_exec_cmd *) GO_REGS_PARM1(ctx);
    } else {
        if (bpf_probe_read_user(&receiver, sizeof(os_exec_cmd *), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;
    }

    os_exec_cmd cmd;

    if (bpf_probe_read_user(&cmd, sizeof(os_exec_cmd), receiver) < 0)
        return 0;

    go_probe_event *event = new_event(0, 1, 1);

    if (!event)
        return 0;

    int n = stringify_string(&cmd.path, event->args[0], ARG_LENGTH);

    if (n < 0)
        return -1;

    if (n == ARG_LENGTH - 1) {
        submit_event(ctx, event);
        return 0;
    }

    event->args[0][BOUND(n , ARG_LENGTH)] = ' ';

    if (stringify_string_slice(&cmd.args, event->args[0] + BOUND(n + 1, ARG_LENGTH), ARG_LENGTH - BOUND(n + 1, ARG_LENGTH)) < 0)
        return -1;

    submit_event(ctx, event);

    return 0;
}
