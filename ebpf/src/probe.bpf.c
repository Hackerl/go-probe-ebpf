#include "type.h"
#include "trace.h"
#include "config.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("uprobe/os_exec_cmd_start")
int os_exec_cmd_start(struct pt_regs *ctx) {
    GoExecCmd *receiver;

    if (is_register_based()) {
        receiver = (GoExecCmd *) GO_REGS_PARM1(ctx);
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
