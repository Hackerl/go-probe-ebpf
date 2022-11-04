#include "trace.h"
#include "stringify.h"
#include "config.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("uprobe/os_exec_cmd_start")
int os_exec_cmd_start(struct pt_regs *ctx) {
    os_exec_cmd *receiver;

    if (is_register_based()) {
        receiver = (os_exec_cmd *) GO_REGS_PARM1(ctx);
    } else {
        if (bpf_probe_read_user(&receiver, sizeof(os_exec_cmd *), (void *) (PT_REGS_SP(ctx) + sizeof(long))) < 0)
            return 0;
    }

    os_exec_cmd cmd;

    if (bpf_probe_read_user(&cmd, sizeof(os_exec_cmd), receiver) < 0)
        return 0;

    struct go_probe_event *event = new_event(0, 0, 2);

    if (!event)
        return 0;

    if (stringify_os_exec_cmd(&cmd, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, event);

    return 0;
}
