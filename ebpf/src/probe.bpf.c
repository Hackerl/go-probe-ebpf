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
        if (bpf_probe_read_user(&receiver, sizeof(struct cmd *), (void *) (PT_REGS_SP(ctx) + sizeof(long))) < 0)
            return 0;
    }

    os_exec_cmd cmd;

    if (bpf_probe_read_user(&cmd, sizeof(os_exec_cmd), (void *)receiver) < 0)
        return 0;

    struct go_probe_event *event = new_event();

    if (!event)
        return 0;

    event->class_id = 0;
    event->method_id = 0;
    event->count = 2;

    __builtin_memset(event->args, 0, event->count * ARG_LENGTH);

    if (stringify_string(&cmd.path, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    if (stringify_string_slice(&cmd.args, event->args[1], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, event);

    return 0;
}
