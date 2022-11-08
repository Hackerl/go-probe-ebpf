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

    if (stringify_string(&path, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    if (stringify_string_slice(&args, event->args[1], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

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

    if (n < 0) {
        free_event(event);
        return 0;
    }

    if (n == ARG_LENGTH - 1) {
        submit_event(ctx, event);
        return 0;
    }

    event->args[0][BOUND(n , ARG_LENGTH)] = ' ';

    if (stringify_string_slice(&cmd.args, event->args[0] + BOUND(n + 1, ARG_LENGTH), ARG_LENGTH - BOUND(n + 1, ARG_LENGTH)) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, event);

    return 0;
}

SEC("uprobe/os_openfile")
int os_openfile(struct pt_regs *ctx) {
    string path;
    go_int flag;
    go_uint32 mode;

    if (is_register_based()) {
        path.data = (const char *) GO_REGS_PARM1(ctx);
        path.length = (size_t) GO_REGS_PARM2(ctx);

        flag = (go_int) GO_REGS_PARM3(ctx);
        mode = (go_uint32) GO_REGS_PARM4(ctx);
    } else {
        if (bpf_probe_read_user(&path, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;

        if (bpf_probe_read_user(&flag, sizeof(go_int), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t) + sizeof(string))) < 0)
            return 0;

        if (bpf_probe_read_user(&mode, sizeof(go_uint32), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t) + sizeof(string) + sizeof(go_int))) < 0)
            return 0;
    }

    go_probe_event *event = new_event(1, 0, 3);

    if (!event)
        return 0;

    if (stringify_string(&path, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    if (stringify_go_int64(flag, event->args[1], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    if (stringify_go_uint64(mode, event->args[2], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, event);

    return 0;
}

SEC("uprobe/os_remove")
int os_remove(struct pt_regs *ctx) {
    string path;

    if (is_register_based()) {
        path.data = (const char *) GO_REGS_PARM1(ctx);
        path.length = (size_t) GO_REGS_PARM2(ctx);
    } else {
        if (bpf_probe_read_user(&path, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;
    }

    go_probe_event *event = new_event(1, 1, 1);

    if (!event)
        return 0;

    if (stringify_string(&path, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, event);

    return 0;
}

SEC("uprobe/os_remove_all")
int os_remove_all(struct pt_regs *ctx) {
    string path;

    if (is_register_based()) {
        path.data = (const char *) GO_REGS_PARM1(ctx);
        path.length = (size_t) GO_REGS_PARM2(ctx);
    } else {
        if (bpf_probe_read_user(&path, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;
    }

    go_probe_event *event = new_event(1, 2, 1);

    if (!event)
        return 0;

    if (stringify_string(&path, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, event);

    return 0;
}

SEC("uprobe/os_rename")
int os_rename(struct pt_regs *ctx) {
    string src;
    string dst;

    if (is_register_based()) {
        src.data = (const char *) GO_REGS_PARM1(ctx);
        src.length = (size_t) GO_REGS_PARM2(ctx);

        dst.data = (const char *) GO_REGS_PARM3(ctx);
        dst.length = (size_t) GO_REGS_PARM4(ctx);
    } else {
        if (bpf_probe_read_user(&src, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;

        if (bpf_probe_read_user(&dst, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t) + sizeof(string))) < 0)
            return 0;
    }

    go_probe_event *event = new_event(1, 3, 2);

    if (!event)
        return 0;

    if (stringify_string(&src, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    if (stringify_string(&dst, event->args[1], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, event);

    return 0;
}

SEC("uprobe/io_ioutil_readdir")
int io_ioutil_readdir(struct pt_regs *ctx) {
    string path;

    if (is_register_based()) {
        path.data = (const char *) GO_REGS_PARM1(ctx);
        path.length = (size_t) GO_REGS_PARM2(ctx);
    } else {
        if (bpf_probe_read_user(&path, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;
    }

    go_probe_event *event = new_event(1, 4, 1);

    if (!event)
        return 0;

    if (stringify_string(&path, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, event);

    return 0;
}