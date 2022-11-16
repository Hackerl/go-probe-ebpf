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

SEC("uprobe/net_dial")
int net_dial(struct pt_regs *ctx) {
    string network;
    string address;

    if (is_register_based()) {
        network.data = (const char *) GO_REGS_PARM1(ctx);
        network.length = (size_t) GO_REGS_PARM2(ctx);

        address.data = (const char *) GO_REGS_PARM3(ctx);
        address.length = (size_t) GO_REGS_PARM4(ctx);
    } else {
        if (bpf_probe_read_user(&network, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;

        if (bpf_probe_read_user(&address, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t) + sizeof(string))) < 0)
            return 0;
    }

    go_probe_event *event = new_event(2, 0, 2);

    if (!event)
        return 0;

    if (stringify_string(&network, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    if (stringify_string(&address, event->args[1], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, event);

    return 0;
}

SEC("uprobe/net_dial_tcp")
int net_dial_tcp(struct pt_regs *ctx) {
    string network;
    tcp_address *remote;

    if (is_register_based()) {
        network.data = (const char *) GO_REGS_PARM1(ctx);
        network.length = (size_t) GO_REGS_PARM2(ctx);

        remote = (tcp_address *) GO_REGS_PARM4(ctx);
    } else {
        if (bpf_probe_read_user(&network, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;

        if (bpf_probe_read_user(&remote, sizeof(tcp_address *), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t) + sizeof(string) + sizeof(uintptr_t))) < 0)
            return 0;
    }

    go_probe_event *event = new_event(2, 1, 3);

    if (!event)
        return 0;

    if (stringify_string(&network, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    if (!remote) {
        free_event(event);
        return 0;
    }

    tcp_address address;

    if (bpf_probe_read_user(&address, sizeof(tcp_address), remote) < 0) {
        free_event(event);
        return 0;
    }

    if (stringify_tcp_address(&address, event->args[2], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, event);

    return 0;
}

SEC("uprobe/net_dial_ip")
int net_dial_ip(struct pt_regs *ctx) {
    string network;
    ip_address *remote;

    if (is_register_based()) {
        network.data = (const char *) GO_REGS_PARM1(ctx);
        network.length = (size_t) GO_REGS_PARM2(ctx);

        remote = (ip_address *) GO_REGS_PARM4(ctx);
    } else {
        if (bpf_probe_read_user(&network, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;

        if (bpf_probe_read_user(&remote, sizeof(ip_address *), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t) + sizeof(string) + sizeof(uintptr_t))) < 0)
            return 0;
    }

    go_probe_event *event = new_event(2, 2, 3);

    if (!event)
        return 0;

    if (stringify_string(&network, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    if (!remote) {
        free_event(event);
        return 0;
    }

    ip_address address;

    if (bpf_probe_read_user(&address, sizeof(ip_address), remote) < 0) {
        free_event(event);
        return 0;
    }

    if (stringify_ip_address(&address, event->args[2], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, event);

    return 0;
}

SEC("uprobe/net_dial_udp")
int net_dial_udp(struct pt_regs *ctx) {
    string network;
    udp_address *remote;

    if (is_register_based()) {
        network.data = (const char *) GO_REGS_PARM1(ctx);
        network.length = (size_t) GO_REGS_PARM2(ctx);

        remote = (udp_address *) GO_REGS_PARM4(ctx);
    } else {
        if (bpf_probe_read_user(&network, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;

        if (bpf_probe_read_user(&remote, sizeof(udp_address *), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t) + sizeof(string) + sizeof(uintptr_t))) < 0)
            return 0;
    }

    go_probe_event *event = new_event(2, 3, 3);

    if (!event)
        return 0;

    if (stringify_string(&network, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    if (!remote) {
        free_event(event);
        return 0;
    }

    udp_address address;

    if (bpf_probe_read_user(&address, sizeof(udp_address), remote) < 0) {
        free_event(event);
        return 0;
    }

    if (stringify_udp_address(&address, event->args[2], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, event);

    return 0;
}

SEC("uprobe/net_dial_unix")
int net_dial_unix(struct pt_regs *ctx) {
    string network;
    unix_address *remote;

    if (is_register_based()) {
        network.data = (const char *) GO_REGS_PARM1(ctx);
        network.length = (size_t) GO_REGS_PARM2(ctx);

        remote = (unix_address *) GO_REGS_PARM4(ctx);
    } else {
        if (bpf_probe_read_user(&network, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;

        if (bpf_probe_read_user(&remote, sizeof(unix_address *), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t) + sizeof(string) + sizeof(uintptr_t))) < 0)
            return 0;
    }

    go_probe_event *event = new_event(2, 4, 3);

    if (!event)
        return 0;

    if (stringify_string(&network, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    if (!remote) {
        free_event(event);
        return 0;
    }

    unix_address address;

    if (bpf_probe_read_user(&address, sizeof(unix_address), remote) < 0) {
        free_event(event);
        return 0;
    }

    if (stringify_unix_address(&address, event->args[2], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, event);

    return 0;
}

SEC("uprobe/net_dialer_dial_context")
int net_dialer_dial_context(struct pt_regs *ctx) {
    string network;
    string address;

    if (is_register_based()) {
        network.data = (const char *) GO_REGS_PARM4(ctx);
        network.length = (size_t) GO_REGS_PARM5(ctx);

        address.data = (const char *) GO_REGS_PARM6(ctx);
        address.length = (size_t) GO_REGS_PARM7(ctx);
    } else {
        if (bpf_probe_read_user(&network, sizeof(string), (void *) (PT_REGS_SP(ctx) + 2 * sizeof(uintptr_t) + sizeof(interface))) < 0)
            return 0;

        if (bpf_probe_read_user(&address, sizeof(string), (void *) (PT_REGS_SP(ctx) + 2 * sizeof(uintptr_t) + sizeof(interface) + sizeof(string))) < 0)
            return 0;
    }

    go_probe_event *event = new_event(2, 5, 4);

    if (!event)
        return 0;

    if (stringify_string(&network, event->args[2], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    if (stringify_string(&address, event->args[3], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, event);

    return 0;
}

SEC("uprobe/net_resolve_tcp_address")
int net_resolve_tcp_address(struct pt_regs *ctx) {
    string network;
    string address;

    if (is_register_based()) {
        network.data = (const char *) GO_REGS_PARM1(ctx);
        network.length = (size_t) GO_REGS_PARM2(ctx);

        address.data = (const char *) GO_REGS_PARM3(ctx);
        address.length = (size_t) GO_REGS_PARM4(ctx);
    } else {
        if (bpf_probe_read_user(&network, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;

        if (bpf_probe_read_user(&address, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t) + sizeof(string))) < 0)
            return 0;
    }

    go_probe_event *event = new_event(3, 0, 2);

    if (!event)
        return 0;

    if (stringify_string(&network, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    if (stringify_string(&address, event->args[1], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, event);

    return 0;
}

SEC("uprobe/net_resolve_ip_address")
int net_resolve_ip_address(struct pt_regs *ctx) {
    string network;
    string address;

    if (is_register_based()) {
        network.data = (const char *) GO_REGS_PARM1(ctx);
        network.length = (size_t) GO_REGS_PARM2(ctx);

        address.data = (const char *) GO_REGS_PARM3(ctx);
        address.length = (size_t) GO_REGS_PARM4(ctx);
    } else {
        if (bpf_probe_read_user(&network, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;

        if (bpf_probe_read_user(&address, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t) + sizeof(string))) < 0)
            return 0;
    }

    go_probe_event *event = new_event(3, 1, 2);

    if (!event)
        return 0;

    if (stringify_string(&network, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    if (stringify_string(&address, event->args[1], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, event);

    return 0;
}

SEC("uprobe/net_resolve_udp_address")
int net_resolve_udp_address(struct pt_regs *ctx) {
    string network;
    string address;

    if (is_register_based()) {
        network.data = (const char *) GO_REGS_PARM1(ctx);
        network.length = (size_t) GO_REGS_PARM2(ctx);

        address.data = (const char *) GO_REGS_PARM3(ctx);
        address.length = (size_t) GO_REGS_PARM4(ctx);
    } else {
        if (bpf_probe_read_user(&network, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;

        if (bpf_probe_read_user(&address, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t) + sizeof(string))) < 0)
            return 0;
    }

    go_probe_event *event = new_event(3, 2, 2);

    if (!event)
        return 0;

    if (stringify_string(&network, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    if (stringify_string(&address, event->args[1], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, event);

    return 0;
}

SEC("uprobe/net_resolve_unix_address")
int net_resolve_unix_address(struct pt_regs *ctx) {
    string network;
    string address;

    if (is_register_based()) {
        network.data = (const char *) GO_REGS_PARM1(ctx);
        network.length = (size_t) GO_REGS_PARM2(ctx);

        address.data = (const char *) GO_REGS_PARM3(ctx);
        address.length = (size_t) GO_REGS_PARM4(ctx);
    } else {
        if (bpf_probe_read_user(&network, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;

        if (bpf_probe_read_user(&address, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t) + sizeof(string))) < 0)
            return 0;
    }

    go_probe_event *event = new_event(3, 3, 2);

    if (!event)
        return 0;

    if (stringify_string(&network, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    if (stringify_string(&address, event->args[1], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, event);

    return 0;
}

SEC("uprobe/net_lookup_address")
int net_lookup_address(struct pt_regs *ctx) {
    string address;

    if (is_register_based()) {
        address.data = (const char *) GO_REGS_PARM1(ctx);
        address.length = (size_t) GO_REGS_PARM2(ctx);
    } else {
        if (bpf_probe_read_user(&address, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;
    }

    go_probe_event *event = new_event(4, 0, 1);

    if (!event)
        return 0;

    if (stringify_string(&address, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, event);

    return 0;
}

SEC("uprobe/net_lookup_cname")
int net_lookup_cname(struct pt_regs *ctx) {
    string host;

    if (is_register_based()) {
        host.data = (const char *) GO_REGS_PARM1(ctx);
        host.length = (size_t) GO_REGS_PARM2(ctx);
    } else {
        if (bpf_probe_read_user(&host, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;
    }

    go_probe_event *event = new_event(4, 1, 1);

    if (!event)
        return 0;

    if (stringify_string(&host, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, event);

    return 0;
}

SEC("uprobe/net_lookup_host")
int net_lookup_host(struct pt_regs *ctx) {
    string host;

    if (is_register_based()) {
        host.data = (const char *) GO_REGS_PARM1(ctx);
        host.length = (size_t) GO_REGS_PARM2(ctx);
    } else {
        if (bpf_probe_read_user(&host, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;
    }

    go_probe_event *event = new_event(4, 2, 1);

    if (!event)
        return 0;

    if (stringify_string(&host, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, event);

    return 0;
}

SEC("uprobe/net_lookup_port")
int net_lookup_port(struct pt_regs *ctx) {
    string network;
    string service;

    if (is_register_based()) {
        network.data = (const char *) GO_REGS_PARM1(ctx);
        network.length = (size_t) GO_REGS_PARM2(ctx);

        service.data = (const char *) GO_REGS_PARM3(ctx);
        service.length = (size_t) GO_REGS_PARM4(ctx);
    } else {
        if (bpf_probe_read_user(&network, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;

        if (bpf_probe_read_user(&service, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t) + sizeof(string))) < 0)
            return 0;
    }

    go_probe_event *event = new_event(4, 3, 2);

    if (!event)
        return 0;

    if (stringify_string(&network, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    if (stringify_string(&service, event->args[1], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, event);

    return 0;
}

SEC("uprobe/net_lookup_txt")
int net_lookup_txt(struct pt_regs *ctx) {
    string name;

    if (is_register_based()) {
        name.data = (const char *) GO_REGS_PARM1(ctx);
        name.length = (size_t) GO_REGS_PARM2(ctx);
    } else {
        if (bpf_probe_read_user(&name, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;
    }

    go_probe_event *event = new_event(4, 4, 1);

    if (!event)
        return 0;

    if (stringify_string(&name, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, event);

    return 0;
}

SEC("uprobe/net_lookup_ip")
int net_lookup_ip(struct pt_regs *ctx) {
    string host;

    if (is_register_based()) {
        host.data = (const char *) GO_REGS_PARM1(ctx);
        host.length = (size_t) GO_REGS_PARM2(ctx);
    } else {
        if (bpf_probe_read_user(&host, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;
    }

    go_probe_event *event = new_event(4, 5, 1);

    if (!event)
        return 0;

    if (stringify_string(&host, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, event);

    return 0;
}

SEC("uprobe/net_lookup_mx")
int net_lookup_mx(struct pt_regs *ctx) {
    string name;

    if (is_register_based()) {
        name.data = (const char *) GO_REGS_PARM1(ctx);
        name.length = (size_t) GO_REGS_PARM2(ctx);
    } else {
        if (bpf_probe_read_user(&name, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;
    }

    go_probe_event *event = new_event(4, 6, 1);

    if (!event)
        return 0;

    if (stringify_string(&name, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, event);

    return 0;
}

SEC("uprobe/net_lookup_ns")
int net_lookup_ns(struct pt_regs *ctx) {
    string name;

    if (is_register_based()) {
        name.data = (const char *) GO_REGS_PARM1(ctx);
        name.length = (size_t) GO_REGS_PARM2(ctx);
    } else {
        if (bpf_probe_read_user(&name, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;
    }

    go_probe_event *event = new_event(4, 7, 1);

    if (!event)
        return 0;

    if (stringify_string(&name, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, event);

    return 0;
}

SEC("uprobe/net_resolver_lookup_address")
int net_resolver_lookup_address(struct pt_regs *ctx) {
    string address;

    if (is_register_based()) {
        address.data = (const char *) GO_REGS_PARM4(ctx);
        address.length = (size_t) GO_REGS_PARM5(ctx);
    } else {
        if (bpf_probe_read_user(&address, sizeof(string), (void *) (PT_REGS_SP(ctx) + 2 * sizeof(uintptr_t) + sizeof(interface))) < 0)
            return 0;
    }

    go_probe_event *event = new_event(4, 8, 3);

    if (!event)
        return 0;

    if (stringify_string(&address, event->args[2], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, event);

    return 0;
}

SEC("uprobe/net_resolver_lookup_cname")
int net_resolver_lookup_cname(struct pt_regs *ctx) {
    string host;

    if (is_register_based()) {
        host.data = (const char *) GO_REGS_PARM4(ctx);
        host.length = (size_t) GO_REGS_PARM5(ctx);
    } else {
        if (bpf_probe_read_user(&host, sizeof(string), (void *) (PT_REGS_SP(ctx) + 2 * sizeof(uintptr_t) + sizeof(interface))) < 0)
            return 0;
    }

    go_probe_event *event = new_event(4, 9, 3);

    if (!event)
        return 0;

    if (stringify_string(&host, event->args[2], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, event);

    return 0;
}

SEC("uprobe/net_resolver_lookup_host")
int net_resolver_lookup_host(struct pt_regs *ctx) {
    string host;

    if (is_register_based()) {
        host.data = (const char *) GO_REGS_PARM4(ctx);
        host.length = (size_t) GO_REGS_PARM5(ctx);
    } else {
        if (bpf_probe_read_user(&host, sizeof(string), (void *) (PT_REGS_SP(ctx) + 2 * sizeof(uintptr_t) + sizeof(interface))) < 0)
            return 0;
    }

    go_probe_event *event = new_event(4, 10, 3);

    if (!event)
        return 0;

    if (stringify_string(&host, event->args[2], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, event);

    return 0;
}

SEC("uprobe/net_resolver_lookup_port")
int net_resolver_lookup_port(struct pt_regs *ctx) {
    string network;
    string service;

    if (is_register_based()) {
        network.data = (const char *) GO_REGS_PARM4(ctx);
        network.length = (size_t) GO_REGS_PARM5(ctx);

        service.data = (const char *) GO_REGS_PARM6(ctx);
        service.length = (size_t) GO_REGS_PARM7(ctx);
    } else {
        if (bpf_probe_read_user(&network, sizeof(string), (void *) (PT_REGS_SP(ctx) + 2 * sizeof(uintptr_t) + sizeof(interface))) < 0)
            return 0;

        if (bpf_probe_read_user(&service, sizeof(string), (void *) (PT_REGS_SP(ctx) + 2 * sizeof(uintptr_t) + sizeof(interface) + sizeof(string))) < 0)
            return 0;
    }

    go_probe_event *event = new_event(4, 11, 4);

    if (!event)
        return 0;

    if (stringify_string(&network, event->args[2], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    if (stringify_string(&service, event->args[3], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, event);

    return 0;
}

SEC("uprobe/net_resolver_lookup_txt")
int net_resolver_lookup_txt(struct pt_regs *ctx) {
    string name;

    if (is_register_based()) {
        name.data = (const char *) GO_REGS_PARM4(ctx);
        name.length = (size_t) GO_REGS_PARM5(ctx);
    } else {
        if (bpf_probe_read_user(&name, sizeof(string), (void *) (PT_REGS_SP(ctx) + 2 * sizeof(uintptr_t) + sizeof(interface))) < 0)
            return 0;
    }

    go_probe_event *event = new_event(4, 12, 3);

    if (!event)
        return 0;

    if (stringify_string(&name, event->args[2], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, event);

    return 0;
}

SEC("uprobe/net_resolver_lookup_ip_address")
int net_resolver_lookup_ip_address(struct pt_regs *ctx) {
    string host;

    if (is_register_based()) {
        host.data = (const char *) GO_REGS_PARM4(ctx);
        host.length = (size_t) GO_REGS_PARM5(ctx);
    } else {
        if (bpf_probe_read_user(&host, sizeof(string), (void *) (PT_REGS_SP(ctx) + 2 * sizeof(uintptr_t) + sizeof(interface))) < 0)
            return 0;
    }

    go_probe_event *event = new_event(4, 13, 3);

    if (!event)
        return 0;

    if (stringify_string(&host, event->args[2], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, event);

    return 0;
}

SEC("uprobe/net_resolver_lookup_mx")
int net_resolver_lookup_mx(struct pt_regs *ctx) {
    string name;

    if (is_register_based()) {
        name.data = (const char *) GO_REGS_PARM4(ctx);
        name.length = (size_t) GO_REGS_PARM5(ctx);
    } else {
        if (bpf_probe_read_user(&name, sizeof(string), (void *) (PT_REGS_SP(ctx) + 2 * sizeof(uintptr_t) + sizeof(interface))) < 0)
            return 0;
    }

    go_probe_event *event = new_event(4, 14, 3);

    if (!event)
        return 0;

    if (stringify_string(&name, event->args[2], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, event);

    return 0;
}

SEC("uprobe/net_resolver_lookup_ns")
int net_resolver_lookup_ns(struct pt_regs *ctx) {
    string name;

    if (is_register_based()) {
        name.data = (const char *) GO_REGS_PARM4(ctx);
        name.length = (size_t) GO_REGS_PARM5(ctx);
    } else {
        if (bpf_probe_read_user(&name, sizeof(string), (void *) (PT_REGS_SP(ctx) + 2 * sizeof(uintptr_t) + sizeof(interface))) < 0)
            return 0;
    }

    go_probe_event *event = new_event(4, 15, 3);

    if (!event)
        return 0;

    if (stringify_string(&name, event->args[2], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, event);

    return 0;
}

SEC("uprobe/net_listen")
int net_listen(struct pt_regs *ctx) {
    string network;
    string address;

    if (is_register_based()) {
        network.data = (const char *) GO_REGS_PARM1(ctx);
        network.length = (size_t) GO_REGS_PARM2(ctx);

        address.data = (const char *) GO_REGS_PARM3(ctx);
        address.length = (size_t) GO_REGS_PARM4(ctx);
    } else {
        if (bpf_probe_read_user(&network, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;

        if (bpf_probe_read_user(&address, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t) + sizeof(string))) < 0)
            return 0;
    }

    go_probe_event *event = new_event(5, 0, 2);

    if (!event)
        return 0;

    if (stringify_string(&network, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    if (stringify_string(&address, event->args[1], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, event);

    return 0;
}

SEC("uprobe/net_listen_tcp")
int net_listen_tcp(struct pt_regs *ctx) {
    string network;
    tcp_address *local;

    if (is_register_based()) {
        network.data = (const char *) GO_REGS_PARM1(ctx);
        network.length = (size_t) GO_REGS_PARM2(ctx);

        local = (tcp_address *) GO_REGS_PARM3(ctx);
    } else {
        if (bpf_probe_read_user(&network, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;

        if (bpf_probe_read_user(&local, sizeof(tcp_address *), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t) + sizeof(string))) < 0)
            return 0;
    }

    go_probe_event *event = new_event(5, 1, 2);

    if (!event)
        return 0;

    if (stringify_string(&network, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    if (!local) {
        free_event(event);
        return 0;
    }

    tcp_address address;

    if (bpf_probe_read_user(&address, sizeof(tcp_address), local) < 0) {
        free_event(event);
        return 0;
    }

    if (stringify_tcp_address(&address, event->args[1], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, event);

    return 0;
}

SEC("uprobe/net_listen_ip")
int net_listen_ip(struct pt_regs *ctx) {
    string network;
    ip_address *local;

    if (is_register_based()) {
        network.data = (const char *) GO_REGS_PARM1(ctx);
        network.length = (size_t) GO_REGS_PARM2(ctx);

        local = (ip_address *) GO_REGS_PARM3(ctx);
    } else {
        if (bpf_probe_read_user(&network, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;

        if (bpf_probe_read_user(&local, sizeof(ip_address *), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t) + sizeof(string))) < 0)
            return 0;
    }

    go_probe_event *event = new_event(5, 2, 2);

    if (!event)
        return 0;

    if (stringify_string(&network, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    if (!local) {
        free_event(event);
        return 0;
    }

    ip_address address;

    if (bpf_probe_read_user(&address, sizeof(ip_address), local) < 0) {
        free_event(event);
        return 0;
    }

    if (stringify_ip_address(&address, event->args[1], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, event);

    return 0;
}

SEC("uprobe/net_listen_udp")
int net_listen_udp(struct pt_regs *ctx) {
    string network;
    udp_address *local;

    if (is_register_based()) {
        network.data = (const char *) GO_REGS_PARM1(ctx);
        network.length = (size_t) GO_REGS_PARM2(ctx);

        local = (udp_address *) GO_REGS_PARM3(ctx);
    } else {
        if (bpf_probe_read_user(&network, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;

        if (bpf_probe_read_user(&local, sizeof(udp_address *), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t) + sizeof(string))) < 0)
            return 0;
    }

    go_probe_event *event = new_event(5, 3, 2);

    if (!event)
        return 0;

    if (stringify_string(&network, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    if (!local) {
        free_event(event);
        return 0;
    }

    udp_address address;

    if (bpf_probe_read_user(&address, sizeof(udp_address), local) < 0) {
        free_event(event);
        return 0;
    }

    if (stringify_udp_address(&address, event->args[1], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, event);

    return 0;
}

SEC("uprobe/net_listen_unix")
int net_listen_unix(struct pt_regs *ctx) {
    string network;
    unix_address *local;

    if (is_register_based()) {
        network.data = (const char *) GO_REGS_PARM1(ctx);
        network.length = (size_t) GO_REGS_PARM2(ctx);

        local = (unix_address *) GO_REGS_PARM3(ctx);
    } else {
        if (bpf_probe_read_user(&network, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;

        if (bpf_probe_read_user(&local, sizeof(unix_address *), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t) + sizeof(string))) < 0)
            return 0;
    }

    go_probe_event *event = new_event(5, 4, 2);

    if (!event)
        return 0;

    if (stringify_string(&network, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    if (!local) {
        free_event(event);
        return 0;
    }

    unix_address address;

    if (bpf_probe_read_user(&address, sizeof(unix_address), local) < 0) {
        free_event(event);
        return 0;
    }

    if (stringify_unix_address(&address, event->args[1], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, event);

    return 0;
}

SEC("uprobe/net_http_new_request")
int net_http_new_request(struct pt_regs *ctx) {
    string method;
    string url;

    if (is_register_based()) {
        method.data = (const char *) GO_REGS_PARM1(ctx);
        method.length = (size_t) GO_REGS_PARM2(ctx);

        url.data = (const char *) GO_REGS_PARM3(ctx);
        url.length = (size_t) GO_REGS_PARM4(ctx);
    } else {
        if (bpf_probe_read_user(&method, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;

        if (bpf_probe_read_user(&url, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t) + sizeof(string))) < 0)
            return 0;
    }

    go_probe_event *event = new_event(6, 0, 2);

    if (!event)
        return 0;

    if (stringify_string(&method, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    if (stringify_string(&url, event->args[1], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, event);

    return 0;
}

SEC("uprobe/net_http_new_request_with_context")
int net_http_new_request_with_context(struct pt_regs *ctx) {
    string method;
    string url;

    if (is_register_based()) {
        method.data = (const char *) GO_REGS_PARM3(ctx);
        method.length = (size_t) GO_REGS_PARM4(ctx);

        url.data = (const char *) GO_REGS_PARM5(ctx);
        url.length = (size_t) GO_REGS_PARM6(ctx);
    } else {
        if (bpf_probe_read_user(&method, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t) + sizeof(interface))) < 0)
            return 0;

        if (bpf_probe_read_user(&url, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t) + sizeof(interface) + sizeof(string))) < 0)
            return 0;
    }

    go_probe_event *event = new_event(6, 1, 4);

    if (!event)
        return 0;

    if (stringify_string(&method, event->args[1], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    if (stringify_string(&url, event->args[2], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, event);

    return 0;
}

SEC("uprobe/plugin_open")
int plugin_open(struct pt_regs *ctx) {
    string path;

    if (is_register_based()) {
        path.data = (const char *) GO_REGS_PARM1(ctx);
        path.length = (size_t) GO_REGS_PARM2(ctx);
    } else {
        if (bpf_probe_read_user(&path, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;
    }

    go_probe_event *event = new_event(7, 0, 1);

    if (!event)
        return 0;

    if (stringify_string(&path, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, event);

    return 0;
}