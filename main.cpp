#include "ebpf/probe.h"
#include "ebpf/probe.skel.h"
#include "go/symbol/line_table.h"
#include "go/symbol/build_info.h"
#include <bpf/bpf.h>
#include <zero/log.h>
#include <zero/cmdline.h>
#include <sys/user.h>

int onLog(libbpf_print_level level, const char *format, va_list args) {
    va_list copy;
    va_copy(copy, args);

    int length = vsnprintf(nullptr, 0, format, args);

    if (length <= 0)
        return 0;

    std::unique_ptr<char> buffer(new char[length + 1]);
    vsnprintf(buffer.get(), length + 1, format, copy);

    switch (level) {
        case LIBBPF_WARN:
            LOG_WARNING("%s", zero::strings::trim(buffer.get()).c_str());
            break;
        case LIBBPF_INFO:
            LOG_INFO("%s", zero::strings::trim(buffer.get()).c_str());
            break;

        case LIBBPF_DEBUG:
            LOG_DEBUG("%s", zero::strings::trim(buffer.get()).c_str());
            break;
    }

    return length;
}

int onEvent(void *ctx, void *data, size_t size) {
    auto e = (event *) data;
    auto context = (std::tuple<int, CLineTable *> *) ctx;

    int fd = std::get<0>(*context);
    CLineTable *lineTable = std::get<1>(*context);

    LOG_INFO("pid: %d class: %d method: %d", e->pid, e->class_id, e->method_id);

    std::list<std::string> args;
    std::list<std::string> stackTrace;

    for (int i = 0; i < e->count; i++)
        args.emplace_back(e->args[i], ARG_LENGTH);

    for (int i = 0; i < TRACE_COUNT; i++) {
        CFunc func = {};

        if (!lineTable->findFunc(e->stack_trace[i], func))
            break;

        char stack[4096] = {};

        snprintf(stack, sizeof(stack),
                 "%s %s:%d +0x%lx",
                 func.getName(),
                 func.getSourceFile(e->stack_trace[i]),
                 func.getSourceLine(e->stack_trace[i]),
                 e->stack_trace[i] - func.getEntry()
        );

        stackTrace.emplace_back(stack);

        if (i != TRACE_COUNT - 1 && e->stack_trace[i + 1] == 0) {
            if (func.isStackTop())
                break;

            uintptr_t pc = e->stack_trace[i];
            int frame_size = func.getFrameSize(pc);

            bpf_map_update_elem(fd, &pc, &frame_size, BPF_NOEXIST);

            break;
        }
    }

    LOG_INFO(
            "args: %s stack trace: %s",
            zero::strings::join(args, " ").c_str(),
            zero::strings::join(stackTrace, " ").c_str()
    );

    return 0;
}

bool getBaseAddress(const std::string &path, uintptr_t &address) {
    ELFIO::elfio reader;

    if (!reader.load(path))
        return false;

    std::vector<ELFIO::segment *> loads;

    std::copy_if(
            reader.segments.begin(),
            reader.segments.end(),
            std::back_inserter(loads),
            [](const auto &i){
                return i->get_type() == PT_LOAD;
            });

    auto minElement = std::min_element(
            loads.begin(),
            loads.end(),
            [](const auto &i, const auto &j) {
                return i->get_virtual_address() < j->get_virtual_address();
            });

    address = (*minElement)->get_virtual_address() & ~(PAGE_SIZE - 1);

    return true;
}

int main(int argc, char **argv) {
    INIT_CONSOLE_LOG(zero::INFO);

    zero::CCmdline cmdline;

    cmdline.add({"pid", "process id", zero::value<int>()});
    cmdline.parse(argc, argv);

    int pid = cmdline.get<int>("pid");
    std::string path = zero::filesystem::path::join("/proc", std::to_string(pid), "exe");

    CLineTable lineTable = {};

    if (!lineTable.load(std::string(path))) {
        LOG_ERROR("line table load failed");
        return -1;
    }

    CBuildInfo buildInfo = {};

    if (buildInfo.load(path)) {
        LOG_INFO("go version: %s", buildInfo.mVersion.c_str());
    }

    uintptr_t base;

    if (!getBaseAddress(path, base)) {
        LOG_ERROR("failed to get elf base address");
        return -1;
    }

    CFunc func = {};

    if (!lineTable.findFunc("os/exec.(*Cmd).Start", func)) {
        LOG_ERROR("failed to get function address");
        return -1;
    }

    LOG_INFO("base: 0x%lx entry: 0x%lx", base, func.getEntry());

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(onLog);

    probe_bpf *skeleton = probe_bpf__open_and_load();

    if (!skeleton) {
        LOG_ERROR("failed to open and load BPF skeleton");
        return -1;
    }

    skeleton->bss->register_based = buildInfo.mRegisterBased;
    skeleton->links.cmd_start = bpf_program__attach_uprobe(
            skeleton->progs.cmd_start,
            false,
            pid,
            path.c_str(),
            func.getEntry() - base
    );

    if (!skeleton->links.cmd_start) {
        LOG_ERROR("failed to attach: %s", strerror(errno));
        probe_bpf__destroy(skeleton);
        return -1;
    }

    std::tuple<int, CLineTable *> context = {
            bpf_map__fd(skeleton->maps.map),
            &lineTable
    };

    ring_buffer *rb = ring_buffer__new(bpf_map__fd(skeleton->maps.rb), onEvent, &context, nullptr);

    if (!rb) {
        LOG_ERROR("failed to create ring buffer: %s", strerror(errno));
        probe_bpf__destroy(skeleton);
        return -1;
    }

    while (ring_buffer__poll(rb, 100) >= 0) {

    }

    ring_buffer__free(rb);
    probe_bpf__destroy(skeleton);

    return 0;
}
