#include <bpf/bpf.h>
#include <zero/log.h>
#include <zero/cmdline.h>
#include <zero/os/process.h>
#include <go/symbol/reader.h>
#include "ebpf/probe.h"
#include "ebpf/probe.skel.h"

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

#ifdef USE_RING_BUFFER
int onEvent(void *ctx, void *data, size_t size) {
#else
void onEvent(void *ctx, int cpu, void *data, __u32 size) {
#endif
    auto event = (go_probe_event *) data;
    auto &[map, symbolTable] = *(std::pair<bpf_map *, go::symbol::SymbolTable &> *) ctx;

    LOG_INFO("pid: %d class: %d method: %d", event->pid, event->class_id, event->method_id);

    std::list<std::string> args;
    std::list<std::string> stackTrace;

    for (int i = 0; i < event->count; i++)
        args.emplace_back(event->args[i], ARG_LENGTH);

    for (int i = 0; i < TRACE_COUNT; i++) {
        auto it = symbolTable.find(event->stack_trace[i]);

        if (it == symbolTable.end())
            break;

        char stack[4096] = {};
        go::symbol::Symbol symbol = it.operator*().symbol();

        snprintf(stack, sizeof(stack),
                 "%s %s:%d +0x%lx",
                 symbol.name(),
                 symbol.sourceFile(event->stack_trace[i]),
                 symbol.sourceLine(event->stack_trace[i]),
                 event->stack_trace[i] - symbol.entry()
        );

        stackTrace.emplace_back(stack);

        if (i != TRACE_COUNT - 1 && event->stack_trace[i + 1] == 0) {
            if (symbol.isStackTop())
                break;

            uintptr_t pc = event->stack_trace[i];
            int frame_size = symbol.frameSize(pc);

            bpf_map__update_elem(map, &pc, sizeof(pc), &frame_size, sizeof(frame_size), BPF_NOEXIST);

            break;
        }
    }

    LOG_INFO(
            "args: %s stack trace: %s",
            zero::strings::join(args, " ").c_str(),
            zero::strings::join(stackTrace, " ").c_str()
    );

#ifdef USE_RING_BUFFER
    return 0;
#endif
}

int main(int argc, char **argv) {
    INIT_CONSOLE_LOG(zero::INFO);

    zero::Cmdline cmdline;

    cmdline.add<int>("pid", "process id");
    cmdline.parse(argc, argv);

    int pid = cmdline.get<int>("pid");

    std::error_code ec;

    std::filesystem::path path = std::filesystem::path("/proc") / std::to_string(pid) / "exe";
    std::filesystem::path realPath = std::filesystem::read_symlink(path, ec);

    if (ec) {
        LOG_ERROR("read symbol link failed, %s", ec.message().c_str());
        return -1;
    }

    go::symbol::Reader reader;

    if (!reader.load(path)) {
        LOG_ERROR("load golang binary failed");
        return -1;
    }

    std::optional<go::symbol::BuildInfo> buildInfo = reader.buildInfo();

    if (!buildInfo) {
        LOG_ERROR("get build info failed");
        return -1;
    }

    std::optional<std::string> version = buildInfo->version();

    if (!version) {
        LOG_ERROR("get golang version failed");
        return -1;
    }

    std::optional<std::tuple<int, int>> versionNumber = buildInfo->versionNumber();

    if (!versionNumber) {
        LOG_ERROR("get golang version number failed");
        return -1;
    }

    auto [major, minor] = *versionNumber;

    LOG_INFO("golang version: %d.%d", major, minor);

    std::optional<zero::os::process::ProcessMapping> processMapping = zero::os::process::getImageBase(
            pid,
            std::filesystem::read_symlink(path).string()
    );

    if (!processMapping) {
        LOG_INFO("get image base failed");
        return -1;
    }

    LOG_INFO("image base: %p", processMapping->start);

    std::optional<go::symbol::SymbolTable> symbolTable = reader.symbols(go::symbol::FileMapping, processMapping->start);

    if (!symbolTable) {
        LOG_INFO("get symbol table failed");
        return -1;
    }

    auto it = symbolTable->find("os/exec.(*Cmd).Start");

    if (it == symbolTable->end()) {
        LOG_INFO("find symbol failed");
        return -1;
    }

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(onLog);

    probe_bpf *skeleton = probe_bpf::open_and_load();

    if (!skeleton) {
        LOG_ERROR("failed to open and load BPF skeleton");
        return -1;
    }

#ifdef BPF_NO_GLOBAL_DATA
    uint32_t index = 0;
    int registerBased = major > 1 || (major == 1 && minor >= 7);

    if (bpf_map__update_elem(skeleton->maps.config_map, &index, sizeof(index), &registerBased, sizeof(registerBased), BPF_ANY) < 0) {
        LOG_ERROR("update map failed");
        probe_bpf::destroy(skeleton);
        return -1;
    }
#else
    skeleton->bss->register_based = major > 1 || (major == 1 && minor >= 7);
#endif

    skeleton->links.cmd_start = bpf_program__attach_uprobe(
            skeleton->progs.cmd_start,
            false,
            pid,
            path.string().c_str(),
            it.operator*().symbol().entry() - processMapping->start
    );

    if (!skeleton->links.cmd_start) {
        LOG_ERROR("failed to attach: %s", strerror(errno));
        probe_bpf::destroy(skeleton);
        return -1;
    }

    std::pair<bpf_map *, go::symbol::SymbolTable &> context = {
            skeleton->maps.frame_map,
            *symbolTable
    };

#ifdef USE_RING_BUFFER
    ring_buffer *rb = ring_buffer__new(bpf_map__fd(skeleton->maps.events), onEvent, &context, nullptr);

    if (!rb) {
        LOG_ERROR("failed to create ring buffer: %s", strerror(errno));
        probe_bpf::destroy(skeleton);
        return -1;
    }

    while (ring_buffer__poll(rb, 100) >= 0) {

    }

    ring_buffer__free(rb);
#else
    perf_buffer *pb = perf_buffer__new(bpf_map__fd(skeleton->maps.events), 64, onEvent, nullptr, &context, nullptr);

    if (!pb) {
        LOG_ERROR("failed to create perf buffer: %s", strerror(errno));
        probe_bpf::destroy(skeleton);
        return -1;
    }

    while (perf_buffer__poll(pb, 100) >= 0) {

    }

    perf_buffer__free(pb);
#endif

    probe_bpf::destroy(skeleton);

    return 0;
}
