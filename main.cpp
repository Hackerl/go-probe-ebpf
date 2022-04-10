#include "ebpf/probe.h"
#include "ebpf/probe.skel.h"
#include "go/symbol/line_table.h"
#include "go/symbol/build_info.h"
#include <bpf/libbpf.h>
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

    LOG_INFO("pid: %d class: %d method: %d", e->pid, e->class_id, e->method_id);

    for (int i = 0; i < e->count; i++) {
        LOG_INFO("argument %d: %s", i, std::string(e->args[i], ARG_LENGTH).c_str());
    }

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

bool getFuncAddress(const std::string &symbol, uintptr_t &address) {
    for (unsigned int i = 0; i < gLineTable->mFuncNum; i++) {
        CFunc func = {};

        if (!gLineTable->getFunc(i, func))
            break;

        if (symbol == func.getName()) {
            address = (uintptr_t) func.getEntry();
            return true;
        }
    }

    return false;
}

int main(int argc, char **argv) {
    INIT_CONSOLE_LOG(zero::DEBUG);

    zero::CCmdline cmdline;

    cmdline.add({"pid", "process id", zero::value<int>()});
    cmdline.parse(argc, argv);

    int pid = cmdline.get<int>("pid");
    std::string path = zero::filesystem::path::join("/proc", std::to_string(pid), "exe");

    if (!gLineTable->load(std::string(path))) {
        LOG_ERROR("line table load failed");
        return -1;
    }

    CBuildInfo buildInfo;

    if (buildInfo.load(path)) {
        LOG_INFO("go version: %s", buildInfo.mVersion.c_str());
    }

    uintptr_t base;

    if (!getBaseAddress(path, base)) {
        LOG_ERROR("failed to get elf base address");
        return -1;
    }

    uintptr_t entry;

    if (!getFuncAddress("os/exec.(*Cmd).Start", entry)) {
        LOG_ERROR("failed to get function address");
        return -1;
    }

    LOG_INFO("base: 0x%lx 0x%lx", base, entry);

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
            entry - base
    );

    if (!skeleton->links.cmd_start) {
        LOG_ERROR("failed to attach: %s", strerror(errno));
        probe_bpf__destroy(skeleton);
        return -1;
    }

    ring_buffer *rb = ring_buffer__new(bpf_map__fd(skeleton->maps.rb), onEvent, nullptr, nullptr);

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
