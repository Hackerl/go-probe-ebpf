#include "api/api.h"
#include "api/config.h"
#include "ebpf/src/event.h"
#include "ebpf/probe.skel.h"
#include <bpf/bpf.h>
#include <Zydis/Zydis.h>
#include <zero/log.h>
#include <zero/cmdline.h>
#include <zero/os/process.h>
#include <go/symbol/reader.h>

constexpr auto MAX_OFFSET = 100;
constexpr auto INSTRUCTION_BUFFER_SIZE = 128;

int onLog(libbpf_print_level level, const char *format, va_list args) {
    va_list copy;
    va_copy(copy, args);

    int length = vsnprintf(nullptr, 0, format, args);

    if (length <= 0)
        return 0;

    std::unique_ptr<char[]> buffer = std::make_unique<char[]>(length + 1);
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
        args.emplace_back(event->args[i]);

    for (int i = 0; i < TRACE_COUNT; i++) {
        uintptr_t pc = event->stack_trace[i];

        if (!pc)
            break;

        auto it = symbolTable.find(pc);

        if (it == symbolTable.end())
            break;

        char stack[4096] = {};
        go::symbol::Symbol symbol = it.operator*().symbol();

        snprintf(stack, sizeof(stack),
                 "%s %s:%d +0x%lx",
                 symbol.name(),
                 symbol.sourceFile(pc),
                 symbol.sourceLine(pc),
                 pc - symbol.entry()
        );

        stackTrace.emplace_back(stack);

        if (!map || i == TRACE_COUNT - 1 || event->stack_trace[i + 1] || symbol.isStackTop())
            continue;

        int frame_size = symbol.frameSize(pc);

        if (frame_size <= 0)
            break;

        bpf_map__update_elem(map, &pc, sizeof(pc), &frame_size, sizeof(frame_size), BPF_NOEXIST);
    }

#ifdef ENABLE_HTTP
    std::list<std::string> headers;

    for (const auto &header : event->request.headers) {
        if (!header[0][0])
            break;

        headers.push_back(zero::strings::format("%s: %s", header[0], header[1]));
    }

    LOG_INFO(
            "g: %p "
            "request: method{%s} uri{%s} host{%s} remote{%s} headers{%s} "
            "args: %s "
            "stack trace: %s",
            event->g,
            event->request.method,
            event->request.uri,
            event->request.host,
            event->request.remote,
            zero::strings::join(headers, " ").c_str(),
            zero::strings::join(args, " ").c_str(),
            zero::strings::join(stackTrace, " ").c_str()
    );
#else
    LOG_INFO(
            "args: %s stack trace: %s",
            zero::strings::join(args, " ").c_str(),
            zero::strings::join(stackTrace, " ").c_str()
    );
#endif

#ifdef USE_RING_BUFFER
    return 0;
#endif
}

std::optional<int> getAPIOffset(const go::symbol::Reader &reader, uint64_t address) {
    std::optional<std::vector<std::byte>> buffer = reader.readVirtualMemory(address, INSTRUCTION_BUFFER_SIZE);

    if (!buffer)
        return std::nullopt;

    ZydisDecoder decoder;

    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64))) {
        LOG_ERROR("disassembler init failed");
        return std::nullopt;
    }

    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

    int offset = 0;

    while (true) {
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, buffer->data() + offset, INSTRUCTION_BUFFER_SIZE - offset, &instruction, operands))) {
            LOG_ERROR("disassemble failed");
            return std::nullopt;
        }

        if ((instruction.mnemonic == ZYDIS_MNEMONIC_SUB || instruction.mnemonic == ZYDIS_MNEMONIC_ADD) && operands[0].reg.value == ZYDIS_REGISTER_RSP)
            break;

        offset += instruction.length;

        if (offset > MAX_OFFSET) {
            LOG_ERROR("offset out of bounds");
            return std::nullopt;
        }
    }

    return offset;
}

int main(int argc, char **argv) {
    INIT_CONSOLE_LOG(zero::INFO);

    zero::Cmdline cmdline;

    cmdline.add<int>("pid", "process id");

    cmdline.addOptional<int>("fp", '\0', "traceback with frame pointer", -1);
    cmdline.addOptional<int>("abi", '\0', "specify golang calling conventions[stack(0)|register(1)]", -1);

    cmdline.parse(argc, argv);

    int pid = cmdline.get<int>("pid");

    int fp = cmdline.getOptional<int>("fp");
    int abi = cmdline.getOptional<int>("abi");

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

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(onLog);

    probe_bpf *skeleton = probe_bpf::open_and_load();

    if (!skeleton) {
        LOG_ERROR("failed to open and load BPF skeleton");
        return -1;
    }

    std::optional<go::symbol::Version> version = reader.version();

    if (version) {
        std::optional<std::tuple<int, int>> versionNumber = version->number();

        if (!versionNumber) {
            LOG_ERROR("get golang version number failed: %s", version->string().c_str());
            probe_bpf::destroy(skeleton);
            return -1;
        }

        auto [major, minor] = *versionNumber;

        LOG_INFO("golang version: %d.%d", major, minor);

        if (abi < 0)
            abi = major > 1 || (major == 1 && minor >= 17) ? 1 : 0;

        if (fp < 0)
            fp = major > 1 || (major == 1 && minor >= 7) ? 1 : 0;
    }

    if (abi >= 0)
        SET_CONFIG(skeleton, REGISTER_BASED, abi)

    if (fp >= 0)
        SET_CONFIG(skeleton, FRAME_POINTER, fp)

    std::optional<zero::os::process::ProcessMapping> processMapping = zero::os::process::getImageBase(
            pid,
            std::filesystem::read_symlink(path).string()
    );

    if (!processMapping) {
        LOG_INFO("get image base failed");
        probe_bpf::destroy(skeleton);
        return -1;
    }

    LOG_INFO("image base: %p", processMapping->start);

    std::optional<go::symbol::SymbolTable> symbolTable = reader.symbols(go::symbol::AnonymousMemory, processMapping->start);

    if (!symbolTable) {
        LOG_INFO("get symbol table failed");
        probe_bpf::destroy(skeleton);
        return -1;
    }

    for (const auto &api: GOLANG_API) {
        auto it = std::find_if(symbolTable->begin(), symbolTable->end(), [&](const auto &entry) {
            const char *name = entry.symbol().name();

            if (api.ignoreCase)
                return strcasecmp(api.name, name) == 0;

            return strcmp(api.name, name) == 0;
        });

        if (it == symbolTable->end()) {
            LOG_WARNING("function %s not found", api.name);
            continue;
        }

        auto program = std::find_if(skeleton->skeleton->progs, skeleton->skeleton->progs + skeleton->skeleton->prog_cnt, [&](const auto &program) {
            return strcmp(api.probe, program.name) == 0;
        });

        if (program == skeleton->skeleton->progs + skeleton->skeleton->prog_cnt) {
            LOG_WARNING("probe %s not found", api.probe);
            continue;
        }

        uint64_t entry = it.operator*().symbol().entry();

        std::optional<int> offset = getAPIOffset(reader, entry);

        if (!offset) {
            LOG_ERROR("get api offset failed");
            continue;
        }

        LOG_INFO("attach function %s: %p+%d", api.name, entry, offset);

        *program->link = bpf_program__attach_uprobe(
                *program->prog,
                false,
                pid,
                path.string().c_str(),
                entry + *offset - processMapping->start
        );

        if (!*program->link) {
            LOG_ERROR("failed to attach: %s", strerror(errno));
            continue;
        }
    }

    std::pair<bpf_map *, go::symbol::SymbolTable &> context = {
            fp != 1 ? skeleton->maps.frame_map : nullptr,
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
