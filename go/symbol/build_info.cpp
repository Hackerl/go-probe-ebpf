#include "build_info.h"
#include <zero/log.h>
#include <zero/filesystem/path.h>
#include <regex>
#include <unistd.h>
#include <elfio/elfio.hpp>

constexpr auto GO_BUILD_INFO = "buildinfo";
constexpr auto GO_BUILD_INFO_MAGIC = "\xff Go buildinf:";
constexpr auto GO_BUILD_INFO_OFFSET = 16;

constexpr auto GO_REGISTER_BASED_MAJOR = 1;
constexpr auto GO_REGISTER_BASED_MINOR = 17;

constexpr auto POINTER_FREE_FLAG = 0x2;
constexpr auto POINTER_FREE_OFFSET = 32;

constexpr auto MAX_VAR_INT_LENGTH = 10;

static bool readUVarInt(const unsigned char **pp, unsigned long &value) {
    unsigned int v = 0;
    unsigned int shift = 0;

    const unsigned char *p = *pp;

    for (int i = 0; i < MAX_VAR_INT_LENGTH; i++) {
        unsigned long b = *p++;

        if (b < 0x80) {
            if (i == MAX_VAR_INT_LENGTH - 1 && b > 1)
                return false;

            *pp = p;
            value = v | b << shift;

            return true;
        }

        v |= (b & 0x7f) << shift;
        shift += 7;
    }

    return false;
}

bool CBuildInfo::load(const std::string &file) {
    ELFIO::elfio reader;

    if (!reader.load(file)) {
        LOG_ERROR("open elf failed: %s", file.c_str());
        return false;
    }

    auto it = std::find_if(
            reader.sections.begin(),
            reader.sections.end(),
            [](const auto& s) {
                return zero::strings::containsIC(s->get_name(), GO_BUILD_INFO);
            });

    if (it == reader.sections.end()) {
        LOG_ERROR("can't find go build info section");
        return false;
    }

    auto peek = [&reader](uint64_t address, char *buffer, size_t length) {
        auto it = std::find_if(
                reader.segments.begin(),
                reader.segments.end(),
                [=](const auto& s) {
                    return address >= s->get_virtual_address() && address <= s->get_virtual_address() + s->get_file_size() - 1;
                });

        if (it == reader.segments.end())
            return false;

        if ((*it)->get_virtual_address() + (*it)->get_file_size() - address < length)
            return false;

        memcpy(buffer, (*it)->get_data() + address - (*it)->get_virtual_address(), length);

        return true;
    };

    auto peekString = [&peek](uint64_t address) -> std::string {
        go::string str = {};

        if (!peek(address, (char *)&str, sizeof(go::string)))
            return "";

        std::unique_ptr<char[]> buffer = std::make_unique<char[]>(str.length);

        if (!peek((uint64_t)str.data, buffer.get(), str.length))
            return "";

        return {buffer.get() , (std::size_t)str.length};
    };

    char *data = (char *)(*it)->get_data();
    size_t magicSize = strlen(GO_BUILD_INFO_MAGIC);

    if (memcmp(data, GO_BUILD_INFO_MAGIC, magicSize) != 0) {
        LOG_ERROR("go build info magic error");
        return false;
    }

    mPtrSize = (unsigned char)data[magicSize];
    mEndian = (go::endian)data[magicSize + 1];

    std::string modInfo;

    if (mEndian & POINTER_FREE_FLAG) {
        mEndian = (go::endian)(mEndian & ~POINTER_FREE_FLAG);

        unsigned long length = 0;
        char *p = &data[POINTER_FREE_OFFSET];

        if (!readUVarInt((const unsigned char **)&p, length))
            return false;

        mVersion = {p, length};
        p += length;

        if (!readUVarInt((const unsigned char **)&p, length))
            return false;

        modInfo = {p, length};
    } else {
        mVersion = peekString(*(uint64_t *)&data[GO_BUILD_INFO_OFFSET]);
        modInfo = peekString(*(uint64_t *)&data[GO_BUILD_INFO_OFFSET + mPtrSize]);
    }

    std::smatch match;

    if (!std::regex_match(mVersion, match, std::regex(R"(^go(\d+)\.(\d+).*)")))
        return false;

    unsigned long major = 0;
    unsigned long minor = 0;

    if (zero::strings::toNumber(match.str(1), major) && zero::strings::toNumber(match.str(2), minor)) {
        mRegisterBased = major > GO_REGISTER_BASED_MAJOR || (major == GO_REGISTER_BASED_MAJOR && minor >= GO_REGISTER_BASED_MINOR);
    }

    if (modInfo.empty()) {
        LOG_INFO("module info empty");
        return true;
    }

    return readModuleInfo(modInfo);
}

bool CBuildInfo::readModuleInfo(const std::string &modInfo) {
    if (modInfo.length() < 32) {
        LOG_ERROR("module info invalid");
        return false;
    }

    std::string info(modInfo.data() + 16, modInfo.length() - 32);
    std::vector<std::string> mods = zero::strings::split(info, "\n");

    auto readEntry = [](const std::string &m, CModule &module) {
        std::vector<std::string> tokens = zero::strings::split(m, "\t");

        if (tokens.size() != 4)
            return false;

        module.path = tokens[1];
        module.version = tokens[2];
        module.sum = tokens[3];

        return true;
    };

    for (const auto &m: mods) {
        if (zero::strings::startsWith(m, "path")) {
            std::vector<std::string> tokens = zero::strings::split(m, "\t");

            if (tokens.size() != 2)
                continue;

            mModuleInfo.path = tokens[1];
        } else if (zero::strings::startsWith(m, "mod")) {
            CModule module = {};

            if (!readEntry(m, module))
                continue;

            mModuleInfo.main = module;
        } else if (zero::strings::startsWith(m, "dep")) {
            CModule module = {};

            if (!readEntry(m, module))
                continue;

            mModuleInfo.deps.push_back(module);
        } else if (zero::strings::startsWith(m, "=>")) {
            CModule module = {};

            if (!readEntry(m, module))
                continue;

            mModuleInfo.deps.back().replace = new CModule(module);
        }
    }

    return true;
}
