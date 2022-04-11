#include "line_table.h"
#include <zero/log.h>
#include <zero/filesystem/path.h>

constexpr auto GO_LINE_TABLE = "gopclntab";

constexpr auto LINE_TABLE_MAGIC_12 = 0xFFFFFFFB;
constexpr auto LINE_TABLE_MAGIC_116 = 0xFFFFFFFA;
constexpr auto LINE_TABLE_MAGIC_118 = 0xFFFFFFF0;

static unsigned int readVarInt(const unsigned char **pp) {
    unsigned int v = 0;
    unsigned int shift = 0;

    const unsigned char *p = *pp;

    while (true) {
        unsigned int b = *p++;
        v |= (b & 0x7F) << shift;

        if ((b & 0x80) == 0)
            break;

        shift += 7;
    }

    *pp = p;

    return v;
}

bool CLineTable::load(const std::string &file) {
    if (!mReader.load(file))
        return false;

    auto it = std::find_if(
            mReader.sections.begin(),
            mReader.sections.end(),
            [](const auto& s) {
                return zero::strings::containsIC(s->get_name(), GO_LINE_TABLE);
            });

    if (it == mReader.sections.end()) {
        LOG_ERROR("can't find line table section");
        return false;
    }

    const char *table = (*it)->get_data();

    mQuantum = (unsigned char)table[6];
    mPtrSize = (unsigned char)table[7];

    auto peek = [&](const char *address) -> uint64_t {
        if (mPtrSize == 4)
            return *(uint32_t *)address;

        return *(uint64_t *)address;
    };

    unsigned int magic = *(unsigned int *)table;

    switch (magic) {
        case LINE_TABLE_MAGIC_12: {
            mVersion = VERSION12;

            mFuncNum = (unsigned int)peek(&table[8]);
            mFuncData = table;
            mFuncNameTable = table;
            mFuncTable = &table[8 + mPtrSize];
            mPCTable = table;

            unsigned int funcTableSize = mFuncNum * 2 * mPtrSize + mPtrSize;
            unsigned int fileOffset = *(unsigned int *)&mFuncTable[funcTableSize];

            mFileTable = &table[fileOffset];
            mFileNum = *(unsigned int *)mFileTable;

            break;
        }

        case LINE_TABLE_MAGIC_116: {
            mVersion = VERSION116;

            mFuncNum = (unsigned int)peek(&table[8]);
            mFileNum = (unsigned int)peek(&table[8 + mPtrSize]);

            mFuncNameTable = &table[peek(&table[8 + 2 * mPtrSize])];
            mCuTable = &table[peek(&table[8 + 3 * mPtrSize])];
            mFileTable = &table[peek(&table[8 + 4 * mPtrSize])];
            mPCTable = &table[peek(&table[8 + 5 * mPtrSize])];
            mFuncData = &table[peek(&table[8 + 6 * mPtrSize])];
            mFuncTable = &table[peek(&table[8 + 6 * mPtrSize])];

            break;
        }

        case LINE_TABLE_MAGIC_118: {
            mVersion = VERSION118;

            mFuncNum = (unsigned int)peek(&table[8]);
            mFileNum = (unsigned int)peek(&table[8 + mPtrSize]);
            mTextStart = (uintptr_t)peek(&table[8 + 2 * mPtrSize]);

            mFuncNameTable = &table[peek(&table[8 + 3 * mPtrSize])];
            mCuTable = &table[peek(&table[8 + 4 * mPtrSize])];
            mFileTable = &table[peek(&table[8 + 5 * mPtrSize])];
            mPCTable = &table[peek(&table[8 + 6 * mPtrSize])];
            mFuncData = &table[peek(&table[8 + 7 * mPtrSize])];
            mFuncTable = &table[peek(&table[8 + 7 * mPtrSize])];

            break;
        }

        default:
            return false;
    }

    return true;
}

CFuncTablePtr CLineTable::getFuncTable() const {
    return CFuncTablePtr(mFuncTable, mVersion >= VERSION118 ? 4 : mPtrSize);
}

bool CLineTable::findFunc(uintptr_t address, CFunc &func) {
    auto begin = getFuncTable();
    auto back = begin + mFuncNum;
    auto end = back + 1;
    auto base = mVersion >= VERSION118 ? mTextStart : 0;

    if (address < begin->entry + base || address >= back->entry + base)
        return false;

    auto it = std::upper_bound(begin, end, address, [&](auto value, const auto& i) {
        return value < i.entry + base;
    });

    if (it == end)
        return false;

    func.mLineTable = this;
    func.mFuncData = &mFuncData[(it - 1)->offset];

    return true;
}

bool CLineTable::getFunc(unsigned int index, CFunc &func) {
    if (index >= mFuncNum)
        return false;

    func.mLineTable = this;
    func.mFuncData = &mFuncData[getFuncTable()[index].offset];

    return true;
}

int CLineTable::getPCValue(unsigned int offset, uintptr_t entry, uintptr_t targetPC) const {
    const unsigned char *p = (unsigned char *)&mPCTable[offset];

    int value = -1;
    uintptr_t pc = entry;

    while (step(&p, &pc, &value, pc == entry)) {
        if (targetPC < pc)
            return value;
    }

    return -1;
}

bool CLineTable::step(const unsigned char **p, uintptr_t *pc, int *value, bool first) const {
    unsigned int uv = readVarInt(p);

    if (uv == 0 && !first)
        return false;

    if ((uv & 1) != 0) {
        uv = ~(uv >> 1);
    } else {
        uv >>= 1;
    }

    *pc += readVarInt(p) * mQuantum;
    *value += (int)uv;

    return true;
}

bool CLineTable::findFunc(const std::string &name, CFunc &func) {
    for (unsigned int i = 0; i < mFuncNum; i++) {
        if (!getFunc(i, func))
            break;

        if (name == func.getName())
            return true;
    }

    return false;
}
