#include "memory_ops.h"
#include "response.h"
#include <cstring>
#include <cstdio>
#include <vector>

// ── Safe Memory Read ─────────────────────────────────────────────────────

bool MemReadSafe(void* addr, void* buf, size_t size) {
    __try {
        memcpy(buf, addr, size);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// ── Safe Memory Write ────────────────────────────────────────────────────

bool MemWriteSafe(void* addr, const void* buf, size_t size) {
    DWORD old_protect;
    if (!VirtualProtect(addr, size, PAGE_EXECUTE_READWRITE, &old_protect))
        return false;

    bool ok = false;
    __try {
        memcpy(addr, buf, size);
        ok = true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        ok = false;
    }

    VirtualProtect(addr, size, old_protect, &old_protect);
    FlushInstructionCache(GetCurrentProcess(), addr, size);
    return ok;
}

// ── Safe Memory Fill ─────────────────────────────────────────────────────

bool MemFillSafe(void* addr, uint8_t byte, size_t size) {
    DWORD old_protect;
    if (!VirtualProtect(addr, size, PAGE_EXECUTE_READWRITE, &old_protect))
        return false;

    bool ok = false;
    __try {
        memset(addr, byte, size);
        ok = true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        ok = false;
    }

    VirtualProtect(addr, size, old_protect, &old_protect);
    return ok;
}

// ── Pointer Validation ──────────────────────────────────────────────────

bool MemIsValidPtr(void* addr) {
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(addr, &mbi, sizeof(mbi)) == 0)
        return false;
    if (mbi.State != MEM_COMMIT)
        return false;
    if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))
        return false;
    return true;
}

// ── Memory Region Query ─────────────────────────────────────────────────

bool MemQueryRegion(void* addr, MemRegionInfo& info) {
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(addr, &mbi, sizeof(mbi)) == 0)
        return false;

    info.base       = (uint64_t)mbi.BaseAddress;
    info.alloc_base = (uint64_t)mbi.AllocationBase;
    info.size       = (uint64_t)mbi.RegionSize;
    info.protect    = mbi.Protect;
    info.state      = mbi.State;
    info.type       = mbi.Type;
    return true;
}

// ── Memory Protection ───────────────────────────────────────────────────

bool MemSetProtect(void* addr, size_t size, DWORD new_protect, DWORD* old_protect) {
    return VirtualProtect(addr, size, new_protect, old_protect) != 0;
}

// ── Allocation ──────────────────────────────────────────────────────────

void* MemAlloc(size_t size, DWORD protect) {
    return VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, protect);
}

bool MemFree(void* addr) {
    return VirtualFree(addr, 0, MEM_RELEASE) != 0;
}

// ── Hex string to bytes ─────────────────────────────────────────────────

static bool hex_to_bytes(const std::string& hex, std::vector<uint8_t>& out) {
    std::string clean;
    for (char c : hex) {
        if (c != ' ' && c != '\t') clean += c;
    }
    if (clean.size() % 2 != 0) return false;

    out.resize(clean.size() / 2);
    for (size_t i = 0; i < out.size(); i++) {
        char hi = clean[i * 2];
        char lo = clean[i * 2 + 1];
        auto nibble = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int h = nibble(hi), l = nibble(lo);
        if (h < 0 || l < 0) return false;
        out[i] = (uint8_t)((h << 4) | l);
    }
    return true;
}

// ═════════════════════════════════════════════════════════════════════════
// Command Handlers (return JSON)
// ═════════════════════════════════════════════════════════════════════════

std::string CmdRead(uint64_t addr, size_t size) {
    if (size == 0 || size > MCP_MAX_READ)
        return ErrorResponse("invalid size (max 1MB)");

    std::vector<uint8_t> buf(size);
    if (!MemReadSafe((void*)addr, buf.data(), size))
        return ErrorResponse("read failed - invalid or protected memory");

    return Response()
        .add("status", "ok")
        .addHex("address", addr)
        .add("size", (int64_t)size)
        .add("hex", bytes_to_hex(buf.data(), size))
        .build();
}

std::string CmdWrite(uint64_t addr, const std::string& hex_data) {
    std::vector<uint8_t> bytes;
    if (!hex_to_bytes(hex_data, bytes))
        return ErrorResponse("invalid hex data");
    if (bytes.empty())
        return ErrorResponse("no data to write");

    if (!MemWriteSafe((void*)addr, bytes.data(), bytes.size()))
        return ErrorResponse("write failed - invalid or protected memory");

    return Response()
        .add("status", "ok")
        .addHex("address", addr)
        .add("bytes_written", (int64_t)bytes.size())
        .build();
}

std::string CmdProtect(uint64_t addr) {
    MemRegionInfo info;
    if (!MemQueryRegion((void*)addr, info))
        return ErrorResponse("VirtualQuery failed");

    auto prot_str = [](DWORD p) -> std::string {
        std::string s;
        if (p & PAGE_NOACCESS)           s += "NOACCESS ";
        if (p & PAGE_READONLY)           s += "READONLY ";
        if (p & PAGE_READWRITE)          s += "READWRITE ";
        if (p & PAGE_WRITECOPY)          s += "WRITECOPY ";
        if (p & PAGE_EXECUTE)            s += "EXECUTE ";
        if (p & PAGE_EXECUTE_READ)       s += "EXECUTE_READ ";
        if (p & PAGE_EXECUTE_READWRITE)  s += "EXECUTE_READWRITE ";
        if (p & PAGE_EXECUTE_WRITECOPY)  s += "EXECUTE_WRITECOPY ";
        if (p & PAGE_GUARD)              s += "GUARD ";
        if (p & PAGE_NOCACHE)            s += "NOCACHE ";
        if (s.empty()) s = "UNKNOWN";
        return s;
    };

    auto state_str = [](DWORD s) -> std::string {
        if (s == MEM_COMMIT)  return "COMMIT";
        if (s == MEM_RESERVE) return "RESERVE";
        if (s == MEM_FREE)    return "FREE";
        return "UNKNOWN";
    };

    auto type_str = [](DWORD t) -> std::string {
        if (t == MEM_IMAGE)   return "IMAGE";
        if (t == MEM_MAPPED)  return "MAPPED";
        if (t == MEM_PRIVATE) return "PRIVATE";
        return "UNKNOWN";
    };

    return Response()
        .add("status", "ok")
        .addHex("address", addr)
        .addHex("region_base", info.base)
        .addHex("alloc_base", info.alloc_base)
        .addHex("region_size", info.size)
        .add("protect", prot_str(info.protect))
        .add("state", state_str(info.state))
        .add("type", type_str(info.type))
        .build();
}

std::string CmdAlloc(size_t size, DWORD protect) {
    void* p = MemAlloc(size, protect);
    if (!p)
        return ErrorResponse("VirtualAlloc failed");

    return Response()
        .add("status", "ok")
        .addHex("address", (uint64_t)p)
        .add("size", (int64_t)size)
        .build();
}

std::string CmdFree(uint64_t addr) {
    if (!MemFree((void*)addr))
        return ErrorResponse("VirtualFree failed");
    return SuccessResponse("memory freed");
}

std::string CmdReadPtr(uint64_t addr, int depth) {
    if (depth < 1) depth = 1;
    if (depth > 16) depth = 16;

    std::vector<std::string> chain;
    uint64_t current = addr;

    for (int i = 0; i < depth; i++) {
        char buf[64];
        snprintf(buf, sizeof(buf), "0x%llX", (unsigned long long)current);

        uint64_t next = 0;
        if (!MemReadSafe((void*)current, &next, sizeof(next))) {
            chain.push_back(std::string(buf) + " -> [INVALID]");
            break;
        }
        snprintf(buf, sizeof(buf), "0x%llX -> 0x%llX",
                 (unsigned long long)current, (unsigned long long)next);
        chain.push_back(buf);
        current = next;
    }

    return Response()
        .add("status", "ok")
        .addHex("start", addr)
        .add("depth", (int64_t)depth)
        .addHex("final_value", current)
        .addArray("chain", chain)
        .build();
}

std::string CmdFill(uint64_t addr, size_t size, uint8_t byte) {
    if (size == 0 || size > MCP_MAX_READ)
        return ErrorResponse("invalid size");

    if (!MemFillSafe((void*)addr, byte, size))
        return ErrorResponse("fill failed");

    return Response()
        .add("status", "ok")
        .addHex("address", addr)
        .add("size", (int64_t)size)
        .addHex("byte", byte)
        .build();
}
