#pragma once
#ifndef MEMORY_OPS_H
#define MEMORY_OPS_H

#include "globals.h"
#include <string>

// ── Safe memory operations (all SEH-wrapped) ────────────────────────────

bool     MemReadSafe(void* addr, void* buf, size_t size);
bool     MemWriteSafe(void* addr, const void* buf, size_t size);
bool     MemFillSafe(void* addr, uint8_t byte, size_t size);
bool     MemIsValidPtr(void* addr);

// Memory protection
struct MemRegionInfo {
    uint64_t base;
    uint64_t alloc_base;
    uint64_t size;
    DWORD    protect;
    DWORD    state;      // MEM_COMMIT, MEM_RESERVE, MEM_FREE
    DWORD    type;       // MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE
};

bool     MemQueryRegion(void* addr, MemRegionInfo& info);
bool     MemSetProtect(void* addr, size_t size, DWORD new_protect, DWORD* old_protect);

// Allocation
void*    MemAlloc(size_t size, DWORD protect = PAGE_EXECUTE_READWRITE);
bool     MemFree(void* addr);

// Command handlers (return JSON strings)
std::string CmdRead(uint64_t addr, size_t size);
std::string CmdWrite(uint64_t addr, const std::string& hex_data);
std::string CmdProtect(uint64_t addr);
std::string CmdAlloc(size_t size, DWORD protect);
std::string CmdFree(uint64_t addr);
std::string CmdReadPtr(uint64_t addr, int depth);
std::string CmdFill(uint64_t addr, size_t size, uint8_t byte);

#endif // MEMORY_OPS_H
