#include "hooks.h"
#include "response.h"
#include "lib/minhook/MinHook.h"
#include <vector>
#include <cstdio>
#include <cstring>

// ── Hook slot with call logging ─────────────────────────────────────────

struct CallLogEntry {
    uint64_t rcx, rdx, r8, r9;   // First 4 args (x64 calling convention)
    uint64_t ret_value;
    uint64_t rsp;
    DWORD    thread_id;
    uint64_t timestamp;
};

struct HookSlot {
    bool     active;
    uint64_t target;
    void*    original;          // Trampoline to call original
    char     name[128];
    int      call_count;
    CallLogEntry log[MCP_HOOK_LOG_SIZE];
    int      log_index;         // Ring buffer index
};

static HookSlot g_hook_slots[MCP_MAX_HOOK_SLOTS];
static CRITICAL_SECTION g_hook_cs;
static bool g_minhook_ready = false;

// ── Generic detour functions (one per slot) ─────────────────────────────
// We need unique function pointers for each slot. Using a macro to generate
// templated detours. Each captures the slot index at compile time.

// Since we can't generate arbitrary functions at runtime in C++ without JIT,
// we use a fixed set of detour functions (16 slots).

#define DETOUR_FUNC(N) \
static uint64_t __fastcall Detour_##N(uint64_t rcx, uint64_t rdx, uint64_t r8, uint64_t r9) { \
    HookSlot& slot = g_hook_slots[N]; \
    EnterCriticalSection(&g_hook_cs); \
    int idx = slot.log_index % MCP_HOOK_LOG_SIZE; \
    slot.log[idx].rcx = rcx; \
    slot.log[idx].rdx = rdx; \
    slot.log[idx].r8 = r8; \
    slot.log[idx].r9 = r9; \
    slot.log[idx].thread_id = GetCurrentThreadId(); \
    slot.log[idx].timestamp = GetTickCount64(); \
    slot.call_count++; \
    LeaveCriticalSection(&g_hook_cs); \
    typedef uint64_t (__fastcall *OrigFn)(uint64_t, uint64_t, uint64_t, uint64_t); \
    uint64_t ret = ((OrigFn)slot.original)(rcx, rdx, r8, r9); \
    EnterCriticalSection(&g_hook_cs); \
    slot.log[idx].ret_value = ret; \
    slot.log_index++; \
    LeaveCriticalSection(&g_hook_cs); \
    return ret; \
}

DETOUR_FUNC(0)  DETOUR_FUNC(1)  DETOUR_FUNC(2)  DETOUR_FUNC(3)
DETOUR_FUNC(4)  DETOUR_FUNC(5)  DETOUR_FUNC(6)  DETOUR_FUNC(7)
DETOUR_FUNC(8)  DETOUR_FUNC(9)  DETOUR_FUNC(10) DETOUR_FUNC(11)
DETOUR_FUNC(12) DETOUR_FUNC(13) DETOUR_FUNC(14) DETOUR_FUNC(15)

static void* g_detour_funcs[MCP_MAX_HOOK_SLOTS] = {
    (void*)Detour_0,  (void*)Detour_1,  (void*)Detour_2,  (void*)Detour_3,
    (void*)Detour_4,  (void*)Detour_5,  (void*)Detour_6,  (void*)Detour_7,
    (void*)Detour_8,  (void*)Detour_9,  (void*)Detour_10, (void*)Detour_11,
    (void*)Detour_12, (void*)Detour_13, (void*)Detour_14, (void*)Detour_15,
};

// ── Init / Cleanup ──────────────────────────────────────────────────────

bool HookInit() {
    InitializeCriticalSection(&g_hook_cs);
    memset(g_hook_slots, 0, sizeof(g_hook_slots));

    if (MH_Initialize() != MH_OK)
        return false;

    g_minhook_ready = true;
    return true;
}

void HookCleanup() {
    if (g_minhook_ready) {
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
        g_minhook_ready = false;
    }
    DeleteCriticalSection(&g_hook_cs);
}

// ── Find free slot / find by address ────────────────────────────────────

static int FindFreeSlot() {
    for (int i = 0; i < MCP_MAX_HOOK_SLOTS; i++) {
        if (!g_hook_slots[i].active) return i;
    }
    return -1;
}

static int FindSlotByAddr(uint64_t addr) {
    for (int i = 0; i < MCP_MAX_HOOK_SLOTS; i++) {
        if (g_hook_slots[i].active && g_hook_slots[i].target == addr)
            return i;
    }
    return -1;
}

// ═════════════════════════════════════════════════════════════════════════
// Command Handlers
// ═════════════════════════════════════════════════════════════════════════

std::string CmdHook(uint64_t addr, const std::string& name) {
    if (!g_minhook_ready)
        return ErrorResponse("MinHook not initialized");

    EnterCriticalSection(&g_hook_cs);

    if (FindSlotByAddr(addr) >= 0) {
        LeaveCriticalSection(&g_hook_cs);
        return ErrorResponse("already hooked at this address");
    }

    int slot = FindFreeSlot();
    if (slot < 0) {
        LeaveCriticalSection(&g_hook_cs);
        return ErrorResponse("no free hook slots (max 16)");
    }

    HookSlot& hs = g_hook_slots[slot];
    memset(&hs, 0, sizeof(hs));
    hs.target = addr;
    strncpy(hs.name, name.empty() ? "unnamed" : name.c_str(), sizeof(hs.name) - 1);

    MH_STATUS status = MH_CreateHook((void*)addr, g_detour_funcs[slot], &hs.original);
    if (status != MH_OK) {
        LeaveCriticalSection(&g_hook_cs);
        return ErrorResponse("MH_CreateHook failed: " + std::to_string(status));
    }

    status = MH_EnableHook((void*)addr);
    if (status != MH_OK) {
        MH_RemoveHook((void*)addr);
        LeaveCriticalSection(&g_hook_cs);
        return ErrorResponse("MH_EnableHook failed: " + std::to_string(status));
    }

    hs.active = true;

    LeaveCriticalSection(&g_hook_cs);

    return Response()
        .add("status", "ok")
        .add("slot", (int64_t)slot)
        .addHex("address", addr)
        .add("name", std::string(hs.name))
        .build();
}

std::string CmdUnhook(uint64_t addr) {
    if (!g_minhook_ready)
        return ErrorResponse("MinHook not initialized");

    EnterCriticalSection(&g_hook_cs);

    int slot = FindSlotByAddr(addr);
    if (slot < 0) {
        LeaveCriticalSection(&g_hook_cs);
        return ErrorResponse("no hook at this address");
    }

    MH_DisableHook((void*)addr);
    MH_RemoveHook((void*)addr);
    g_hook_slots[slot].active = false;

    LeaveCriticalSection(&g_hook_cs);

    return SuccessResponse("hook removed");
}

std::string CmdHookList() {
    EnterCriticalSection(&g_hook_cs);

    std::vector<std::string> hooks;
    for (int i = 0; i < MCP_MAX_HOOK_SLOTS; i++) {
        if (!g_hook_slots[i].active) continue;
        HookSlot& hs = g_hook_slots[i];
        hooks.push_back(
            Response()
                .add("slot", (int64_t)i)
                .addHex("address", hs.target)
                .add("name", std::string(hs.name))
                .add("call_count", (int64_t)hs.call_count)
                .build()
        );
    }

    LeaveCriticalSection(&g_hook_cs);

    return Response()
        .add("status", "ok")
        .add("count", (int64_t)hooks.size())
        .addRawArray("hooks", hooks)
        .build();
}

std::string CmdHookLog(uint64_t addr, int count) {
    EnterCriticalSection(&g_hook_cs);

    int slot = FindSlotByAddr(addr);
    if (slot < 0) {
        LeaveCriticalSection(&g_hook_cs);
        return ErrorResponse("no hook at this address");
    }

    HookSlot& hs = g_hook_slots[slot];
    if (count <= 0 || count > MCP_HOOK_LOG_SIZE) count = MCP_HOOK_LOG_SIZE;

    int total = hs.log_index;
    int start = total > count ? total - count : 0;

    std::vector<std::string> entries;
    for (int i = start; i < total && i < start + count; i++) {
        int idx = i % MCP_HOOK_LOG_SIZE;
        CallLogEntry& e = hs.log[idx];
        entries.push_back(
            Response()
                .add("call_number", (int64_t)i)
                .addHex("rcx", e.rcx).addHex("rdx", e.rdx)
                .addHex("r8", e.r8).addHex("r9", e.r9)
                .addHex("return_value", e.ret_value)
                .add("thread_id", (int64_t)e.thread_id)
                .add("timestamp", (int64_t)e.timestamp)
                .build()
        );
    }

    LeaveCriticalSection(&g_hook_cs);

    return Response()
        .add("status", "ok")
        .addHex("address", addr)
        .add("name", std::string(hs.name))
        .add("total_calls", (int64_t)hs.call_count)
        .addRawArray("log", entries)
        .build();
}
