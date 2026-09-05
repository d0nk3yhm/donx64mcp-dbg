#include "hooks.h"
#include "response.h"
#include "memory_ops.h"
#include "lib/minhook/MinHook.h"
#include <vector>
#include <cstdio>
#include <cstring>
#include <intrin.h>

#pragma intrinsic(_ReturnAddress)

// -- Hook slot with call logging + optional native scan/patch action --------
//
// Three modes, chosen per-hook at install time. Nothing here is specific to
// any particular target, API, or check -- the caller supplies the address,
// the byte pattern, and the replacement; this file only knows how to find
// and rewrite bytes relative to a call, generically.
//
//   MODE_LOG          passive: log args + return value, change nothing.
//   MODE_SCAN_CALLER  after calling the original, scan forward from the
//                     CALLER's own return address for `pattern` and
//                     overwrite it with `replacement` if found.
//   MODE_SCAN_OUTPUT  after calling the original, scan one of the call's
//                     own arguments (treated as a buffer pointer) for
//                     `pattern` and overwrite bytes at an offset from the
//                     match.

#define MCP_MAX_HOOK_PATTERN 48

enum HookMode {
    MODE_LOG         = 0,
    MODE_SCAN_CALLER = 1,
    MODE_SCAN_OUTPUT = 2,
};

struct CallLogEntry {
    uint64_t rcx, rdx, r8, r9;   // First 4 args (x64 calling convention)
    uint64_t ret_value;
    uint64_t rsp;
    DWORD    thread_id;
    uint64_t timestamp;
    bool     patched;            // true if this call's scan/patch action matched and wrote bytes
};

struct HookSlot {
    bool     active;
    uint64_t target;
    void*    original;          // Trampoline to call original
    char     name[128];
    int      call_count;
    CallLogEntry log[MCP_HOOK_LOG_SIZE];
    int      log_index;         // Ring buffer index

    int      mode;

    // MODE_SCAN_CALLER config
    int      scan_window;       // bytes to scan forward from the caller's return address

    // MODE_SCAN_OUTPUT config
    int      buf_arg_index;     // which of rcx/rdx/r8/r9 (0-3) holds the buffer pointer
    int      len_arg_index;     // which arg tells us how many bytes are valid
    bool     len_is_out_pointer;// true: dereference that arg as a DWORD* AFTER calling original
    int      patch_offset;      // signed offset from match start to where replacement is written

    // Shared pattern/replacement (used by both scan modes)
    uint8_t  pat_bytes[MCP_MAX_HOOK_PATTERN];
    bool     pat_wild[MCP_MAX_HOOK_PATTERN];
    int      pat_len;
    uint8_t  repl_bytes[MCP_MAX_HOOK_PATTERN];
    bool     repl_skip[MCP_MAX_HOOK_PATTERN];  // true = leave this byte of the match unchanged
    int      repl_len;
};

static HookSlot g_hook_slots[MCP_MAX_HOOK_SLOTS];
static CRITICAL_SECTION g_hook_cs;
static bool g_minhook_ready = false;

// -- Comma-separated hex pattern parser: "48,8B,??,05" -----------------------
// Shared by pattern (?? = wildcard-match-anything) and replacement
// (?? = leave that byte of the match unchanged).

static int ParseCsvPattern(const std::string& csv, uint8_t* out_bytes, bool* out_flag, int max_len) {
    int count = 0;
    size_t i = 0;
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    while (i < csv.size() && count < max_len) {
        while (i < csv.size() && csv[i] == ',') i++;
        if (i >= csv.size()) break;
        if (csv[i] == '?') {
            out_bytes[count] = 0;
            out_flag[count] = true;
            count++;
            i++;
            if (i < csv.size() && csv[i] == '?') i++;
        } else {
            if (i + 1 >= csv.size()) return -1;
            int hi = nibble(csv[i]), lo = nibble(csv[i + 1]);
            if (hi < 0 || lo < 0) return -1;
            out_bytes[count] = (uint8_t)((hi << 4) | lo);
            out_flag[count] = false;
            count++;
            i += 2;
        }
        while (i < csv.size() && csv[i] == ',') i++;
    }
    return count;
}

// -- Native scan/patch actions, run in-process at hook time ------------------

// Debug logging for scan attempts — file at C:\Users\sys5\AppData\Local\Temp\mcp_scan.log
static void DebugScanLog(const char* fmt, ...) {
    char buf[512];
    va_list args; va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    HANDLE h = CreateFileA("C:\\Users\\sys5\\AppData\\Local\\Temp\\mcp_scan.log",
        FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
        OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        char line[600];
        int n = snprintf(line, sizeof(line), "[tid=%lu] %s\r\n", GetCurrentThreadId(), buf);
        DWORD w; WriteFile(h, line, (DWORD)n, &w, NULL);
        CloseHandle(h);
    }
}

static void RunScanCaller(HookSlot& slot, uint64_t caller) {
    if (slot.pat_len <= 0 || slot.scan_window <= 0) return;
    int window = slot.scan_window;
    if (window > 4096) window = 4096;
    uint8_t buf[4096];
    if (!MemReadSafe((void*)caller, buf, window)) {
        DebugScanLog("caller=0x%llX MemReadSafe FAILED", (unsigned long long)caller);
        return;
    }
    DebugScanLog("caller=0x%llX first16=%02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
        (unsigned long long)caller,
        buf[0],buf[1],buf[2],buf[3],buf[4],buf[5],buf[6],buf[7],
        buf[8],buf[9],buf[10],buf[11],buf[12],buf[13],buf[14],buf[15]);

    for (int i = 0; i + slot.pat_len <= window; i++) {
        bool match = true;
        for (int p = 0; p < slot.pat_len; p++) {
            if (!slot.pat_wild[p] && buf[i + p] != slot.pat_bytes[p]) { match = false; break; }
        }
        if (!match) continue;

        uint8_t patch[MCP_MAX_HOOK_PATTERN];
        memcpy(patch, buf + i, slot.pat_len);
        for (int p = 0; p < slot.pat_len; p++) {
            if (p < slot.repl_len && !slot.repl_skip[p]) patch[p] = slot.repl_bytes[p];
            else if (p >= slot.repl_len) patch[p] = 0x90; // NOP-fill a shorter replacement
        }
        bool ok = MemWriteSafe((void*)(caller + i), patch, slot.pat_len);
        DebugScanLog("MATCH offset=+0x%X target=0x%llX write_ok=%d patch_bytes=%02X %02X %02X",
            i, (unsigned long long)(caller + i), ok ? 1 : 0,
            patch[0], slot.pat_len > 1 ? patch[1] : 0, slot.pat_len > 2 ? patch[2] : 0);
        return;
    }
    DebugScanLog("no match in window of %d bytes", window);
}

static void RunScanOutput(HookSlot& slot, uint64_t rcx, uint64_t rdx, uint64_t r8, uint64_t r9) {
    if (slot.pat_len <= 0) return;
    uint64_t args[4] = { rcx, rdx, r8, r9 };
    if (slot.buf_arg_index < 0 || slot.buf_arg_index > 3) return;
    if (slot.len_arg_index < 0 || slot.len_arg_index > 3) return;

    uint64_t buf_ptr = args[slot.buf_arg_index];
    if (!buf_ptr) return;

    uint32_t len = 0;
    if (slot.len_is_out_pointer) {
        uint64_t len_ptr = args[slot.len_arg_index];
        if (!len_ptr || !MemReadSafe((void*)len_ptr, &len, sizeof(len))) return;
    } else {
        len = (uint32_t)args[slot.len_arg_index];
    }
    if (len == 0) return;
    if (len > (16 * 1024 * 1024)) len = 16 * 1024 * 1024;

    std::vector<uint8_t> data(len);
    if (!MemReadSafe((void*)buf_ptr, data.data(), len)) return;

    for (size_t i = 0; i + (size_t)slot.pat_len <= data.size(); i++) {
        bool match = true;
        for (int p = 0; p < slot.pat_len; p++) {
            if (!slot.pat_wild[p] && data[i + p] != slot.pat_bytes[p]) { match = false; break; }
        }
        if (!match) continue;

        int64_t target = (int64_t)i + slot.patch_offset;
        if (target < 0 || target + slot.repl_len > (int64_t)data.size()) return;

        uint8_t patch[MCP_MAX_HOOK_PATTERN];
        MemReadSafe((void*)(buf_ptr + target), patch, slot.repl_len);
        for (int p = 0; p < slot.repl_len; p++) {
            if (!slot.repl_skip[p]) patch[p] = slot.repl_bytes[p];
        }
        MemWriteSafe((void*)(buf_ptr + target), patch, slot.repl_len);
        return;
    }
}

// -- Generic detour functions (one per slot) ---------------------------------
// We need unique function pointers for each slot. Using a macro to generate
// templated detours (16 fixed slots -- can't generate arbitrary functions at
// runtime in C++ without JIT).

#define DETOUR_FUNC(N) \
static uint64_t __fastcall Detour_##N(uint64_t rcx, uint64_t rdx, uint64_t r8, uint64_t r9) { \
    /* Capture the return address IMMEDIATELY on entry. Because MinHook uses \
       a JMP (not CALL) to enter this detour, _ReturnAddress() here yields \
       the address in the ORIGINAL caller's code (right after their CALL to \
       the hooked function) -- exactly what MODE_SCAN_CALLER needs. Calling \
       _ReturnAddress() inside a nested helper like RunScanCaller instead \
       would give a debugger-DLL-internal address, which is wrong. */ \
    uint64_t orig_caller = (uint64_t)_ReturnAddress(); \
    HookSlot& slot = g_hook_slots[N]; \
    EnterCriticalSection(&g_hook_cs); \
    int idx = slot.log_index % MCP_HOOK_LOG_SIZE; \
    slot.log[idx].rcx = rcx; \
    slot.log[idx].rdx = rdx; \
    slot.log[idx].r8 = r8; \
    slot.log[idx].r9 = r9; \
    slot.log[idx].thread_id = GetCurrentThreadId(); \
    slot.log[idx].timestamp = GetTickCount64(); \
    slot.log[idx].patched = false; \
    slot.call_count++; \
    LeaveCriticalSection(&g_hook_cs); \
    typedef uint64_t (__fastcall *OrigFn)(uint64_t, uint64_t, uint64_t, uint64_t); \
    uint64_t ret = ((OrigFn)slot.original)(rcx, rdx, r8, r9); \
    if (slot.mode == MODE_SCAN_CALLER) RunScanCaller(slot, orig_caller); \
    else if (slot.mode == MODE_SCAN_OUTPUT) RunScanOutput(slot, rcx, rdx, r8, r9); \
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

// -- Init / Cleanup -----------------------------------------------------------

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

// -- Find free slot / find by address ----------------------------------------

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

// =============================================================================
// Command Handlers
// =============================================================================

// Shared: allocate a slot, create + enable the MinHook hook. Caller fills in
// slot-specific config (mode, pattern, etc.) via the returned slot pointer.
// Must be called with g_hook_cs held.
static std::string InstallHook(uint64_t addr, const std::string& name, HookSlot** out_slot, int* out_idx) {
    if (!g_minhook_ready)
        return "MinHook not initialized";

    if (FindSlotByAddr(addr) >= 0)
        return "already hooked at this address";

    int slot = FindFreeSlot();
    if (slot < 0)
        return "no free hook slots (max 16)";

    HookSlot& hs = g_hook_slots[slot];
    memset(&hs, 0, sizeof(hs));
    hs.target = addr;
    strncpy(hs.name, name.empty() ? "unnamed" : name.c_str(), sizeof(hs.name) - 1);

    MH_STATUS status = MH_CreateHook((void*)addr, g_detour_funcs[slot], &hs.original);
    if (status != MH_OK)
        return "MH_CreateHook failed: " + std::to_string((int)status);

    status = MH_EnableHook((void*)addr);
    if (status != MH_OK) {
        MH_RemoveHook((void*)addr);
        return "MH_EnableHook failed: " + std::to_string((int)status);
    }

    hs.active = true;
    *out_slot = &hs;
    *out_idx = slot;
    return "";
}

std::string CmdHook(uint64_t addr, const std::string& name) {
    EnterCriticalSection(&g_hook_cs);
    HookSlot* hs = nullptr; int slot = -1;
    std::string err = InstallHook(addr, name, &hs, &slot);
    if (!err.empty()) { LeaveCriticalSection(&g_hook_cs); return ErrorResponse(err); }
    hs->mode = MODE_LOG;
    std::string hookName = hs->name;
    LeaveCriticalSection(&g_hook_cs);

    return Response()
        .add("status", "ok")
        .add("slot", (int64_t)slot)
        .addHex("address", addr)
        .add("name", hookName)
        .add("mode", "log")
        .build();
}

std::string CmdHookScanCaller(uint64_t addr, int scan_window, const std::string& pattern_csv,
                               const std::string& replacement_csv, const std::string& name) {
    uint8_t pat[MCP_MAX_HOOK_PATTERN], repl[MCP_MAX_HOOK_PATTERN];
    bool pat_wild[MCP_MAX_HOOK_PATTERN], repl_skip[MCP_MAX_HOOK_PATTERN];
    int pat_len = ParseCsvPattern(pattern_csv, pat, pat_wild, MCP_MAX_HOOK_PATTERN);
    if (pat_len <= 0) return ErrorResponse("invalid pattern (comma-separated hex, ?? for wildcard)");
    int repl_len = ParseCsvPattern(replacement_csv, repl, repl_skip, MCP_MAX_HOOK_PATTERN);
    if (repl_len < 0) return ErrorResponse("invalid replacement (comma-separated hex, ?? to leave a byte unchanged)");
    if (repl_len > pat_len) return ErrorResponse("replacement must not be longer than pattern");
    if (scan_window <= 0 || scan_window > 4096) return ErrorResponse("scan_window must be 1-4096");

    EnterCriticalSection(&g_hook_cs);
    HookSlot* hs = nullptr; int slot = -1;
    std::string err = InstallHook(addr, name, &hs, &slot);
    if (!err.empty()) { LeaveCriticalSection(&g_hook_cs); return ErrorResponse(err); }

    hs->mode = MODE_SCAN_CALLER;
    hs->scan_window = scan_window;
    hs->pat_len = pat_len;
    memcpy(hs->pat_bytes, pat, pat_len);
    memcpy(hs->pat_wild, pat_wild, pat_len * sizeof(bool));
    hs->repl_len = repl_len;
    memcpy(hs->repl_bytes, repl, repl_len);
    memcpy(hs->repl_skip, repl_skip, repl_len * sizeof(bool));
    std::string hookName = hs->name;
    LeaveCriticalSection(&g_hook_cs);

    return Response()
        .add("status", "ok")
        .add("slot", (int64_t)slot)
        .addHex("address", addr)
        .add("name", hookName)
        .add("mode", "scan_caller")
        .add("scan_window", (int64_t)scan_window)
        .add("pattern_len", (int64_t)pat_len)
        .build();
}

std::string CmdHookScanOutput(uint64_t addr, int buf_arg_index, int len_arg_index, bool len_is_out_pointer,
                               const std::string& pattern_csv, int patch_offset,
                               const std::string& replacement_csv, const std::string& name) {
    if (buf_arg_index < 0 || buf_arg_index > 3) return ErrorResponse("buf_arg_index must be 0-3");
    if (len_arg_index < 0 || len_arg_index > 3) return ErrorResponse("len_arg_index must be 0-3");

    uint8_t pat[MCP_MAX_HOOK_PATTERN], repl[MCP_MAX_HOOK_PATTERN];
    bool pat_wild[MCP_MAX_HOOK_PATTERN], repl_skip[MCP_MAX_HOOK_PATTERN];
    int pat_len = ParseCsvPattern(pattern_csv, pat, pat_wild, MCP_MAX_HOOK_PATTERN);
    if (pat_len <= 0) return ErrorResponse("invalid pattern (comma-separated hex, ?? for wildcard)");
    int repl_len = ParseCsvPattern(replacement_csv, repl, repl_skip, MCP_MAX_HOOK_PATTERN);
    if (repl_len <= 0) return ErrorResponse("invalid replacement (comma-separated hex, ?? to leave a byte unchanged)");

    EnterCriticalSection(&g_hook_cs);
    HookSlot* hs = nullptr; int slot = -1;
    std::string err = InstallHook(addr, name, &hs, &slot);
    if (!err.empty()) { LeaveCriticalSection(&g_hook_cs); return ErrorResponse(err); }

    hs->mode = MODE_SCAN_OUTPUT;
    hs->buf_arg_index = buf_arg_index;
    hs->len_arg_index = len_arg_index;
    hs->len_is_out_pointer = len_is_out_pointer;
    hs->patch_offset = patch_offset;
    hs->pat_len = pat_len;
    memcpy(hs->pat_bytes, pat, pat_len);
    memcpy(hs->pat_wild, pat_wild, pat_len * sizeof(bool));
    hs->repl_len = repl_len;
    memcpy(hs->repl_bytes, repl, repl_len);
    memcpy(hs->repl_skip, repl_skip, repl_len * sizeof(bool));
    std::string hookName = hs->name;
    LeaveCriticalSection(&g_hook_cs);

    return Response()
        .add("status", "ok")
        .add("slot", (int64_t)slot)
        .addHex("address", addr)
        .add("name", hookName)
        .add("mode", "scan_output")
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

static const char* ModeName(int mode) {
    if (mode == MODE_SCAN_CALLER) return "scan_caller";
    if (mode == MODE_SCAN_OUTPUT) return "scan_output";
    return "log";
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
                .add("mode", ModeName(hs.mode))
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
