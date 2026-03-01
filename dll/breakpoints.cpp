#include "breakpoints.h"
#include "memory_ops.h"
#include "response.h"
#include <cstdio>
#include <vector>

// ── Breakpoint storage ──────────────────────────────────────────────────

static Breakpoint g_breakpoints[MCP_MAX_BREAKPOINTS];
static int        g_bp_count = 0;
static PVOID      g_veh_handle = NULL;
static HANDLE     g_bp_events[MCP_MAX_BREAKPOINTS]; // One event per BP for BP_WAIT

// Track which BP we're single-stepping over (per-thread would be better,
// but for simplicity we use a global — works for sequential LLM debugging)
static volatile uint64_t g_stepping_over_bp = 0;

// ── Find breakpoint by address ──────────────────────────────────────────

static int FindBp(uint64_t addr) {
    for (int i = 0; i < g_bp_count; i++) {
        if (g_breakpoints[i].address == addr)
            return i;
    }
    return -1;
}

// ── Write INT3 / restore original byte ──────────────────────────────────

static bool WriteInt3(uint64_t addr, uint8_t* save_original) {
    if (!MemReadSafe((void*)addr, save_original, 1))
        return false;
    uint8_t int3 = 0xCC;
    return MemWriteSafe((void*)addr, &int3, 1);
}

static bool RestoreOriginal(uint64_t addr, uint8_t original) {
    return MemWriteSafe((void*)addr, &original, 1);
}

// ── Vectored Exception Handler ──────────────────────────────────────────

static LONG WINAPI BreakpointVEH(EXCEPTION_POINTERS* ep) {
    DWORD code = ep->ExceptionRecord->ExceptionCode;

    // ── INT3 breakpoint hit ─────────────────────────────────────────
    if (code == EXCEPTION_BREAKPOINT) {
        uint64_t bp_addr = (uint64_t)ep->ExceptionRecord->ExceptionAddress;

        EnterCriticalSection(&g_bp_cs);
        int idx = FindBp(bp_addr);

        if (idx >= 0 && g_breakpoints[idx].active) {
            Breakpoint& bp = g_breakpoints[idx];

            // Capture context
            bp.last_context   = *ep->ContextRecord;
            bp.last_thread_id = GetCurrentThreadId();
            bp.last_hit_tick  = GetTickCount64();
            bp.hit_count++;
            bp.hit_pending = true;

            // Restore original byte so we can execute it
            RestoreOriginal(bp.address, bp.original_byte);

            // Set trap flag for single-step (re-arm after one instruction)
            ep->ContextRecord->EFlags |= 0x100; // TF
            g_stepping_over_bp = bp.address;

            // Signal the wait event
            if (g_bp_events[idx])
                SetEvent(g_bp_events[idx]);

            LeaveCriticalSection(&g_bp_cs);
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        LeaveCriticalSection(&g_bp_cs);
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // ── Single-step: re-arm the breakpoint ──────────────────────────
    if (code == EXCEPTION_SINGLE_STEP) {
        uint64_t rearm_addr = g_stepping_over_bp;
        if (rearm_addr != 0) {
            EnterCriticalSection(&g_bp_cs);
            int idx = FindBp(rearm_addr);

            if (idx >= 0 && g_breakpoints[idx].enabled) {
                // Re-write INT3
                uint8_t int3 = 0xCC;
                MemWriteSafe((void*)rearm_addr, &int3, 1);
                g_breakpoints[idx].active = true;

                // Handle one-shot: disable after first hit
                if (g_breakpoints[idx].one_shot) {
                    g_breakpoints[idx].enabled = false;
                    g_breakpoints[idx].active = false;
                    RestoreOriginal(rearm_addr, g_breakpoints[idx].original_byte);
                }
            }

            g_stepping_over_bp = 0;
            // Clear trap flag
            ep->ContextRecord->EFlags &= ~0x100;

            LeaveCriticalSection(&g_bp_cs);
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        return EXCEPTION_CONTINUE_SEARCH;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

// ── Init / Cleanup ──────────────────────────────────────────────────────

void BreakpointInit() {
    InitializeCriticalSection(&g_bp_cs);
    memset(g_breakpoints, 0, sizeof(g_breakpoints));
    memset(g_bp_events, 0, sizeof(g_bp_events));
    g_bp_count = 0;

    // Register VEH with highest priority
    g_veh_handle = AddVectoredExceptionHandler(1, BreakpointVEH);
}

void BreakpointCleanup() {
    EnterCriticalSection(&g_bp_cs);

    // Remove all active breakpoints
    for (int i = 0; i < g_bp_count; i++) {
        if (g_breakpoints[i].active) {
            RestoreOriginal(g_breakpoints[i].address, g_breakpoints[i].original_byte);
        }
        SAFE_CLOSE_HANDLE(g_bp_events[i]);
    }
    g_bp_count = 0;

    LeaveCriticalSection(&g_bp_cs);

    if (g_veh_handle) {
        RemoveVectoredExceptionHandler(g_veh_handle);
        g_veh_handle = NULL;
    }

    DeleteCriticalSection(&g_bp_cs);
}

// ═════════════════════════════════════════════════════════════════════════
// Command Handlers
// ═════════════════════════════════════════════════════════════════════════

std::string CmdBpSet(uint64_t addr) {
    EnterCriticalSection(&g_bp_cs);

    if (FindBp(addr) >= 0) {
        LeaveCriticalSection(&g_bp_cs);
        return ErrorResponse("breakpoint already exists at this address");
    }

    if (g_bp_count >= MCP_MAX_BREAKPOINTS) {
        LeaveCriticalSection(&g_bp_cs);
        return ErrorResponse("max breakpoints reached");
    }

    int idx = g_bp_count;
    Breakpoint& bp = g_breakpoints[idx];
    memset(&bp, 0, sizeof(bp));
    bp.address = addr;
    bp.enabled = true;

    if (!WriteInt3(addr, &bp.original_byte)) {
        LeaveCriticalSection(&g_bp_cs);
        return ErrorResponse("failed to write INT3 at address");
    }

    bp.active = true;
    g_bp_events[idx] = CreateEventA(NULL, FALSE, FALSE, NULL); // Auto-reset
    g_bp_count++;

    LeaveCriticalSection(&g_bp_cs);

    return Response()
        .add("status", "ok")
        .addHex("address", addr)
        .add("index", (int64_t)idx)
        .add("original_byte", bytes_to_hex(&bp.original_byte, 1))
        .build();
}

std::string CmdBpDel(uint64_t addr) {
    EnterCriticalSection(&g_bp_cs);

    int idx = FindBp(addr);
    if (idx < 0) {
        LeaveCriticalSection(&g_bp_cs);
        return ErrorResponse("no breakpoint at this address");
    }

    if (g_breakpoints[idx].active) {
        RestoreOriginal(addr, g_breakpoints[idx].original_byte);
    }

    SAFE_CLOSE_HANDLE(g_bp_events[idx]);

    // Compact array
    for (int i = idx; i < g_bp_count - 1; i++) {
        g_breakpoints[i] = g_breakpoints[i + 1];
        g_bp_events[i] = g_bp_events[i + 1];
    }
    g_bp_count--;

    LeaveCriticalSection(&g_bp_cs);
    return SuccessResponse("breakpoint removed");
}

std::string CmdBpList() {
    EnterCriticalSection(&g_bp_cs);

    std::vector<std::string> bps;
    for (int i = 0; i < g_bp_count; i++) {
        Breakpoint& bp = g_breakpoints[i];
        bps.push_back(
            Response()
                .addHex("address", bp.address)
                .add("enabled", bp.enabled)
                .add("active", bp.active)
                .add("hit_count", (int64_t)bp.hit_count)
                .add("hit_pending", bp.hit_pending)
                .add("original_byte", bytes_to_hex(&bp.original_byte, 1))
                .build()
        );
    }

    LeaveCriticalSection(&g_bp_cs);

    return Response()
        .add("status", "ok")
        .add("count", (int64_t)bps.size())
        .addRawArray("breakpoints", bps)
        .build();
}

// ── Get register context from last BP hit ───────────────────────────────

static std::string ContextToJson(const CONTEXT& ctx, DWORD tid) {
    return Response()
        .addHex("rax", ctx.Rax).addHex("rbx", ctx.Rbx)
        .addHex("rcx", ctx.Rcx).addHex("rdx", ctx.Rdx)
        .addHex("rsi", ctx.Rsi).addHex("rdi", ctx.Rdi)
        .addHex("rbp", ctx.Rbp).addHex("rsp", ctx.Rsp)
        .addHex("r8",  ctx.R8) .addHex("r9",  ctx.R9)
        .addHex("r10", ctx.R10).addHex("r11", ctx.R11)
        .addHex("r12", ctx.R12).addHex("r13", ctx.R13)
        .addHex("r14", ctx.R14).addHex("r15", ctx.R15)
        .addHex("rip", ctx.Rip).addHex("rflags", ctx.EFlags)
        .add("thread_id", (int64_t)tid)
        .build();
}

std::string CmdBpCtx(uint64_t addr) {
    EnterCriticalSection(&g_bp_cs);

    int idx = FindBp(addr);
    if (idx < 0) {
        LeaveCriticalSection(&g_bp_cs);
        return ErrorResponse("no breakpoint at this address");
    }

    Breakpoint& bp = g_breakpoints[idx];
    if (bp.hit_count == 0) {
        LeaveCriticalSection(&g_bp_cs);
        return ErrorResponse("breakpoint has not been hit yet");
    }

    bp.hit_pending = false;

    std::string ctx_json = ContextToJson(bp.last_context, bp.last_thread_id);

    LeaveCriticalSection(&g_bp_cs);

    return Response()
        .add("status", "ok")
        .addHex("address", addr)
        .add("hit_count", (int64_t)bp.hit_count)
        .addRaw("context", ctx_json)
        .build();
}

// ── Wait for breakpoint to hit ──────────────────────────────────────────

std::string CmdBpWait(uint64_t addr, DWORD timeout_ms) {
    EnterCriticalSection(&g_bp_cs);

    int idx = FindBp(addr);
    if (idx < 0) {
        LeaveCriticalSection(&g_bp_cs);
        return ErrorResponse("no breakpoint at this address");
    }

    HANDLE evt = g_bp_events[idx];
    int pre_count = g_breakpoints[idx].hit_count;

    LeaveCriticalSection(&g_bp_cs);

    // Wait outside the critical section!
    if (timeout_ms == 0) timeout_ms = 10000; // Default 10s
    DWORD result = WaitForSingleObject(evt, timeout_ms);

    EnterCriticalSection(&g_bp_cs);
    idx = FindBp(addr); // Re-find in case array changed
    if (idx < 0) {
        LeaveCriticalSection(&g_bp_cs);
        return ErrorResponse("breakpoint was removed while waiting");
    }

    if (result == WAIT_TIMEOUT) {
        LeaveCriticalSection(&g_bp_cs);
        return Response()
            .add("status", "timeout")
            .addHex("address", addr)
            .add("hit_count", (int64_t)g_breakpoints[idx].hit_count)
            .build();
    }

    Breakpoint& bp = g_breakpoints[idx];
    bp.hit_pending = false;
    std::string ctx_json = ContextToJson(bp.last_context, bp.last_thread_id);

    LeaveCriticalSection(&g_bp_cs);

    return Response()
        .add("status", "ok")
        .add("message", "breakpoint hit")
        .addHex("address", addr)
        .add("hit_count", (int64_t)bp.hit_count)
        .addRaw("context", ctx_json)
        .build();
}

std::string CmdBpEnable(uint64_t addr) {
    EnterCriticalSection(&g_bp_cs);

    int idx = FindBp(addr);
    if (idx < 0) {
        LeaveCriticalSection(&g_bp_cs);
        return ErrorResponse("no breakpoint at this address");
    }

    Breakpoint& bp = g_breakpoints[idx];
    if (bp.enabled) {
        LeaveCriticalSection(&g_bp_cs);
        return SuccessResponse("already enabled");
    }

    bp.enabled = true;
    uint8_t int3 = 0xCC;
    if (MemWriteSafe((void*)addr, &int3, 1)) {
        bp.active = true;
    }

    LeaveCriticalSection(&g_bp_cs);
    return SuccessResponse("breakpoint enabled");
}

std::string CmdBpDisable(uint64_t addr) {
    EnterCriticalSection(&g_bp_cs);

    int idx = FindBp(addr);
    if (idx < 0) {
        LeaveCriticalSection(&g_bp_cs);
        return ErrorResponse("no breakpoint at this address");
    }

    Breakpoint& bp = g_breakpoints[idx];
    bp.enabled = false;
    if (bp.active) {
        RestoreOriginal(addr, bp.original_byte);
        bp.active = false;
    }

    LeaveCriticalSection(&g_bp_cs);
    return SuccessResponse("breakpoint disabled");
}
