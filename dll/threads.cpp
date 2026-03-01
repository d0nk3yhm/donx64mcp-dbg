#include "threads.h"
#include "response.h"
#include <windows.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <vector>
#include <cstdio>
#include <algorithm>

#pragma comment(lib, "dbghelp.lib")

// ── List all threads ────────────────────────────────────────────────────

std::string CmdThreads() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return ErrorResponse("CreateToolhelp32Snapshot failed");

    THREADENTRY32 te;
    te.dwSize = sizeof(te);

    std::vector<std::string> threads;

    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == g_pid) {
                threads.push_back(
                    Response()
                        .add("thread_id", (int64_t)te.th32ThreadID)
                        .add("base_priority", (int64_t)te.tpBasePri)
                        .build()
                );
            }
        } while (Thread32Next(snap, &te));
    }

    CloseHandle(snap);

    return Response()
        .add("status", "ok")
        .add("pid", (int64_t)g_pid)
        .add("count", (int64_t)threads.size())
        .addRawArray("threads", threads)
        .build();
}

// ── Get thread context (all registers) ──────────────────────────────────

std::string CmdThreadCtx(DWORD tid) {
    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, tid);
    if (!hThread)
        return ErrorResponse("failed to open thread");

    SuspendThread(hThread);

    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_ALL;
    BOOL ok = GetThreadContext(hThread, &ctx);

    ResumeThread(hThread);
    CloseHandle(hThread);

    if (!ok)
        return ErrorResponse("GetThreadContext failed");

    return Response()
        .add("status", "ok")
        .add("thread_id", (int64_t)tid)
        .addHex("rax", ctx.Rax).addHex("rbx", ctx.Rbx)
        .addHex("rcx", ctx.Rcx).addHex("rdx", ctx.Rdx)
        .addHex("rsi", ctx.Rsi).addHex("rdi", ctx.Rdi)
        .addHex("rbp", ctx.Rbp).addHex("rsp", ctx.Rsp)
        .addHex("r8",  ctx.R8) .addHex("r9",  ctx.R9)
        .addHex("r10", ctx.R10).addHex("r11", ctx.R11)
        .addHex("r12", ctx.R12).addHex("r13", ctx.R13)
        .addHex("r14", ctx.R14).addHex("r15", ctx.R15)
        .addHex("rip", ctx.Rip).addHex("rflags", ctx.EFlags)
        .addHex("cs", ctx.SegCs).addHex("ss", ctx.SegSs)
        .addHex("ds", ctx.SegDs).addHex("es", ctx.SegEs)
        .addHex("fs", ctx.SegFs).addHex("gs", ctx.SegGs)
        .build();
}

// ── Set a single register ───────────────────────────────────────────────

std::string CmdThreadSet(DWORD tid, const std::string& reg, uint64_t value) {
    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, tid);
    if (!hThread)
        return ErrorResponse("failed to open thread");

    SuspendThread(hThread);

    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_ALL;
    if (!GetThreadContext(hThread, &ctx)) {
        ResumeThread(hThread);
        CloseHandle(hThread);
        return ErrorResponse("GetThreadContext failed");
    }

    // Map register name to context field
    std::string r = reg;
    std::transform(r.begin(), r.end(), r.begin(), ::tolower);

    bool found = true;
    if      (r == "rax") ctx.Rax = value;
    else if (r == "rbx") ctx.Rbx = value;
    else if (r == "rcx") ctx.Rcx = value;
    else if (r == "rdx") ctx.Rdx = value;
    else if (r == "rsi") ctx.Rsi = value;
    else if (r == "rdi") ctx.Rdi = value;
    else if (r == "rbp") ctx.Rbp = value;
    else if (r == "rsp") ctx.Rsp = value;
    else if (r == "r8")  ctx.R8  = value;
    else if (r == "r9")  ctx.R9  = value;
    else if (r == "r10") ctx.R10 = value;
    else if (r == "r11") ctx.R11 = value;
    else if (r == "r12") ctx.R12 = value;
    else if (r == "r13") ctx.R13 = value;
    else if (r == "r14") ctx.R14 = value;
    else if (r == "r15") ctx.R15 = value;
    else if (r == "rip") ctx.Rip = value;
    else found = false;

    if (!found) {
        ResumeThread(hThread);
        CloseHandle(hThread);
        return ErrorResponse("unknown register: " + reg);
    }

    BOOL ok = SetThreadContext(hThread, &ctx);
    ResumeThread(hThread);
    CloseHandle(hThread);

    if (!ok)
        return ErrorResponse("SetThreadContext failed");

    return Response()
        .add("status", "ok")
        .add("register", reg)
        .addHex("value", value)
        .build();
}

// ── Suspend / Resume ────────────────────────────────────────────────────

std::string CmdThreadSuspend(DWORD tid) {
    HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
    if (!hThread)
        return ErrorResponse("failed to open thread");

    DWORD prev = SuspendThread(hThread);
    CloseHandle(hThread);

    if (prev == (DWORD)-1)
        return ErrorResponse("SuspendThread failed");

    return Response()
        .add("status", "ok")
        .add("thread_id", (int64_t)tid)
        .add("previous_suspend_count", (int64_t)prev)
        .build();
}

std::string CmdThreadResume(DWORD tid) {
    HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
    if (!hThread)
        return ErrorResponse("failed to open thread");

    DWORD prev = ResumeThread(hThread);
    CloseHandle(hThread);

    if (prev == (DWORD)-1)
        return ErrorResponse("ResumeThread failed");

    return Response()
        .add("status", "ok")
        .add("thread_id", (int64_t)tid)
        .add("previous_suspend_count", (int64_t)prev)
        .build();
}

// ── Call stack ───────────────────────────────────────────────────────────

std::string CmdCallStack(DWORD tid) {
    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, tid);
    if (!hThread)
        return ErrorResponse("failed to open thread");

    SuspendThread(hThread);

    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(hThread, &ctx)) {
        ResumeThread(hThread);
        CloseHandle(hThread);
        return ErrorResponse("GetThreadContext failed");
    }

    // Use CaptureStackBackTrace-style manual walk
    STACKFRAME64 frame;
    memset(&frame, 0, sizeof(frame));
    frame.AddrPC.Offset    = ctx.Rip;
    frame.AddrPC.Mode      = AddrModeFlat;
    frame.AddrFrame.Offset = ctx.Rbp;
    frame.AddrFrame.Mode   = AddrModeFlat;
    frame.AddrStack.Offset = ctx.Rsp;
    frame.AddrStack.Mode   = AddrModeFlat;

    HANDLE hProcess = GetCurrentProcess();

    std::vector<std::string> frames;
    int max_frames = 64;

    for (int i = 0; i < max_frames; i++) {
        if (!StackWalk64(IMAGE_FILE_MACHINE_AMD64, hProcess, hThread,
                         &frame, &ctx, NULL,
                         SymFunctionTableAccess64, SymGetModuleBase64, NULL)) {
            break;
        }

        if (frame.AddrPC.Offset == 0)
            break;

        // Try to get module name for this address
        HMODULE hMod = NULL;
        char mod_name[256] = "???";
        if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                (LPCSTR)frame.AddrPC.Offset, &hMod)) {
            GetModuleFileNameA(hMod, mod_name, sizeof(mod_name));
            // Extract just the filename
            char* slash = strrchr(mod_name, '\\');
            if (slash) memmove(mod_name, slash + 1, strlen(slash + 1) + 1);
        }

        uint64_t mod_base = hMod ? (uint64_t)hMod : 0;
        uint64_t rva = mod_base ? frame.AddrPC.Offset - mod_base : 0;

        frames.push_back(
            Response()
                .add("frame", (int64_t)i)
                .addHex("address", frame.AddrPC.Offset)
                .addHex("return_address", frame.AddrReturn.Offset)
                .addHex("stack_pointer", frame.AddrStack.Offset)
                .add("module", std::string(mod_name))
                .addHex("rva", rva)
                .build()
        );
    }

    ResumeThread(hThread);
    CloseHandle(hThread);

    return Response()
        .add("status", "ok")
        .add("thread_id", (int64_t)tid)
        .add("depth", (int64_t)frames.size())
        .addRawArray("frames", frames)
        .build();
}
