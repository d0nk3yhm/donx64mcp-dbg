#include "anti_debug.h"
#include "response.h"
#include "lib/minhook/MinHook.h"
#include <tlhelp32.h>
#include <vector>
#include <cstdio>
#include <cstring>
#include <intrin.h>

// ═════════════════════════════════════════════════════════════════════════
// Global state
// ═════════════════════════════════════════════════════════════════════════

StealthStatus g_stealth = {};

static CRITICAL_SECTION g_stealth_cs;
static bool g_stealth_initialized = false;

// ── Saved original bytes for non-hook patches ───────────────────────────

static BYTE g_orig_etw_bytes[16] = {};
static DWORD g_orig_etw_size = 0;
static void* g_etw_addr = nullptr;

static BYTE g_orig_peb_being_debugged = 0;
static ULONG g_orig_peb_ntglobalflag = 0;
static ULONG g_orig_heap_flags = 0;
static ULONG g_orig_heap_force_flags = 0;
static bool g_peb_saved = false;

// ── Original function pointers (filled by MH_CreateHook) ────────────────

static pfnNtQueryInformationProcess  o_NtQueryInformationProcess = nullptr;
static pfnNtSetInformationThread     o_NtSetInformationThread = nullptr;
static pfnNtGetContextThread         o_NtGetContextThread = nullptr;
static pfnNtSetContextThread         o_NtSetContextThread = nullptr;
static pfnNtContinue                 o_NtContinue = nullptr;
static pfnNtClose                    o_NtClose = nullptr;
static pfnNtQueryObject              o_NtQueryObject = nullptr;
static pfnNtQuerySystemInformation   o_NtQuerySystemInformation = nullptr;
static pfnNtCreateThreadEx           o_NtCreateThreadEx = nullptr;
static pfnNtSetInformationProcess    o_NtSetInformationProcess = nullptr;
static pfnIsDebuggerPresent          o_IsDebuggerPresent = nullptr;
static pfnCheckRemoteDebuggerPresent o_CheckRemoteDebuggerPresent = nullptr;
static pfnQueryPerformanceCounter    o_QueryPerformanceCounter = nullptr;
static pfnGetTickCount               o_GetTickCount = nullptr;
static pfnGetTickCount64             o_GetTickCount64 = nullptr;
static pfnFindWindowA                o_FindWindowA = nullptr;
static pfnFindWindowW                o_FindWindowW = nullptr;
static pfnEnumWindows                o_EnumWindows = nullptr;

// ── Timing state for consistent spoofing ────────────────────────────────

static LARGE_INTEGER g_timing_base_qpc = {};
static ULONGLONG     g_timing_base_tick = 0;
static LARGE_INTEGER g_timing_real_start = {};
static ULONGLONG     g_timing_real_tick_start = 0;
static double        g_timing_scale = 1.0; // How much to compress time (1.0 = no change)
static bool          g_timing_initialized = false;

// ── Debugger window class/title blacklist ───────────────────────────────

static const char* g_debugger_window_classes[] = {
    "OLLYDBG", "WinDbgFrameClass", "ID",           // OllyDbg, WinDbg, IDA
    "Zeta Debugger", "Rock Debugger",
    "ObsidianGUI", "x64dbg", "x32dbg",
    nullptr
};

static const char* g_debugger_window_titles[] = {
    "x64dbg", "x32dbg", "OllyDbg", "WinDbg", "Immunity",
    "IDA -", "IDA Pro", "Ghidra", "Binary Ninja",
    "Cheat Engine", "ReClass", "Process Hacker",
    nullptr
};

static const wchar_t* g_debugger_process_names[] = {
    L"x64dbg.exe", L"x32dbg.exe", L"ollydbg.exe", L"windbg.exe",
    L"idaq.exe", L"idaq64.exe", L"ida.exe", L"ida64.exe",
    L"ghidra.exe", L"ghidraRun.exe",
    L"cheatengine-x86_64.exe", L"cheatengine.exe",
    L"processhacker.exe", L"procmon.exe", L"procmon64.exe",
    L"procexp.exe", L"procexp64.exe",
    L"dnSpy.exe", L"dotPeek64.exe",
    L"httpdebugger.exe", L"fiddler.exe",
    L"wireshark.exe",
    L"die.exe", L"peid.exe", L"pestudio.exe",
    L"scylla.exe", L"scylla_x64.exe",
    L"ImportREC.exe",
    nullptr
};

// ═════════════════════════════════════════════════════════════════════════
// TIER 1: PEB Patching
// ═════════════════════════════════════════════════════════════════════════

static MCP_PEB* GetPEB() {
#ifdef _M_X64
    return (MCP_PEB*)__readgsqword(0x60);
#else
    return (MCP_PEB*)__readfsdword(0x30);
#endif
}

bool PatchPEB() {
    __try {
        MCP_PEB* peb = GetPEB();
        if (!peb) return false;

        // Save original values first time
        if (!g_peb_saved) {
            g_orig_peb_being_debugged = peb->BeingDebugged;
            g_orig_peb_ntglobalflag = *(ULONG*)((BYTE*)peb + 0xBC); // NtGlobalFlag at +0xBC on x64
            g_peb_saved = true;
        }

        // 1. Clear BeingDebugged flag
        peb->BeingDebugged = 0;

        // 2. Clear NtGlobalFlag (offset 0xBC on x64)
        //    Debugger sets: FLG_HEAP_ENABLE_TAIL_CHECK (0x10) |
        //                   FLG_HEAP_ENABLE_FREE_CHECK (0x20) |
        //                   FLG_HEAP_VALIDATE_PARAMETERS (0x40) = 0x70
        ULONG* pNtGlobalFlag = (ULONG*)((BYTE*)peb + 0xBC);
        *pNtGlobalFlag &= ~0x70UL;

        // 3. Patch ProcessHeap flags
        //    ProcessHeap at PEB+0x30 (x64)
        //    Flags at heap+0x70, ForceFlags at heap+0x74 (x64, NT 6.x+)
        void* process_heap = peb->ProcessHeap;
        if (process_heap) {
            ULONG* heapFlags = (ULONG*)((BYTE*)process_heap + 0x70);
            ULONG* heapForceFlags = (ULONG*)((BYTE*)process_heap + 0x74);

            if (!g_peb_saved) {
                g_orig_heap_flags = *heapFlags;
                g_orig_heap_force_flags = *heapForceFlags;
            }

            // HEAP_GROWABLE (0x2) is normal, everything else is suspect
            *heapFlags = HEAP_GROWABLE;
            *heapForceFlags = 0;
        }

        g_stealth.peb_patched = true;
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool RestorePEB() {
    if (!g_peb_saved) return false;

    __try {
        MCP_PEB* peb = GetPEB();
        if (!peb) return false;

        peb->BeingDebugged = g_orig_peb_being_debugged;

        ULONG* pNtGlobalFlag = (ULONG*)((BYTE*)peb + 0xBC);
        *pNtGlobalFlag = g_orig_peb_ntglobalflag;

        void* process_heap = peb->ProcessHeap;
        if (process_heap) {
            ULONG* heapFlags = (ULONG*)((BYTE*)process_heap + 0x70);
            ULONG* heapForceFlags = (ULONG*)((BYTE*)process_heap + 0x74);
            *heapFlags = g_orig_heap_flags;
            *heapForceFlags = g_orig_heap_force_flags;
        }

        g_stealth.peb_patched = false;
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// ═════════════════════════════════════════════════════════════════════════
// TIER 1: ETW Disable
// ═════════════════════════════════════════════════════════════════════════

bool DisableETW() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return false;

    g_etw_addr = GetProcAddress(ntdll, "EtwEventWrite");
    if (!g_etw_addr) return false;

    // Save original bytes
    DWORD old_prot;
    if (!VirtualProtect(g_etw_addr, 16, PAGE_EXECUTE_READWRITE, &old_prot))
        return false;

    memcpy(g_orig_etw_bytes, g_etw_addr, 16);
    g_orig_etw_size = 16;

    // Patch with: xor eax, eax; ret (return 0 = STATUS_SUCCESS)
    BYTE patch[] = { 0x33, 0xC0, 0xC3 }; // xor eax,eax; ret
    memcpy(g_etw_addr, patch, sizeof(patch));

    VirtualProtect(g_etw_addr, 16, old_prot, &old_prot);

    g_stealth.etw_disabled = true;
    return true;
}

bool RestoreETW() {
    if (!g_etw_addr || g_orig_etw_size == 0) return false;

    DWORD old_prot;
    if (!VirtualProtect(g_etw_addr, g_orig_etw_size, PAGE_EXECUTE_READWRITE, &old_prot))
        return false;

    memcpy(g_etw_addr, g_orig_etw_bytes, g_orig_etw_size);
    VirtualProtect(g_etw_addr, g_orig_etw_size, old_prot, &old_prot);

    g_stealth.etw_disabled = false;
    g_etw_addr = nullptr;
    return true;
}

// ═════════════════════════════════════════════════════════════════════════
// TIER 1: Module Hiding (PEB Loader List Unlinking)
// ═════════════════════════════════════════════════════════════════════════

// Saved links for re-linking
static LIST_ENTRY g_saved_load_flink, g_saved_load_blink;
static LIST_ENTRY g_saved_mem_flink, g_saved_mem_blink;
static LIST_ENTRY g_saved_init_flink, g_saved_init_blink;
static _LDR_DATA_TABLE_ENTRY_FULL* g_hidden_entry = nullptr;

bool HideModuleFromPEB(HMODULE hMod) {
    if (!hMod) hMod = g_dll_module;

    __try {
        MCP_PEB* peb = GetPEB();
        if (!peb) return false;

        _PEB_LDR_DATA_FULL* ldr = (_PEB_LDR_DATA_FULL*)peb->Ldr;
        if (!ldr) return false;

        // Walk InLoadOrderModuleList to find our module
        LIST_ENTRY* head = &ldr->InLoadOrderModuleList;
        LIST_ENTRY* entry = head->Flink;

        while (entry != head) {
            _LDR_DATA_TABLE_ENTRY_FULL* mod = CONTAINING_RECORD(entry, _LDR_DATA_TABLE_ENTRY_FULL, InLoadOrderLinks);

            if (mod->DllBase == (PVOID)hMod) {
                g_hidden_entry = mod;

                // Save links for restoration
                g_saved_load_flink = *entry;
                g_saved_mem_flink = mod->InMemoryOrderLinks;
                g_saved_init_flink = mod->InInitializationOrderLinks;

                // Unlink from InLoadOrderModuleList
                entry->Blink->Flink = entry->Flink;
                entry->Flink->Blink = entry->Blink;

                // Unlink from InMemoryOrderModuleList
                mod->InMemoryOrderLinks.Blink->Flink = mod->InMemoryOrderLinks.Flink;
                mod->InMemoryOrderLinks.Flink->Blink = mod->InMemoryOrderLinks.Blink;

                // Unlink from InInitializationOrderModuleList
                if (mod->InInitializationOrderLinks.Flink && mod->InInitializationOrderLinks.Blink) {
                    mod->InInitializationOrderLinks.Blink->Flink = mod->InInitializationOrderLinks.Flink;
                    mod->InInitializationOrderLinks.Flink->Blink = mod->InInitializationOrderLinks.Blink;
                }

                // Null out our links so we're fully orphaned
                entry->Flink = entry;
                entry->Blink = entry;
                mod->InMemoryOrderLinks.Flink = &mod->InMemoryOrderLinks;
                mod->InMemoryOrderLinks.Blink = &mod->InMemoryOrderLinks;

                g_stealth.module_hidden = true;
                return true;
            }

            entry = entry->Flink;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    return false;
}

bool UnhideModuleFromPEB(HMODULE hMod) {
    if (!g_hidden_entry) return false;

    __try {
        // Re-link using saved pointers
        LIST_ENTRY* load_entry = &g_hidden_entry->InLoadOrderLinks;

        // Restore InLoadOrderModuleList
        load_entry->Flink = g_saved_load_flink.Flink;
        load_entry->Blink = g_saved_load_flink.Blink;
        g_saved_load_flink.Blink->Flink = load_entry;
        g_saved_load_flink.Flink->Blink = load_entry;

        // Restore InMemoryOrderModuleList
        g_hidden_entry->InMemoryOrderLinks.Flink = g_saved_mem_flink.Flink;
        g_hidden_entry->InMemoryOrderLinks.Blink = g_saved_mem_flink.Blink;
        g_saved_mem_flink.Blink->Flink = &g_hidden_entry->InMemoryOrderLinks;
        g_saved_mem_flink.Flink->Blink = &g_hidden_entry->InMemoryOrderLinks;

        // Restore InInitializationOrderModuleList
        if (g_saved_init_flink.Flink && g_saved_init_flink.Blink) {
            g_hidden_entry->InInitializationOrderLinks.Flink = g_saved_init_flink.Flink;
            g_hidden_entry->InInitializationOrderLinks.Blink = g_saved_init_flink.Blink;
            g_saved_init_flink.Blink->Flink = &g_hidden_entry->InInitializationOrderLinks;
            g_saved_init_flink.Flink->Blink = &g_hidden_entry->InInitializationOrderLinks;
        }

        g_hidden_entry = nullptr;
        g_stealth.module_hidden = false;
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    return false;
}

// ═════════════════════════════════════════════════════════════════════════
// TIER 1: Core API Hooks
// ═════════════════════════════════════════════════════════════════════════

// Helper: sanitize debug registers in a CONTEXT struct
static void SanitizeDRRegs(CONTEXT* ctx) {
    if (!ctx) return;
    if (ctx->ContextFlags & CONTEXT_DEBUG_REGISTERS) {
        ctx->Dr0 = 0;
        ctx->Dr1 = 0;
        ctx->Dr2 = 0;
        ctx->Dr3 = 0;
        ctx->Dr6 = 0;
        ctx->Dr7 = 0;
    }
}

// ── IsDebuggerPresent ───────────────────────────────────────────────────

static BOOL WINAPI Hook_IsDebuggerPresent() {
    return FALSE;
}

// ── CheckRemoteDebuggerPresent ──────────────────────────────────────────

static BOOL WINAPI Hook_CheckRemoteDebuggerPresent(HANDLE hProcess, PBOOL pbDebuggerPresent) {
    if (pbDebuggerPresent) *pbDebuggerPresent = FALSE;
    return TRUE;
}

// ── NtQueryInformationProcess ───────────────────────────────────────────
// Handles: ProcessDebugPort, ProcessDebugFlags, ProcessDebugObjectHandle,
//          ProcessBasicInformation (parent PID spoof)

static NTSTATUS NTAPI Hook_NtQueryInformationProcess(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength)
{
    NTSTATUS status = o_NtQueryInformationProcess(
        ProcessHandle, ProcessInformationClass,
        ProcessInformation, ProcessInformationLength, ReturnLength);

    if (NT_SUCCESS(status) && ProcessInformation) {
        switch (ProcessInformationClass) {
        case ProcessDebugPort:
            // ProcessDebugPort returns DWORD_PTR, non-zero = debugged
            *(DWORD_PTR*)ProcessInformation = 0;
            break;

        case ProcessDebugObjectHandle:
            // ProcessDebugObjectHandle returns a handle if debug object exists
            *(HANDLE*)ProcessInformation = NULL;
            // Return error to indicate no debug object
            return STATUS_PORT_NOT_SET;

        case ProcessDebugFlags:
            // ProcessDebugFlags returns 0 if debugged, 1 if not
            *(ULONG*)ProcessInformation = 1;
            break;

        case ProcessBasicInformation:
            // Spoof parent PID to explorer.exe
            {
                // PROCESS_BASIC_INFORMATION.InheritedFromUniqueProcessId is at offset 0x20 (x64)
                // Find explorer.exe PID
                DWORD explorer_pid = 0;
                HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                if (snap != INVALID_HANDLE_VALUE) {
                    PROCESSENTRY32W pe = { sizeof(pe) };
                    if (Process32FirstW(snap, &pe)) {
                        do {
                            if (_wcsicmp(pe.szExeFile, L"explorer.exe") == 0) {
                                explorer_pid = pe.th32ProcessID;
                                break;
                            }
                        } while (Process32NextW(snap, &pe));
                    }
                    CloseHandle(snap);
                }
                if (explorer_pid) {
                    // InheritedFromUniqueProcessId at offset 0x20
                    *(ULONG_PTR*)((BYTE*)ProcessInformation + 0x20) = (ULONG_PTR)explorer_pid;
                }
            }
            break;
        }
    }

    return status;
}

// ── NtSetInformationThread (ThreadHideFromDebugger) ─────────────────────

static NTSTATUS NTAPI Hook_NtSetInformationThread(
    HANDLE ThreadHandle,
    ULONG ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength)
{
    // Block ThreadHideFromDebugger — just pretend it succeeded
    if (ThreadInformationClass == ThreadHideFromDebugger) {
        return STATUS_SUCCESS;
    }

    return o_NtSetInformationThread(ThreadHandle, ThreadInformationClass,
                                     ThreadInformation, ThreadInformationLength);
}

// ── NtClose (invalid handle trap) ───────────────────────────────────────

static NTSTATUS NTAPI Hook_NtClose(HANDLE Handle) {
    // Under debugger, closing invalid handle raises EXCEPTION_INVALID_HANDLE
    // We validate the handle first to prevent the exception
    __try {
        return o_NtClose(Handle);
    }
    __except (GetExceptionCode() == EXCEPTION_INVALID_HANDLE ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        return STATUS_SUCCESS; // Swallow the exception
    }
}

// ── NtQueryObject (filter DebugObject) ──────────────────────────────────

static NTSTATUS NTAPI Hook_NtQueryObject(
    HANDLE Handle,
    ULONG ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength)
{
    NTSTATUS status = o_NtQueryObject(Handle, ObjectInformationClass,
                                       ObjectInformation, ObjectInformationLength, ReturnLength);

    // For ObjectAllInformation, filter out DebugObject type entries
    // This is complex — the structure has variable-length entries
    // For now, we handle ObjectTypeInformation (class 2) specifically
    if (NT_SUCCESS(status) && ObjectInformationClass == 2 && ObjectInformation) {
        // OBJECT_TYPE_INFORMATION has TypeName as first field (UNICODE_STRING layout)
        MCP_UNICODE_STRING* typeName = (MCP_UNICODE_STRING*)ObjectInformation;
        if (typeName->Buffer && typeName->Length >= 20) {
            // Check if it's "DebugObject" — hide it
            if (wcsstr(typeName->Buffer, L"DebugObject")) {
                // Zero the name so it's not detectable
                typeName->Length = 0;
                typeName->MaximumLength = 0;
            }
        }
    }

    return status;
}

// ── NtQuerySystemInformation ────────────────────────────────────────────

#define SystemKernelDebuggerInformation 0x23

static NTSTATUS NTAPI Hook_NtQuerySystemInformation(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength)
{
    NTSTATUS status = o_NtQuerySystemInformation(
        SystemInformationClass, SystemInformation,
        SystemInformationLength, ReturnLength);

    if (NT_SUCCESS(status) && SystemInformation) {
        if (SystemInformationClass == SystemKernelDebuggerInformation) {
            // SYSTEM_KERNEL_DEBUGGER_INFORMATION:
            //   BOOLEAN KernelDebuggerEnabled;    // offset 0
            //   BOOLEAN KernelDebuggerNotPresent;  // offset 1
            ((BYTE*)SystemInformation)[0] = 0; // KernelDebuggerEnabled = FALSE
            ((BYTE*)SystemInformation)[1] = 1; // KernelDebuggerNotPresent = TRUE
        }
    }

    return status;
}

// ═════════════════════════════════════════════════════════════════════════
// TIER 2: Context / DR Register Sanitization
// ═════════════════════════════════════════════════════════════════════════

static NTSTATUS NTAPI Hook_NtGetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext) {
    NTSTATUS status = o_NtGetContextThread(ThreadHandle, ThreadContext);
    if (NT_SUCCESS(status)) {
        SanitizeDRRegs(ThreadContext);
    }
    return status;
}

static NTSTATUS NTAPI Hook_NtSetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext) {
    // Prevent clearing our debug registers
    // For now, strip DR writes from context
    if (ThreadContext && (ThreadContext->ContextFlags & CONTEXT_DEBUG_REGISTERS)) {
        // Remove the debug registers flag so they aren't modified
        CONTEXT copy = *ThreadContext;
        copy.ContextFlags &= ~CONTEXT_DEBUG_REGISTERS;
        return o_NtSetContextThread(ThreadHandle, &copy);
    }
    return o_NtSetContextThread(ThreadHandle, ThreadContext);
}

static NTSTATUS NTAPI Hook_NtContinue(PCONTEXT ContextRecord, BOOLEAN TestAlert) {
    // Sanitize DR registers to prevent clearing our hardware breakpoints
    SanitizeDRRegs(ContextRecord);
    return o_NtContinue(ContextRecord, TestAlert);
}

// ═════════════════════════════════════════════════════════════════════════
// TIER 2: Timing Hooks
// ═════════════════════════════════════════════════════════════════════════

static void InitTimingState() {
    if (g_timing_initialized) return;

    // Record the "real" starting values
    QueryPerformanceCounter(&g_timing_real_start);
    g_timing_real_tick_start = GetTickCount64();

    // These become our "apparent" starting values
    g_timing_base_qpc = g_timing_real_start;
    g_timing_base_tick = g_timing_real_tick_start;

    g_timing_scale = 1.0;
    g_timing_initialized = true;
}

static BOOL WINAPI Hook_QueryPerformanceCounter(LARGE_INTEGER* lpPerformanceCount) {
    BOOL result = o_QueryPerformanceCounter(lpPerformanceCount);
    if (result && lpPerformanceCount && g_timing_initialized) {
        // Compress elapsed time to hide debugger-induced delays
        LONGLONG real_elapsed = lpPerformanceCount->QuadPart - g_timing_real_start.QuadPart;
        LONGLONG apparent_elapsed = (LONGLONG)(real_elapsed * g_timing_scale);
        lpPerformanceCount->QuadPart = g_timing_base_qpc.QuadPart + apparent_elapsed;
    }
    return result;
}

static DWORD WINAPI Hook_GetTickCount() {
    DWORD real = o_GetTickCount();
    if (g_timing_initialized) {
        DWORD real_elapsed = real - (DWORD)g_timing_real_tick_start;
        DWORD apparent_elapsed = (DWORD)(real_elapsed * g_timing_scale);
        return (DWORD)g_timing_base_tick + apparent_elapsed;
    }
    return real;
}

static ULONGLONG WINAPI Hook_GetTickCount64() {
    ULONGLONG real = o_GetTickCount64();
    if (g_timing_initialized) {
        ULONGLONG real_elapsed = real - g_timing_real_tick_start;
        ULONGLONG apparent_elapsed = (ULONGLONG)(real_elapsed * g_timing_scale);
        return g_timing_base_tick + apparent_elapsed;
    }
    return real;
}

// ═════════════════════════════════════════════════════════════════════════
// TIER 2: Thread Creation Hooks
// ═════════════════════════════════════════════════════════════════════════

static NTSTATUS NTAPI Hook_NtCreateThreadEx(
    PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes, HANDLE ProcessHandle,
    PVOID StartRoutine, PVOID Argument,
    ULONG CreateFlags, SIZE_T ZeroBits,
    SIZE_T StackSize, SIZE_T MaximumStackSize,
    PVOID AttributeList)
{
    // Strip THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER
    CreateFlags &= ~THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER;

    return o_NtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes,
        ProcessHandle, StartRoutine, Argument, CreateFlags,
        ZeroBits, StackSize, MaximumStackSize, AttributeList);
}

// ═════════════════════════════════════════════════════════════════════════
// TIER 2: Window / Process Enumeration Filtering
// ═════════════════════════════════════════════════════════════════════════

static bool IsDebuggerWindowClass(const char* cls) {
    if (!cls) return false;
    for (int i = 0; g_debugger_window_classes[i]; i++) {
        if (_stricmp(cls, g_debugger_window_classes[i]) == 0)
            return true;
    }
    return false;
}

static bool IsDebuggerWindowTitle(const char* title) {
    if (!title) return false;
    for (int i = 0; g_debugger_window_titles[i]; i++) {
        // Use substring match for titles (e.g. "IDA - filename.exe")
        if (strstr(title, g_debugger_window_titles[i]) != nullptr)
            return true;
    }
    return false;
}

static HWND WINAPI Hook_FindWindowA(LPCSTR lpClassName, LPCSTR lpWindowName) {
    if (IsDebuggerWindowClass(lpClassName) || IsDebuggerWindowTitle(lpWindowName))
        return NULL;
    return o_FindWindowA(lpClassName, lpWindowName);
}

static HWND WINAPI Hook_FindWindowW(LPCWSTR lpClassName, LPCWSTR lpWindowName) {
    // Convert to narrow for checking
    char narrow_class[256] = {};
    char narrow_title[256] = {};
    if (lpClassName)  WideCharToMultiByte(CP_UTF8, 0, lpClassName, -1, narrow_class, sizeof(narrow_class), NULL, NULL);
    if (lpWindowName) WideCharToMultiByte(CP_UTF8, 0, lpWindowName, -1, narrow_title, sizeof(narrow_title), NULL, NULL);

    if (IsDebuggerWindowClass(narrow_class) || IsDebuggerWindowTitle(narrow_title))
        return NULL;
    return o_FindWindowW(lpClassName, lpWindowName);
}

// ── EnumWindows filtering ───────────────────────────────────────────────

// We wrap the user's callback to skip debugger windows
struct EnumWindowsContext {
    WNDENUMPROC originalCallback;
    LPARAM       originalParam;
};

static BOOL CALLBACK FilteredEnumProc(HWND hwnd, LPARAM lParam) {
    EnumWindowsContext* ctx = (EnumWindowsContext*)lParam;

    char cls[256] = {};
    char title[256] = {};
    GetClassNameA(hwnd, cls, sizeof(cls));
    GetWindowTextA(hwnd, title, sizeof(title));

    // Skip debugger windows
    if (IsDebuggerWindowClass(cls) || IsDebuggerWindowTitle(title))
        return TRUE; // Continue enumeration, but don't pass to user callback

    return ctx->originalCallback(hwnd, ctx->originalParam);
}

static BOOL WINAPI Hook_EnumWindows(WNDENUMPROC lpEnumFunc, LPARAM lParam) {
    EnumWindowsContext ctx;
    ctx.originalCallback = lpEnumFunc;
    ctx.originalParam = lParam;
    return o_EnumWindows(FilteredEnumProc, (LPARAM)&ctx);
}

// ═════════════════════════════════════════════════════════════════════════
// TIER 2: NtSetInformationProcess (Instrumentation Callback)
// ═════════════════════════════════════════════════════════════════════════

static NTSTATUS NTAPI Hook_NtSetInformationProcess(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength)
{
    // Block instrumentation callback installation
    if (ProcessInformationClass == ProcessInstrumentationCallback) {
        return STATUS_SUCCESS; // Pretend it worked
    }

    return o_NtSetInformationProcess(ProcessHandle, ProcessInformationClass,
                                      ProcessInformation, ProcessInformationLength);
}

// ═════════════════════════════════════════════════════════════════════════
// TIER 3: Instrumentation Callback Neutralizer
// ═════════════════════════════════════════════════════════════════════════

bool KillInstrumentationCallback() {
    // Clear any existing instrumentation callback by setting it to NULL
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return false;

    auto pNtSetInformationProcess = (pfnNtSetInformationProcess)
        GetProcAddress(ntdll, "NtSetInformationProcess");
    if (!pNtSetInformationProcess) return false;

    // PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION structure:
    // ULONG Version = 0; ULONG Reserved = 0; PVOID Callback = NULL;
    struct {
        ULONG Version;
        ULONG Reserved;
        PVOID Callback;
    } info = { 0, 0, nullptr };

    NTSTATUS status = pNtSetInformationProcess(
        GetCurrentProcess(),
        ProcessInstrumentationCallback,
        &info, sizeof(info));

    g_stealth.instrumentation_killed = NT_SUCCESS(status);
    return g_stealth.instrumentation_killed;
}

// ═════════════════════════════════════════════════════════════════════════
// Hook Installation
// ═════════════════════════════════════════════════════════════════════════

// Helper: create and enable a hook, track count
static bool InstallHook(void* target, void* detour, void** original) {
    if (MH_CreateHook(target, detour, original) != MH_OK)
        return false;
    if (MH_EnableHook(target) != MH_OK) {
        MH_RemoveHook(target);
        return false;
    }
    g_stealth.hooks_installed++;
    return true;
}

bool InstallApiHooks() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
    if (!ntdll || !kernel32) return false;

    int ok = 0, total = 0;

    // IsDebuggerPresent
    total++;
    if (InstallHook(GetProcAddress(kernel32, "IsDebuggerPresent"),
                    (void*)Hook_IsDebuggerPresent, (void**)&o_IsDebuggerPresent))
        ok++;

    // CheckRemoteDebuggerPresent
    total++;
    if (InstallHook(GetProcAddress(kernel32, "CheckRemoteDebuggerPresent"),
                    (void*)Hook_CheckRemoteDebuggerPresent, (void**)&o_CheckRemoteDebuggerPresent))
        ok++;

    // NtQueryInformationProcess
    total++;
    if (InstallHook(GetProcAddress(ntdll, "NtQueryInformationProcess"),
                    (void*)Hook_NtQueryInformationProcess, (void**)&o_NtQueryInformationProcess))
        ok++;

    // NtSetInformationThread
    total++;
    if (InstallHook(GetProcAddress(ntdll, "NtSetInformationThread"),
                    (void*)Hook_NtSetInformationThread, (void**)&o_NtSetInformationThread))
        ok++;

    // NtClose
    total++;
    if (InstallHook(GetProcAddress(ntdll, "NtClose"),
                    (void*)Hook_NtClose, (void**)&o_NtClose))
        ok++;

    // NtQuerySystemInformation
    total++;
    if (InstallHook(GetProcAddress(ntdll, "NtQuerySystemInformation"),
                    (void*)Hook_NtQuerySystemInformation, (void**)&o_NtQuerySystemInformation))
        ok++;

    g_stealth.api_hooks_installed = (ok > 0);
    return ok == total;
}

bool InstallContextHooks() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return false;

    int ok = 0, total = 0;

    // NtGetContextThread
    total++;
    if (InstallHook(GetProcAddress(ntdll, "NtGetContextThread"),
                    (void*)Hook_NtGetContextThread, (void**)&o_NtGetContextThread))
        ok++;

    // NtSetContextThread
    total++;
    if (InstallHook(GetProcAddress(ntdll, "NtSetContextThread"),
                    (void*)Hook_NtSetContextThread, (void**)&o_NtSetContextThread))
        ok++;

    // NtContinue
    total++;
    if (InstallHook(GetProcAddress(ntdll, "NtContinue"),
                    (void*)Hook_NtContinue, (void**)&o_NtContinue))
        ok++;

    g_stealth.context_hooks = (ok > 0);
    return ok == total;
}

bool InstallTimingHooks() {
    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
    if (!kernel32) return false;

    InitTimingState();

    int ok = 0, total = 0;

    // QueryPerformanceCounter
    total++;
    if (InstallHook(GetProcAddress(kernel32, "QueryPerformanceCounter"),
                    (void*)Hook_QueryPerformanceCounter, (void**)&o_QueryPerformanceCounter))
        ok++;

    // GetTickCount
    total++;
    if (InstallHook(GetProcAddress(kernel32, "GetTickCount"),
                    (void*)Hook_GetTickCount, (void**)&o_GetTickCount))
        ok++;

    // GetTickCount64
    total++;
    if (InstallHook(GetProcAddress(kernel32, "GetTickCount64"),
                    (void*)Hook_GetTickCount64, (void**)&o_GetTickCount64))
        ok++;

    g_stealth.timing_hooks = (ok > 0);
    return ok == total;
}

bool InstallThreadHooks() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return false;

    int ok = 0, total = 0;

    // NtCreateThreadEx
    total++;
    void* pNtCreateThreadEx = GetProcAddress(ntdll, "NtCreateThreadEx");
    if (pNtCreateThreadEx) {
        if (InstallHook(pNtCreateThreadEx, (void*)Hook_NtCreateThreadEx, (void**)&o_NtCreateThreadEx))
            ok++;
    }

    // NtSetInformationProcess (block instrumentation callback)
    total++;
    void* pNtSetInformationProcess = GetProcAddress(ntdll, "NtSetInformationProcess");
    if (pNtSetInformationProcess) {
        if (InstallHook(pNtSetInformationProcess, (void*)Hook_NtSetInformationProcess, (void**)&o_NtSetInformationProcess))
            ok++;
    }

    g_stealth.thread_hooks = (ok > 0);
    return ok == total;
}

bool InstallWindowHooks() {
    HMODULE user32 = GetModuleHandleA("user32.dll");
    if (!user32) {
        // user32 might not be loaded yet — load it
        user32 = LoadLibraryA("user32.dll");
        if (!user32) return false;
    }

    int ok = 0, total = 0;

    // FindWindowA
    total++;
    if (InstallHook(GetProcAddress(user32, "FindWindowA"),
                    (void*)Hook_FindWindowA, (void**)&o_FindWindowA))
        ok++;

    // FindWindowW
    total++;
    if (InstallHook(GetProcAddress(user32, "FindWindowW"),
                    (void*)Hook_FindWindowW, (void**)&o_FindWindowW))
        ok++;

    // EnumWindows
    total++;
    if (InstallHook(GetProcAddress(user32, "EnumWindows"),
                    (void*)Hook_EnumWindows, (void**)&o_EnumWindows))
        ok++;

    g_stealth.window_hooks = (ok > 0);
    return ok == total;
}

bool InstallNtdllHooks() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return false;

    int ok = 0, total = 0;

    // NtQueryObject
    total++;
    if (InstallHook(GetProcAddress(ntdll, "NtQueryObject"),
                    (void*)Hook_NtQueryObject, (void**)&o_NtQueryObject))
        ok++;

    g_stealth.ntdll_hooks = (ok > 0);
    return ok == total;
}

// ═════════════════════════════════════════════════════════════════════════
// Remove all stealth hooks
// ═════════════════════════════════════════════════════════════════════════

bool RemoveAllStealthHooks() {
    // Disable all our hooks — MinHook tracks them all
    // We use targeted disable since MH_ALL_HOOKS would also disable user hooks from hooks.cpp

    struct { void* target; void** original; } hooks[] = {
        { nullptr, (void**)&o_IsDebuggerPresent },
        { nullptr, (void**)&o_CheckRemoteDebuggerPresent },
        { nullptr, (void**)&o_NtQueryInformationProcess },
        { nullptr, (void**)&o_NtSetInformationThread },
        { nullptr, (void**)&o_NtClose },
        { nullptr, (void**)&o_NtQuerySystemInformation },
        { nullptr, (void**)&o_NtGetContextThread },
        { nullptr, (void**)&o_NtSetContextThread },
        { nullptr, (void**)&o_NtContinue },
        { nullptr, (void**)&o_NtCreateThreadEx },
        { nullptr, (void**)&o_NtSetInformationProcess },
        { nullptr, (void**)&o_QueryPerformanceCounter },
        { nullptr, (void**)&o_GetTickCount },
        { nullptr, (void**)&o_GetTickCount64 },
        { nullptr, (void**)&o_FindWindowA },
        { nullptr, (void**)&o_FindWindowW },
        { nullptr, (void**)&o_EnumWindows },
        { nullptr, (void**)&o_NtQueryObject },
    };

    // We need to resolve the addresses again to disable
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
    HMODULE user32 = GetModuleHandleA("user32.dll");

    // Disable and remove each hook if the original was set
    auto tryRemove = [](HMODULE mod, const char* name) {
        if (!mod) return;
        void* addr = GetProcAddress(mod, name);
        if (addr) {
            MH_DisableHook(addr);
            MH_RemoveHook(addr);
        }
    };

    if (kernel32) {
        tryRemove(kernel32, "IsDebuggerPresent");
        tryRemove(kernel32, "CheckRemoteDebuggerPresent");
        tryRemove(kernel32, "QueryPerformanceCounter");
        tryRemove(kernel32, "GetTickCount");
        tryRemove(kernel32, "GetTickCount64");
    }

    if (ntdll) {
        tryRemove(ntdll, "NtQueryInformationProcess");
        tryRemove(ntdll, "NtSetInformationThread");
        tryRemove(ntdll, "NtClose");
        tryRemove(ntdll, "NtQuerySystemInformation");
        tryRemove(ntdll, "NtGetContextThread");
        tryRemove(ntdll, "NtSetContextThread");
        tryRemove(ntdll, "NtContinue");
        tryRemove(ntdll, "NtCreateThreadEx");
        tryRemove(ntdll, "NtSetInformationProcess");
        tryRemove(ntdll, "NtQueryObject");
    }

    if (user32) {
        tryRemove(user32, "FindWindowA");
        tryRemove(user32, "FindWindowW");
        tryRemove(user32, "EnumWindows");
    }

    // Clear all originals
    o_IsDebuggerPresent = nullptr;
    o_CheckRemoteDebuggerPresent = nullptr;
    o_NtQueryInformationProcess = nullptr;
    o_NtSetInformationThread = nullptr;
    o_NtClose = nullptr;
    o_NtQuerySystemInformation = nullptr;
    o_NtGetContextThread = nullptr;
    o_NtSetContextThread = nullptr;
    o_NtContinue = nullptr;
    o_NtCreateThreadEx = nullptr;
    o_NtSetInformationProcess = nullptr;
    o_QueryPerformanceCounter = nullptr;
    o_GetTickCount = nullptr;
    o_GetTickCount64 = nullptr;
    o_FindWindowA = nullptr;
    o_FindWindowW = nullptr;
    o_EnumWindows = nullptr;
    o_NtQueryObject = nullptr;

    g_stealth.api_hooks_installed = false;
    g_stealth.context_hooks = false;
    g_stealth.timing_hooks = false;
    g_stealth.thread_hooks = false;
    g_stealth.window_hooks = false;
    g_stealth.ntdll_hooks = false;
    g_stealth.hooks_installed = 0;

    return true;
}

// ═════════════════════════════════════════════════════════════════════════
// Stealth Activation (by level)
// ═════════════════════════════════════════════════════════════════════════

bool AntiDebugInit() {
    InitializeCriticalSection(&g_stealth_cs);
    memset(&g_stealth, 0, sizeof(g_stealth));
    g_stealth_initialized = true;
    return true;
}

void AntiDebugCleanup() {
    if (!g_stealth_initialized) return;

    StealthDeactivate();
    DeleteCriticalSection(&g_stealth_cs);
    g_stealth_initialized = false;
}

bool StealthActivate(int level) {
    if (!g_stealth_initialized) return false;

    EnterCriticalSection(&g_stealth_cs);

    bool success = true;

    // ── Tier 1 ──────────────────────────────────────────────────────
    if (level >= STEALTH_BASIC) {
        if (!g_stealth.peb_patched)         PatchPEB();
        if (!g_stealth.etw_disabled)        DisableETW();
        if (!g_stealth.module_hidden)       HideModuleFromPEB(g_dll_module);
        if (!g_stealth.api_hooks_installed) InstallApiHooks();
    }

    // ── Tier 2 ──────────────────────────────────────────────────────
    if (level >= STEALTH_FULL) {
        if (!g_stealth.context_hooks)   InstallContextHooks();
        if (!g_stealth.timing_hooks)    InstallTimingHooks();
        if (!g_stealth.thread_hooks)    InstallThreadHooks();
        if (!g_stealth.window_hooks)    InstallWindowHooks();
        if (!g_stealth.ntdll_hooks)     InstallNtdllHooks();
    }

    // ── Tier 3 ──────────────────────────────────────────────────────
    if (level >= STEALTH_MAX) {
        if (!g_stealth.instrumentation_killed) KillInstrumentationCallback();
    }

    g_stealth.level = level;

    LeaveCriticalSection(&g_stealth_cs);
    return success;
}

bool StealthDeactivate() {
    if (!g_stealth_initialized) return false;

    EnterCriticalSection(&g_stealth_cs);

    RemoveAllStealthHooks();
    RestoreETW();
    RestorePEB();
    if (g_stealth.module_hidden) UnhideModuleFromPEB(g_dll_module);

    g_stealth.level = STEALTH_NONE;

    LeaveCriticalSection(&g_stealth_cs);
    return true;
}

// ═════════════════════════════════════════════════════════════════════════
// Command Handlers
// ═════════════════════════════════════════════════════════════════════════

std::string CmdStealthOn(int level) {
    if (level < STEALTH_BASIC || level > STEALTH_MAX)
        return ErrorResponse("invalid level (1=basic, 2=full, 3=max)");

    bool ok = StealthActivate(level);

    const char* level_names[] = { "none", "basic", "full", "max" };

    return Response()
        .add("status", ok ? "ok" : "partial")
        .add("level", std::string(level_names[level]))
        .add("peb_patched", g_stealth.peb_patched)
        .add("etw_disabled", g_stealth.etw_disabled)
        .add("module_hidden", g_stealth.module_hidden)
        .add("api_hooks", g_stealth.api_hooks_installed)
        .add("context_hooks", g_stealth.context_hooks)
        .add("timing_hooks", g_stealth.timing_hooks)
        .add("thread_hooks", g_stealth.thread_hooks)
        .add("window_hooks", g_stealth.window_hooks)
        .add("ntdll_hooks", g_stealth.ntdll_hooks)
        .add("instrumentation_killed", g_stealth.instrumentation_killed)
        .add("total_hooks", (int64_t)g_stealth.hooks_installed)
        .build();
}

std::string CmdStealthOff() {
    bool ok = StealthDeactivate();
    return Response()
        .add("status", ok ? "ok" : "error")
        .add("message", ok ? "stealth deactivated" : "failed to deactivate")
        .build();
}

std::string CmdStealthStatus() {
    const char* level_names[] = { "none", "basic", "full", "max" };

    return Response()
        .add("status", "ok")
        .add("level", std::string(level_names[g_stealth.level]))
        .add("peb_patched", g_stealth.peb_patched)
        .add("etw_disabled", g_stealth.etw_disabled)
        .add("module_hidden", g_stealth.module_hidden)
        .add("api_hooks", g_stealth.api_hooks_installed)
        .add("context_hooks", g_stealth.context_hooks)
        .add("timing_hooks", g_stealth.timing_hooks)
        .add("thread_hooks", g_stealth.thread_hooks)
        .add("window_hooks", g_stealth.window_hooks)
        .add("ntdll_hooks", g_stealth.ntdll_hooks)
        .add("instrumentation_killed", g_stealth.instrumentation_killed)
        .add("total_hooks", (int64_t)g_stealth.hooks_installed)
        .build();
}

std::string CmdStealthPatchPEB() {
    bool ok = PatchPEB();
    return Response()
        .add("status", ok ? "ok" : "error")
        .add("message", ok ? "PEB patched (BeingDebugged=0, NtGlobalFlag cleared, heap flags cleaned)" : "PEB patch failed")
        .build();
}

std::string CmdStealthHideModule() {
    bool ok = HideModuleFromPEB(g_dll_module);
    return Response()
        .add("status", ok ? "ok" : "error")
        .add("message", ok ? "DLL hidden from PEB loader lists" : "failed to hide module")
        .build();
}

std::string CmdStealthUnhideModule() {
    bool ok = UnhideModuleFromPEB(g_dll_module);
    return Response()
        .add("status", ok ? "ok" : "error")
        .add("message", ok ? "DLL restored in PEB loader lists" : "failed to unhide module")
        .build();
}
