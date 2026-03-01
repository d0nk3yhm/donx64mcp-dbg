#pragma once
#ifndef ANTI_DEBUG_H
#define ANTI_DEBUG_H

#include "globals.h"
#include <string>

// ── Anti-Anti-Debug Engine ──────────────────────────────────────────────
//
// Defeats anti-debugging protections in the target process.
// Three tiers of protection bypass:
//
// Tier 1 (STEALTH_BASIC):  PEB patches, core API hooks, ETW disable, module hiding
// Tier 2 (STEALTH_FULL):   + Exception/context sanitization, timing, integrity, window/process filter
// Tier 3 (STEALTH_MAX):    + Direct syscall stubs, instrumentation callback, ntdll remap defense
//

// ── Stealth levels ──────────────────────────────────────────────────────

#define STEALTH_NONE    0
#define STEALTH_BASIC   1   // Tier 1
#define STEALTH_FULL    2   // Tier 1 + 2
#define STEALTH_MAX     3   // Tier 1 + 2 + 3

// ── Status tracking ─────────────────────────────────────────────────────

struct StealthStatus {
    int  level;                  // Current stealth level
    bool peb_patched;            // PEB.BeingDebugged, NtGlobalFlag, heap flags
    bool api_hooks_installed;    // Core API hooks (IsDebuggerPresent, NtQIP, etc.)
    bool etw_disabled;           // EtwEventWrite patched
    bool module_hidden;          // DLL unlinked from PEB loader lists
    bool context_hooks;          // NtGetContextThread/NtSetContextThread/NtContinue/KiUserExceptionDispatcher
    bool timing_hooks;           // QPC, GetTickCount, etc.
    bool thread_hooks;           // NtSetInformationThread, NtCreateThreadEx
    bool window_hooks;           // FindWindowA/W, EnumWindows filter
    bool process_hooks;          // EnumProcesses / CreateToolhelp32Snapshot filter
    bool ntdll_hooks;            // NtClose, NtQueryObject
    bool instrumentation_killed; // Instrumentation callback neutralized
    int  hooks_installed;        // Total number of hooks active
};

extern StealthStatus g_stealth;

// ── Init / Cleanup ──────────────────────────────────────────────────────

bool AntiDebugInit();
void AntiDebugCleanup();

// ── Activation ──────────────────────────────────────────────────────────

bool StealthActivate(int level);        // Activate stealth to given level
bool StealthDeactivate();               // Remove all stealth hooks/patches

// ── Individual components (can be called independently) ─────────────────

bool PatchPEB();                         // Zero BeingDebugged, NtGlobalFlag, heap flags
bool RestorePEB();                       // Undo PEB patches

bool HideModuleFromPEB(HMODULE hMod);    // Unlink module from PEB loader lists
bool UnhideModuleFromPEB(HMODULE hMod);  // Re-link module

bool DisableETW();                       // Patch EtwEventWrite → ret
bool RestoreETW();                       // Restore original EtwEventWrite

bool InstallApiHooks();                  // Core API hooks (Tier 1)
bool InstallContextHooks();              // DR register sanitization (Tier 2)
bool InstallTimingHooks();               // Timing bypass (Tier 2)
bool InstallThreadHooks();               // Thread hiding bypass (Tier 2)
bool InstallWindowHooks();               // Window/process enumeration filter (Tier 2)
bool InstallNtdllHooks();                // NtClose, NtQueryObject (Tier 2)
bool KillInstrumentationCallback();      // Neutralize instrumentation callback (Tier 3)

bool RemoveAllStealthHooks();            // Disable and remove all hooks

// ── Command handlers (pipe commands) ────────────────────────────────────

std::string CmdStealthOn(int level);
std::string CmdStealthOff();
std::string CmdStealthStatus();
std::string CmdStealthPatchPEB();
std::string CmdStealthHideModule();
std::string CmdStealthUnhideModule();

// ── NT internals needed for hooks ───────────────────────────────────────

// ProcessInformationClass values
#define ProcessDebugPort                 7
#define ProcessDebugObjectHandle         30
#define ProcessDebugFlags                31
#define ProcessBasicInformation          0
#define ProcessInstrumentationCallback   40

// ThreadInformationClass values
#define ThreadHideFromDebugger           17

// Thread creation flags
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER 0x00000004

// NtQueryObject classes
#define ObjectAllInformation             3

// NTSTATUS type
#ifndef _NTSTATUS_DEFINED
#define _NTSTATUS_DEFINED
typedef LONG NTSTATUS;
#endif

// NTSTATUS codes
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000)
#endif
#define STATUS_PORT_NOT_SET              ((NTSTATUS)0xC0000353)
#define STATUS_INFO_LENGTH_MISMATCH      ((NTSTATUS)0xC0000004)

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// ── NT function typedefs ────────────────────────────────────────────────

typedef NTSTATUS (NTAPI *pfnNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS (NTAPI *pfnNtSetInformationThread)(
    HANDLE ThreadHandle,
    ULONG ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength
);

typedef NTSTATUS (NTAPI *pfnNtGetContextThread)(
    HANDLE ThreadHandle,
    PCONTEXT ThreadContext
);

typedef NTSTATUS (NTAPI *pfnNtSetContextThread)(
    HANDLE ThreadHandle,
    PCONTEXT ThreadContext
);

typedef NTSTATUS (NTAPI *pfnNtContinue)(
    PCONTEXT ContextRecord,
    BOOLEAN TestAlert
);

typedef NTSTATUS (NTAPI *pfnNtClose)(
    HANDLE Handle
);

typedef NTSTATUS (NTAPI *pfnNtQueryObject)(
    HANDLE Handle,
    ULONG ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS (NTAPI *pfnNtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS (NTAPI *pfnNtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);

typedef NTSTATUS (NTAPI *pfnNtSetInformationProcess)(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength
);

typedef ULONG (NTAPI *pfnEtwEventWrite)(
    UINT64 RegHandle,
    PVOID EventDescriptor,
    ULONG UserDataCount,
    PVOID UserData
);

typedef BOOL (WINAPI *pfnIsDebuggerPresent)();

typedef BOOL (WINAPI *pfnCheckRemoteDebuggerPresent)(
    HANDLE hProcess,
    PBOOL  pbDebuggerPresent
);

typedef BOOL (WINAPI *pfnQueryPerformanceCounter)(
    LARGE_INTEGER* lpPerformanceCount
);

typedef DWORD (WINAPI *pfnGetTickCount)();
typedef ULONGLONG (WINAPI *pfnGetTickCount64)();

typedef HWND (WINAPI *pfnFindWindowA)(LPCSTR lpClassName, LPCSTR lpWindowName);
typedef HWND (WINAPI *pfnFindWindowW)(LPCWSTR lpClassName, LPCWSTR lpWindowName);

typedef BOOL (WINAPI *pfnEnumWindows)(WNDENUMPROC lpEnumFunc, LPARAM lParam);

typedef HANDLE (WINAPI *pfnCreateToolhelp32Snapshot)(DWORD dwFlags, DWORD th32ProcessID);

// ── PEB structures for direct manipulation ──────────────────────────────

// Our own UNICODE_STRING to avoid winternl.h dependency
struct MCP_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
};

// Minimal PEB structure (x64) — only fields we need
// We access everything by raw offset, this is just for readability
struct MCP_PEB {
    BOOLEAN InheritedAddressSpace;      // +0x00
    BOOLEAN ReadImageFileExecOptions;   // +0x01
    BOOLEAN BeingDebugged;              // +0x02
    BYTE    padding1[5];                // +0x03 .. +0x07
    PVOID   Mutant;                     // +0x08
    PVOID   ImageBaseAddress;           // +0x10
    PVOID   Ldr;                        // +0x18  -> PEB_LDR_DATA
    PVOID   ProcessParameters;          // +0x20
    BYTE    padding2[8];                // +0x28
    PVOID   ProcessHeap;                // +0x30
    // NtGlobalFlag is at +0xBC, accessed via raw offset
};

// Simplified PEB_LDR_DATA for our needs (x64)
struct _PEB_LDR_DATA_FULL {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
};

struct _LDR_DATA_TABLE_ENTRY_FULL {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    MCP_UNICODE_STRING FullDllName;
    MCP_UNICODE_STRING BaseDllName;
    // ... more fields we don't need
};

#endif // ANTI_DEBUG_H
