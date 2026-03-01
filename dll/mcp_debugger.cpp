#include "globals.h"
#include "commands.h"
#include "disasm.h"
#include "breakpoints.h"
#include "hooks.h"
#include "anti_debug.h"

#include <cstdio>
#include <string>

// ── Global state definitions ────────────────────────────────────────────

DWORD_PTR      g_base_address    = 0;
DWORD          g_pid             = 0;
HMODULE        g_dll_module      = NULL;
HANDLE         g_pipe_handle     = INVALID_HANDLE_VALUE;
volatile bool  g_server_running  = false;

CRITICAL_SECTION g_cs;
CRITICAL_SECTION g_bp_cs;

// ── Pipe server thread ──────────────────────────────────────────────────

static DWORD WINAPI ServerThread(LPVOID param) {
    char pipe_name[128];
    snprintf(pipe_name, sizeof(pipe_name), "%s%lu", MCP_PIPE_PREFIX, g_pid);

    while (g_server_running) {
        // Create a new pipe instance for each connection
        g_pipe_handle = CreateNamedPipeA(
            pipe_name,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            1,                          // Max instances
            MCP_PIPE_BUF_SIZE,
            MCP_PIPE_BUF_SIZE,
            0,
            NULL
        );

        if (g_pipe_handle == INVALID_HANDLE_VALUE) {
            Sleep(1000);
            continue;
        }

        // Wait for client to connect
        BOOL connected = ConnectNamedPipe(g_pipe_handle, NULL)
                         ? TRUE
                         : (GetLastError() == ERROR_PIPE_CONNECTED);

        if (!connected || !g_server_running) {
            CloseHandle(g_pipe_handle);
            g_pipe_handle = INVALID_HANDLE_VALUE;
            continue;
        }

        // Connection loop — handle commands until disconnect
        while (g_server_running) {
            char buffer[MCP_PIPE_BUF_SIZE] = {0};
            DWORD bytes_read = 0;

            BOOL ok = ReadFile(g_pipe_handle, buffer, sizeof(buffer) - 1, &bytes_read, NULL);
            if (!ok || bytes_read == 0) {
                break; // Client disconnected
            }

            buffer[bytes_read] = '\0';

            // Strip trailing newline/whitespace
            std::string cmd(buffer);
            while (!cmd.empty() && (cmd.back() == '\n' || cmd.back() == '\r' || cmd.back() == ' '))
                cmd.pop_back();

            if (cmd.empty()) continue;

            // Dispatch and get response
            std::string response = DispatchCommand(cmd);

            // Send response
            DWORD bytes_written = 0;
            WriteFile(g_pipe_handle, response.c_str(), (DWORD)response.length(), &bytes_written, NULL);
        }

        // Client disconnected, clean up and wait for next
        DisconnectNamedPipe(g_pipe_handle);
        CloseHandle(g_pipe_handle);
        g_pipe_handle = INVALID_HANDLE_VALUE;
    }

    return 0;
}

// ── DLL Entry Point ─────────────────────────────────────────────────────

// ── Core initialization logic (shared by DllMain and ManualMapInit) ──────

static void CoreAttach(HMODULE hModule) {
    g_dll_module = hModule;
    g_pid = GetCurrentProcessId();
    g_base_address = (DWORD_PTR)GetModuleHandleA(NULL);

    InitializeCriticalSection(&g_cs);

    // Initialize subsystems
    DisasmInit();
    HookInit();
    BreakpointInit();
    AntiDebugInit();

    // Start pipe server
    g_server_running = true;
    HANDLE hThread = CreateThread(NULL, 0, ServerThread, NULL, 0, NULL);
    if (hThread) CloseHandle(hThread);
}

static void CoreDetach() {
    g_server_running = false;

    // Close pipe to unblock the server thread
    if (g_pipe_handle != INVALID_HANDLE_VALUE) {
        DisconnectNamedPipe(g_pipe_handle);
        CloseHandle(g_pipe_handle);
        g_pipe_handle = INVALID_HANDLE_VALUE;
    }

    Sleep(100); // Give server thread time to exit

    AntiDebugCleanup();
    BreakpointCleanup();
    HookCleanup();
    DeleteCriticalSection(&g_cs);
}

// ── Manual-Map entry point ──────────────────────────────────────────────
// Called by the manual mapper's shellcode. Avoids CRT startup entirely.
// Uses only Win32 APIs — no CRT dependency.
// Signature matches LPTHREAD_START_ROUTINE so CreateRemoteThread can call it.

// Forward-declare the CRT initialization function.
// _CRT_INIT is provided by the MSVC static CRT (/MT).
// It initializes the CRT heap, stdio, TLS, static constructors, etc.
// without calling DllMain.
extern "C" BOOL WINAPI _CRT_INIT(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);

extern "C" __declspec(dllexport) DWORD WINAPI ManualMapInit(LPVOID pImageBase) {
    // Phase 1: Initialize the CRT so we can use std::string, snprintf, etc.
    if (!_CRT_INIT((HINSTANCE)pImageBase, DLL_PROCESS_ATTACH, NULL)) {
        return 0; // CRT init failed
    }

    // Phase 2: Now CRT is ready — run our actual initialization
    CoreAttach((HMODULE)pImageBase);
    return 1; // success
}

// ── DLL Entry Point (used by LoadLibrary injection) ─────────────────────

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH: {
        // Guard DisableThreadLibraryCalls — it crashes when called with
        // a module handle that isn't in the PEB loader list (manual mapping).
        {
            HMODULE hCheck = NULL;
            if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                    GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                    (LPCSTR)hModule, &hCheck) && hCheck == hModule) {
                DisableThreadLibraryCalls(hModule);
            }
        }
        CoreAttach(hModule);
        break;
    }

    case DLL_PROCESS_DETACH: {
        CoreDetach();
        break;
    }
    }

    return TRUE;
}
