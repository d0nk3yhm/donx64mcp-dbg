#pragma once
#ifndef GLOBALS_H
#define GLOBALS_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>

// ── Shared global state ──────────────────────────────────────────────────

extern DWORD_PTR   g_base_address;       // Main module base address
extern DWORD       g_pid;                // Current process ID
extern HMODULE     g_dll_module;         // Our DLL module handle
extern HANDLE      g_pipe_handle;        // Named pipe handle
extern volatile bool g_server_running;   // Pipe server active flag

extern CRITICAL_SECTION g_cs;           // General thread safety
extern CRITICAL_SECTION g_bp_cs;        // Breakpoint data safety

// ── Constants ────────────────────────────────────────────────────────────

#define MCP_PIPE_PREFIX     "\\\\.\\pipe\\mcp_dbg_"
#define MCP_PIPE_BUF_SIZE   65536
#define MCP_MAX_READ        (1 * 1024 * 1024)   // 1MB max read
#define MCP_MAX_DISASM      500                  // Max instructions per disasm call
#define MCP_MAX_SCAN_RESULTS 256
#define MCP_MAX_BREAKPOINTS  64
#define MCP_MAX_HOOK_SLOTS   16
#define MCP_HOOK_LOG_SIZE    64

// ── Utility macros ───────────────────────────────────────────────────────

#define SAFE_CLOSE_HANDLE(h) do { if ((h) && (h) != INVALID_HANDLE_VALUE) { CloseHandle(h); (h) = NULL; } } while(0)

#endif // GLOBALS_H
