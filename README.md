# donx64mcp-dbg

A powerful in-process debugging toolkit that lets AI agents (Claude, Codex) debug and inspect **any** Windows x64 process in real time. Inject a DLL, get 40+ debug commands over a named pipe, and control it all through MCP tools.

Designed for authorized security research, reverse engineering, and CTF challenges.

## Features

- **Memory** — read, write, allocate, fill, pointer chain dereferencing
- **Disassembly** — Zydis-powered instruction and function disassembly
- **Pattern scanning** — IDA-style byte patterns with wildcards, string extraction
- **Breakpoints** — INT3 software breakpoints with hit counts, register context, wait-for-hit
- **API hooking** — MinHook-based function hooking with argument + return value logging
- **Module inspection** — enumerate loaded modules, exports, imports, PE sections
- **Thread control** — list, suspend, resume, get/set registers, call stacks
- **Heap walking** — enumerate heaps and walk allocations
- **Anti-anti-debug** — 3-tier stealth engine (18 hooks) defeating common debugger detection
- **Stealth injection** — manual map mode (no PEB entry, PE headers erased)

---

## Quick Install

### Prerequisites

- **Windows 10/11 x64**
- **Visual Studio 2022** (Community, Professional, or Enterprise) with the **"Desktop development with C++"** workload
- **Python 3.10+** on PATH with pip

### One-command install

```batch

git clone https://github.com/d0nk3yhm/donx64mcp-dbg.git
cd donx64mcp-dbg
install.bat
```

The install script will:
1. Build `mcp_debugger.dll` and `mcp_inject.exe` from source
2. Install Python dependencies (`pywin32`, `mcp` SDK)
3. Register the MCP server **globally** with Claude Code (written to `~/.claude/settings.json`)

After install, the `dbg_*` tools are available in **every** Claude Code session — no per-project config needed.

### Manual build

If you prefer to build manually or use the Visual Studio IDE:

```batch
:: Option A: Command-line build
build_all.bat

:: Option B: Open in Visual Studio
:: Open mcp_debugger.sln, set to Release|x64, build solution

:: Install Python deps
pip install pywin32 mcp
```

---

## Setup with Claude Code

### Automatic (via install.bat)

The installer registers the MCP server globally using `claude mcp add`. After install, restart Claude Code and the `dbg_*` tools will be available in any project.

### Manual (CLI)

```bash
claude mcp add donx64mcp-dbg -s user -- python "C:/path/to/donx64mcp-dbg/bridge/mcp_debugger_server.py"
```

The `-s user` flag registers it globally in `~/.claude/settings.json` so it works from any project directory.

### Manual (config file)

Add to `%USERPROFILE%\.claude\settings.json` (create the `mcpServers` key if it doesn't exist):

```json
{
  "mcpServers": {
    "donx64mcp-dbg": {
      "command": "python",
      "args": ["C:/path/to/donx64mcp-dbg/bridge/mcp_debugger_server.py"]
    }
  }
}
```

### Per-project only (optional)

If you only want the debugger available in a specific project, add a `.mcp.json` in the project root:

```json
{
  "mcpServers": {
    "donx64mcp-dbg": {
      "command": "python",
      "args": ["C:/path/to/donx64mcp-dbg/bridge/mcp_debugger_server.py"]
    }
  }
}
```

## Setup with Codex

Add to your Codex MCP configuration:

```json
{
  "mcpServers": {
    "donx64mcp-dbg": {
      "command": "python",
      "args": ["C:/path/to/donx64mcp-dbg/bridge/mcp_debugger_server.py"]
    }
  }
}
```

---

## How It Works

```
Claude / Codex
      |
      | MCP protocol (stdio)
      v
mcp_debugger_server.py        mcp_inject.exe
   (Python MCP bridge)          (injector)
      |                             |
      |  Named Pipe                 |  DLL injection
      |  \\.\pipe\mcp_dbg_<PID>    |  (LoadLibrary / Manual Map)
      v                             v
               mcp_debugger.dll
             (inside target process)
```

1. You call `dbg_attach("target.exe")` from Claude/Codex
2. The Python bridge finds the process, runs `mcp_inject.exe` to inject the DLL
3. The DLL starts a named pipe server inside the target process
4. The bridge connects to the pipe and forwards all `dbg_*` commands
5. Commands execute in-process and return JSON results

| Component | Path | Description |
|-----------|------|-------------|
| `mcp_debugger.dll` | `dll/` | Core DLL injected into target process |
| `mcp_inject.exe` | `injector/` | CLI injector with LoadLibrary + Manual Map modes |
| `mcp_debugger_server.py` | `bridge/` | Python MCP bridge exposing DLL commands as MCP tools |

---

## Usage

Once the MCP server is registered, use it from Claude or Codex:

```
1. dbg_attach("target.exe")     <- injects DLL, opens pipe, ready
2. dbg_info()                    <- process name, PID, base address
3. dbg_disasm("7FF612340000")    <- disassemble at address
4. dbg_stealth_on(2)             <- activate anti-anti-debug
```

### Injection modes

```bash
# Inject into a running process
mcp_inject.exe --name target.exe --dll path\to\mcp_debugger.dll

# Manual map (stealth - DLL hidden from module lists)
mcp_inject.exe --name target.exe --dll path\to\mcp_debugger.dll --mm

# Launch suspended, inject before any user code runs
mcp_inject.exe --launch target.exe --dll path\to\mcp_debugger.dll --mm

# Wait for a DLL to load, then inject
mcp_inject.exe --wait-dll engine.dll --in target.exe --dll path\to\mcp_debugger.dll --mm --timeout 30000
```

Note: When using from Claude/Codex, `dbg_attach()` handles injection automatically using LoadLibrary mode. For manual map or advanced scenarios, use `mcp_inject.exe` directly.

---

## Command Reference

### Core
| Command | Description |
|---------|-------------|
| `PING` | Heartbeat |
| `INFO` | Process info (name, PID, base address, architecture) |
| `HELP` | List all available commands |

### Memory Operations
| Command | Description |
|---------|-------------|
| `READ <addr> <size>` | Read memory as hex string (max 1 MB) |
| `WRITE <addr> <hex>` | Write hex bytes to memory |
| `READPTR <addr> [depth]` | Dereference pointer chain |
| `PROTECT <addr>` | Query memory protection flags |
| `ALLOC <size>` | Allocate RWX memory in target |
| `FREE <addr>` | Free allocated memory |
| `FILL <addr> <size> <byte>` | Fill memory region with byte |

### Disassembly (Zydis)
| Command | Description |
|---------|-------------|
| `DISASM <addr> [count]` | Disassemble instructions (default 10, max 500) |
| `DISASM_FUNC <addr>` | Disassemble entire function until RET |

### Pattern Scanning
| Command | Description |
|---------|-------------|
| `SCAN <start> <size> <pattern>` | Find first pattern match (IDA-style wildcards) |
| `SCAN_ALL <start> <size> <pattern>` | Find all pattern matches |
| `STRINGS <start> <size> [minlen]` | Extract ASCII strings from memory |

### Breakpoints
| Command | Description |
|---------|-------------|
| `BP_SET <addr>` | Set software breakpoint (INT3) |
| `BP_LIST` | List all breakpoints and hit counts |
| `BP_DEL <addr>` | Remove breakpoint |
| `BP_DEL_ALL` | Remove all breakpoints |
| `BP_CTX <addr>` | Get register context from last hit |
| `BP_WAIT <addr> [timeout_ms]` | Block until breakpoint is hit |

### Module Inspection
| Command | Description |
|---------|-------------|
| `MODULES` | List all loaded modules with base/size |
| `EXPORTS <module>` | List exports of a module |
| `IMPORTS <module>` | List imports of a module |
| `SECTIONS <module>` | List PE sections of a module |

### API Hooking (MinHook)
| Command | Description |
|---------|-------------|
| `HOOK <addr> [name]` | Hook a function and log calls |
| `UNHOOK <addr>` | Remove hook |
| `HOOK_LIST` | List active hooks |
| `HOOK_LOG <addr> [count]` | View hook call log |

### Thread Control
| Command | Description |
|---------|-------------|
| `THREADS` | List all threads |
| `THREAD_CTX <tid>` | Get all registers for a thread |
| `THREAD_SET <tid> <reg> <val>` | Set a register value |
| `THREAD_SUSPEND <tid>` | Suspend a thread |
| `THREAD_RESUME <tid>` | Resume a suspended thread |
| `CALLSTACK <tid>` | Get call stack |

### Heap Inspection
| Command | Description |
|---------|-------------|
| `HEAPS` | List all process heaps |
| `HEAP_WALK <heap_handle>` | Walk heap entries |

### Stealth / Anti-Anti-Debug
| Command | Description |
|---------|-------------|
| `STEALTH_ON <level>` | Activate stealth (1=basic, 2=full, 3=max) |
| `STEALTH_OFF` | Deactivate all stealth protections |
| `STEALTH_STATUS` | Show current stealth state and hook count |
| `STEALTH_PATCH_PEB` | Manually patch PEB debug flags |

---

## Anti-Anti-Debug Engine

Three tiers of protection bypass via `STEALTH_ON <level>`:

**Tier 1 (Basic):** PEB patching (BeingDebugged, NtGlobalFlag, heap flags), ETW disable, hooks on `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `NtQueryInformationProcess`, `NtClose`.

**Tier 2 (Full, includes Tier 1):** Debug register sanitization (`NtGetContextThread`, `NtSetContextThread`, `NtContinue`), timing hooks (`QueryPerformanceCounter`, `GetTickCount`, `GetTickCount64`), thread hooks (`NtSetInformationThread`, `NtCreateThreadEx`), window/process filtering (`FindWindowA/W`, `EnumWindows`), ntdll hooks (`NtQueryObject`, `NtQuerySystemInformation`).

**Tier 3 (Max, includes Tier 2):** Instrumentation callback kill (`NtSetInformationProcess` class 40 block).

Total hooks at max level: **18**.

---

## Source Layout

```
donx64mcp-dbg/
├── dll/                        # DLL source code
│   ├── mcp_debugger.cpp        # Entry point, pipe server
│   ├── commands.cpp/h          # Command dispatcher
│   ├── memory_ops.cpp/h        # Memory read/write/alloc
│   ├── breakpoints.cpp/h       # INT3 breakpoints + VEH
│   ├── disasm.cpp/h            # Zydis disassembly
│   ├── threads.cpp/h           # Thread enumeration/control
│   ├── modules.cpp/h           # Module/export/import/section info
│   ├── hooks.cpp/h             # MinHook API hooking
│   ├── scanner.cpp/h           # Pattern scanning + strings
│   ├── heap.cpp/h              # Heap walking
│   ├── anti_debug.cpp/h        # Anti-anti-debug engine
│   ├── globals.h               # Global state
│   ├── response.h              # JSON response helpers
│   ├── lib/minhook/            # MinHook (vendored)
│   └── lib/zydis/              # Zydis disassembler (vendored)
├── injector/                   # Injector source
│   └── mcp_inject.cpp          # LoadLibrary + manual map injector
├── bridge/                     # Python MCP bridge
│   └── mcp_debugger_server.py  # MCP server (all dbg_* tools)
├── scripts/                    # Utility scripts
│   └── quick_test.py           # Pipe connectivity test
├── build_all.bat               # Build DLL + injector
├── install.bat                 # Build + install + register
├── mcp_debugger.sln            # Visual Studio solution
└── .mcp.json                   # MCP server config (project-local)
```

---

## Named Pipe Protocol

After injection, the DLL creates a named pipe at `\\.\pipe\mcp_dbg_<PID>`.

- **Format:** Send UTF-8 command string, receive JSON response
- **Mode:** Message-mode pipe
- **Buffer:** 64 KB

---

## Manual Map Technical Details

The manual mapper (`--mm` flag) performs stealth injection:

1. Read PE from disk and validate (x64 DLL check)
2. Allocate memory in target (prefers original ImageBase)
3. Map sections with correct RVA offsets
4. Process base relocations (IMAGE_REL_BASED_DIR64)
5. Pre-load non-system dependencies (e.g. `dbghelp.dll`) via LoadLibrary
6. Resolve imports with remote base delta
7. Write mapped image and set per-section memory protections
8. Call exported `ManualMapInit` via `CreateRemoteThread`
9. Erase PE headers (zero first 0x1000 bytes)

The DLL uses static CRT (`/MT`). `ManualMapInit` calls `_CRT_INIT()` to bootstrap the C runtime before starting the pipe server, since `_DllMainCRTStartup` cannot be called from a manually-mapped context.

---

## License

[MIT](LICENSE)


## Author

d0nk3y @ 2026
