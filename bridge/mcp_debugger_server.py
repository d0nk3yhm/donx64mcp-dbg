# donx64mcp-dbg — MCP Debugger Server
#
# Works with ANY process. Workflow:
#   1. Claude calls dbg_attach("target.exe") - any process name
#   2. Server finds the PID via tasklist
#   3. Injects mcp_debugger.dll into that PID
#   4. Pipe opens inside the target
#   5. All dbg_* tools now work against that process
#
# No PID needed in the MCP config - just add this server once, use dbg_attach per session.

import sys, os, json, time, subprocess

_THIS  = os.path.dirname(os.path.abspath(__file__))
_ROOT  = os.path.dirname(_THIS)
INJECTOR = os.path.join(_ROOT, "injector", "mcp_inject.exe")
DBG_DLL  = os.path.join(_ROOT, "dll",      "mcp_debugger.dll")

try:
    import win32file, win32pipe, pywintypes
except ImportError:
    print("ERROR: pywin32 required — pip install pywin32", file=sys.stderr)
    sys.exit(1)

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    print("ERROR: MCP SDK required — pip install mcp", file=sys.stderr)
    sys.exit(1)


# ── Helpers ────────────────────────────────────────────────────────────────

def find_pid(exe_name: str) -> int:
    """Find a process PID by exact exe name (case-insensitive) via tasklist CSV."""
    try:
        out = subprocess.check_output(
            ["tasklist", "/FO", "CSV", "/NH"],
            text=True, stderr=subprocess.DEVNULL
        )
        for line in out.strip().splitlines():
            parts = [p.strip('"') for p in line.strip().split(',')]
            if len(parts) >= 2 and parts[0].lower() == exe_name.lower():
                return int(parts[1])
    except Exception:
        pass
    return 0


def inject(pid: int) -> tuple[bool, str]:
    """Run mcp_inject.exe --pid PID --dll DLL. Returns (success, message)."""
    if not os.path.exists(INJECTOR):
        return False, f"Injector not found: {INJECTOR}"
    if not os.path.exists(DBG_DLL):
        return False, f"DLL not found: {DBG_DLL}"
    try:
        r = subprocess.run(
            [INJECTOR, "--pid", str(pid), "--dll", DBG_DLL],
            capture_output=True, text=True, timeout=15
        )
        msg = (r.stdout + r.stderr).strip()
        return r.returncode == 0, msg
    except Exception as e:
        return False, str(e)


def pipe_name(pid: int) -> str:
    return f"\\\\.\\pipe\\mcp_dbg_{pid}"


# ── Pipe client ────────────────────────────────────────────────────────────

class PipeClient:
    def __init__(self):
        self.pid  = 0
        self.pipe = None

    def attach(self, pid: int) -> tuple[bool, str]:
        """Connect to the pipe for the given PID. Retries up to 3s."""
        self.close()
        self.pid = pid
        pn = pipe_name(pid)
        deadline = time.time() + 3.0
        while time.time() < deadline:
            try:
                h = win32file.CreateFile(
                    pn,
                    win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                    0, None, win32file.OPEN_EXISTING, 0, None
                )
                win32pipe.SetNamedPipeHandleState(
                    h, win32pipe.PIPE_READMODE_MESSAGE, None, None
                )
                self.pipe = h
                return True, f"Connected to {pn}"
            except pywintypes.error as e:
                err = e.args[0]
                if err == 231:          # ERROR_PIPE_BUSY — wait for free instance
                    try: win32pipe.WaitNamedPipe(pn, 500)
                    except: pass
                else:
                    time.sleep(0.2)
        return False, f"Could not connect to {pn} after 3s"

    def send(self, cmd: str) -> dict:
        if self.pipe is None or self.pid == 0:
            return {"status": "error", "message": "Not attached. Call dbg_attach first."}
        # Try send; on failure reconnect once
        for attempt in range(2):
            try:
                win32file.WriteFile(self.pipe, cmd.encode())
                _, data = win32file.ReadFile(self.pipe, 131072)
                return json.loads(data.decode())
            except pywintypes.error:
                self.pipe = None
                if attempt == 0:
                    ok, _ = self.attach(self.pid)
                    if ok: continue
                return {"status": "error", "message": "Pipe broke; reconnect failed. Call dbg_attach again."}
            except json.JSONDecodeError as e:
                return {"status": "error", "message": f"Bad JSON from DLL: {e}"}
        return {"status": "error", "message": "Send failed"}

    def close(self):
        if self.pipe:
            try: win32file.CloseHandle(self.pipe)
            except: pass
            self.pipe = None


# ── Globals ───────────────────────────────────────────────────────────────

_client = PipeClient()
mcp     = FastMCP("donx64mcp-dbg")

def send(cmd: str) -> str:
    return json.dumps(_client.send(cmd), indent=2)


# ═════════════════════════════════════════════════════════════════════════
# MCP Tools
# ═════════════════════════════════════════════════════════════════════════

# ── Attach / Control ──────────────────────────────────────────────────────

@mcp.tool()
def dbg_attach(exe_name: str) -> str:
    """
    Attach the debugger to a running process by EXE name.
    Steps: find PID → inject mcp_debugger.dll → open pipe → ready.

    exe_name: The process executable name, e.g. "NWX-Win64-Shipping.exe" or "notepad.exe"

    Call this FIRST before any other dbg_* tool.
    Call again if the game restarts (new PID).
    """
    result = {"exe": exe_name}

    # 1. Find PID
    pid = find_pid(exe_name)
    if not pid:
        result["status"] = "error"
        result["message"] = f"Process not found: {exe_name}. Is it running?"
        return json.dumps(result, indent=2)
    result["pid"] = pid
    result["pipe"] = pipe_name(pid)

    # 2. Inject
    ok, msg = inject(pid)
    result["inject"] = msg
    if not ok:
        result["status"] = "error"
        result["message"] = f"Injection failed: {msg}"
        return json.dumps(result, indent=2)

    # 3. Connect pipe (DLL needs a moment to start its pipe server)
    time.sleep(0.8)
    ok2, conn_msg = _client.attach(pid)
    result["connect"] = conn_msg
    if not ok2:
        result["status"] = "error"
        result["message"] = f"Pipe connect failed: {conn_msg}"
        return json.dumps(result, indent=2)

    # 4. Verify with PING
    ping = _client.send("PING")
    result["ping"] = ping
    if ping.get("status") is True or ping.get("message") == "pong":
        result["status"] = "ok"
        result["message"] = f"Attached to {exe_name} PID={pid}. All dbg_* tools ready."
    else:
        result["status"] = "error"
        result["message"] = f"Pipe connected but PING failed: {ping}"

    return json.dumps(result, indent=2)


@mcp.tool()
def dbg_ping() -> str:
    """Heartbeat — check if debugger DLL is alive and responding."""
    return send("PING")

@mcp.tool()
def dbg_info() -> str:
    """Get process info: name, PID, base address (module base), architecture."""
    return send("INFO")

@mcp.tool()
def dbg_help() -> str:
    """List all commands the debugger DLL supports."""
    return send("HELP")

# ── Memory ────────────────────────────────────────────────────────────────

@mcp.tool()
def dbg_read(address: str, size: int) -> str:
    """Read memory at an absolute virtual address.

    address: hex address string, e.g. "7FF612340000"
    size: number of bytes to read (max 1048576 = 1 MB)

    Response JSON has a "hex" field with space-separated hex bytes, e.g. "4D 5A 90 00 ..."
    To parse in Python: bytes.fromhex(j['hex'].replace(' ', ''))
    """
    return send(f"READ {address} {size}")

@mcp.tool()
def dbg_write(address: str, hex_bytes: str) -> str:
    """Write bytes to memory at an absolute virtual address.

    address: hex address string
    hex_bytes: space-separated hex bytes, e.g. "90 90 90" for 3 NOPs
    """
    return send(f"WRITE {address} {hex_bytes}")

@mcp.tool()
def dbg_readptr(address: str, depth: int = 1) -> str:
    """Dereference a pointer chain starting at address.

    address: hex address
    depth: number of pointer dereferences (default 1, max 16)

    Returns each intermediate address in the chain.
    """
    return send(f"READPTR {address} {depth}")

@mcp.tool()
def dbg_protect(address: str) -> str:
    """Query memory protection for the region containing address (VirtualQuery).
    Returns protection flags, state (COMMIT/FREE/RESERVE), type, and region size."""
    return send(f"PROTECT {address}")

@mcp.tool()
def dbg_alloc(size: int) -> str:
    """Allocate RWX (PAGE_EXECUTE_READWRITE) memory in the target process.
    Returns the allocated address."""
    return send(f"ALLOC {size}")

@mcp.tool()
def dbg_free(address: str) -> str:
    """Free a previously allocated memory region."""
    return send(f"FREE {address}")

@mcp.tool()
def dbg_fill(address: str, size: int, byte_val: str = "90") -> str:
    """Fill a memory region with a single byte value.

    address: hex start address
    size: number of bytes
    byte_val: hex byte, default "90" (NOP)
    """
    return send(f"FILL {address} {size} {byte_val}")

# ── Disassembly ───────────────────────────────────────────────────────────

@mcp.tool()
def dbg_disasm(address: str, count: int = 20) -> str:
    """Disassemble instructions using Zydis.

    address: hex start address
    count: number of instructions (default 20, max 500)

    Returns mnemonic, operands, raw bytes, and length for each instruction.
    """
    return send(f"DISASM {address} {count}")

@mcp.tool()
def dbg_disasm_func(address: str) -> str:
    """Disassemble an entire function body until RET or INT3."""
    return send(f"DISASM_FUNC {address}")

# ── Pattern scanning ──────────────────────────────────────────────────────

@mcp.tool()
def dbg_scan(start: str, size: str, pattern: str) -> str:
    """Find first IDA-style byte pattern match in memory.

    start: hex start address
    size: hex size of region to search
    pattern: IDA-style with ?? wildcards, e.g. "48 8B 05 ?? ?? ?? ??"
    """
    return send(f"SCAN {start} {size} {pattern}")

@mcp.tool()
def dbg_scan_all(start: str, size: str, pattern: str) -> str:
    """Find ALL matches of an IDA-style byte pattern (up to 256 results)."""
    return send(f"SCAN_ALL {start} {size} {pattern}")

@mcp.tool()
def dbg_strings(start: str, size: str, min_length: int = 4) -> str:
    """Extract all ASCII and Unicode strings from a memory region."""
    return send(f"STRINGS {start} {size} {min_length}")

# ── Breakpoints ───────────────────────────────────────────────────────────

@mcp.tool()
def dbg_bp_set(address: str) -> str:
    """Set software breakpoint (INT3) at address. Re-arms after each hit."""
    return send(f"BP_SET {address}")

@mcp.tool()
def dbg_bp_del(address: str) -> str:
    """Remove breakpoint and restore the original byte."""
    return send(f"BP_DEL {address}")

@mcp.tool()
def dbg_bp_list() -> str:
    """List all breakpoints with hit counts and enabled/disabled status."""
    return send("BP_LIST")

@mcp.tool()
def dbg_bp_ctx(address: str) -> str:
    """Get the full register context (RAX–R15, RIP, RFLAGS) from last BP hit."""
    return send(f"BP_CTX {address}")

@mcp.tool()
def dbg_bp_wait(address: str, timeout_ms: int = 10000) -> str:
    """Block until a breakpoint is hit or timeout expires. Returns register context."""
    return send(f"BP_WAIT {address} {timeout_ms}")

# ── Threads ───────────────────────────────────────────────────────────────

@mcp.tool()
def dbg_threads() -> str:
    """List all threads with IDs and priorities."""
    return send("THREADS")

@mcp.tool()
def dbg_thread_ctx(thread_id: int) -> str:
    """Get all registers for a thread. Briefly suspends the thread to read context."""
    return send(f"THREAD_CTX {thread_id}")

@mcp.tool()
def dbg_thread_set(thread_id: int, register: str, value: str) -> str:
    """Set a register value for a thread.
    register: rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp, r8–r15, rip
    value: hex value"""
    return send(f"THREAD_SET {thread_id} {register} {value}")

@mcp.tool()
def dbg_thread_suspend(thread_id: int) -> str:
    """Suspend a thread."""
    return send(f"THREAD_SUSPEND {thread_id}")

@mcp.tool()
def dbg_thread_resume(thread_id: int) -> str:
    """Resume a suspended thread."""
    return send(f"THREAD_RESUME {thread_id}")

@mcp.tool()
def dbg_callstack(thread_id: int) -> str:
    """Get call stack for a thread (return addresses, modules, RVAs)."""
    return send(f"CALLSTACK {thread_id}")

# ── Modules ───────────────────────────────────────────────────────────────

@mcp.tool()
def dbg_modules() -> str:
    """List all loaded modules (DLLs + EXE) with base addresses, sizes, paths."""
    return send("MODULES")

@mcp.tool()
def dbg_exports(module_name: str) -> str:
    """List exported functions of a module.
    module_name: e.g. "kernel32.dll" or "NWX-Win64-Shipping.exe"
    Returns name, ordinal, RVA, absolute address."""
    return send(f"EXPORTS {module_name}")

@mcp.tool()
def dbg_imports(module_name: str) -> str:
    """List imported functions of a module."""
    return send(f"IMPORTS {module_name}")

@mcp.tool()
def dbg_sections(module_name: str) -> str:
    """List PE sections (.text, .data, .rdata, etc) with addresses and protections."""
    return send(f"SECTIONS {module_name}")

# ── API hooks ─────────────────────────────────────────────────────────────

@mcp.tool()
def dbg_hook(address: str, name: str = "") -> str:
    """Hook a function to log all calls to it.
    Captures first 4 args (RCX, RDX, R8, R9) and return value each call.
    address: hex address of function to hook
    name: optional label for the hook"""
    cmd = f"HOOK {address}"
    if name: cmd += f" {name}"
    return send(cmd)

@mcp.tool()
def dbg_unhook(address: str) -> str:
    """Remove a function hook and restore original code."""
    return send(f"UNHOOK {address}")

@mcp.tool()
def dbg_hook_list() -> str:
    """List all active hooks with addresses, names, and call counts."""
    return send("HOOK_LIST")

@mcp.tool()
def dbg_hook_log(address: str, count: int = 64) -> str:
    """Get the call log for a hooked function.
    Shows args and return values for recent calls."""
    return send(f"HOOK_LOG {address} {count}")

# ── Heap ──────────────────────────────────────────────────────────────────

@mcp.tool()
def dbg_heaps() -> str:
    """List all process heaps with handles and sizes."""
    return send("HEAPS")

@mcp.tool()
def dbg_heap_walk(heap_id: str, max_entries: int = 100) -> str:
    """Walk a heap and list allocations.
    heap_id: hex heap handle from dbg_heaps
    max_entries: max blocks to return"""
    return send(f"HEAP_WALK {heap_id} {max_entries}")

# ── Stealth / anti-anti-debug ─────────────────────────────────────────────

@mcp.tool()
def dbg_stealth_on(level: int = 2) -> str:
    """Activate anti-anti-debug stealth. Defeats debugger detection in target.
    level 1: PEB patch + core API hooks + ETW disable
    level 2: + DR sanitization, timing hooks, window/process filtering (default)
    level 3: + instrumentation callback kill (max stealth)"""
    return send(f"STEALTH_ON {level}")

@mcp.tool()
def dbg_stealth_off() -> str:
    """Remove all stealth hooks and restore PEB."""
    return send("STEALTH_OFF")

@mcp.tool()
def dbg_stealth_status() -> str:
    """Show which stealth protections are active and hook count."""
    return send("STEALTH_STATUS")

@mcp.tool()
def dbg_stealth_patch_peb() -> str:
    """Patch PEB only: clear BeingDebugged, NtGlobalFlag, heap debug flags."""
    return send("STEALTH_PATCH_PEB")


# ── Entry point ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("[donx64mcp-dbg] Server ready.", file=sys.stderr)
    print(f"[donx64mcp-dbg] Injector : {INJECTOR}", file=sys.stderr)
    print(f"[donx64mcp-dbg] DLL      : {DBG_DLL}", file=sys.stderr)
    print("[donx64mcp-dbg] Call dbg_attach('YourProcess.exe') to begin.", file=sys.stderr)
    mcp.run(transport="stdio")
