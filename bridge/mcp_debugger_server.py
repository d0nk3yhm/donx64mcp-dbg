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

import sys, os, json, time, re, subprocess, tempfile

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
    Call again if the application restarts (new PID).
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
def dbg_launch(exe_path: str, args: str = "", hold: bool = True) -> str:
    """
    Launch a NEW process suspended and inject the debugger DLL before its main
    thread executes a single instruction -- then (by default) leave it
    suspended so you can install hooks/breakpoints/patches before anything in
    the target runs. Use this instead of dbg_attach whenever what you need to
    hook must be in place before the target's own startup code runs even once.

    WORKFLOW:
      1. dbg_launch(exe_path, hold=True)  ← target suspended, DLL injected
      2. dbg_exports("module.dll") or dbg_disasm() to find target functions
      3. dbg_hook_scan_caller() or dbg_bp_set() to install patches/breakpoints
      4. dbg_stealth_on() if target has anti-debug checks
      5. dbg_thread_resume(main_thread_id) ← target runs with patches in place
      6. dbg_bp_wait() or dbg_read() to monitor/verify patches worked

    exe_path: full path to the executable to launch
    args: optional command-line arguments, as one string
    hold: True (default) leaves the main thread suspended after injecting.
          Read `main_thread_id` from the result and call
          dbg_thread_resume(main_thread_id) once you're set up.
          False resumes immediately after injection, like a normal launch.
    """
    if not os.path.exists(INJECTOR):
        return json.dumps({"status": "error", "message": f"Injector not found: {INJECTOR}"})
    if not os.path.exists(DBG_DLL):
        return json.dumps({"status": "error", "message": f"DLL not found: {DBG_DLL}"})

    cmd = [INJECTOR, "--launch", exe_path]
    if args:
        cmd += ["--args", args]
    cmd += ["--dll", DBG_DLL]
    if hold:
        cmd += ["--hold"]

    # IMPORTANT: capture_output=True creates INHERITABLE pipes on Windows.
    # mcp_inject's suspended child (via shared console) ends up holding the
    # other end of those pipes, and subprocess.run() then blocks forever
    # waiting for pipe close after the injector has already exited.
    # Route the injector's stdio through real files instead.
    with tempfile.NamedTemporaryFile(mode='w', suffix='.out', delete=False) as fo, \
         tempfile.NamedTemporaryFile(mode='w', suffix='.err', delete=False) as fe:
        out_path, err_path = fo.name, fe.name
    try:
        with open(out_path, 'w') as fo, open(err_path, 'w') as fe:
            r = subprocess.run(cmd, stdout=fo, stderr=fe, timeout=20)
        with open(out_path) as f: stdout = f.read()
        with open(err_path) as f: stderr = f.read()
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})
    # Deliberately don't unlink — the suspended target may inherit the handle
    # via the shared console. The files land in %TEMP% and Windows cleans them.

    out = stdout + stderr
    result = {"exe": exe_path, "injector_output": out.strip()}

    pid_m = re.search(r"mcp_dbg_(\d+)", out)
    tid_m = re.search(r"MainThreadId:\s*(\d+)", out)
    if r.returncode != 0 or not pid_m:
        result["status"] = "error"
        result["message"] = "Launch/inject failed -- see injector_output"
        return json.dumps(result, indent=2)

    pid = int(pid_m.group(1))
    result["pid"] = pid
    result["pipe"] = pipe_name(pid)
    if tid_m:
        result["main_thread_id"] = int(tid_m.group(1))
    result["held"] = hold

    time.sleep(0.5)
    ok2, conn_msg = _client.attach(pid)
    result["connect"] = conn_msg
    if not ok2:
        result["status"] = "error"
        result["message"] = f"Pipe connect failed: {conn_msg}"
        return json.dumps(result, indent=2)

    ping = _client.send("PING")
    if ping.get("status") is True or ping.get("message") == "pong":
        result["status"] = "ok"
        if hold:
            result["message"] = (f"Launched PID={pid}, held suspended at main_thread_id="
                                  f"{result.get('main_thread_id')}. Set up hooks, then call "
                                  f"dbg_thread_resume({result.get('main_thread_id')}).")
        else:
            result["message"] = f"Launched and running, PID={pid}."
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
def dbg_bp_set(address: str, halt: bool = False) -> str:
    """Set software breakpoint (INT3) at address. Re-arms after each hit.

    halt=False (default): report-and-continue - the thread keeps running after the
    hit; dbg_bp_wait just captures the register context.
    halt=True: a HALTING breakpoint - the target thread is FROZEN at the hit until
    dbg_continue(address) is called. While it is frozen you can dbg_read/dbg_write
    memory (to inspect data that would otherwise be overwritten, or to patch code
    before it executes). This is what lets you break-and-hold, then continue.

    DECRYPTION WORKFLOW (catching .text decrypt mid-flight):
      1. dbg_launch(exe, hold=True) ← process suspended
      2. Identify the decryption routine (dbg_disasm, reverse engineering, etc)
      3. dbg_bp_set(decrypt_addr, halt=True) ← install halting breakpoint
      4. dbg_thread_resume(main_thread_id) ← process runs, hits breakpoint
      5. dbg_bp_wait(decrypt_addr, 10000) ← blocks until breakpoint fires
      6. dbg_read(.text_addr, size) ← read plaintext while halted
      7. Verify/understand, then patch: dbg_write(addr, new_bytes)
      8. dbg_bp_continue(decrypt_addr) ← release thread, execute patched code
      9. Repeat for next check point, or dbg_bp_del to remove
    """
    return send(f"BP_SET {address} {1 if halt else 0}")

@mcp.tool()
def dbg_continue(address: str) -> str:
    """Release a HALTING breakpoint (set with halt=True) so the target thread
    resumes. Call after dbg_bp_wait returns and you have read/patched what you need.
    A held thread also auto-continues after a safety timeout if never released."""
    return send(f"BP_CONTINUE {address}")

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
def dbg_hook_scan_caller(address: str, scan_window: int, pattern: str, replacement: str, name: str = "") -> str:
    """
    Install a NATIVE in-process hook that, on every call, calls the real function
    first, then scans forward from the CALLER's own return address (the exact
    spot in the target's code that called it) for a byte pattern, and patches it
    in place if found. Runs entirely inside the target -- no MCP round-trip per
    call, so it's fast enough for functions called continuously (e.g. a polled
    tick/time function).

    USE CASE:
      Target calls a function. Right after the call, a comparison instruction
      checks the return value. If it fails, execution branches to an error path.
      → Hook the function, scan for the comparison instruction after the call,
        and patch it to skip the check. Use dbg_disasm to find the exact bytes.

    WORKFLOW:
      1. dbg_exports(module_name) → find target function address
      2. dbg_hook_scan_caller(addr, 4096, "pattern", "replacement", "hook_name")
         ← hook installed, will fire on every call
      3. dbg_hook_list() → verify call_count increments as target runs
      4. If target still fails → pattern didn't match. Use dbg_disasm to find
         the exact bytes, or try larger scan_window.

    address: hex address of the function to hook (see dbg_exports, or dbg_hook's
             "module.dll FunctionName" resolution style)
    scan_window: bytes to scan forward from the caller's return address (e.g. 64, max 4096)
    pattern: comma-separated hex bytes, ?? = wildcard, e.g. "3C,30" or "80,FB,30"
    replacement: comma-separated hex, same length or shorter than pattern
                 (shorter is NOP-padded); ?? = leave that byte of the match alone
    name: optional label

    Returns: hook installed in a slot, ready to fire on next call.
    """
    return send(f"HOOK_SCAN_CALLER {address} {scan_window} "
                f"{pattern.replace(' ', '')} {replacement.replace(' ', '')} {name}".rstrip())

@mcp.tool()
def dbg_hook_scan_output(address: str, buf_arg_index: int, len_arg_index: int,
                          len_is_out_pointer: bool, pattern: str, patch_offset: int,
                          replacement: str, name: str = "") -> str:
    """
    Install a NATIVE in-process hook that calls the real function, then scans one
    of its arguments (treated as a buffer pointer) for a byte pattern and patches
    bytes at an offset from the match.

    Generalizes: "hook a function that fills a buffer, find a known marker in the
    data it just produced, overwrite a value near it" -- e.g. hooking a file-read
    function to find a marker string in the bytes just read and overwrite an
    integer that follows it. Parameterized entirely by argument position and
    calling convention; nothing here is specific to any file format or target.

    address: hex address of the function to hook
    buf_arg_index: which of the function's first 4 args (0=rcx,1=rdx,2=r8,3=r9)
                   holds the pointer to the buffer to scan (e.g. ReadFile's
                   lpBuffer is arg 1)
    len_arg_index: which arg tells you how many bytes are valid to scan
    len_is_out_pointer: True if that arg is a pointer to a length only filled in
                   AFTER the real call returns (e.g. ReadFile's
                   lpNumberOfBytesRead, arg 3) -- dereferenced as a DWORD post-call.
                   False to treat the arg itself as a literal byte count.
    pattern: comma-separated hex bytes, ?? = wildcard
    patch_offset: byte offset from the START of the match to where replacement is
                  written (can be negative to patch bytes just before the match)
    replacement: comma-separated hex bytes to write; ?? = leave that byte alone
    name: optional label
    """
    return send(f"HOOK_SCAN_OUTPUT {address} {buf_arg_index} {len_arg_index} "
                f"{1 if len_is_out_pointer else 0} {pattern.replace(' ', '')} "
                f"{patch_offset} {replacement.replace(' ', '')} {name}".rstrip())

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
    level 2: + DR sanitization, timing hooks (GetTickCount, QueryPerformanceCounter, etc.),
             window/process filtering (default)
    level 3: + instrumentation callback kill (max stealth)

    TIMING HOOKS (Level 2):
      Hooks GetTickCount, GetTickCount64, QueryPerformanceCounter to return fake/consistent
      values. Use this when the target checks elapsed time to detect debugger slowdown.
      After calling dbg_stealth_on(2+), timing checks will see consistent tick counts
      even while you're debugging."""
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
