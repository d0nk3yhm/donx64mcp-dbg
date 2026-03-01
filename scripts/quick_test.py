"""
Quick connection test for MCP Debugger DLL.
Tests basic pipe connectivity and a few commands.

Usage: python quick_test.py <PID>
"""

import sys
import json

try:
    import win32file
    import win32pipe
    import pywintypes
except ImportError:
    print("pip install pywin32")
    sys.exit(1)


def send_cmd(pipe, cmd):
    win32file.WriteFile(pipe, cmd.encode('utf-8'))
    _, data = win32file.ReadFile(pipe, 65536)
    return json.loads(data.decode('utf-8'))


def main():
    if len(sys.argv) < 2:
        print("Usage: python quick_test.py <PID>")
        sys.exit(1)

    pid = int(sys.argv[1])
    pipe_name = f"\\\\.\\pipe\\mcp_dbg_{pid}"

    print(f"Connecting to {pipe_name}...")
    try:
        pipe = win32file.CreateFile(
            pipe_name,
            win32file.GENERIC_READ | win32file.GENERIC_WRITE,
            0, None, win32file.OPEN_EXISTING, 0, None
        )
        win32pipe.SetNamedPipeHandleState(pipe, win32pipe.PIPE_READMODE_MESSAGE, None, None)
    except pywintypes.error as e:
        print(f"FAILED: {e}")
        sys.exit(1)

    print("Connected!\n")

    tests = [
        ("PING",       "Heartbeat"),
        ("INFO",       "Process info"),
        ("MODULES",    "Module list"),
        ("THREADS",    "Thread list"),
        ("HELP",       "Command list"),
    ]

    for cmd, desc in tests:
        print(f"[{desc}] {cmd}")
        try:
            result = send_cmd(pipe, cmd)
            status = result.get("status", "?")
            if status == "ok":
                # Print a summary
                for k, v in result.items():
                    if k == "status":
                        continue
                    if isinstance(v, list):
                        print(f"  {k}: [{len(v)} items]")
                    elif isinstance(v, str) and len(v) > 80:
                        print(f"  {k}: {v[:80]}...")
                    else:
                        print(f"  {k}: {v}")
            else:
                print(f"  ERROR: {result.get('message', '?')}")
        except Exception as e:
            print(f"  EXCEPTION: {e}")
        print()

    win32file.CloseHandle(pipe)
    print("All tests complete.")


if __name__ == "__main__":
    main()
