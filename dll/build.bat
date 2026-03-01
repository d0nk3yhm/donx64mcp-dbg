@echo off
REM ═══════════════════════════════════════════════════════════════════════
REM  MCP Debugger DLL — Build Script
REM  Run from: x64 Native Tools Command Prompt for VS 2022
REM ═══════════════════════════════════════════════════════════════════════

echo Building mcp_debugger.dll...

cl /LD /O2 /EHsc /W3 /MT /D_CRT_SECURE_NO_WARNINGS /DZYDIS_STATIC_BUILD /DZYCORE_STATIC_BUILD ^
    /I"." /I"lib\minhook" /I"lib\zydis" ^
    mcp_debugger.cpp commands.cpp memory_ops.cpp breakpoints.cpp ^
    disasm.cpp threads.cpp modules.cpp hooks.cpp scanner.cpp heap.cpp anti_debug.cpp ^
    lib\minhook\hook.c lib\minhook\trampoline.c lib\minhook\buffer.c ^
    lib\minhook\hde64.c lib\zydis\Zydis.c ^
    /Fe:mcp_debugger.dll ^
    /link /DLL dbghelp.lib user32.lib

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ══════════════════════════════════════
    echo  BUILD SUCCESSFUL: mcp_debugger.dll
    echo ══════════════════════════════════════
) else (
    echo.
    echo  BUILD FAILED
)
