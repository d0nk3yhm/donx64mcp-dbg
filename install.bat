@echo off
setlocal enabledelayedexpansion

REM ═══════════════════════════════════════════════════════════════════════
REM  donx64mcp-dbg — Install Script
REM
REM  This script:
REM    1. Builds mcp_debugger.dll and mcp_inject.exe from source
REM    2. Installs Python dependencies (pywin32, mcp SDK)
REM    3. Registers the MCP server with Claude Code (globally)
REM
REM  Prerequisites:
REM    - Visual Studio 2022 with "Desktop development with C++" workload
REM    - Python 3.10+ on PATH
REM ═══════════════════════════════════════════════════════════════════════

echo.
echo  donx64mcp-dbg — Installer
echo  ══════════════════════════
echo.

REM --- Step 1: Check Python ---
where python >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Python not found on PATH.
    echo         Install Python 3.10+ from https://python.org and ensure it is on PATH.
    exit /b 1
)
echo [OK] Python found:
python --version

REM --- Step 2: Install Python dependencies ---
echo.
echo Installing Python dependencies...
pip install pywin32 mcp
if %ERRORLEVEL% NEQ 0 (
    echo [WARN] pip install had issues. You may need to run: pip install pywin32 mcp
)

REM --- Step 3: Auto-detect Visual Studio 2022 ---
set "VCVARS="
for %%E in (Community Professional Enterprise) do (
    if exist "C:\Program Files\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvars64.bat" (
        set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvars64.bat"
    )
)
if "%VCVARS%"=="" (
    echo.
    echo [ERROR] Visual Studio 2022 not found.
    echo         Install VS 2022 with the "Desktop development with C++" workload.
    echo         https://visualstudio.microsoft.com/downloads/
    exit /b 1
)
echo [OK] Visual Studio found: %VCVARS%

REM --- Step 4: Build ---
echo.
echo Building from source...
call "%VCVARS%" >nul 2>&1

echo   Building mcp_debugger.dll...
pushd "%~dp0dll"
cl /LD /O2 /EHsc /W3 /MT /D_CRT_SECURE_NO_WARNINGS /DZYDIS_STATIC_BUILD /DZYCORE_STATIC_BUILD ^
    /I. /Ilib\minhook /Ilib\zydis ^
    mcp_debugger.cpp commands.cpp memory_ops.cpp breakpoints.cpp ^
    disasm.cpp threads.cpp modules.cpp hooks.cpp scanner.cpp heap.cpp anti_debug.cpp ^
    lib\minhook\hook.c lib\minhook\trampoline.c lib\minhook\buffer.c ^
    lib\minhook\hde64.c lib\zydis\Zydis.c ^
    /Fe:mcp_debugger.dll /link /DLL dbghelp.lib user32.lib >nul 2>&1
if !ERRORLEVEL! NEQ 0 (
    echo   [FAILED] DLL build failed. Run build_all.bat for detailed output.
    popd
    exit /b 1
)
echo   [OK] mcp_debugger.dll
popd

echo   Building mcp_inject.exe...
pushd "%~dp0injector"
cl /O2 /EHsc /W3 /MT /D_CRT_SECURE_NO_WARNINGS mcp_inject.cpp /Fe:mcp_inject.exe /link Shlwapi.lib >nul 2>&1
if !ERRORLEVEL! NEQ 0 (
    echo   [FAILED] Injector build failed. Run build_all.bat for detailed output.
    popd
    exit /b 1
)
echo   [OK] mcp_inject.exe
popd

REM --- Step 5: Register with Claude Code (global config) ---
echo.
set "BRIDGE=%~dp0bridge\mcp_debugger_server.py"

echo Registering MCP server with Claude Code...
where claude >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    claude mcp add donx64mcp-dbg -s user -- python "%BRIDGE%"
    if !ERRORLEVEL! EQU 0 (
        echo [OK] Registered globally with Claude Code.
        echo     Server name: donx64mcp-dbg
        echo     Config file: %%USERPROFILE%%\.claude\settings.json
    ) else (
        echo [WARN] Claude CLI registration failed. See manual setup below.
    )
) else (
    echo [INFO] Claude CLI not found on PATH.
    echo        To register manually, run:
    echo.
    echo   claude mcp add donx64mcp-dbg -s user -- python "%BRIDGE%"
    echo.
    echo        Or add to %%USERPROFILE%%\.claude\settings.json:
    echo.
    echo   "mcpServers": {
    echo     "donx64mcp-dbg": {
    echo       "command": "python",
    echo       "args": ["%BRIDGE%"]
    echo     }
    echo   }
)

echo.
echo ═══════════════════════════════════════════════════════════════
echo  Installation complete!
echo.
echo  The MCP server is registered globally — it works from ANY
echo  project directory in Claude Code. No per-project config needed.
echo.
echo  Quick start:
echo    1. Restart Claude Code (or open a new session)
echo    2. Call: dbg_attach("yourprocess.exe")
echo    3. All dbg_* tools are now available
echo ═══════════════════════════════════════════════════════════════
