@echo off
setlocal enabledelayedexpansion

REM ═══════════════════════════════════════════════════════════════════════
REM  donx64mcp-dbg — Build All (DLL + Injector)
REM
REM  Usage:  build_all.bat
REM  Requires: Visual Studio 2022 (Community/Professional/Enterprise)
REM ═══════════════════════════════════════════════════════════════════════

REM --- Auto-detect Visual Studio 2022 vcvars64.bat ---
set "VCVARS="
for %%E in (Community Professional Enterprise) do (
    if exist "C:\Program Files\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvars64.bat" (
        set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvars64.bat"
    )
)
if "%VCVARS%"=="" (
    echo ERROR: Could not find Visual Studio 2022 vcvars64.bat
    echo Install Visual Studio 2022 with the "Desktop development with C++" workload.
    exit /b 1
)

call "%VCVARS%"

echo.
echo ===== Building mcp_debugger.dll =====
echo.

pushd "%~dp0dll"

cl /LD /O2 /EHsc /W3 /MT /D_CRT_SECURE_NO_WARNINGS /DZYDIS_STATIC_BUILD /DZYCORE_STATIC_BUILD ^
    /I. /Ilib\minhook /Ilib\zydis ^
    mcp_debugger.cpp commands.cpp memory_ops.cpp breakpoints.cpp ^
    disasm.cpp threads.cpp modules.cpp hooks.cpp scanner.cpp heap.cpp anti_debug.cpp ^
    lib\minhook\hook.c lib\minhook\trampoline.c lib\minhook\buffer.c ^
    lib\minhook\hde64.c lib\zydis\Zydis.c ^
    /Fe:mcp_debugger.dll /link /DLL dbghelp.lib user32.lib

if !ERRORLEVEL! NEQ 0 (
    echo DLL BUILD FAILED
    popd
    exit /b 1
)
popd

echo.
echo ===== Building mcp_inject.exe =====
echo.

pushd "%~dp0injector"

cl /O2 /EHsc /W3 /MT /D_CRT_SECURE_NO_WARNINGS mcp_inject.cpp /Fe:mcp_inject.exe /link Shlwapi.lib

if !ERRORLEVEL! NEQ 0 (
    echo INJECTOR BUILD FAILED
    popd
    exit /b 1
)
popd

echo.
echo ===== BUILD COMPLETE =====
echo.
echo Output:
echo   dll\mcp_debugger.dll
echo   injector\mcp_inject.exe
