@echo off
REM ═══════════════════════════════════════════════════════════════════════
REM  MCP Inject — Build Script
REM  Run from: x64 Native Tools Command Prompt for VS 2022
REM ═══════════════════════════════════════════════════════════════════════

echo Building mcp_inject.exe...

cl /O2 /EHsc /W3 /MT /D_CRT_SECURE_NO_WARNINGS mcp_inject.cpp /Fe:mcp_inject.exe /link Shlwapi.lib

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ══════════════════════════════════════
    echo  BUILD SUCCESSFUL: mcp_inject.exe
    echo ══════════════════════════════════════
) else (
    echo.
    echo  BUILD FAILED
)
