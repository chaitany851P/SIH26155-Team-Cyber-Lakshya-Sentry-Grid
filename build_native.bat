@echo off
REM ==============================================================================
REM  SENTRY-GRID Native C11 Build Automation Script
REM  Compiles sentry_native.dll and sentry_cli.exe with MinGW-w64 GCC
REM ==============================================================================

echo [*] Initializing SENTRY-GRID Native Build Environment...

if not exist bin (
    mkdir bin
    echo [+] Created output directory: bin/
)

set GCC_CMD=gcc
where gcc >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] ERROR: GCC compiler not found in system PATH.
    echo [!] Please install MinGW-w64 or ensure GCC is available.
    exit /b 1
)

echo [*] Compiling Native C Shared Library (bin/sentry_native.dll)...
gcc -shared -O3 -DSENTRY_EXPORTS -o bin/sentry_native.dll ^
    src_native/sentry_crypto.c ^
    src_native/sentry_vector.c ^
    src_native/sentry_lexer.c ^
    src_native/sentry_policy.c ^
    src_native/sentry_core.c
if %errorlevel% neq 0 (
    echo [!] Failed to compile bin/sentry_native.dll
    exit /b %errorlevel%
)
echo [+] Successfully compiled bin/sentry_native.dll

echo [*] Compiling Standalone Native CLI Executable (bin/sentry_cli.exe)...
gcc -O3 -DSENTRY_CLI_APP -o bin/sentry_cli.exe ^
    src_native/sentry_crypto.c ^
    src_native/sentry_vector.c ^
    src_native/sentry_lexer.c ^
    src_native/sentry_policy.c ^
    src_native/sentry_core.c
if %errorlevel% neq 0 (
    echo [!] Failed to compile bin/sentry_cli.exe
    exit /b %errorlevel%
)
echo [+] Successfully compiled bin/sentry_cli.exe

echo.
echo ==============================================================================
echo  SENTRY-GRID Native C11 Engine Build COMPLETE!
echo  Shared Library: bin/sentry_native.dll
echo  CLI Executable: bin/sentry_cli.exe
echo ==============================================================================
