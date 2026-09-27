@echo off
setlocal enabledelayedexpansion

echo =======================================================
echo  SENTRY-GRID - Sovereign Network Compliance Auditor
echo  National Technical Research Organisation (NTRO)
echo  Theme: Blockchain and Cybersecurity (SIH26155)
echo =======================================================

cd /d "%~dp0"

:: 1. Check Python runtime
echo [1/3] Checking Python 3.12 runtime and environment...
py -3.12 -c "import fastapi, uvicorn, jinja2; print('Dependencies ready!')" 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [WARNING] py -3.12 check failed, checking python in PATH...
    python -c "import fastapi, uvicorn, jinja2; print('Dependencies ready!')" 2>nul
    if !ERRORLEVEL! NEQ 0 (
        echo [ERROR] FastAPI/Uvicorn dependencies not found!
        echo Please ensure Python 3.12 and required packages are installed.
        exit /b 1
    )
    set PY_CMD=python
) else (
    set PY_CMD=py -3.12
)

:: 2. Target Port selection (default 8090)
set TARGET_PORT=8090
if not "%~1"=="" (
    if not "%~1"=="--background" (
        set TARGET_PORT=%~1
    )
)

echo [2/3] Checking port %TARGET_PORT%...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":%TARGET_PORT% " ^| findstr "LISTENING"') do (
    echo Port %TARGET_PORT% is currently occupied by PID %%a. Releasing port...
    taskkill /f /pid %%a >nul 2>&1
)

:: Wait 1 second for socket release
powershell -Command "Start-Sleep -Seconds 1" >nul 2>&1

echo Port %TARGET_PORT% is available.
echo %TARGET_PORT% > "%~dp0.run.port"

:: 3. Launch Sentry-Grid service
echo [3/3] Launching Sentry-Grid on port %TARGET_PORT%...
if "%~1"=="--background" (
    start /b "" %PY_CMD% -m uvicorn backend.server:app --host 0.0.0.0 --port %TARGET_PORT% > "%~dp0sentrygrid.log" 2>&1
) else if "%~2"=="--background" (
    start /b "" %PY_CMD% -m uvicorn backend.server:app --host 0.0.0.0 --port %TARGET_PORT% > "%~dp0sentrygrid.log" 2>&1
) else (
    start "Sentry-Grid Defense Engine (%TARGET_PORT%)" %PY_CMD% -m uvicorn backend.server:app --host 0.0.0.0 --port %TARGET_PORT%
)

:: Wait for process startup
powershell -Command "Start-Sleep -Seconds 2" >nul 2>&1

:: Obtain PID and write to .run.pid
set FOUND_PID=
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":%TARGET_PORT% " ^| findstr "LISTENING"') do (
    set FOUND_PID=%%a
    echo %%a > "%~dp0.run.pid"
)

echo.
echo =======================================================
echo  [SUCCESS] Sentry-Grid is running!
echo  Dashboard: http://localhost:%TARGET_PORT%
echo  Open Source Hub: http://localhost:%TARGET_PORT% (Tab 5)
echo  Ledger Explorer: http://localhost:%TARGET_PORT%/ledger
echo  API Documentation: http://localhost:%TARGET_PORT%/docs
if defined FOUND_PID (
    echo  Process PID: %FOUND_PID% (saved to .run.pid)
)
echo  To stop the service anytime, run: stop.bat
echo =======================================================
