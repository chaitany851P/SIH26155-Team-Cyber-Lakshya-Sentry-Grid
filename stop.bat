@echo off
setlocal enabledelayedexpansion

echo =======================================================
echo  Stopping Sentry-Grid Compliance Engine...
echo =======================================================

cd /d "%~dp0"

:: 1. Read recorded port and terminate
if exist "%~dp0.run.port" (
    set /p RUN_PORT=<"%~dp0.run.port"
    set RUN_PORT=!RUN_PORT: =!
    if defined RUN_PORT (
        echo Terminating process listening on port !RUN_PORT!...
        for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":!RUN_PORT! " ^| findstr "LISTENING"') do (
            echo Killing PID %%a...
            taskkill /f /pid %%a >nul 2>&1
        )
    )
    del "%~dp0.run.port" >nul 2>&1
)

:: 2. Also ensure default port 8090 is cleared
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8090 " ^| findstr "LISTENING"') do (
    echo Killing lingering process on port 8090 [PID %%a]...
    taskkill /f /pid %%a >nul 2>&1
)

:: 3. Terminate recorded PID if still active
if exist "%~dp0.run.pid" (
    set /p RUN_PID=<"%~dp0.run.pid"
    set RUN_PID=!RUN_PID: =!
    if defined RUN_PID (
        echo Terminating PID !RUN_PID!...
        taskkill /f /pid !RUN_PID! >nul 2>&1
    )
    del "%~dp0.run.pid" >nul 2>&1
)

echo.
echo =======================================================
echo  [SUCCESS] Sentry-Grid has been completely stopped.
echo  Ports and system resources released.
echo =======================================================
