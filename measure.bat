@echo off
REM measure.bat -- Windows entry point for ./measure.sh.
REM
REM Native Windows is not supported because the Nix flake assumes a
REM POSIX environment. This script dispatches into WSL2 (Ubuntu by
REM default), where measure.sh runs natively. Install WSL2 once with
REM `wsl --install` from an elevated PowerShell, then re-run.
REM
REM First-time WSL2 setup:
REM   1. Open PowerShell as Administrator.
REM   2. Run:    wsl --install
REM   3. Reboot.
REM   4. Open a new terminal here and run measure.bat.
REM
REM See docs/reproducible-builds.md for the full reproducibility story.

setlocal
cd /d "%~dp0"

where wsl >nul 2>&1
if errorlevel 1 (
    echo.
    echo Windows Subsystem for Linux ^(WSL2^) is required to verify the
    echo firmware on Windows. Install it with:
    echo.
    echo     wsl --install
    echo.
    echo from an elevated PowerShell, then reboot and re-run measure.bat.
    echo.
    exit /b 1
)

wsl --status >nul 2>&1
if errorlevel 1 (
    echo.
    echo WSL is installed but no Linux distribution is configured.
    echo Open PowerShell as Administrator and run:
    echo.
    echo     wsl --install -d Ubuntu
    echo.
    echo Then reboot and re-run measure.bat.
    echo.
    exit /b 1
)

echo Dispatching into WSL...
wsl bash ./measure.sh %*
exit /b %errorlevel%
