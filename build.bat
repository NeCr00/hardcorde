@echo off
REM ──────────────────────────────────────────────
REM  HARDCORDE Release Builder (Windows)
REM ──────────────────────────────────────────────
REM  Usage:
REM    build.bat                  Native Windows build
REM    build.bat --native         Same as above
REM    build.bat --linux-x64      Cross-compile Linux (Docker required)
REM    build.bat --all            Native + Linux x64
REM    build.bat --clean          Wipe dist\ before building
REM ──────────────────────────────────────────────

cd /d "%~dp0"

where pyinstaller >nul 2>&1
if errorlevel 1 (
    echo [*] Installing PyInstaller...
    pip install pyinstaller
)

if "%~1"=="" (
    python build\build.py --native
) else (
    python build\build.py %*
)
