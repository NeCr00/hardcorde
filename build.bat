@echo off
REM ──────────────────────────────────────────────
REM  HARDCORDE Release Builder (Windows)
REM ──────────────────────────────────────────────
REM  Usage:
REM    build.bat               Native build for this machine
REM    build.bat --native      Same as above
REM ──────────────────────────────────────────────

cd /d "%~dp0"

where pyinstaller >nul 2>&1
if errorlevel 1 (
    echo [*] Installing PyInstaller...
    pip install pyinstaller
)

python build\build.py --native %*
