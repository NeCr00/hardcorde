#!/bin/bash
# ──────────────────────────────────────────────
#  HARDCORDE Release Builder
# ──────────────────────────────────────────────
#  ./build.sh                 # Native build (host platform)
#  ./build.sh --all           # native + linux-x64 + windows-x64
#  ./build.sh --linux-x64     # Linux x64 binary (Docker required)
#  ./build.sh --windows-x64   # Windows x64 binary (Docker + Wine)
#  ./build.sh --clean         # Wipe ./dist before building
#
#  Cross-compile targets require Docker. Linux x64 builds on
#  python:3.11-slim-bullseye for broad glibc compatibility.
#  Windows x64 builds inside tobix/pywine:3.10.
# ──────────────────────────────────────────────
set -e
cd "$(dirname "$0")"

# Ensure PyInstaller for native builds
if ! python3 -m PyInstaller --version &>/dev/null 2>&1; then
    echo "[*] Installing PyInstaller..."
    pip3 install pyinstaller 2>/dev/null || pip3 install --break-system-packages pyinstaller
fi

python3 build/build.py "$@"
