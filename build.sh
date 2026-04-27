#!/bin/bash
# ──────────────────────────────────────────────
#  HARDCORDE Release Builder
# ──────────────────────────────────────────────
#  ./build.sh                 # Native build
#  ./build.sh --all           # All 5 targets
#  ./build.sh --linux         # All Linux (x64, x86, arm64)
#  ./build.sh --windows       # Both Windows (x64, x86)
#  ./build.sh --linux-x64     # Single target
# ──────────────────────────────────────────────
set -e
cd "$(dirname "$0")"

# Ensure PyInstaller for native builds
if ! python3 -m PyInstaller --version &>/dev/null 2>&1; then
    echo "[*] Installing PyInstaller..."
    pip3 install pyinstaller 2>/dev/null || pip3 install --break-system-packages pyinstaller
fi

python3 build/build.py "$@"
