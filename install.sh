#!/bin/bash

# OpenLoader Installer

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PYTHON_DIR="$SCRIPT_DIR/python"
VENV_DIR="$SCRIPT_DIR/venv"

echo "[*] Installing OpenLoader..."

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "[!] Python3 not found"
    exit 1
fi

# Create venv if not exists
if [ ! -d "$VENV_DIR" ]; then
    echo "[*] Creating virtual environment..."
    python3 -m venv "$VENV_DIR"
fi

# Activate venv
source "$VENV_DIR/bin/activate"

# Install package
cd "$PYTHON_DIR"
pip install -e .

# Create output directory
mkdir -p "$SCRIPT_DIR/output"

# Create agent.bin placeholder if missing
if [ ! -f "$SCRIPT_DIR/shellcode/agent.bin" ]; then
    echo -ne '\xcc' > "$SCRIPT_DIR/shellcode/agent.bin"
    echo "[*] Created shellcode/agent.bin placeholder"
fi

echo "[+] Installed. Run:"
echo "    source venv/bin/activate"
echo "    openloader-build --help"
