#!/bin/bash
# OpenLoader - Auto Install Script
set -e

echo "[+] Installing OpenLoader dependencies..."

# Check if pip is available
if ! command -v pip3 &> /dev/null; then
    echo "[!] pip3 not found, installing..."
    sudo apt-get update && sudo apt-get install -y python3-pip
fi

# Install Python dependencies
echo "[+] Installing Python packages..."
pip3 install --break-system-packages -e . 2>/dev/null || pip3 install -e . 2>/dev/null || {
    echo "[!] Trying without -e flag..."
    pip3 install --break-system-packages . 2>/dev/null || pip3 install . 2>/dev/null
}

# Check for cross-compiler
if ! command -v x86_64-w64-mingw32-g++ &> /dev/null; then
    echo "[!] MinGW cross-compiler not found"
    echo "[?] Install? [Y/n]"
    read -r answer
    if [[ "$answer" != "n" && "$answer" != "N" ]]; then
        sudo apt-get install -y mingw-w64
    fi
fi

# Verify installation
python3 -c "from src.generator import main; print('[+] OpenLoader installed successfully')" 2>/dev/null || \
python3 -c "import sys; sys.path.insert(0,'.'); from src.generator import main; print('[+] OpenLoader installed successfully')"

echo "[+] Done! Run: python3 src/generator.py -c malleable_profile.json"
