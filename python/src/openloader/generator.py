"""
generator.py — Shellcode generation từ C source.
Dùng MinGW cross-compiler để compile C → position-independent shellcode.
"""

import os
import subprocess
import tempfile
from pathlib import Path


DEFAULT_CC = "x86_64-w64-mingw32-gcc"
SHELLCODE_DIR = Path(__file__).resolve().parent.parent.parent.parent / "shellcode"


class ShellcodeGenerator:
    """Generate shellcode from C/C++ source files."""

    def __init__(self, cc: str = DEFAULT_CC):
        self.cc = cc
        self.shellcode_dir = SHELLCODE_DIR
        self.shellcode_dir.mkdir(parents=True, exist_ok=True)

    def compile_to_object(self, source: Path, output: Path) -> bool:
        """Compile source to position-independent object file."""
        cmd = [
            self.cc, "-c", str(source), "-o", str(output),
            "-Os", "-fPIC", "-fPIE",
            "-ffunction-sections", "-fdata-sections",
            "-fno-stack-protector", "-nostdlib",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"[!] Compilation failed:\n{result.stderr}")
            return False
        return True

    def extract_shellcode(self, obj_file: Path, output: Path) -> bool:
        """Extract raw shellcode bytes from .text section."""
        cmd = [
            "objcopy", "-O", "binary",
            "--only-section=.text",
            str(obj_file), str(output),
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"[!] Extraction failed:\n{result.stderr}")
            return False
        return True

    def generate(self, source: Path, name: str = None) -> Path | None:
        """Generate shellcode binary from C source."""
        if not source.exists():
            print(f"[!] Source not found: {source}")
            return None

        name = name or source.stem
        obj_file = self.shellcode_dir / f"{name}.o"
        bin_file = self.shellcode_dir / f"{name}.bin"

        print(f"[*] Compiling: {source}")
        if not self.compile_to_object(source, obj_file):
            return None

        print(f"[*] Extracting shellcode: {bin_file}")
        if not self.extract_shellcode(obj_file, bin_file):
            return None

        size = bin_file.stat().st_size
        print(f"[+] Generated: {bin_file} ({size} bytes)")
        return bin_file
