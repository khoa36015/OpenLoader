# OpenLoader — Modular Shellcode Loader Framework

A modular shellcode loader with C++ core and Python build orchestration.

Every component is toggleable via `config.json`.

## Quick Start

```bash
# 1. Install Python package
cd python
pip install -e .

# 2. Build loader with default config
openloader-build build -config ../config.json

# 3. Build with custom shellcode input
openloader-build build -config ../config.json -i ../shellcode/payload.bin

# 4. Build as DLL
openloader-build build -config ../config.json --format dll -o myloader
```

## Installation

```bash
cd python
pip install -e .
```

After install, `openloader-build` command is available globally.

## Commands

### `build` — Build loader

```bash
openloader-build build [options]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-config` | Config JSON file | `config.json` |
| `-i`, `--input` | Shellcode input file | Auto-find in `shellcode/` |
| `-o`, `--output` | Output filename | `loader` |
| `--format` | Output format (`exe` or `dll`) | `exe` |

**Examples:**
```bash
# Basic build
openloader-build build -config config.json

# With specific shellcode
openloader-build build -config config.json -i shellcode/payload.bin

# Custom output name and format
openloader-build build -config config.json -o myloader --format dll

# Output auto-adds extension (loader.exe, myloader.dll)
```

### `encode` — Encode shellcode file

```bash
openloader-build encode -i input.bin -o encoded.bin --algorithm xor
```

| Flag | Description | Default |
|------|-------------|---------|
| `-i`, `--input` | Input shellcode file | Required |
| `-o`, `--output` | Output file | `<input>.encoded.bin` |
| `--algorithm` | `xor` or `aes` | From config |
| `--key` | Encryption key (hex or string) | From config |

**Examples:**
```bash
# XOR encode with random key
openloader-build encode -i payload.bin -o encoded.bin

# XOR encode with specific key
openloader-build encode -i payload.bin -o encoded.bin --key 0x5A5B5C5D

# AES encode
openloader-build encode -i payload.bin -o encoded.bin --algorithm aes
```

### `enable` / `disable` — Toggle modules

```bash
openloader-build enable bypass_etw
openloader-build disable bypass_amsi
```

**Available modules:**
- `bypass_static` — Static AV/EDR evasion
- `bypass_etw` — ETW telemetry blinding
- `bypass_amsi` — AMSI scan bypass
- `bypass_unhook` — NTDLL unhooking + syscalls
- `inject_process` — Process injection
- `inject_stomp` — Module stomping

### `config` — Show current config

```bash
openloader-build config
```

### `list` — List shellcode files

```bash
openloader-build list
```

Shows all files in `shellcode/` folder with sizes.

## Configuration

Edit `config.json` to customize behavior:

```json
{
  "modules": {
    "bypass_static": true,
    "bypass_etw": false,
    "bypass_amsi": false,
    "bypass_unhook": false,
    "inject_process": true,
    "inject_stomp": false
  },
  "static": {
    "encryption": {
      "enabled": true,
      "algorithm": "xor",
      "key": "random",
      "payload_section": ".rsrc"
    },
    "string_encryption": {
      "enabled": true,
      "algorithm": "xor",
      "key": "random"
    },
    "dead_code": {
      "enabled": true,
      "density": "medium",
      "type": "mixed"
    }
  },
  "output": {
    "format": "exe",
    "filename": "loader"
  },
  "build": {
    "compiler": "msvc",
    "c++_standard": 17
  }
}
```

### Module Options

**Encryption:**
- `algorithm`: `xor` (fast) or `aes` (stronger)
- `key`: `random` (auto-generate) or hex string like `0x5A5B5C5D`
- `payload_section`: `.rsrc`, `.data`, or `.text`

**String Encryption:**
- `algorithm`: `xor` or `aes`
- `key`: `random` or hex string

**Dead Code:**
- `density`: `low` (5 junk lines), `medium` (20), `high` (50)
- `type`: `nop` (NOP only), `junk` (random instructions), `mixed` (both)

## Shellcode Input

Place shellcode files in `shellcode/` folder. Supported formats:
- `*.bin` — Raw binary
- `*.shc` — Shellcode
- `*.raw` — Raw payload
- `*.dll`, `*.exe` — PE files

Builder auto-finds first matching file if `-i` not specified.

## Output

Default output folder: `output/`

Build generates `build/loader_generated.cpp` with:
- XOR key array + decode function
- String encryption macros
- Dead code injection functions
- Embedded encoded shellcode
- VirtualAlloc + memcpy + execute pattern

## Structure

```
OpenLoader/
├── config.json              ← Centralized config
├── CMakeLists.txt
├── cpp/
│   ├── core/                ← Loader engine
│   ├── bypass/              ← 4 bypass layers
│   ├── inject/              ← Injection techniques
│   └── stubs/               ← ASM shellcode stubs
├── python/
│   └── src/openloader/
│       ├── builder.py       ← CLI entry point
│       ├── compiler.py      ← Config → C++ → compile
│       ├── encoder.py       ← XOR/AES encoding
│       └── generator.py     ← Shellcode generation
├── shellcode/               ← Input shellcode files
└── output/                  ← Generated loader output
```
