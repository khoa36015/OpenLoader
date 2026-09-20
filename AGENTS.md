# OpenLoader — Agent Instructions

## Project Overview

Modular shellcode loader with C++ core and Python build orchestration. Each bypass/injection module is toggleable via `config.json`.

## Build Commands

### Python Package (Primary)
```bash
cd python
pip install -e .
openloader-build build -config ../config.json -i ../shellcode/helloworld.bin
```

### CMake (Direct)
```bash
mkdir -p build && cd build
cmake .. -DOPENLOADER_BYPASS_STATIC=ON -DOPENLOADER_INJECT_PROCESS=ON
make
```

## Key Files

- `config.json` — Centralized config (enable/disable modules, encryption settings)
- `python/src/openloader/builder.py` — CLI entry point
- `python/src/openloader/compiler.py` — Config → C++ source generation → compile
- `python/src/openloader/encoder.py` — XOR/AES encoding
- `cpp/core/` — Loader engine (static library)
- `cpp/bypass/` — 4 bypass layers (static, etw, amsi, unhook)
- `cpp/inject/` — Injection techniques (process, stomp)
- `shellcode/` — Input shellcode files (auto-find: *.bin, *.shc, *.raw)

## Build Flow

1. `config.json` → Python reads modules + static settings
2. `compiler.py` generates C++ source with XOR keys, dead code, string encryption
3. Compiles with MSVC (`cl.exe`) or GCC (`g++`) based on `build.compiler`
4. Output: `build/<filename>.exe` or `.dll`

## Config Structure

```json
{
  "modules": { "bypass_static": true, "inject_process": true, ... },
  "static": {
    "encryption": { "enabled": true, "algorithm": "xor", "key": "random" },
    "string_encryption": { "enabled": true, "algorithm": "xor" },
    "dead_code": { "enabled": true, "density": "medium", "type": "mixed" }
  },
  "output": { "format": "exe", "filename": "loader" },
  "build": { "compiler": "msvc", "c++_standard": 17 }
}
```

## Module Toggles

Enable/disable via CLI:
```bash
openloader-build enable bypass_etw
openloader-build disable bypass_amsi
```

## Compiler Notes

- MSVC: `/O2 /MT /EHsc` — static CRT, speed optimized
- GCC: `-O2 -static -luser32` — static linking
- Shellcode-specific flags: `-fPIC -fPIE -Os -fno-exceptions -fno-rtti`

## Shellcode Auto-Find

Without `-i` flag, builder auto-searches `shellcode/` for:
`*.bin`, `*.shc`, `*.raw`, `*.dll`, `*.exe`

## Generated C++ Source

Compiler generates `build/loader_generated.cpp` with:
- XOR key array + `xor_decode()` function
- String encryption: `STR_KEY[]` + `decrypt_string()` + `S()` macro
- Dead code injection functions
- Embedded encoded shellcode bytes
- VirtualAlloc + memcpy + execute pattern

## Development Rules

- **After writing each new module**, test it using `shellcode/agent.bin` as input
- Output goes to `output/` folder (create if missing — this is the default output directory)
- Command: `openloader-build build -config config.json -i shellcode/agent.bin -o output/test_module`
