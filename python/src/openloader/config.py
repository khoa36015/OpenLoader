"""
config.py — Load, parse, validate config.json.
Supports -config flag to specify custom config file.
"""

import json
import sys
from pathlib import Path
from typing import Optional


# Default config path
DEFAULT_CONFIG = Path(__file__).resolve().parent.parent.parent.parent / "config.json"


class Config:
    """Centralized config loader with validation."""

    def __init__(self, config_path: Optional[str] = None):
        self.path = Path(config_path) if config_path else DEFAULT_CONFIG
        self._data = {}
        self.load()

    def load(self) -> dict:
        """Load config from JSON file."""
        if not self.path.exists():
            print(f"[!] Config not found: {self.path}")
            print("[*] Using default config")
            self._data = self._default_config()
            return self._data

        with open(self.path, "r") as f:
            self._data = json.load(f)

        self._validate()
        return self._data

    def save(self):
        """Save current config back to file."""
        with open(self.path, "w") as f:
            json.dump(self._data, f, indent=2)

    def get(self, *keys, default=None):
        """Nested dict access: config.get('static', 'encryption', 'algorithm')"""
        obj = self._data
        for key in keys:
            if isinstance(obj, dict) and key in obj:
                obj = obj[key]
            else:
                return default
        return obj

    def set(self, value, *keys):
        """Nested dict set: config.set('xor', 'static', 'encryption', 'algorithm')"""
        obj = self._data
        for key in keys[:-1]:
            if key not in obj:
                obj[key] = {}
            obj = obj[key]
        obj[keys[-1]] = value

    @property
    def modules(self) -> dict:
        return self._data.get("modules", {})

    @property
    def static(self) -> dict:
        return self._data.get("static", {})

    @property
    def output(self) -> dict:
        return self._data.get("output", {})

    def is_module_enabled(self, name: str) -> bool:
        return self.modules.get(name, False)

    def _validate(self):
        """Validate required fields exist."""
        # Ensure sections exist
        for section in ["modules", "static", "output"]:
            if section not in self._data:
                print(f"[!] Missing section in config: {section}")
                self._data[section] = {}

        # Validate static.encryption
        enc = self._data.get("static", {}).get("encryption", {})
        if enc.get("algorithm") not in (None, "xor", "aes"):
            print(f"[!] Invalid encryption algorithm: {enc.get('algorithm')}")
            enc["algorithm"] = "xor"

        # Validate output.format
        fmt = self._data.get("output", {}).get("format", "exe")
        if fmt not in ("exe", "dll"):
            print(f"[!] Invalid output format: {fmt}")
            self._data["output"]["format"] = "exe"

    def _default_config(self) -> dict:
        return {
            "modules": {
                "bypass_static": True,
                "bypass_etw": False,
                "bypass_amsi": False,
                "bypass_unhook": False,
                "inject_process": True,
                "inject_stomp": False,
            },
            "static": {
                "encryption": {
                    "enabled": True,
                    "algorithm": "xor",
                    "key": "random",
                    "payload_section": ".rsrc",
                },
                "string_encryption": {
                    "enabled": True,
                    "algorithm": "xor",
                    "key": "random",
                },
                "dead_code": {
                    "enabled": True,
                    "density": "medium",
                    "type": "mixed",
                },
            },
            "output": {
                "format": "exe",
                "filename": "loader",
            },
            "build": {
                "compiler": "msvc",
                "c++_standard": 17,
                "optimization": "size",
                "strip_symbols": True,
                "position_independent": True,
            },
        }

    def print_summary(self):
        """Print config summary."""
        print(f"\n{'='*50}")
        print(f"  Config: {self.path}")
        print(f"{'='*50}")

        print(f"\n  Modules:")
        for name, enabled in self.modules.items():
            if name.startswith("_"):
                continue
            status = "ON" if enabled else "OFF"
            print(f"    {name}: {status}")

        print(f"\n  Static Bypass:")
        enc = self.static.get("encryption", {})
        print(f"    Encryption:  {'ON' if enc.get('enabled') else 'OFF'} "
              f"(algo={enc.get('algorithm')}, section={enc.get('payload_section')})")

        str_enc = self.static.get("string_encryption", {})
        print(f"    Strings:     {'ON' if str_enc.get('enabled') else 'OFF'} "
              f"(algo={str_enc.get('algorithm')})")

        dead = self.static.get("dead_code", {})
        print(f"    Dead Code:   {'ON' if dead.get('enabled') else 'OFF'} "
              f"(density={dead.get('density')}, type={dead.get('type')})")

        print(f"\n  Output:")
        out = self.output
        print(f"    Format:   {out.get('format', 'exe')}")
        print(f"    Filename: {out.get('filename', 'loader')}")
        print()


def parse_args(args: list[str]) -> dict:
    """Parse CLI args for config/input/output."""
    result = {"config": None, "input": None, "output": None, "format": None}

    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "-config" and i + 1 < len(args):
            result["config"] = args[i + 1]
            i += 2
        elif arg in ("-i", "--input") and i + 1 < len(args):
            result["input"] = args[i + 1]
            i += 2
        elif arg in ("-o", "--output") and i + 1 < len(args):
            result["output"] = args[i + 1]
            i += 2
        elif arg == "--format" and i + 1 < len(args):
            result["format"] = args[i + 1]
            i += 2
        else:
            i += 1

    return result
