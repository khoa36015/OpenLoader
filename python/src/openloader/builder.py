"""
builder.py — Main CLI entry point.
openloader-build -config <file>.json -i <shellcode> -o <output> --format <exe|dll>

Flow: load config → parse → generate C++ → compile
"""

import sys
import argparse
from pathlib import Path

from .config import Config, parse_args
from .compiler import compile_from_config, find_shellcode, BUILD_DIR
from .encoder import get_encoder, encode_shellcode_file


def cmd_build(args):
    """Build loader từ config."""
    config = Config(args.config)

    # Override output options from CLI
    if args.format:
        config.set(args.format, "output", "format")
    if args.output:
        config.set(args.output, "output", "filename")

    config.print_summary()
    return compile_from_config(
        config,
        input_path=args.input,
        output_path=args.output,
        output_format=args.format,
    )


def cmd_config(args):
    """Hiển thị hoặc sửa config."""
    config = Config(args.config)
    config.print_summary()
    return 0


def cmd_enable(args):
    """Enable một module."""
    config = Config(args.config)
    config.set(True, "modules", args.module)
    config.save()
    print(f"[+] Enabled: {args.module}")
    return 0


def cmd_disable(args):
    """Disable một module."""
    config = Config(args.config)
    config.set(False, "modules", args.module)
    config.save()
    print(f"[-] Disabled: {args.module}")
    return 0


def cmd_encode(args):
    """Encode shellcode file."""
    config = Config(args.config)

    enc_cfg = config.static.get("encryption", {})
    algo = args.algorithm or enc_cfg.get("algorithm", "xor")
    key = args.key or enc_cfg.get("key", "random")

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"[!] File not found: {input_path}")
        return 1

    output_path = Path(args.output) if args.output else input_path.with_suffix(".encoded.bin")
    encode_shellcode_file(input_path, output_path, algo, key)
    return 0


def cmd_list(args):
    """List shellcode files trong shellcode/ folder."""
    from .compiler import SHELLCODE_DIR

    if not SHELLCODE_DIR.exists():
        print(f"[*] Shellcode directory not found: {SHELLCODE_DIR}")
        return 0

    files = list(SHELLCODE_DIR.glob("*"))
    if not files:
        print(f"[*] No files in {SHELLCODE_DIR}")
    else:
        print(f"\nShellcode files in {SHELLCODE_DIR}:\n")
        for f in sorted(files):
            size = f.stat().st_size
            print(f"  {f.name:<30} {size:>10} bytes")
    print()
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="OpenLoader — Shellcode Loader Builder",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  openloader-build build -config config.json -i payload.bin
  openloader-build build -config config.json -o myloader.exe --format exe
  openloader-build encode -i payload.bin -o encoded.bin --algorithm xor
  openloader-build enable bypass_etw
  openloader-build disable bypass_amsi
  openloader-build list
  openloader-build config
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Command")

    # build
    p_build = subparsers.add_parser("build", help="Build loader")
    p_build.add_argument("-config", help="Config JSON file")
    p_build.add_argument("-i", "--input", help="Shellcode input file")
    p_build.add_argument("-o", "--output", help="Output filename")
    p_build.add_argument("--format", choices=["exe", "dll"], help="Output format")

    # config
    p_config = subparsers.add_parser("config", help="Show config")
    p_config.add_argument("-config", help="Config JSON file")

    # enable
    p_enable = subparsers.add_parser("enable", help="Enable module")
    p_enable.add_argument("module", help="Module name")
    p_enable.add_argument("-config", help="Config JSON file")

    # disable
    p_disable = subparsers.add_parser("disable", help="Disable module")
    p_disable.add_argument("module", help="Module name")
    p_disable.add_argument("-config", help="Config JSON file")

    # encode
    p_encode = subparsers.add_parser("encode", help="Encode shellcode file")
    p_encode.add_argument("-i", "--input", required=True, help="Input file")
    p_encode.add_argument("-o", "--output", help="Output file")
    p_encode.add_argument("--algorithm", choices=["xor", "aes"], help="Algorithm")
    p_encode.add_argument("--key", help="Encryption key (hex or string)")
    p_encode.add_argument("-config", help="Config JSON file")

    # list
    subparsers.add_parser("list", help="List shellcode files")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    commands = {
        "build": cmd_build,
        "config": cmd_config,
        "enable": cmd_enable,
        "disable": cmd_disable,
        "encode": cmd_encode,
        "list": cmd_list,
    }

    return commands[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
