"""
Cryptographic primitives matching the C++ aegis namespace.

Provides djb2 hashing, XOR encrypt/decrypt, pure-Python AES-128-CBC
(with PKCS7 padding), and string obfuscation helpers for code generation.
"""

from __future__ import annotations

import os
import struct
from typing import Dict, List, Tuple

# ---------------------------------------------------------------------------
# AES S-box (identical to aegis::_sb in aes.hpp)
# ---------------------------------------------------------------------------
_SBOX = bytes([
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16,
])

# Inverse S-box (matching aegis::_rsb)
_RSBOX = bytearray(256)
for _i, _v in enumerate(_SBOX):
    _RSBOX[_v] = _i

# ShiftRows permutation indices (column-major state, matching aegis::sr)
_SR = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11]
# Inverse ShiftRows (matching aegis::isr)
_ISR = [0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3]


# ---------------------------------------------------------------------------
# Galois field helpers
# ---------------------------------------------------------------------------

def _galois_mul(a: int, b: int) -> int:
    """Multiply two bytes in GF(2^8) using the irreducible polynomial
    x^8 + x^4 + x^3 + x + 1 (0x11b).  Matches aegis::_gm."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    """Bytewise XOR of two equal-length byte strings."""
    return bytes(x ^ y for x, y in zip(a, b))


# ---------------------------------------------------------------------------
# AES key expansion  (matches aegis::_ke)
# ---------------------------------------------------------------------------

def aes_key_expansion(key: bytes) -> bytes:
    """Expand a 16-byte AES-128 key into 176 bytes of round-key material.

    Returns 11 round keys (16 bytes each) concatenated — bytes 0-15 are
    round key 0, 16-31 round key 1, … 160-175 round key 10.
    """
    if len(key) != 16:
        raise ValueError("AES-128 requires a 16-byte key")

    # Round constants (x-time of 0x01 repeatedly)
    rcon = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)

    w = bytearray(key)          # first 16 bytes = original key
    r = 0x01                     # initial round constant
    for i in range(4, 44):      # 44 words = 176 bytes
        # last word (4 bytes) before expansion
        t = bytearray(w[(i - 1) * 4: i * 4])

        if i % 4 == 0:
            # RotWord
            o = t[0]
            t[0], t[1], t[2], t[3] = t[1], t[2], t[3], o
            # SubWord + XOR with round constant
            t[0] = _SBOX[t[0]] ^ r
            t[1] = _SBOX[t[1]]
            t[2] = _SBOX[t[2]]
            t[3] = _SBOX[t[3]]
            # Next round constant
            r = _galois_mul(r, 2)

        # XOR with word 4 positions back
        prev = w[(i - 4) * 4: i * 4]
        for j in range(4):
            w.append(prev[j] ^ t[j])

    return bytes(w)


# ---------------------------------------------------------------------------
# AES block operations (column-major state)
# ---------------------------------------------------------------------------

def _sub_bytes(state: bytearray) -> None:
    for i in range(16):
        state[i] = _SBOX[state[i]]


def _inv_sub_bytes(state: bytearray) -> None:
    for i in range(16):
        state[i] = _RSBOX[state[i]]


def _shift_rows(state: bytearray) -> None:
    original = bytes(state)
    for i in range(16):
        state[i] = original[_SR[i]]


def _inv_shift_rows(state: bytearray) -> None:
    original = bytes(state)
    for i in range(16):
        state[i] = original[_ISR[i]]


def _mix_columns(state: bytearray) -> None:
    for c in range(4):
        i = c * 4
        a = [state[i], state[i + 1], state[i + 2], state[i + 3]]
        state[i]     = _galois_mul(a[0], 2) ^ _galois_mul(a[1], 3) ^ a[2] ^ a[3]
        state[i + 1] = a[0] ^ _galois_mul(a[1], 2) ^ _galois_mul(a[2], 3) ^ a[3]
        state[i + 2] = a[0] ^ a[1] ^ _galois_mul(a[2], 2) ^ _galois_mul(a[3], 3)
        state[i + 3] = _galois_mul(a[0], 3) ^ a[1] ^ a[2] ^ _galois_mul(a[3], 2)


def _inv_mix_columns(state: bytearray) -> None:
    for c in range(4):
        i = c * 4
        a = [state[i], state[i + 1], state[i + 2], state[i + 3]]
        state[i]     = _galois_mul(a[0], 14) ^ _galois_mul(a[1], 11) ^ _galois_mul(a[2], 13) ^ _galois_mul(a[3], 9)
        state[i + 1] = _galois_mul(a[0], 9) ^ _galois_mul(a[1], 14) ^ _galois_mul(a[2], 11) ^ _galois_mul(a[3], 13)
        state[i + 2] = _galois_mul(a[0], 13) ^ _galois_mul(a[1], 9) ^ _galois_mul(a[2], 14) ^ _galois_mul(a[3], 11)
        state[i + 3] = _galois_mul(a[0], 11) ^ _galois_mul(a[1], 13) ^ _galois_mul(a[2], 9) ^ _galois_mul(a[3], 14)


def _aes_encrypt_block(block: bytes, w: bytes) -> bytes:
    """Encrypt one 16-byte block with expanded key *w* (176 bytes).

    Matches aegis::_ec.
    """
    state = bytearray(block)

    # AddRoundKey 0
    for i in range(16):
        state[i] ^= w[i]

    for rnd in range(1, 11):
        # SubBytes
        _sub_bytes(state)
        # ShiftRows
        _shift_rows(state)
        # MixColumns (skip on last round)
        if rnd < 10:
            _mix_columns(state)
        # AddRoundKey
        rk = w[rnd * 16: (rnd + 1) * 16]
        for i in range(16):
            state[i] ^= rk[i]

    return bytes(state)


def _aes_decrypt_block(block: bytes, w: bytes) -> bytes:
    """Decrypt one 16-byte block with expanded key *w* (176 bytes).

    Matches aegis::_dc.
    """
    state = bytearray(block)

    # AddRoundKey 10
    for i in range(16):
        state[i] ^= w[160 + i]

    for rnd in range(9, -1, -1):
        # Inverse ShiftRows
        _inv_shift_rows(state)
        # Inverse SubBytes
        _inv_sub_bytes(state)
        # AddRoundKey
        rk = w[rnd * 16: (rnd + 1) * 16]
        for i in range(16):
            state[i] ^= rk[i]
        # Inverse MixColumns (skip round 0)
        if rnd > 0:
            _inv_mix_columns(state)

    return bytes(state)


# ---------------------------------------------------------------------------
# AES-CBC public API
# ---------------------------------------------------------------------------

def aes_cbc_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-128-CBC encrypt *data* with PKCS7 padding.

    Args:
        data: Plaintext of any length.
        key:  16-byte AES key.
        iv:   16-byte initialisation vector.

    Returns:
        Ciphertext (length will be a multiple of 16).
    """
    w = aes_key_expansion(key)

    # PKCS7 padding
    pad_len = 16 - (len(data) % 16)
    padded = data + bytes([pad_len] * pad_len)

    result = bytearray()
    prev = iv
    for i in range(0, len(padded), 16):
        block = _xor_bytes(padded[i:i + 16], prev)
        enc = _aes_encrypt_block(block, w)
        result.extend(enc)
        prev = enc
    return bytes(result)


def aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-128-CBC decrypt *ciphertext* with PKCS7 unpadding.

    Args:
        ciphertext: Data to decrypt (must be multiple of 16 bytes).
        key:  16-byte AES key.
        iv:   16-byte initialisation vector.

    Returns:
        Original plaintext.
    """
    if len(ciphertext) % 16 != 0:
        raise ValueError("Ciphertext length must be a multiple of 16")

    w = aes_key_expansion(key)

    result = bytearray()
    prev = iv
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i + 16]
        dec = _aes_decrypt_block(block, w)
        result.extend(_xor_bytes(dec, prev))
        prev = block

    # Strip PKCS7 padding
    pad_len = result[-1]
    if 1 <= pad_len <= 16:
        return bytes(result[:-pad_len])
    return bytes(result)


# ---------------------------------------------------------------------------
# XOR operations
# ---------------------------------------------------------------------------

def xor_encrypt(data: bytes, key: bytes) -> bytes:
    """Encrypt *data* by XOR-ing with *key* (repeated cyclically)."""
    out = bytearray(len(data))
    klen = len(key) if key else 1
    for i, b in enumerate(data):
        out[i] = b ^ key[i % klen]
    return bytes(out)


def xor_decrypt(data: bytes, key: bytes) -> bytes:
    """Decrypt *data* by XOR-ing with *key* (identical to encrypt)."""
    return xor_encrypt(data, key)


# ---------------------------------------------------------------------------
# djb2 hash  (matches C++ `_hash()` in syscalls.hpp)
# ---------------------------------------------------------------------------

def djb2_hash(s: str) -> int:
    """Compute the djb2 hash of a string.

    ``h = 5381; while ((c = *s++)) h = ((h << 5) + h) + c``

    Returns a 32-bit unsigned integer.
    """
    h = 5381
    for c in s:
        h = ((h << 5) + h) + ord(c)
    return h & 0xFFFFFFFF


# ---------------------------------------------------------------------------
# Random key generation
# ---------------------------------------------------------------------------

def random_key(length: int = 16) -> bytes:
    """Generate *length* cryptographically random bytes."""
    return os.urandom(length)


# ---------------------------------------------------------------------------
# String obfuscation helpers (for C++ code generation)
# ---------------------------------------------------------------------------

def xor_obfuscate_string(s: str, key_byte: int) -> str:
    """Return a C array initialiser ``{0x.., 0x.., ...}`` where each
    character of *s* is XOR-ed with *key_byte*.
    """
    encoded = [f"0x{ord(c) ^ key_byte:02x}" for c in s]
    # Include the terminator pattern: key_byte signals end
    encoded.append(f"0x{0 ^ key_byte:02x}")
    return "{" + ", ".join(encoded) + "}"


def prehash_strings(strings: Dict[str, str], key_byte: int = 0x9A) -> Dict[str, Tuple[int, str]]:
    """Pre-compute djb2 hashes and XOR-obfuscated byte arrays for a
    dictionary of *name* → *string* pairs.

    Returns:
        A dict mapping each name to a ``(hash_value, xor_bytes_string)``
        tuple.  The XOR string uses *key_byte*.
    """
    result: Dict[str, Tuple[int, str]] = {}
    for name, value in strings.items():
        h = djb2_hash(value)
        xor_str = xor_obfuscate_string(value, key_byte)
        result[name] = (h, xor_str)
    return result
