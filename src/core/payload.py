"""
Payload processing module.

Handles reading raw .bin shellcode files, encrypting payload data with XOR,
generating C++ array declarations, and deriving encrypt/decrypt keys.
"""

from __future__ import annotations

import os

from .crypto import random_key, xor_encrypt


def process_payload(filepath: str) -> bytes:
    """Read and return the raw bytes from a ``.bin`` shellcode file.

    Args:
        filepath: Absolute or relative path to the binary payload.

    Returns:
        Raw shellcode bytes.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the file is empty.
    """
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"Payload file not found: {filepath}")

    with open(filepath, "rb") as f:
        data = f.read()

    if not data:
        raise ValueError(f"Payload file is empty: {filepath}")

    return data


def encrypt_payload(data: bytes, xor_key: bytes) -> bytes:
    """Encrypt (XOR) payload *data* with the given *xor_key*.

    The key is repeated cyclically if shorter than the data.

    Args:
        data: Raw payload bytes.
        xor_key: XOR key bytes.

    Returns:
        XOR-encrypted payload bytes.
    """
    return xor_encrypt(data, xor_key)


def generate_payload_declaration(data: bytes, line_width: int = 32) -> str:
    """Generate a C++ array initialisation string for *data*.

    Produces output of the form::

        unsigned char enc_payload[] = {
            0xXX, 0xXX, ...,
            0xXX, 0xXX, ...
        };
        const int PAYLOAD_LEN = <N>;

    Args:
        data: The (encrypted) payload bytes.
        line_width: Maximum number of bytes per source line.

    Returns:
        A complete C++ declaration block.
    """
    hex_lines: list[str] = []
    for i in range(0, len(data), line_width):
        chunk = data[i:i + line_width]
        hex_lines.append("    " + ", ".join(f"0x{b:02x}" for b in chunk))

    return (
        f"unsigned char enc_payload[] = {{\n"
        f"{',\n'.join(hex_lines)}\n"
        f"}};\n"
        f"const int PAYLOAD_LEN = {len(data)};"
    )


def calculate_xor_key(data: bytes) -> bytes:
    """Generate a random 16-byte XOR key.

    The key is cryptographically random, independent of *data* (the
    argument is accepted for API consistency with future key-derivation
    schemes).

    Args:
        data: Payload bytes (ignored in this implementation).

    Returns:
        16 cryptographically random bytes.
    """
    return random_key(16)
