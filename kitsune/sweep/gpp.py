"""Group Policy Preferences ``cpassword`` decryption.

GPP stores passwords encrypted with a fixed, public AES-256 key (the one
Microsoft published and later documented). Decrypting a ``cpassword`` value is
deterministic and needs no secrets."""

from __future__ import annotations

import base64
from typing import Optional


def _cipher(iv: bytes):
    # Imported lazily so the rest of the toolkit runs without `cryptography`
    # installed — only `sweep --gpp` needs it.
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    return Cipher(algorithms.AES(GPP_KEY), modes.CBC(iv))


# The well-known 32-byte GPP AES key (public, documented by Microsoft).
GPP_KEY = bytes(
    [
        0x4E, 0x99, 0x06, 0xE8, 0xFC, 0xB6, 0x6C, 0xC9, 0xFA, 0xF4, 0x93, 0x10, 0x62, 0x0F, 0xFE, 0xE8,
        0xF4, 0x96, 0xE8, 0x06, 0xCC, 0x05, 0x79, 0x90, 0x20, 0x9B, 0x09, 0xA4, 0x33, 0xB6, 0x6C, 0x1B,
    ]
)
_IV = b"\x00" * 16


def _b64_decode_padded(cpassword: str) -> Optional[bytes]:
    s = cpassword.strip()
    # GPP base64 is often unpadded; pad to a multiple of 4.
    pad = (-len(s)) % 4
    try:
        return base64.b64decode(s + ("=" * pad))
    except Exception:  # noqa: BLE001
        return None


def decrypt_cpassword(cpassword: str) -> Optional[str]:
    """Decrypt a base64 ``cpassword`` into the plaintext password, or None if it
    does not decrypt."""
    ct = _b64_decode_padded(cpassword)
    if ct is None or len(ct) == 0 or len(ct) % 16 != 0:
        return None
    try:
        dec = _cipher(_IV).decryptor()
        padded = dec.update(ct) + dec.finalize()
        pad_len = padded[-1]
        if pad_len < 1 or pad_len > 16 or pad_len > len(padded):
            return None
        if padded[-pad_len:] != bytes([pad_len]) * pad_len:
            return None
        return padded[:-pad_len].decode("utf-8")
    except Exception:  # noqa: BLE001
        return None


def encrypt_cpassword(plain: bytes) -> str:
    """Encrypt a plaintext into a ``cpassword`` value. Round-trip helper only."""
    pad_len = 16 - (len(plain) % 16)
    padded = plain + bytes([pad_len]) * pad_len
    enc = _cipher(_IV).encryptor()
    ct = enc.update(padded) + enc.finalize()
    return base64.b64encode(ct).decode("ascii")
