"""Small utilities shared by plugins: masking, base64 shape tests, the
secret-key dictionary, text/line helpers and a capped file reader."""

from __future__ import annotations

import os
from typing import List, Optional

# --------------------------------------------------------------------------
# masking
# --------------------------------------------------------------------------

# The length below which a secret is masked in full. Head and tail disclose
# four characters between them; a mask must not disclose more than half the
# value.
SHAPE_MIN_LEN = 8


def mask(value: str) -> str:
    """Mask a secret: first two + last two characters with the middle replaced
    by ``***``. Anything shorter than SHAPE_MIN_LEN becomes asterisks of the
    same length."""
    chars = list(value)
    n = len(chars)
    if n == 0:
        return ""
    if n < SHAPE_MIN_LEN:
        return "*" * n
    return f"{chars[0]}{chars[1]}***{chars[n - 2]}{chars[n - 1]}"


def _is_word_char(c: str) -> bool:
    return c.isalnum() or c == "_"


def _replace_token(text: str, needle: str, replacement: str) -> str:
    """str.replace restricted to occurrences that stand on their own (not glued
    to a word character)."""
    out: List[str] = []
    rest = text
    while True:
        pos = rest.find(needle)
        if pos < 0:
            break
        before = rest[:pos]
        after = rest[pos + len(needle):]
        out.append(before)
        before_char = before[-1] if before else None
        after_char = after[0] if after else None
        standalone = (before_char is None or not _is_word_char(before_char)) and (
            after_char is None or not _is_word_char(after_char)
        )
        out.append(replacement if standalone else needle)
        rest = after
    out.append(rest)
    return "".join(out)


def redact(text: str, secret: Optional[str]) -> str:
    """``text`` with every standalone occurrence of ``secret`` replaced by its
    mask. An empty/None secret is the identity."""
    if not secret:
        return text
    return _replace_token(text, secret, mask(secret))


def redact_argv(argv: List[str], secret: Optional[str]) -> List[str]:
    return [redact(a, secret) for a in argv]


def mask_url_userinfo(text: str) -> str:
    """Mask the ``user:password@`` part of every URL in ``text``."""
    out: List[str] = []
    rest = text
    while True:
        scheme_end = rest.find("://")
        if scheme_end < 0:
            break
        authority_start = scheme_end + len("://")
        out.append(rest[:authority_start])
        tail = rest[authority_start:]
        authority_end = len(tail)
        for i, c in enumerate(tail):
            if c.isspace() or c in "/\"'<>,;":
                authority_end = i
                break
        authority = tail[:authority_end]
        at = authority.rfind("@")
        if at >= 0:
            userinfo = authority[:at]
            colon = userinfo.find(":")
            if colon >= 0:
                out.append(userinfo[:colon])
                out.append(":")
                out.append(mask(userinfo[colon + 1:]))
            else:
                out.append(userinfo)
            out.append(authority[at:])
        else:
            out.append(authority)
        rest = tail[authority_end:]
    out.append(rest)
    return "".join(out)


def _is_account(s: str) -> bool:
    return (
        len(s) > 0
        and any(c.isascii() and c.isalnum() for c in s)
        and all((c.isascii() and c.isalnum()) or c in "\\/.-_$" for c in s)
    )


def _is_credential_secret(s: str) -> bool:
    return len(s) > 0 and not s.startswith(("/", "\\")) and ":" not in s


def mask_credential_tokens(text: str) -> str:
    """Mask the secret half of every ``account:secret`` credential pair the
    wrappers print, by shape (for the offline --parse-file path, which has no
    supplied credential to redact against)."""
    out: List[str] = []
    rest = text
    while True:
        colon = rest.find(":")
        if colon < 0:
            break
        before = rest[:colon]
        after = rest[colon:]
        ws = max((i for i, c in enumerate(before) if c.isspace()), default=-1)
        start = ws + 1
        account = before[start:]
        tail = after[1:]
        end = len(tail)
        for i, c in enumerate(tail):
            if c.isspace():
                end = i
                break
        secret = tail[:end]
        if _is_account(account) and _is_credential_secret(secret):
            out.append(before[:start])
            out.append(account)
            out.append(":")
            out.append(mask(secret))
        else:
            out.append(before)
            out.append(":")
            out.append(secret)
        rest = tail[end:]
    out.append(rest)
    return "".join(out)


# --------------------------------------------------------------------------
# base64 shape
# --------------------------------------------------------------------------

PADDING_REQUIRED = "required"
PADDING_OPTIONAL = "optional"
_B64_MIN_LEN = 16


def looks_base64(s: str, padding: str) -> bool:
    """Whether ``s`` looks like base64 under the given dialect (a shape test,
    not a decoder)."""
    trimmed = s.rstrip("=")
    has_padding = len(trimmed) < len(s)
    if padding == PADDING_REQUIRED:
        if len(s) < _B64_MIN_LEN or len(s) % 4 != 0 or not has_padding:
            return False
    else:  # optional
        if len(trimmed) == 0 or len(trimmed) % 4 == 1:
            return False
    return all(c.isascii() and (c.isalnum() or c in "+/") for c in trimmed)


# --------------------------------------------------------------------------
# secret-key dictionary
# --------------------------------------------------------------------------

SECRET_KEYS = [
    "password",
    "passwd",
    "passphrase",
    "pass",
    "pwd",
    "secret",
    "credential",
    "creds",
    "apikey",
    "token",
    "auth",
    "privatekey",
    "connectionstring",
    "connection",
    "key",
]


def looks_secret(name: str) -> bool:
    """Whether a name — env var, config key, JSON field — reads as a secret
    holder."""
    return matches_key_word(name, SECRET_KEYS)


def matches_key_word(text: str, keys: List[str]) -> bool:
    """Whether ``text`` contains one of ``keys`` as a whole word. Words are cut
    at every non-alphanumeric character and at lower->upper transitions."""
    keyset = set(keys)
    word = ""
    prev_lower = False
    for c in list(text) + [" "]:
        if not c.isalnum():
            if word in keyset:
                return True
            word = ""
            prev_lower = False
            continue
        if c.isascii() and c.isupper() and prev_lower and word:
            if word in keyset:
                return True
            word = ""
        prev_lower = c.isascii() and c.islower()
        word += c.lower()
    return False


# --------------------------------------------------------------------------
# text / fs
# --------------------------------------------------------------------------


def lines(s: str) -> List[str]:
    """Split console output into lines, dropping a trailing CR."""
    return [line.rstrip("\r") for line in s.splitlines()]


def read_text_capped(path: str, cap: int) -> str:
    """Read a file as lossy UTF-8, bounded to ``cap + 1`` bytes."""
    with open(path, "rb") as f:
        buf = f.read(cap + 1)
    return buf.decode("utf-8", errors="replace")


def is_binary(text: str) -> bool:
    """A NUL byte means the file is binary, not text."""
    return "\0" in text
