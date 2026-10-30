"""Parsers for NetExec/CrackMapExec transcripts, as pure functions so they can
be unit-tested against recorded fixtures with no live AD."""

from __future__ import annotations

from typing import List, Optional, Tuple

from kitsune.model import SweepFinding
from kitsune.sweep import gpp
from kitsune.util import PADDING_OPTIONAL, looks_base64


# NetExec/CrackMapExec status markers. Only these count as result lines — nxc
# and impacket also print argparse usage/error text ("[-h]", "[--version]",
# "[-t THREADS]") whose bracketed tokens must NOT be mistaken for findings.
_MARKERS = ("[+]", "[-]", "[*]", "[!]")


def parse_nxc(text: str) -> List[SweepFinding]:
    out: List[SweepFinding] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        # Earliest real status marker on the line, if any.
        mpos = -1
        marker = None
        for m in _MARKERS:
            i = line.find(m)
            if i >= 0 and (mpos < 0 or i < mpos):
                mpos, marker = i, m
        if marker is None:
            continue
        detail = line[mpos + len(marker):].strip()

        head = line[:mpos].split()
        if len(head) < 2:
            continue
        protocol = head[0].lower()
        host = head[1]
        credential_works = marker == "[+]"
        reason = failure_reason(detail) if marker == "[-]" else None

        out.append(
            SweepFinding(
                target=host,
                protocol=protocol,
                credential_works=credential_works,
                detail=f"{marker} {detail}",
                evidence=None,
                failure_reason=reason,
            )
        )
    return out


def failure_reason(detail: str) -> Optional[str]:
    for prefix in ("STATUS_", "KRB_AP_ERR_"):
        pos = detail.find(prefix)
        if pos >= 0:
            run = []
            for c in detail[pos:]:
                if c.isalnum() or c == "_":
                    run.append(c)
                else:
                    break
            return "".join(run)
    if "clock skew" in detail.lower():
        return "clock skew"
    return None


def extract_asrep_hashes(text: str) -> List[str]:
    return [line.strip() for line in text.splitlines() if "$krb5asrep$" in line]


def extract_tgs_hashes(text: str) -> List[str]:
    return [line.strip() for line in text.splitlines() if "$krb5tgs$" in line]


def extract_hashdump_lines(text: str) -> List[str]:
    out = []
    for line in text.splitlines():
        if (
            ":aad3b435b51404eeaad3b435b51404ee:" in line
            or ":::" in line
            or "$DCC2$" in line
            or "$DCC1$" in line
        ):
            out.append(line.strip())
    return out


def extract_cpasswords(text: str) -> List[Tuple[str, Optional[str]]]:
    out: List[Tuple[str, Optional[str]]] = []
    for line in text.splitlines():
        if "cpassword" not in line.lower():
            continue
        # `=` is not a separator: base64 padding is part of the value.
        word = ""
        for c in line + " ":
            if c.isspace() or c in "()[]{}'\",:;<>":
                if word:
                    if looks_base64(word, PADDING_OPTIONAL) and len(word) >= 20:
                        out.append((word, gpp.decrypt_cpassword(word)))
                    word = ""
            else:
                word += c
    return out
