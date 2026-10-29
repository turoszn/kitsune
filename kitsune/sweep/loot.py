"""Pull the domain facts worth reusing out of the transcripts the sweep already
recorded, and fold them into one loot payload. Nothing here talks to a target.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from kitsune.model import (
    CheckResult,
    as_ad_payload,
    as_protocol_payload,
    as_spn_payload,
    loot_payload,
)

_AES_SUITES = ["aes256-cts-hmac-sha1-96:", "aes128-cts-hmac-sha1-96:"]


def from_checks(checks: List[CheckResult]) -> Dict[str, Any]:
    lines: List[str] = []
    for check in checks:
        if check.plugin != "sweep":
            continue
        ad = as_ad_payload(check.data)
        if ad is not None:
            lines.extend(str(x) for x in ad.get("stdout_lines", []))
            continue
        proto = as_protocol_payload(check.data)
        if proto is not None:
            for f in proto.get("findings", []):
                if isinstance(f, dict):
                    lines.append(str(f.get("detail", "")))
            continue
        spn = as_spn_payload(check.data)
        if spn is not None:
            lines.extend(str(x) for x in spn.get("stdout_lines", []))
    return extract_loot("\n".join(lines))


def extract_loot(text: str) -> Dict[str, Any]:
    domain: Optional[str] = None
    domain_sid: Optional[str] = None
    host_name: Optional[str] = None
    os_str: Optional[str] = None
    smb_signing: Optional[bool] = None
    aes_keys: List[str] = []

    for line in text.splitlines():
        if domain is None:
            domain = _nonempty(_parenthesised(line, "domain:"))
        if host_name is None:
            host_name = _nonempty(_parenthesised(line, "name:"))
        if os_str is None:
            os_str = _nonempty(_os_string(line))
        if smb_signing is None:
            sig = _parenthesised(line, "signing:")
            if sig is not None:
                smb_signing = _parse_bool(sig)
        if domain_sid is None:
            domain_sid = _nonempty(_domain_sid(line))

        if any(s in line for s in _AES_SUITES):
            key = line.strip()
            if key not in aes_keys:
                aes_keys.append(key)

    return loot_payload(
        domain=domain,
        domain_sid=domain_sid,
        host_name=host_name,
        os=os_str,
        smb_signing=smb_signing,
        aes_keys=aes_keys,
    )


def is_empty(loot: Dict[str, Any]) -> bool:
    return not loot


def _nonempty(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    return value if value != "" else None


def _parenthesised(line: str, key: str) -> Optional[str]:
    open_token = f"({key}"
    start = line.find(open_token)
    if start < 0:
        return None
    start += len(open_token)
    rest = line[start:]
    end = rest.find(")")
    if end < 0:
        end = len(rest)
    return rest[:end].strip()


def _os_string(line: str) -> Optional[str]:
    start = line.find("Windows")
    if start < 0:
        return None
    rest = line[start:]
    end = rest.find("(")
    if end < 0:
        end = len(rest)
    os_str = rest[:end].strip()
    return os_str if os_str else None


def _parse_bool(value: str) -> Optional[bool]:
    low = value.lower()
    if low == "true":
        return True
    if low == "false":
        return False
    return None


def _domain_sid(line: str) -> Optional[str]:
    prefix = "S-1-5-21-"
    start = line.find(prefix)
    if start < 0:
        return None
    digits = line[start + len(prefix):]
    groups: List[str] = []
    for part in digits.split("-"):
        run = ""
        for c in part:
            if c.isdigit():
                run += c
            else:
                break
        if run == "":
            break
        groups.append(run)
        if len(groups) == 3:
            break
    if len(groups) == 3:
        return prefix + "-".join(groups)
    return None
