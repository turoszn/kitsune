"""Probe the domain controller's clock (nmap ``smb2-time``) and measure the skew
from the local one, for the ``--fix-time`` faketime wrap."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional, Tuple

from kitsune import tools
from kitsune.shell import CommandError, CommandSpec, run


@dataclass
class DcClock:
    dc_time_utc: str  # "YYYY-MM-DD HH:MM:SS", UTC
    skew_secs: int    # dc_epoch - local_epoch; positive when the DC is ahead


def probe_dc_time(dc: str, timeout: float) -> Optional[DcClock]:
    spec = CommandSpec(
        program=tools.NMAP.program,
        args=["-Pn", "-sT", "-p", "445", "--script", "smb2-time", dc],
        timeout=timeout,
    )
    try:
        out = run(spec)
    except CommandError:
        return None
    parsed = parse_smb2_time(out.combined())
    if parsed is None:
        return None
    dc_time_utc, dc_epoch = parsed
    return DcClock(dc_time_utc=dc_time_utc, skew_secs=dc_epoch - _local_epoch())


def parse_smb2_time(text: str) -> Optional[Tuple[str, int]]:
    for raw in text.splitlines():
        line = raw.lstrip("|_ ")
        if line.startswith("date:"):
            iso = line[len("date:"):].strip()
            epoch = iso_to_epoch(iso)
            if epoch is None:
                return None
            faketime = iso.replace("T", " ").rstrip("Z").strip()
            return faketime, epoch
    return None


def iso_to_epoch(iso: str) -> Optional[int]:
    if len(iso) < 19 or iso[10] not in ("T", " "):
        return None
    if iso[19:] not in ("", "Z"):
        return None
    date, t = iso[:10], iso[11:19]
    try:
        y, mo, da = (int(x) for x in date.split("-"))
        h, mi, se = (int(x) for x in t.split(":"))
    except ValueError:
        return None
    if not (1 <= mo <= 12) or not (1 <= da <= 31) or h > 23 or mi > 59 or se > 60:
        return None
    if da > _days_in_month(y, mo):
        return None
    return _days_from_civil(y, mo, da) * 86_400 + h * 3_600 + mi * 60 + se


def _days_in_month(y: int, m: int) -> int:
    if m in (1, 3, 5, 7, 8, 10, 12):
        return 31
    if m in (4, 6, 9, 11):
        return 30
    if m == 2:
        return 29 if (y % 4 == 0 and (y % 100 != 0 or y % 400 == 0)) else 28
    return 0


def _days_from_civil(y: int, m: int, d: int) -> int:
    y = y - 1 if m <= 2 else y
    era = (y if y >= 0 else y - 399) // 400
    yoe = y - era * 400
    doy = (153 * (m - 3 if m > 2 else m + 9) + 2) // 5 + d - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146_097 + doe - 719_468


def _local_epoch() -> int:
    return int(time.time())
