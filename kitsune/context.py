"""Per-run options, the backend inventory, and the shared run context handed to
every plugin."""

from __future__ import annotations

import sys
import time
from dataclasses import dataclass, field
from typing import List, Optional

from kitsune.tools import Protocol

# The read/scan budget a run gets when nothing overrides the flags.
DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024
DEFAULT_MAX_FILES = 100_000
DEFAULT_TIMEOUT_SECS = 30

# Confidence levels (shared with the CLI's --min-confidence and the report).
CONFIDENCE_LOW = "low"
CONFIDENCE_MEDIUM = "medium"
CONFIDENCE_HIGH = "high"
CONFIDENCE_ORDER = {CONFIDENCE_LOW: 0, CONFIDENCE_MEDIUM: 1, CONFIDENCE_HIGH: 2}


@dataclass
class RunOptions:
    reveal: bool = False
    context_names: List[str] = field(default_factory=list)
    allow: List[str] = field(default_factory=list)
    deny: List[str] = field(default_factory=list)
    max_file_size: int = DEFAULT_MAX_FILE_SIZE
    max_files: int = DEFAULT_MAX_FILES
    timeout_secs: int = DEFAULT_TIMEOUT_SECS
    sweep_username: Optional[str] = None
    sweep_domain: Optional[str] = None
    sweep_dc_ip: Optional[str] = None
    sweep_protocols: List[str] = field(default_factory=lambda: list(Protocol.ALL))
    # On by default; the CLI's --no-progress clears it.
    sweep_progress: bool = True
    sweep_fix_time: bool = False
    sweep_local_auth: bool = False
    sweep_faketime: Optional[str] = None
    sweep_spn: bool = False
    sweep_asreproast: bool = False
    sweep_laps: bool = False
    sweep_gpp: bool = False
    sweep_rbcd: bool = False
    sweep_exec: Optional[str] = None
    sweep_exec_ps: Optional[str] = None
    sweep_sam: bool = False
    sweep_lsa: bool = False
    sweep_ntds: bool = False
    sweep_secretsdump: bool = False
    sweep_kerberoast: bool = False
    sweep_rbcd_attack: bool = False
    sweep_machine: Optional[str] = None
    sweep_machine_pass: Optional[str] = None
    sweep_delegate_to: Optional[str] = None
    sweep_getst_spn: Optional[str] = None
    sweep_impersonate: Optional[str] = None
    sweep_coerce: Optional[str] = None
    min_confidence: str = CONFIDENCE_MEDIUM
    progress: bool = False


class BackendInventory:
    """Cache of which binaries/backends exist on this host, probed once."""

    def __init__(self) -> None:
        self._available: set = set()

    def has(self, name: str) -> bool:
        return name in self._available

    def insert(self, name: str) -> None:
        self._available.add(name)

    def names(self) -> List[str]:
        return sorted(self._available)


def now_ms() -> int:
    return int(time.time() * 1000)


class RunContext:
    """Shared, read-only context handed to every plugin in a run."""

    def __init__(self, target: str) -> None:
        self.target = target
        self.credential = None
        self.options = RunOptions()
        self.backend_inventory = BackendInventory()
        self.started_at_ms = now_ms()

    def is_windows(self) -> bool:
        return sys.platform.startswith("win")
