"""Backend/binary availability detection, cached in the RunContext's inventory.

The probe table *is* :mod:`kitsune.tools`: the same definitions that name a tool
for argv and for the reported backend answer whether it exists."""

from __future__ import annotations

from typing import Tuple

from kitsune.context import RunContext
from kitsune.shell import CommandError, CommandSpec, run
from kitsune.tools import NATIVE_TOOLS, SWEEP_TOOLS


def probe(program: str, args: Tuple[str, ...]) -> bool:
    """Whether ``program`` exists and can be spawned. Presence is spawn success,
    not exit code: a program that runs and exits non-zero is still present."""
    spec = CommandSpec(program=program, args=list(args), timeout=5.0)
    try:
        run(spec)
        return True
    except CommandError:
        return False


def build_inventory(ctx: RunContext) -> None:
    """Probe every relevant backend once and record which exist in ``ctx``."""
    for tool in list(NATIVE_TOOLS) + list(SWEEP_TOOLS):
        if probe(tool.program, tool.probe_args):
            ctx.backend_inventory.insert(tool.program)
