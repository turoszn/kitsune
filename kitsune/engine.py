"""Plugin engine: the protocol a plugin implements and the exception-isolating
runner that returns checks sorted by (plugin, check_id)."""

from __future__ import annotations

from typing import List

from kitsune.context import RunContext
from kitsune.model import STATUS_FAILED, CheckResult


class Plugin:
    """A plugin produces zero or more CheckResults for one run. It must never
    raise to signal "backend not available" — that is a status. The runner
    isolates exceptions so one broken plugin cannot kill the run."""

    #: (id, name, description)
    meta = ("", "", "")

    def run(self, ctx: RunContext) -> List[CheckResult]:
        raise NotImplementedError


def run_all(plugins: List[Plugin], ctx: RunContext) -> List[CheckResult]:
    out: List[CheckResult] = []
    for plugin in plugins:
        pid, pname, _ = plugin.meta
        try:
            out.extend(plugin.run(ctx))
        except Exception as e:  # noqa: BLE001 — isolation is the point
            out.append(
                CheckResult(
                    check_id=f"{pid}.panic",
                    plugin=pid,
                    status=STATUS_FAILED,
                    title=f"{pname} panicked",
                    data={},
                    error=f"plugin panicked: {e}",
                )
            )
    out.sort(key=lambda c: (c.plugin, c.check_id))
    return out
