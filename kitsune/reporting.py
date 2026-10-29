"""Report renderers and the offline comparison: deterministic JSON, a Markdown
view of the same data, and ``diff`` over two saved reports."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from kitsune.model import (
    STATUS_FAILED,
    STATUS_SKIPPED,
    STATUS_SUCCESS,
    STATUS_UNAVAILABLE,
    Report,
)

# --------------------------------------------------------------------------
# JSON
# --------------------------------------------------------------------------


def to_json(report: Report) -> str:
    """Serialize to pretty JSON with sorted keys (deterministic, like serde's
    default BTreeMap). Arrays are sorted by the runner and the plugins."""
    return json.dumps(report.to_dict(), indent=2, sort_keys=True, ensure_ascii=False)


# --------------------------------------------------------------------------
# Markdown
# --------------------------------------------------------------------------

_STATUS_ICON = {
    STATUS_SUCCESS: "\u2714",      # heavy check mark
    STATUS_FAILED: "\u2718",       # heavy ballot x
    STATUS_UNAVAILABLE: "\u2205",  # empty set
    STATUS_SKIPPED: "\u2192",      # right arrow
}


def _backtick_run(s: str) -> int:
    longest = run = 0
    for c in s:
        run = run + 1 if c == "`" else 0
        longest = max(longest, run)
    return longest


def _code_span(s: str) -> str:
    fence = "`" * (_backtick_run(s) + 1)
    pad = " " if (s.startswith("`") or s.endswith("`")) else ""
    return f"{fence}{pad}{s}{pad}{fence}"


def _cell(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def _loot_table(data: Any) -> Optional[str]:
    if not isinstance(data, dict):
        return None
    rows: List = []
    if data.get("domain") is not None:
        rows.append(("domain", str(data["domain"])))
    if data.get("domain_sid") is not None:
        rows.append(("domain SID", str(data["domain_sid"])))
    if data.get("host_name") is not None:
        rows.append(("Host name", str(data["host_name"])))
    if data.get("os") is not None:
        rows.append(("OS", str(data["os"])))
    if data.get("smb_signing") is not None:
        rows.append(("SMB signing", "true" if data["smb_signing"] else "false"))

    out = "| fact | value |\n|---|---|\n"
    for fact, value in rows:
        out += f"| {_cell(fact)} | {_code_span(_cell(value))} |\n"
    out += "\n"

    aes_keys = data.get("aes_keys") or []
    if aes_keys:
        out += "| AES key |\n|---|\n"
        for key in aes_keys:
            out += f"| {_code_span(_cell(str(key)))} |\n"
        out += "\n"
    return out


def to_markdown(report: Report) -> str:
    from kitsune import TOOL_NAME

    out = f"# {TOOL_NAME} report\n\n"
    out += f"- **target**: `{report.target}`\n"
    out += f"- **tool**: {report.tool} {report.version}\n"
    out += f"- **checks**: {len(report.checks)}\n\n"

    for check in report.checks:
        icon = _STATUS_ICON.get(check.status, "?")
        out += f"## {icon} {check.title}\n\n"
        out += f"- `{check.check_id}`\n"
        out += f"- status: **{check.status}**\n"
        if check.backend is not None:
            out += f"- backend: `{check.backend}`\n"
        if check.error is not None:
            out += f"- error: {check.error}\n"
        if check.source is not None:
            out += f"- source: `{check.source}`\n"
        out += "\n"

        if check.check_id == "sweep.loot":
            table = _loot_table(check.data)
            if table is not None:
                out += table
        elif check.data is not None:
            rendered = json.dumps(check.data, indent=2, sort_keys=True, ensure_ascii=False)
            fence = "`" * (max(_backtick_run(rendered), 2) + 1)
            out += f"{fence}json\n{rendered}\n{fence}\n\n"

        if check.findings:
            out += "| file | line | key | value | score | confidence |\n|---|---|---|---|---|---|\n"
            for f in check.findings:
                fd = f if isinstance(f, dict) else f.to_dict()
                value = fd.get("value") if fd.get("value") is not None else fd.get("masked", "")
                out += "| {} | {} | {} | {} | {:.2f} | {} |\n".format(
                    _cell(str(fd.get("file", ""))),
                    fd.get("line") or 0,
                    _cell(str(fd.get("key") or "")),
                    _code_span(_cell(str(value))),
                    float(fd.get("score", 0.0)),
                    fd.get("confidence", ""),
                )
            out += "\n"

        if check.suggestions:
            out += "### suggestions\n\n"
            for s in check.suggestions:
                sd = s if isinstance(s, dict) else s.to_dict()
                out += f"- **{sd.get('title', '')}** — `{sd.get('kind', '')}`\n"
                out += f"  {sd.get('description', '')}\n"
                for c in sd.get("commands", []):
                    out += f"  - {_code_span(str(c))}\n"
            out += "\n"
    return out


# --------------------------------------------------------------------------
# diff
# --------------------------------------------------------------------------


def _by_id(report: Report) -> Dict[str, Any]:
    """Checks by id, last occurrence winning."""
    out: Dict[str, Any] = {}
    for check in report.checks:
        out[check.check_id] = check
    return out


def _diff_value(before: Any, after: Any) -> Optional[Any]:
    if before == after:
        return None
    if isinstance(before, dict) and isinstance(after, dict):
        changed: Dict[str, Any] = {}
        for key, after_value in after.items():
            if key in before:
                delta = _diff_value(before[key], after_value)
                if delta is not None:
                    changed[key] = delta
            else:
                changed[key] = {"before": None, "after": after_value}
        for key, before_value in before.items():
            if key not in after:
                changed[key] = {"before": before_value, "after": None}
        return changed
    return {"before": before, "after": after}


def diff(before: Report, after: Report) -> Dict[str, Any]:
    before_checks = _by_id(before)
    after_checks = _by_id(after)

    added = sorted(k for k in after_checks if k not in before_checks)
    removed = sorted(k for k in before_checks if k not in after_checks)

    changed: Dict[str, Any] = {}
    for cid in sorted(after_checks):
        if cid not in before_checks:
            continue
        delta = _diff_value(before_checks[cid].data, after_checks[cid].data)
        if delta is not None:
            changed[cid] = delta

    return {"added_checks": added, "removed_checks": removed, "changed": changed}
