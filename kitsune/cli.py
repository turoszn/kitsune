"""CLI: the flags each subcommand parses, and the dispatch that turns them into
plugins, runs them and writes the report.

``emit`` is the single exit point of every report-producing subcommand: it owns
the format, the output file, the 0600 permissions and the --no-timestamps
policy. Every failure is a CliError -> exit code 2 with a message on stderr.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import List, Optional

from kitsune import TOOL_NAME, __version__
from kitsune import availability, reporting
from kitsune.context import DEFAULT_TIMEOUT_SECS, RunContext, RunOptions
from kitsune.engine import run_all
from kitsune.model import SCHEMA_VERSION, CheckResult, Credential, Report
from kitsune.suggester import Suggester
from kitsune.sweep import Sweep, parse_transcript
from kitsune.sweep import plan as plan_mod
from kitsune.sysenum import SysEnum
from kitsune.tools import Protocol

EXIT_FAILURE = 2
DEFAULT_SWEEP_TIMEOUT_SECS = 60


class CliError(Exception):
    pass


# --------------------------------------------------------------------------
# argument wiring
# --------------------------------------------------------------------------


def _add_output_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--format", choices=["json", "md"], default="json")
    p.add_argument("--out")
    p.add_argument("--no-timestamps", action="store_true")


def _add_sweep_flags(p: argparse.ArgumentParser) -> None:
    p.add_argument("-d", "--domain")
    p.add_argument("-u", "--username")
    p.add_argument("--dc-ip", dest="dc_ip")
    p.add_argument("--no-progress", dest="no_progress", action="store_true")
    p.add_argument("--fix-time", dest="fix_time", action="store_true")
    p.add_argument("--local-auth", dest="local_auth", action="store_true")
    p.add_argument("--faketime")
    cred = p.add_mutually_exclusive_group()
    cred.add_argument("-p", "--password")
    cred.add_argument("--ntlm")
    cred.add_argument("--aes")
    cred.add_argument("--ticket")
    p.add_argument("--protocol", dest="protocol", default="smb,ldap,winrm,mssql,wmi")
    p.add_argument("--spn", action="store_true")
    p.add_argument("--asreproast", action="store_true")
    p.add_argument("--laps", action="store_true")
    p.add_argument("--gpp", action="store_true")
    p.add_argument("--rbcd", action="store_true")
    p.add_argument("--exec")
    p.add_argument("--exec-ps", dest="exec_ps")
    p.add_argument("--sam", action="store_true")
    p.add_argument("--lsa", action="store_true")
    p.add_argument("--ntds", action="store_true")
    p.add_argument("--secretsdump", action="store_true")
    p.add_argument("--kerberoast", action="store_true")
    p.add_argument("--rbcd-attack", dest="rbcd_attack", action="store_true")
    p.add_argument("--machine")
    p.add_argument("--machine-pass", dest="machine_pass")
    p.add_argument("--delegate-to", dest="delegate_to")
    p.add_argument("--getst-spn", dest="getst_spn")
    p.add_argument("--impersonate")
    p.add_argument("--coerce")


def _parse_protocols(raw: str) -> List[str]:
    protocols = [p.strip() for p in raw.split(",") if p.strip()]
    for p in protocols:
        if p not in Protocol.ALL:
            raise CliError(f"invalid --protocol value {p!r}: expected one of {', '.join(Protocol.ALL)}")
    return protocols


def _credential_from(args) -> Credential:
    if args.password is not None:
        return Credential.password(args.password)
    if args.ntlm is not None:
        return Credential.ntlm(args.ntlm)
    if args.aes is not None:
        return Credential.aes(args.aes)
    if args.ticket is not None:
        return Credential.ticket(args.ticket)
    raise CliError("no credential provided; pass --password, --ntlm, --aes or --ticket")


def _apply_sweep_flags(args, options: RunOptions) -> None:
    options.sweep_username = args.username
    options.sweep_domain = args.domain
    options.sweep_dc_ip = args.dc_ip
    options.sweep_progress = not args.no_progress
    options.sweep_fix_time = args.fix_time
    options.sweep_local_auth = args.local_auth
    options.sweep_faketime = args.faketime
    options.sweep_protocols = _parse_protocols(args.protocol)
    options.sweep_spn = args.spn
    options.sweep_asreproast = args.asreproast
    options.sweep_laps = args.laps
    options.sweep_gpp = args.gpp
    options.sweep_rbcd = args.rbcd
    options.sweep_exec = args.exec
    options.sweep_exec_ps = args.exec_ps
    options.sweep_sam = args.sam
    options.sweep_lsa = args.lsa
    options.sweep_ntds = args.ntds
    options.sweep_secretsdump = args.secretsdump
    options.sweep_kerberoast = args.kerberoast
    options.sweep_rbcd_attack = args.rbcd_attack
    options.sweep_machine = args.machine
    options.sweep_machine_pass = args.machine_pass
    options.sweep_delegate_to = args.delegate_to
    options.sweep_getst_spn = args.getst_spn
    options.sweep_impersonate = args.impersonate
    options.sweep_coerce = args.coerce


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Windows/AD enumeration toolkit for authorized labs, CTF and pentest exams",
    )
    parser.add_argument("--version", action="version", version=f"{TOOL_NAME} {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_sys = sub.add_parser("sysenum", help="Local Windows system enumeration (self-healing backends)")
    p_sys.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_SECS)
    p_sys.add_argument("--suggest", action="store_true", help="append passive next-step suggestions")
    _add_output_args(p_sys)

    p_sweep = sub.add_parser("sweep", help="Credential/AD sweep via NetExec/Impacket wrappers")
    p_sweep.add_argument("--target", required=True)
    p_sweep.add_argument("--parse-file", dest="parse_file")
    p_sweep.add_argument("--timeout", type=int, default=DEFAULT_SWEEP_TIMEOUT_SECS)
    p_sweep.add_argument("--suggest", action="store_true", help="append passive next-step suggestions")
    _add_sweep_flags(p_sweep)
    _add_output_args(p_sweep)

    p_plan = sub.add_parser("plan", help="Print the sweep's commands as a run-by-hand note sheet (runs nothing)")
    p_plan.add_argument("--target", required=True)
    _add_sweep_flags(p_plan)
    _add_output_args(p_plan)

    p_sugg = sub.add_parser("suggester", help="Passive suggestions from a saved JSON report")
    p_sugg.add_argument("--report", required=True, help="a saved JSON report to analyze")
    _add_output_args(p_sugg)

    p_run = sub.add_parser("run", help="Run sweep + suggester in one report")
    p_run.add_argument("--target")
    p_run.add_argument("--timeout", type=int, default=DEFAULT_SWEEP_TIMEOUT_SECS)
    _add_sweep_flags(p_run)
    _add_output_args(p_run)

    p_diff = sub.add_parser("diff", help="Compare two saved JSON reports")
    p_diff.add_argument("--before", required=True)
    p_diff.add_argument("--after", required=True)
    _add_output_args(p_diff)

    return parser


# --------------------------------------------------------------------------
# dispatch
# --------------------------------------------------------------------------


def _build_report(ctx: RunContext, start: float, checks: List[CheckResult]) -> Report:
    return Report(
        tool=TOOL_NAME,
        version=__version__,
        schema_version=SCHEMA_VERSION,
        started_at_ms=ctx.started_at_ms,
        duration_ms=int((time.monotonic() - start) * 1000),
        target=ctx.target,
        checks=checks,
    )


def _emit(report: Report, args) -> None:
    if args.no_timestamps:
        report.zero_timestamps()
    if args.format == "json":
        text = reporting.to_json(report)
    else:
        text = reporting.to_markdown(report)
    _write_or_print(args.out, text)


def _write_or_print(out: Optional[str], text: str) -> None:
    if out is None:
        sys.stdout.write(text)
        return
    _write_report(out, text)


def _write_report(path: str, text: str) -> None:
    flags = os.O_CREAT | os.O_TRUNC | os.O_WRONLY
    try:
        if os.name == "posix":
            fd = os.open(path, flags, 0o600)
        else:
            fd = os.open(path, flags)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
    except OSError as e:
        raise CliError(f"write {path}: {e}") from e


def _read_text(path: str) -> str:
    try:
        # utf-8-sig so a report written by the PowerShell secret-hunter (which
        # emits a UTF-8 BOM on Windows PowerShell) still parses cleanly.
        with open(path, "r", encoding="utf-8-sig") as f:
            return f.read()
    except OSError as e:
        raise CliError(f"read {path}: {e}") from e


def _read_report(path: str) -> Report:
    text = _read_text(path)
    try:
        return Report.from_dict(json.loads(text))
    except (ValueError, TypeError) as e:
        raise CliError(f"saved report is not valid JSON: {e}") from e


def _append_suggestions(checks: List[CheckResult], ctx: RunContext, suggest: bool) -> None:
    if suggest:
        checks.extend(run_all([Suggester(list(checks))], ctx))


def _local_hostname() -> str:
    return os.environ.get("HOSTNAME") or os.environ.get("COMPUTERNAME") or "localhost"


def _run_sysenum(args) -> None:
    start = time.monotonic()
    ctx = RunContext(_local_hostname())
    ctx.options.timeout_secs = args.timeout
    availability.build_inventory(ctx)
    checks = run_all([SysEnum()], ctx)
    _append_suggestions(checks, ctx, args.suggest)
    _emit(_build_report(ctx, start, checks), args)


def _run_sweep(args) -> None:
    start = time.monotonic()
    if args.parse_file is not None:
        text = _read_text(args.parse_file)
        findings = parse_transcript(text)
        ctx = RunContext(args.target)
        checks = [
            CheckResult.success(
                "sweep.parse",
                "sweep",
                "Parsed NetExec transcript",
                {"source_file": args.parse_file, "findings": [f.to_dict() for f in findings]},
            )
        ]
        _emit(_build_report(ctx, start, checks), args)
        return

    credential = _credential_from(args)
    if args.username is None:
        raise CliError("no username provided (--username)")
    ctx = RunContext(args.target)
    ctx.credential = credential
    _apply_sweep_flags(args, ctx.options)
    ctx.options.timeout_secs = args.timeout
    availability.build_inventory(ctx)
    checks = run_all([Sweep()], ctx)
    _append_suggestions(checks, ctx, args.suggest)
    _emit(_build_report(ctx, start, checks), args)


def _run_plan(args) -> None:
    credential = _credential_from(args)
    if args.username is None:
        raise CliError("no username provided (--username)")
    ctx = RunContext(args.target)
    ctx.credential = credential
    _apply_sweep_flags(args, ctx.options)
    steps = plan_mod.plan(ctx)
    if args.format == "md":
        text = plan_mod.to_markdown(args.target, steps)
    else:
        text = json.dumps(
            {"target": args.target, "steps": [s.to_dict() for s in steps]},
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
    _write_or_print(args.out, text)


def _run_suggester(args) -> None:
    start = time.monotonic()
    text = _read_text(args.report)
    try:
        sugg = Suggester.from_report_json(text)
    except (ValueError, TypeError) as e:
        raise CliError(f"saved report is not valid JSON: {e}") from e
    ctx = RunContext("(report)")
    checks = run_all([sugg], ctx)
    _emit(_build_report(ctx, start, checks), args)


def _run_diff(args) -> None:
    start = time.monotonic()
    before = _read_report(args.before)
    after = _read_report(args.after)
    checks = [CheckResult.success("diff.summary", "diff", "Report diff", reporting.diff(before, after))]
    ctx = RunContext("(diff)")
    _emit(_build_report(ctx, start, checks), args)


def _run_run(args) -> None:
    start = time.monotonic()
    combined_target = args.target or "(run)"
    report_ctx = RunContext(combined_target)
    checks: List[CheckResult] = []

    if args.target is not None and args.username is not None:
        wctx = RunContext(args.target)
        wctx.credential = _credential_from(args)
        _apply_sweep_flags(args, wctx.options)
        wctx.options.timeout_secs = args.timeout
        availability.build_inventory(wctx)
        checks.extend(run_all([Sweep()], wctx))

    gctx = RunContext("(run)")
    checks.extend(run_all([Suggester(list(checks))], gctx))

    _emit(_build_report(report_ctx, start, checks), args)


_DISPATCH = {
    "sysenum": _run_sysenum,
    "sweep": _run_sweep,
    "plan": _run_plan,
    "suggester": _run_suggester,
    "diff": _run_diff,
    "run": _run_run,
}


def run(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        _DISPATCH[args.command](args)
        return 0
    except CliError as e:
        print(f"{TOOL_NAME}: {e}", file=sys.stderr)
        return EXIT_FAILURE
