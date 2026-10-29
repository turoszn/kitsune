"""``kitsune plan``: turn the sweep flags into a note sheet of the exact commands
they would run — without running anything. Only renders the argv the builders
produce, through :meth:`CommandSpec.command_line`, rendered unredacted (the
credential you typed is echoed back so the line is copy-pasteable)."""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from kitsune import TOOL_NAME, tools
from kitsune.context import RunContext
from kitsune.shell import CommandSpec
from kitsune.sweep.sweep import _non_empty, _with_faketime, faketime_manual_args
from kitsune.sweep.wrapper import (
    IMPERSONATED_ACCOUNT,
    SweepRequest,
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
)

_UNUSED_TIMEOUT = 30.0


@dataclass
class PlanStep:
    id: str
    title: str
    command: Optional[str]
    reason: Optional[str]
    note: str

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"id": self.id, "title": self.title, "note": self.note}
        if self.command is not None:
            d["command"] = self.command
        if self.reason is not None:
            d["reason"] = self.reason
        return d


def plan(ctx: RunContext) -> List[PlanStep]:
    steps: List[PlanStep] = []
    if ctx.credential is None or ctx.options.sweep_username is None:
        return steps

    faketime = None
    if ctx.options.sweep_faketime is not None:
        faketime = faketime_manual_args(ctx.options.sweep_faketime)

    for target in (t.strip() for t in ctx.target.split(",")):
        if not target:
            continue
        req = SweepRequest(
            target=target,
            dc_ip=ctx.options.sweep_dc_ip,
            domain=ctx.options.sweep_domain,
            username=ctx.options.sweep_username,
            credential=ctx.credential,
            local_auth=ctx.options.sweep_local_auth,
            faketime=faketime,
        )
        _steps_for_target(ctx, req, steps)
    return steps


def _push(steps, req, cid, title, spec: Optional[CommandSpec], note) -> None:
    if spec is not None:
        command = _with_faketime(spec, req.faketime).command_line()
        reason = None
    else:
        command = None
        reason = "needs a password credential (a hash or ticket cannot build this)"
    steps.append(PlanStep(cid, title, command, reason, note))


def _steps_for_target(ctx: RunContext, req: SweepRequest, steps: List[PlanStep]) -> None:
    o = ctx.options
    for protocol in o.sweep_protocols:
        _push(
            steps, req, f"sweep.{protocol}", f"{protocol.upper()} credential validation",
            build_command(protocol, req, tools.NXC, _UNUSED_TIMEOUT),
            "credential valid? `(Pwn3d!)` on SMB = local admin; note shares/users/computers",
        )

    if o.sweep_spn:
        _push(steps, req, "sweep.spn", "Service principal names",
              build_getuserspns(req, _UNUSED_TIMEOUT), "accounts with an SPN — the Kerberoast targets")
    if o.sweep_asreproast:
        _push(steps, req, "sweep.asreproast", "ASREPRoast",
              build_asreproast(tools.NXC, req, _UNUSED_TIMEOUT), "`$krb5asrep$` hashes → crack with `hashcat -m 18200`")
    if o.sweep_laps:
        _push(steps, req, "sweep.laps", "LAPS passwords",
              build_laps(tools.NXC, req, _UNUSED_TIMEOUT), "cleartext local-admin passwords the account can read")
    if o.sweep_gpp:
        _push(steps, req, "sweep.gpp", "GPP cpassword",
              build_getgpp(req, _UNUSED_TIMEOUT), "decrypted `cpassword` values from SYSVOL")
    if o.sweep_rbcd:
        _push(steps, req, "sweep.rbcd", "RBCD enumeration",
              build_rbcd(tools.NXC, req, _UNUSED_TIMEOUT), "accounts with `msDS-AllowedToActOnBehalfOfOtherIdentity` set")

    for family, ps, cmd in [
        ("sweep.exec", False, o.sweep_exec),
        ("sweep.exec_ps", True, o.sweep_exec_ps),
    ]:
        if cmd is not None:
            for protocol in (p for p in o.sweep_protocols if p != tools.Protocol.LDAP):
                _push(
                    steps, req, f"{family}.{protocol}", f"{protocol.upper()} command execution",
                    build_exec(protocol, req, tools.NXC, cmd, ps, _UNUSED_TIMEOUT),
                    "output of your command on the target",
                )

    for flag, cid, title, dumpflag in [
        (o.sweep_sam, "sweep.sam", "SAM database dump", "--sam"),
        (o.sweep_lsa, "sweep.lsa", "LSA secrets dump", "--lsa"),
        (o.sweep_ntds, "sweep.ntds", "NTDS.dit dump", "--ntds"),
    ]:
        if flag:
            _push(steps, req, cid, title, build_dump(tools.NXC, req, _UNUSED_TIMEOUT, dumpflag),
                  "hash lines (needs local admin on the target)")
    if o.sweep_secretsdump:
        _push(steps, req, "sweep.secretsdump", "SAM/LSA/NTDS dump (secretsdump)",
              build_secretsdump(req, _UNUSED_TIMEOUT), "NT hashes and `$DCC2$` cached creds (needs local admin on the target)")
    if o.sweep_kerberoast:
        _push(steps, req, "sweep.kerberoast", "Kerberoast (TGS request)",
              build_kerberoast(req, _UNUSED_TIMEOUT), "`$krb5tgs$` hashes → crack with `hashcat -m 13100`")

    if o.sweep_rbcd_attack:
        _rbcd_chain_steps(ctx, req, steps)

    if o.sweep_coerce is not None:
        _push(steps, req, "sweep.coerce", "Authentication coercion",
              build_coerce(req, o.sweep_coerce, _UNUSED_TIMEOUT),
              "provokes NTLM auth to the listener — the relay runs separately. CHECK EXAM RULES: coercion + relay is spoofing-adjacent and often prohibited.")


def _rbcd_chain_steps(ctx: RunContext, req: SweepRequest, steps: List[PlanStep]) -> None:
    machine = _non_empty(ctx.options.sweep_machine)
    machine_pass = _non_empty(ctx.options.sweep_machine_pass)
    delegate_to = _non_empty(ctx.options.sweep_delegate_to)
    if machine is None or machine_pass is None or delegate_to is None:
        steps.append(PlanStep(
            "sweep.rbcd_attack",
            "RBCD attack",
            None,
            "requires --machine, --machine-pass and --delegate-to",
            "the RBCD chain (addcomputer → rbcd write → getST) needs the machine account, its password and the victim computer",
        ))
        return
    spn = ctx.options.sweep_getst_spn or default_getst_spn(delegate_to)
    impersonate = ctx.options.sweep_impersonate or IMPERSONATED_ACCOUNT
    ccache = os.path.join(tempfile.gettempdir(), f"kitsune-{machine}.ccache")

    _push(steps, req, "sweep.rbcd.addcomputer", "Create the machine account (addcomputer)",
          build_addcomputer(req, machine, machine_pass, _UNUSED_TIMEOUT), "confirms the machine account was created")
    _push(steps, req, "sweep.rbcd.write", "Write the RBCD delegation (rbcd)",
          build_rbcd_write(req, machine, delegate_to, _UNUSED_TIMEOUT), "confirms the delegation was written")
    _push(steps, req, "sweep.rbcd.getst", "Request the impersonated ticket (getST)",
          build_getst(req, machine, machine_pass, spn, impersonate, ccache, _UNUSED_TIMEOUT),
          "writes the ticket; import it with `export KRB5CCNAME=<ccache>`")


def _fence_for(s: str) -> str:
    longest = 0
    run = 0
    for c in s:
        run = run + 1 if c == "`" else 0
        longest = max(longest, run)
    return "`" * (max(longest, 2) + 1)


def to_markdown(target: str, steps: List[PlanStep]) -> str:
    out = f"# {TOOL_NAME} plan\n\n"
    out += f"- **target**: `{target}`\n"
    out += "- Run each command yourself; paste its output in the block beneath it.\n"
    out += "- Commands include the credential in the clear — this is your note sheet.\n\n"
    for step in steps:
        out += f"## {step.title}\n\n"
        out += f"- `{step.id}`\n"
        out += f"- {step.note}\n\n"
        if step.command is not None:
            fence = _fence_for(step.command)
            out += f"{fence}sh\n{step.command}\n{fence}\n\n"
            out += "```text\n\n```\n\n"
        elif step.reason is not None:
            out += f"_skipped: {step.reason}_\n\n"
    return out
