"""The external tools kitsune wraps, each defined once.

Three things need a tool's name: availability probing (does it exist?),
argument building (run it), and backend attribution in the report. Defining the
name once here means a rename cannot leave the probe and the call site
disagreeing.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple


@dataclass(frozen=True)
class NativeTool:
    """A native Windows tool the ``sysenum`` fallback chains can use."""

    program: str
    probe_args: Tuple[str, ...]


# The native tools, in probe order. The attribute names mirror the Rust enum.
POWERSHELL = NativeTool("powershell", ("-NoProfile", "-Command", "$PSVersionTable.PSVersion.ToString()"))
PWSH = NativeTool("pwsh", ("-NoProfile", "-Command", "$PSVersionTable.PSVersion.ToString()"))
WMIC = NativeTool("wmic", ("/?",))
REG = NativeTool("reg", ("/?",))
SC = NativeTool("sc", ("/?",))
WHOAMI = NativeTool("whoami", ("/?",))
NET = NativeTool("net", ("help",))
NLTEST = NativeTool("nltest", ("/?",))
DSQUERY = NativeTool("dsquery", ("/?",))
SYSTEMINFO = NativeTool("systeminfo", ("/?",))
TASKLIST = NativeTool("tasklist", ("/?",))
SCHTASKS = NativeTool("schtasks", ("/?",))
IPCONFIG = NativeTool("ipconfig", ("/?",))

NATIVE_TOOLS: List[NativeTool] = [
    POWERSHELL,
    PWSH,
    WMIC,
    REG,
    SC,
    WHOAMI,
    NET,
    NLTEST,
    DSQUERY,
    SYSTEMINFO,
    TASKLIST,
    SCHTASKS,
    IPCONFIG,
]


@dataclass(frozen=True)
class SweepTool:
    """A NetExec/Impacket wrapper the ``sweep`` plugin can drive."""

    program: str
    probe_args: Tuple[str, ...]


NXC = SweepTool("nxc", ("--version",))
NETEXEC = SweepTool("netexec", ("--version",))
CRACKMAPEXEC = SweepTool("crackmapexec", ("--version",))
GET_USER_SPNS = SweepTool("impacket-GetUserSPNs", ("-h",))
GET_NP_USERS = SweepTool("impacket-GetNPUsers", ("-h",))
GET_GPP_PASSWORD = SweepTool("impacket-Get-GPPPassword", ("-h",))
SECRETSDUMP = SweepTool("impacket-secretsdump", ("-h",))
ADD_COMPUTER = SweepTool("impacket-addcomputer", ("-h",))
RBCD = SweepTool("impacket-rbcd", ("-h",))
# Impacket spells the program `getST`; the file on PATH is exactly
# `impacket-getST`. A case change here is an `unavailable` check, not a spawn
# error, because the inventory probe uses the same string.
GET_ST = SweepTool("impacket-getST", ("-h",))
COERCER = SweepTool("coercer", ("-h",))
# Not wrappers kitsune drives for a finding: `nmap` probes the DC clock
# (smb2-time) and `faketime` prefixes a wrapper. They ride this list only to
# reuse the one inventory probe.
NMAP = SweepTool("nmap", ("--version",))
FAKETIME = SweepTool("faketime", ("--version",))

# `Nxc`/`Netexec`/`Crackmapexec` come first because `pick_wrapper` takes the
# first one present.
PROTOCOL_DRIVERS: List[SweepTool] = [NXC, NETEXEC, CRACKMAPEXEC]

SWEEP_TOOLS: List[SweepTool] = [
    NXC,
    NETEXEC,
    CRACKMAPEXEC,
    GET_USER_SPNS,
    GET_NP_USERS,
    GET_GPP_PASSWORD,
    SECRETSDUMP,
    ADD_COMPUTER,
    RBCD,
    GET_ST,
    COERCER,
    NMAP,
    FAKETIME,
]


class Protocol:
    """NetExec protocols kitsune drives, each enumeration/validation only."""

    SMB = "smb"
    LDAP = "ldap"
    WINRM = "winrm"
    MSSQL = "mssql"
    WMI = "wmi"

    # Every protocol, in the order the CLI defaults to.
    ALL = ["smb", "ldap", "winrm", "mssql", "wmi"]
