"""Self-healing Windows enumeration plugin.

Every module is an ordered chain of backend steps (PowerShell -> CIM/WMI ->
registry -> native); the runner picks the first backend that is available and
returns data, and reports which backend answered. On a non-Windows attacker box
local enumeration is skipped — the target is remote and reached via ``sweep``.
"""

from __future__ import annotations

import os
from typing import Any, Callable, List, Optional, Tuple

from kitsune import tools
from kitsune.context import RunContext
from kitsune.engine import Plugin
from kitsune.model import CheckResult
from kitsune.shell import CommandError, CommandSpec, run
from kitsune.util import lines, looks_secret, mask, mask_url_userinfo

# Backend kinds.
B_POWERSHELL = "powershell"
B_WMI = "wmi"
B_REGISTRY = "registry"
B_LDAP = "ldap"
B_NATIVE = "native"
B_ALWAYS = "always"


class CollectError(Exception):
    pass


# A step is (backend_kind, native_tool_or_None, collect(ctx) -> value).
Step = Tuple[str, Optional[tools.NativeTool], Callable[[RunContext], Any]]


def backend_available(kind: str, native_tool: Optional[tools.NativeTool], ctx: RunContext) -> bool:
    inv = ctx.backend_inventory
    if kind == B_POWERSHELL:
        return inv.has(tools.POWERSHELL.program) or inv.has(tools.PWSH.program)
    if kind == B_WMI:
        return inv.has(tools.WMIC.program)
    if kind == B_REGISTRY:
        return inv.has(tools.REG.program)
    if kind == B_LDAP:
        return inv.has(tools.NLTEST.program) or inv.has(tools.DSQUERY.program)
    if kind == B_NATIVE:
        return native_tool is not None and inv.has(native_tool.program)
    if kind == B_ALWAYS:
        return True
    return False


def backend_name(kind: str, native_tool: Optional[tools.NativeTool]) -> str:
    if kind == B_NATIVE and native_tool is not None:
        return f"native:{native_tool.program}"
    if kind == B_ALWAYS:
        return "native"
    return kind


def run_chain(ctx: RunContext, steps: List[Step]) -> Tuple[str, Any]:
    last: Optional[Exception] = None
    for kind, native_tool, collect in steps:
        if backend_available(kind, native_tool, ctx):
            try:
                value = collect(ctx)
                return backend_name(kind, native_tool), value
            except Exception as e:  # noqa: BLE001
                last = e
    if last is not None:
        raise last
    raise CollectError("no backend available")


def run_cmd(ctx: RunContext, tool: tools.NativeTool, args: List[str]) -> Any:
    spec = CommandSpec(program=tool.program, args=list(args), timeout=float(ctx.options.timeout_secs))
    out = run(spec)
    return {
        "argv": out.argv,
        "exit_code": out.exit_code(),
        "timed_out": out.timed_out(),
        "stdout_lines": lines(out.stdout),
        "stderr_lines": lines(out.stderr),
    }


def run_cmd_json(ctx: RunContext, tool: tools.NativeTool, args: List[str]) -> Any:
    import json

    spec = CommandSpec(program=tool.program, args=list(args), timeout=float(ctx.options.timeout_secs))
    out = run(spec)
    if not out.stdout.strip():
        return {"stdout_lines": lines(out.stdout)}
    try:
        return json.loads(out.stdout.strip())
    except Exception:  # noqa: BLE001
        return {"stdout_lines": lines(out.stdout)}


def powershell(ctx: RunContext, script: str) -> Any:
    tool = tools.POWERSHELL if ctx.backend_inventory.has(tools.POWERSHELL.program) else tools.PWSH
    return run_cmd_json(ctx, tool, ["-NoProfile", "-Command", script])


_ENV_KEYS = [
    "APPDATA",
    "LOCALAPPDATA",
    "USERPROFILE",
    "USERDOMAIN",
    "COMPUTERNAME",
    "PROGRAMDATA",
    "HOME",
    "ProgramFiles",
    "SystemRoot",
]
_ENV_SPELLINGS = [("%", "%"), ("$", ""), ("${", "}")]


def _expand_env(s: str) -> str:
    result = s
    for key in _ENV_KEYS:
        value = os.environ.get(key)
        if value is None:
            continue
        for prefix, suffix in _ENV_SPELLINGS:
            result = result.replace(f"{prefix}{key}{suffix}", value)
    if result.startswith("~/"):
        home = os.environ.get("HOME")
        if home is not None:
            result = f"{home}/{result[2:]}"
    return result


def fs_check(entries: List[Tuple[str, str]]) -> Any:
    out = []
    for label, raw in sorted(entries):
        expanded = _expand_env(raw)
        out.append({"name": label, "path": expanded, "exists": os.path.exists(expanded)})
    return out


# An env-var name whose *value* is a credential even though its name says
# nothing: a Kerberos credential cache is a path to live tickets.
_EXTRA_SECRET_NAMES = ["KRB5CCNAME", "KRB5_CLIENT_KTNAME"]


def _environment_payload(vars_list: List[Tuple[str, str]]) -> Any:
    out = []
    for name, value in sorted(vars_list):
        value = mask_url_userinfo(value)
        secret = looks_secret(name) or any(name.lower() == e.lower() for e in _EXTRA_SECRET_NAMES)
        out.append({"name": name, "value": mask(value) if secret else value})
    return out


def _ps(script: str) -> Callable[[RunContext], Any]:
    return lambda ctx: powershell(ctx, script)


def _cmd(tool: tools.NativeTool, *args: str) -> Callable[[RunContext], Any]:
    return lambda ctx: run_cmd(ctx, tool, list(args))


def _environment_collect(_ctx: RunContext) -> Any:
    return _environment_payload(list(os.environ.items()))


def modules() -> List[dict]:
    return [
        {
            "check_id": "sysenum.system_info",
            "title": "System information",
            "steps": [
                (B_POWERSHELL, None, _ps("Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,OSArchitecture,LastBootUpTime | ConvertTo-Json")),
                (B_WMI, None, _cmd(tools.WMIC, "os", "get", "Caption,Version,OSArchitecture", "/format:csv")),
                (B_NATIVE, tools.SYSTEMINFO, _cmd(tools.SYSTEMINFO)),
            ],
        },
        {
            "check_id": "sysenum.users_groups",
            "title": "Local and domain users/groups",
            "steps": [
                (B_POWERSHELL, None, _ps("Get-LocalUser | Select-Object Name,Enabled,SID | ConvertTo-Json")),
                (B_WMI, None, _cmd(tools.WMIC, "useraccount", "get", "Name,Disabled,SID", "/format:csv")),
                (B_NATIVE, tools.NET, _cmd(tools.NET, "user")),
            ],
        },
        {
            "check_id": "sysenum.privileges",
            "title": "Token privileges",
            "steps": [
                (B_NATIVE, tools.WHOAMI, _cmd(tools.WHOAMI, "/priv")),
                (B_POWERSHELL, None, _ps("whoami /priv | Out-String")),
            ],
        },
        {
            "check_id": "sysenum.environment",
            "title": "Environment variables",
            "steps": [
                (B_ALWAYS, None, _environment_collect),
                (B_POWERSHELL, None, _ps("Get-ChildItem Env: | Select-Object Name,Value | ConvertTo-Json")),
            ],
        },
        {
            "check_id": "sysenum.network",
            "title": "Network configuration",
            "steps": [
                (B_POWERSHELL, None, _ps("Get-NetIPConfiguration | Select-Object InterfaceAlias,IPv4Address,IPv4DefaultGateway,DNSServer | ConvertTo-Json")),
                (B_NATIVE, tools.IPCONFIG, _cmd(tools.IPCONFIG, "/all")),
            ],
        },
        {
            "check_id": "sysenum.processes",
            "title": "Running processes",
            "steps": [
                (B_POWERSHELL, None, _ps("Get-Process | Select-Object Name,Id,Path | ConvertTo-Json")),
                (B_NATIVE, tools.TASKLIST, _cmd(tools.TASKLIST, "/FO", "CSV")),
            ],
        },
        {
            "check_id": "sysenum.services",
            "title": "Services",
            "steps": [
                (B_POWERSHELL, None, _ps("Get-CimInstance Win32_Service | Select-Object Name,State,PathName,StartName | ConvertTo-Json")),
                (B_WMI, None, _cmd(tools.WMIC, "service", "get", "Name,PathName,StartName", "/format:csv")),
                (B_NATIVE, tools.SC, _cmd(tools.SC, "query")),
            ],
        },
        {
            "check_id": "sysenum.installed_software",
            "title": "Installed software",
            "steps": [
                (B_REGISTRY, None, _cmd(tools.REG, "query", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", "/s")),
                (B_WMI, None, _cmd(tools.WMIC, "product", "get", "Name,Version", "/format:csv")),
                (B_POWERSHELL, None, _ps("Get-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName,DisplayVersion | ConvertTo-Json")),
            ],
        },
        {
            "check_id": "sysenum.scheduled_tasks",
            "title": "Scheduled tasks",
            "steps": [
                (B_POWERSHELL, None, _ps("Get-ScheduledTask | Select-Object TaskName,State | ConvertTo-Json")),
                (B_NATIVE, tools.SCHTASKS, _cmd(tools.SCHTASKS, "/query", "/fo", "csv")),
            ],
        },
        {
            "check_id": "sysenum.shares",
            "title": "Network shares",
            "steps": [
                (B_POWERSHELL, None, _ps("Get-SmbShare | Select-Object Name,Path,Description | ConvertTo-Json")),
                (B_NATIVE, tools.NET, _cmd(tools.NET, "share")),
            ],
        },
        {
            "check_id": "sysenum.registry",
            "title": "Interesting registry paths",
            "steps": [
                (B_NATIVE, tools.REG, _cmd(tools.REG, "query", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run")),
            ],
        },
        {
            "check_id": "sysenum.always_install_elevated",
            "title": "AlwaysInstallElevated registry value",
            "steps": [
                (B_NATIVE, tools.REG, _cmd(tools.REG, "query", "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer", "/v", "AlwaysInstallElevated")),
                (B_POWERSHELL, None, _ps("Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue | Select-Object AlwaysInstallElevated | ConvertTo-Json")),
            ],
        },
        {
            "check_id": "sysenum.ad_context",
            "title": "Active Directory context (domain-joined)",
            "steps": [
                (B_LDAP, None, _cmd(tools.NLTEST, "/dsgetdc:")),
                (B_POWERSHELL, None, _ps("try { [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain() | ConvertTo-Json } catch { 'not-domain-joined' }")),
            ],
        },
        {
            "check_id": "sysenum.config_locations",
            "title": "Common config locations",
            "steps": [
                (B_ALWAYS, None, lambda _ctx: fs_check([
                    ("userprofile", "%USERPROFILE%"),
                    ("appdata", "%APPDATA%"),
                    ("localappdata", "%LOCALAPPDATA%"),
                    ("programdata", "%PROGRAMDATA%"),
                    ("ssh-config", "%USERPROFILE%\\.ssh\\config"),
                    ("ssh-known-hosts", "%USERPROFILE%\\.ssh\\known_hosts"),
                    ("aws-credentials", "%USERPROFILE%\\.aws\\credentials"),
                    ("git-credentials", "%USERPROFILE%\\.git-credentials"),
                ])),
            ],
        },
        {
            "check_id": "sysenum.powershell_history",
            "title": "PowerShell history artefacts",
            "steps": [
                (B_ALWAYS, None, lambda _ctx: fs_check([
                    ("psreadline-history", "%APPDATA%\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt"),
                    ("powershell-profile", "%USERPROFILE%\\Documents\\WindowsPowerShell\\Microsoft.PowerShell_profile.ps1"),
                ])),
            ],
        },
        {
            "check_id": "sysenum.client_configs",
            "title": "RDP/SSH/client config artefacts",
            "steps": [
                (B_ALWAYS, None, lambda _ctx: fs_check([
                    ("default-rdp", "%USERPROFILE%\\Documents\\Default.rdp"),
                    ("rdp-history", "%USERPROFILE%\\AppData\\Local\\Microsoft\\Terminal Server Client\\Servers"),
                    ("putty-sessions", "HKCU\\SOFTWARE\\SimonTatham\\PuTTY\\Sessions"),
                ])),
            ],
        },
        {
            "check_id": "sysenum.sql_web_configs",
            "title": "SQL/web/app config files",
            "steps": [
                (B_ALWAYS, None, lambda _ctx: fs_check([
                    ("pgpass", "%APPDATA%\\postgresql\\pgpass.conf"),
                    ("my-ini", "%ProgramFiles%\\MySQL\\MySQL Server 8.0\\my.ini"),
                    ("web-config", "%SystemRoot%\\Microsoft.NET\\Framework64\\v4.0.30319\\Config\\web.config"),
                ])),
            ],
        },
        {
            "check_id": "sysenum.credential_artifacts",
            "title": "High-yield credential artefacts",
            "steps": [
                (B_ALWAYS, None, lambda _ctx: fs_check([
                    ("regback-sam", "%SystemRoot%\\System32\\config\\RegBack\\SAM"),
                    ("regback-system", "%SystemRoot%\\System32\\config\\RegBack\\SYSTEM"),
                    ("regback-security", "%SystemRoot%\\System32\\config\\RegBack\\SECURITY"),
                    ("dpapi-roaming-credentials", "%APPDATA%\\Microsoft\\Credentials"),
                    ("dpapi-local-credentials", "%LOCALAPPDATA%\\Microsoft\\Credentials"),
                    ("dpapi-masterkeys", "%APPDATA%\\Microsoft\\Protect"),
                    ("chrome-login-data", "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data"),
                    ("edge-login-data", "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Login Data"),
                    ("firefox-logins", "%APPDATA%\\Mozilla\\Firefox\\Profiles"),
                    ("unattend-panther", "%SystemRoot%\\Panther\\Unattend.xml"),
                    ("unattend-sysprep", "%SystemRoot%\\System32\\sysprep\\sysprep.xml"),
                    ("sysprep-inf", "%SystemRoot%\\sysprep.inf"),
                ])),
            ],
        },
    ]


class SysEnum(Plugin):
    meta = (
        "sysenum",
        "Self-healing system enumeration",
        "Enumerates the local Windows host, falling back PowerShell -> CIM/WMI -> registry -> native.",
    )

    def run(self, ctx: RunContext) -> List[CheckResult]:
        if not ctx.is_windows():
            return [
                CheckResult.skipped(
                    m["check_id"],
                    "sysenum",
                    m["title"],
                    "local host is not a Windows target; enumerate the remote host via `sweep`",
                )
                for m in modules()
            ]

        checks: List[CheckResult] = [
            CheckResult.success(
                "sysenum.capabilities",
                "sysenum",
                "Available enumeration backends",
                {"available": ctx.backend_inventory.names()},
            )
        ]

        for m in modules():
            try:
                backend, data = run_chain(ctx, m["steps"])
                checks.append(
                    CheckResult.success(m["check_id"], "sysenum", m["title"], data).with_backend(backend)
                )
            except Exception as e:  # noqa: BLE001
                checks.append(CheckResult.unavailable(m["check_id"], "sysenum", m["title"], e))

        return checks
