"""Shared data model: check status, confidence, report, findings, credentials,
suggestions, and the typed payload views over a check's ``data``.

``data`` stays a plain JSON value (dict/list/scalar): it *is* the report
document and the wire format between a live run and the offline suggester. The
payload decoders below reproduce serde's shape-checked decoding — a decode that
does not match returns ``None`` and the caller treats the signal as absent."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# Bump when the report shape changes incompatibly. 2 — SweepFinding no longer
# carries the always-empty `evidence` key.
SCHEMA_VERSION = 2

# Status values.
STATUS_SUCCESS = "success"
STATUS_FAILED = "failed"
STATUS_UNAVAILABLE = "unavailable"
STATUS_SKIPPED = "skipped"

# Suggestion action kinds.
KIND_ENUMERATION = "enumeration"
KIND_EXPLOIT = "exploit"
KIND_HINT = "hint"


# --------------------------------------------------------------------------
# credentials
# --------------------------------------------------------------------------

CRED_PASSWORD = "password"
CRED_NTLM = "ntlm hash"
CRED_AES = "aes key"
CRED_TICKET = "ticket"


class Credential:
    """A credential as handed to NetExec/Impacket. The variant *is* the
    mechanism NetExec is told to authenticate with."""

    def __init__(self, kind: str, value: str) -> None:
        self._kind = kind
        self._value = value

    @staticmethod
    def password(v: str) -> "Credential":
        return Credential(CRED_PASSWORD, v)

    @staticmethod
    def ntlm(v: str) -> "Credential":
        return Credential(CRED_NTLM, v)

    @staticmethod
    def aes(v: str) -> "Credential":
        return Credential(CRED_AES, v)

    @staticmethod
    def ticket(path: str) -> "Credential":
        return Credential(CRED_TICKET, path)

    def kind(self) -> str:
        return self._kind

    def secret(self) -> Optional[str]:
        """The secret material, if this variant has any. A ticket path is not a
        secret and returns None."""
        if self._kind == CRED_TICKET:
            return None
        return self._value

    def password_value(self) -> Optional[str]:
        return self._value if self._kind == CRED_PASSWORD else None

    def ticket_path(self) -> Optional[str]:
        return self._value if self._kind == CRED_TICKET else None

    def __repr__(self) -> str:  # never print the secret
        return f"Credential::{self._kind}(<redacted>)"


# --------------------------------------------------------------------------
# findings and suggestions
# --------------------------------------------------------------------------


@dataclass
class SweepFinding:
    """One parsed line of a NetExec transcript, as recorded in a payload."""

    target: str
    protocol: str
    credential_works: bool
    detail: str
    evidence: Optional[Any] = None
    failure_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "target": self.target,
            "protocol": self.protocol,
            "credential_works": self.credential_works,
            "detail": self.detail,
        }
        if self.evidence is not None:
            d["evidence"] = self.evidence
        if self.failure_reason is not None:
            d["failure_reason"] = self.failure_reason
        return d


@dataclass
class Suggestion:
    id: str
    title: str
    kind: str
    description: str
    commands: List[str]
    confidence: str
    evidence: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "kind": self.kind,
            "description": self.description,
            "commands": list(self.commands),
            "confidence": self.confidence,
            "evidence": list(self.evidence),
        }


# --------------------------------------------------------------------------
# check result and report
# --------------------------------------------------------------------------


@dataclass
class CheckResult:
    check_id: str
    plugin: str
    status: str = STATUS_SKIPPED
    title: str = ""
    backend: Optional[str] = None
    data: Any = None
    findings: List[Any] = field(default_factory=list)
    suggestions: List[Any] = field(default_factory=list)
    error: Optional[str] = None
    source: Optional[str] = None
    duration_ms: int = 0

    @staticmethod
    def success(check_id: str, plugin: str, title: str, data: Any) -> "CheckResult":
        return CheckResult(check_id, plugin, STATUS_SUCCESS, title, data=data)

    @staticmethod
    def skipped(check_id: str, plugin: str, title: str, reason: Any) -> "CheckResult":
        return CheckResult(check_id, plugin, STATUS_SKIPPED, title, error=str(reason))

    @staticmethod
    def unavailable(check_id: str, plugin: str, title: str, reason: Any) -> "CheckResult":
        return CheckResult(check_id, plugin, STATUS_UNAVAILABLE, title, error=str(reason))

    @staticmethod
    def failed(check_id: str, plugin: str, title: str, reason: Any) -> "CheckResult":
        return CheckResult(check_id, plugin, STATUS_FAILED, title, error=str(reason))

    def with_backend(self, backend: str) -> "CheckResult":
        self.backend = backend
        return self

    def with_source(self, source: str) -> "CheckResult":
        self.source = source
        return self

    def with_findings(self, findings: List[Any]) -> "CheckResult":
        self.findings = findings
        return self

    def with_suggestions(self, suggestions: List[Any]) -> "CheckResult":
        self.suggestions = suggestions
        return self

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "check_id": self.check_id,
            "plugin": self.plugin,
            "status": self.status,
            "title": self.title,
            "data": self.data,
            "findings": [_as_dict(f) for f in self.findings],
            "suggestions": [_as_dict(s) for s in self.suggestions],
            "duration_ms": self.duration_ms,
        }
        if self.backend is not None:
            d["backend"] = self.backend
        if self.error is not None:
            d["error"] = self.error
        if self.source is not None:
            d["source"] = self.source
        return d

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "CheckResult":
        return CheckResult(
            check_id=d.get("check_id", ""),
            plugin=d.get("plugin", ""),
            status=d.get("status", STATUS_SKIPPED),
            title=d.get("title", ""),
            backend=d.get("backend"),
            data=d.get("data"),
            findings=d.get("findings", []) or [],
            suggestions=d.get("suggestions", []) or [],
            error=d.get("error"),
            source=d.get("source"),
            duration_ms=d.get("duration_ms", 0),
        )


@dataclass
class Report:
    tool: str
    version: str
    schema_version: int
    started_at_ms: int
    duration_ms: int
    target: str
    checks: List[CheckResult]

    def zero_timestamps(self) -> None:
        self.started_at_ms = 0
        self.duration_ms = 0
        for c in self.checks:
            c.duration_ms = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": self.tool,
            "version": self.version,
            "schema_version": self.schema_version,
            "started_at_ms": self.started_at_ms,
            "duration_ms": self.duration_ms,
            "target": self.target,
            "checks": [c.to_dict() for c in self.checks],
        }

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "Report":
        return Report(
            tool=d.get("tool", ""),
            version=d.get("version", ""),
            schema_version=d.get("schema_version", 0),
            started_at_ms=d.get("started_at_ms", 0),
            duration_ms=d.get("duration_ms", 0),
            target=d.get("target", ""),
            checks=[CheckResult.from_dict(c) for c in d.get("checks", [])],
        )


def _as_dict(x: Any) -> Any:
    return x.to_dict() if hasattr(x, "to_dict") else x


# --------------------------------------------------------------------------
# payload builders (producer side)
# --------------------------------------------------------------------------


def protocol_payload(argv, exit_code, timed_out, credential_works, findings, host) -> Dict[str, Any]:
    return {
        "argv": list(argv),
        "exit_code": exit_code,
        "timed_out": timed_out,
        "credential_works": credential_works,
        "findings": [_as_dict(f) for f in findings],
        "host": host,
    }


def spn_payload(argv, exit_code, stdout_lines) -> Dict[str, Any]:
    return {"argv": list(argv), "exit_code": exit_code, "stdout_lines": list(stdout_lines)}


def ad_payload(argv, exit_code, timed_out, stdout, stdout_lines) -> Dict[str, Any]:
    return {
        "argv": list(argv),
        "exit_code": exit_code,
        "timed_out": timed_out,
        "stdout": stdout,
        "stdout_lines": list(stdout_lines),
    }


def loot_payload(domain=None, domain_sid=None, host_name=None, os=None, smb_signing=None, aes_keys=None) -> Dict[str, Any]:
    d: Dict[str, Any] = {}
    if domain is not None:
        d["domain"] = domain
    if domain_sid is not None:
        d["domain_sid"] = domain_sid
    if host_name is not None:
        d["host_name"] = host_name
    if os is not None:
        d["os"] = os
    if smb_signing is not None:
        d["smb_signing"] = smb_signing
    if aes_keys:
        d["aes_keys"] = list(aes_keys)
    return d


# --------------------------------------------------------------------------
# payload decoders (consumer side) — reproduce serde's shape checking
# --------------------------------------------------------------------------


def _is_list(x) -> bool:
    return isinstance(x, list)


def as_protocol_payload(data: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(data, dict):
        return None
    if not (_is_list(data.get("argv")) and isinstance(data.get("timed_out"), bool)
            and isinstance(data.get("credential_works"), bool)
            and _is_list(data.get("findings")) and isinstance(data.get("host"), str)):
        return None
    return data


def as_ad_payload(data: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(data, dict):
        return None
    if not (_is_list(data.get("argv")) and isinstance(data.get("timed_out"), bool)
            and isinstance(data.get("stdout"), str) and _is_list(data.get("stdout_lines"))):
        return None
    return data


def as_spn_payload(data: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(data, dict):
        return None
    if not (_is_list(data.get("argv")) and _is_list(data.get("stdout_lines"))):
        return None
    return data


def as_asreproast_payload(data: Any) -> Optional[Dict[str, Any]]:
    if as_ad_payload(data) is None:
        return None
    if not _is_list(data.get("asrep_hashes")):
        return None
    return data


def stdout_lines_of(data: Any) -> List[str]:
    """The StdoutLines shape: any object decodes, missing -> []."""
    if isinstance(data, dict):
        v = data.get("stdout_lines")
        if isinstance(v, list):
            return [str(x) for x in v]
    return []


def service_paths_of(data: Any) -> List[str]:
    """ServicePayload (untagged): an array of {PathName} rows, or a line list."""
    if isinstance(data, list):
        out = []
        for row in data:
            if isinstance(row, dict) and isinstance(row.get("PathName"), str):
                out.append(row["PathName"])
        return out
    return stdout_lines_of(data)
