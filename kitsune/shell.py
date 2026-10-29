"""Safe subprocess execution: no shell interpolation, bounded output, timeouts.

The security property comes from building an argv list and spawning it
directly (``subprocess.Popen([program, *args])``) — never joining an argv into
a string for ``sh -c`` / ``cmd /c``. :meth:`CommandSpec.validate` is a second
line of defence: it accepts only a bare program name.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
from dataclasses import dataclass, field, replace
from typing import List, Optional, Tuple

# Outcome kinds.
EXITED = "exited"
SIGNALED = "signaled"
TIMED_OUT = "timed_out"

_DEFAULT_OUTPUT_CAP = 16 * 1024 * 1024


class CommandError(Exception):
    """A command could not be run, or did not exit as required."""


@dataclass
class CommandSpec:
    program: str
    args: List[str] = field(default_factory=list)
    # Environment for the child, on top of the inherited one.
    env: List[Tuple[str, str]] = field(default_factory=list)
    timeout: float = 30.0
    # Exit codes treated as success by run_checked. Empty means nothing passes.
    allowed_exit: List[int] = field(default_factory=lambda: [0])
    output_cap: int = _DEFAULT_OUTPUT_CAP

    def arg(self, a: str) -> "CommandSpec":
        self.args.append(a)
        return self

    def add_args(self, it) -> "CommandSpec":
        self.args.extend(str(x) for x in it)
        return self

    def set_env(self, key: str, value: str) -> "CommandSpec":
        self.env.append((key, value))
        return self

    def set_envs(self, it) -> "CommandSpec":
        self.env.extend((str(k), str(v)) for k, v in it)
        return self

    def set_timeout(self, seconds: float) -> "CommandSpec":
        self.timeout = seconds
        return self

    def faketime(self, ft_args: List[str]) -> "CommandSpec":
        """Prefix the command with ``faketime <ft_args...>`` so the child (and
        everything it spawns) runs under a faked clock. The original program
        becomes an argument of ``faketime``."""
        wrapped = list(ft_args) + [self.program] + list(self.args)
        return replace(self, program="faketime", args=wrapped)

    def argv(self) -> List[str]:
        return [self.program] + list(self.args)

    def command_line(self) -> str:
        """The command as a single copy-pasteable shell line (for ``plan``):
        env as ``KEY=val`` prefixes, then the program and its arguments, each
        POSIX-quoted. Renders values in the clear — it never runs anything."""
        parts = [f"{k}={_sh_quote(v)}" for k, v in self.env]
        parts.append(_sh_quote(self.program))
        parts.extend(_sh_quote(a) for a in self.args)
        return " ".join(parts)

    def validate(self) -> None:
        p = self.program
        bare = (
            len(p) > 0
            and p not in (".", "..")
            and all((c.isascii() and c.isalnum()) or c in "-_." for c in p)
        )
        if not bare:
            raise CommandError(
                f"invalid program {p!r}: expected a bare program name "
                "(ASCII alphanumerics, `-`, `_`, `.`)"
            )


@dataclass
class CommandOutput:
    outcome: str
    code: Optional[int]
    stdout: str
    stderr: str
    argv: List[str]

    def exit_code(self) -> Optional[int]:
        return self.code if self.outcome == EXITED else None

    def timed_out(self) -> bool:
        return self.outcome == TIMED_OUT

    def combined(self) -> str:
        """The child's whole console output — stdout then stderr.

        The wrappers print most of what matters to stderr (Impacket/NetExec log
        through Python's stderr-defaulting StreamHandler), so a parser that read
        only stdout saw an empty stream. Order, not interleaving."""
        if not self.stderr:
            return self.stdout
        if not self.stdout:
            return self.stderr
        return f"{self.stdout}\n{self.stderr}"

    def is_success(self, allowed: List[int]) -> bool:
        code = self.exit_code()
        return code is not None and code in allowed


def _sh_quote(word: str) -> str:
    safe = len(word) > 0 and all(
        (c.isascii() and c.isalnum()) or c in "_@%+=:,./-" for c in word
    )
    if safe:
        return word
    return "'" + word.replace("'", "'\\''") + "'"


def _decode(buf: bytes, cap: int) -> str:
    return buf[:cap].decode("utf-8", errors="replace")


def _kill_tree(proc: subprocess.Popen) -> None:
    try:
        if os.name == "posix":
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        else:
            subprocess.run(
                ["taskkill", "/T", "/F", "/PID", str(proc.pid)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
    except Exception:
        pass


def run(spec: CommandSpec) -> CommandOutput:
    """Run a command, capturing output (capped), enforcing the timeout. The
    exit status is recorded but not treated as an error."""
    spec.validate()

    child_env = dict(os.environ)
    for k, v in spec.env:
        child_env[k] = v

    popen_kwargs = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "env": child_env,
    }
    if os.name == "posix":
        # Own process group so the timeout can reap grandchildren too.
        popen_kwargs["start_new_session"] = True

    try:
        proc = subprocess.Popen([spec.program] + list(spec.args), **popen_kwargs)
    except OSError as e:
        raise CommandError(f"spawn failed: {e}") from e

    timed_out = False
    try:
        out_b, err_b = proc.communicate(timeout=spec.timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_tree(proc)
        try:
            out_b, err_b = proc.communicate(timeout=10)
        except Exception:
            out_b, err_b = b"", b""

    argv = spec.argv()
    stdout = _decode(out_b or b"", spec.output_cap)
    stderr = _decode(err_b or b"", spec.output_cap)

    if timed_out:
        return CommandOutput(TIMED_OUT, None, stdout, stderr, argv)
    code = proc.returncode
    if code is None:
        return CommandOutput(SIGNALED, None, stdout, stderr, argv)
    # On POSIX a signalled child reports a negative return code.
    if code < 0:
        return CommandOutput(SIGNALED, None, stdout, stderr, argv)
    return CommandOutput(EXITED, code, stdout, stderr, argv)


def run_checked(spec: CommandSpec) -> CommandOutput:
    out = run(spec)
    if not out.is_success(spec.allowed_exit):
        raise CommandError(f"outcome {out.outcome} not in allowlist for {out.argv}")
    return out
