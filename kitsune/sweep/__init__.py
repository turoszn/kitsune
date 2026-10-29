"""Credential/AD sweep plugin: a wrapper around NetExec/Impacket for credential
validation and enumeration, plus the offensive actions the operator opts into by
flag. Nothing chains: one flag produces the commands that flag names.
"""

from kitsune.sweep.sweep import Sweep, parse_transcript  # noqa: F401
