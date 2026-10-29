"""kitsune — Windows/AD enumeration toolkit for authorized labs, CTF and pentest exams.

The package is a library plus a thin
``__main__`` entry point. All plugins share one report model (:mod:`kitsune.model`)
and every external command goes through one shell layer (:mod:`kitsune.shell`)
that never uses a shell interpreter.
"""

__version__ = "0.1.0"
TOOL_NAME = "kitsune"
