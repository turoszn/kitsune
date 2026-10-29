"""Entry point so `python -m kitsune ...` and the `kitsune` console script
both dispatch into the CLI."""

import sys

from kitsune.cli import run


def main() -> int:
    return run(sys.argv[1:])


if __name__ == "__main__":
    sys.exit(main())
