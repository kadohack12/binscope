"""Regenerate docs/demo.svg from a real analysis run (no hand-written output).

Usage:  python docs/make_demo.py [fixture] [output.svg]
"""

import os
import sys

from rich.console import Console

from binscope.cli import analyze
from binscope.report import render_console

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURE = os.path.join(ROOT, "tests", "fixtures", "sample_stdin_file")


def main() -> int:
    target = sys.argv[1] if len(sys.argv) > 1 else FIXTURE
    out = sys.argv[2] if len(sys.argv) > 2 else os.path.join(ROOT, "docs", "demo.svg")

    console = Console(record=True, width=100, force_terminal=True, color_system="truecolor")
    render_console(analyze(target), console)
    title = f"binscope analyze {os.path.basename(target)}"
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(console.export_svg(title=title))
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
