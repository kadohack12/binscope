"""Command-line interface for binscope."""

from __future__ import annotations

import argparse
import os
import sys

from rich.console import Console

from . import __version__
from .engine import run_stimulation
from .model import AnalysisResult
from .report import build_synthesis, render_console, to_json, to_markdown
from .static import analyze_capabilities, analyze_identity, analyze_protections


def analyze(path: str, auto_stub: bool = False, timeout: float = 2.0) -> AnalysisResult:
    """Run the full static + dynamic analysis and return the result model."""
    result = AnalysisResult()
    if not os.path.exists(path):
        result.warnings.append(f"Target not found: {path}")
        return result
    if not os.path.isfile(path):
        result.warnings.append(f"Target is not a regular file: {path}")
        return result

    result.identity = analyze_identity(path)
    result.protections = analyze_protections(path)
    result.capabilities = analyze_capabilities(path)

    try:
        with open(path, "rb") as fh:
            is_elf = fh.read(4) == b"\x7fELF"
    except OSError:
        is_elf = False
    if not is_elf:
        result.warnings.append(f"{path} does not look like an ELF binary; dynamic analysis skipped.")
        result.synthesis = build_synthesis(result)
        return result

    runs, stimuli, behavior, warnings = run_stimulation(
        path,
        static_strings=result.capabilities.interesting_strings,
        auto_stub=auto_stub,
        timeout=timeout,
    )
    result.runs = runs
    result.stimuli = stimuli
    result.behavior = behavior
    result.warnings.extend(warnings)
    result.synthesis = build_synthesis(result)
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="binscope",
        description="Understand quickly what a Linux ELF binary expects and what it does.",
    )
    parser.add_argument("--version", action="version", version=f"binscope {__version__}")
    sub = parser.add_subparsers(dest="command")

    ap = sub.add_parser("analyze", help="analyze an ELF binary")
    ap.add_argument("target", help="path to the ELF binary")
    ap.add_argument("--json", dest="json_out", metavar="FILE", help="write a JSON report to FILE ('-' for stdout)")
    ap.add_argument("--md", dest="md_out", metavar="FILE", help="write a Markdown report to FILE ('-' for stdout)")
    ap.add_argument("--auto-stub", action="store_true",
                    help="create fake files for missing paths and re-run")
    ap.add_argument("--timeout", type=float, default=2.0,
                    help="per-pass timeout in seconds (default: 2.0)")
    return parser


def _emit(path: str, content: str, console: Console) -> None:
    if path == "-":
        sys.stdout.write(content)
        if not content.endswith("\n"):
            sys.stdout.write("\n")
        sys.stdout.flush()
    else:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        console.print(f"[green]wrote {path}[/green]")


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    console = Console()

    if args.command != "analyze":
        parser.print_help()
        return 0

    target = os.path.abspath(args.target)
    if not os.path.exists(target):
        console.print(f"[red]error:[/red] no such file: {args.target}")
        return 2

    result = analyze(target, auto_stub=args.auto_stub, timeout=args.timeout)

    # When a machine-readable report goes to stdout, suppress the console table
    # so the stream stays valid JSON / Markdown.
    machine_to_stdout = args.json_out == "-" or args.md_out == "-"
    if args.json_out:
        _emit(args.json_out, to_json(result), console)
    if args.md_out:
        _emit(args.md_out, to_markdown(result), console)

    if not machine_to_stdout:
        render_console(result, console)
    return 0


if __name__ == "__main__":
    sys.exit(main())
