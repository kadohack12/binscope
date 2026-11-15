"""Command-line interface for binscope."""

from __future__ import annotations

import argparse
import os
import shutil
import struct
import sys
import tempfile
import warnings

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from . import __version__
from .engine import run_stimulation
from .model import AnalysisResult
from .report import build_synthesis, render_console, to_json, to_markdown
from .static import analyze_capabilities, analyze_identity, analyze_protections


def detect_format(path: str) -> str:
    """Sniff the container format from magic bytes: 'ELF', 'PE' or ''."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(4)
            if head == b"\x7fELF":
                return "ELF"
            if head[:2] == b"MZ":
                fh.seek(0x3C)
                off = struct.unpack("<I", fh.read(4))[0]
                fh.seek(off)
                if fh.read(4) == b"PE\x00\x00":
                    return "PE"
    except (OSError, struct.error):
        return ""
    return ""


def analyze(path: str, auto_stub: bool = False, timeout: float = 2.0) -> AnalysisResult:
    """Run the full static + dynamic analysis and return the result model."""
    result = AnalysisResult()
    if not os.path.exists(path):
        result.warnings.append(f"Target not found: {path}")
        return result
    if not os.path.isfile(path):
        result.warnings.append(f"Target is not a regular file: {path}")
        return result

    fmt = detect_format(path)

    if fmt == "PE":
        _analyze_pe(path, result, timeout)
    else:
        _analyze_elf(path, result, auto_stub, timeout, fmt)

    result.synthesis = build_synthesis(result)
    return result


def _analyze_pe(path: str, result: AnalysisResult, timeout: float) -> None:
    from . import pe_engine

    result.identity = pe_engine.analyze_pe_identity(path)
    result.protections = pe_engine.analyze_pe_protections(path)
    result.capabilities = pe_engine.analyze_pe_capabilities(path)

    runs, stimuli, behavior, warnings_list = pe_engine.run_pe_emulation(
        path,
        static_strings=result.capabilities.interesting_strings,
        timeout=max(timeout, 4.0),
    )
    result.runs = runs
    result.stimuli = stimuli
    result.behavior = behavior
    result.warnings.extend(warnings_list)


def _analyze_elf(path: str, result: AnalysisResult, auto_stub: bool,
                 timeout: float, fmt: str) -> None:
    result.identity = analyze_identity(path)
    result.identity.format = "ELF"
    result.protections = analyze_protections(path)
    result.capabilities = analyze_capabilities(path)

    if fmt != "ELF":
        result.identity.format = "UNKNOWN"
        result.identity.stripped = None
        result.warnings.append(
            f"{path} does not look like an ELF or PE binary; dynamic analysis skipped."
        )
        return

    run_path = path
    temp_exec_dir = None
    if not os.access(path, os.X_OK):
        try:
            temp_exec_dir = tempfile.mkdtemp(prefix="binscope_exec_")
            copied = os.path.join(temp_exec_dir, os.path.basename(path))
            shutil.copy2(path, copied)
            os.chmod(copied, 0o755)
            run_path = copied
            result.warnings.append("target lacked +x permission; traced via temporary executable copy.")
        except OSError:
            if temp_exec_dir:
                shutil.rmtree(temp_exec_dir, ignore_errors=True)
                temp_exec_dir = None

    try:
        runs, stimuli, behavior, warnings_list = run_stimulation(
            run_path,
            static_strings=result.capabilities.interesting_strings,
            auto_stub=auto_stub,
            timeout=timeout,
        )
    finally:
        if temp_exec_dir:
            shutil.rmtree(temp_exec_dir, ignore_errors=True)
    result.runs = runs
    result.stimuli = stimuli
    result.behavior = behavior
    result.warnings.extend(warnings_list)


def run_doctor(console: Console) -> int:
    """Check system & Python dependencies and show clear install hints."""
    t = Table(show_header=True, box=None, header_style="bold cyan")
    t.add_column("Component")
    t.add_column("Role")
    t.add_column("Status")
    t.add_column("How to fix (if missing)")

    sys_tools = [
        ("file", "File type detection", "apt install file / pacman -S file"),
        ("readelf", "ELF headers & protections", "apt install binutils / pacman -S binutils"),
        ("strings", "ASCII / UTF-16 string extraction", "apt install binutils / pacman -S binutils"),
        ("nm", "ELF imported symbols", "apt install binutils / pacman -S binutils"),
        ("strace", "ELF syscall tracing (required for ELF dynamic)", "apt install strace / pacman -S strace"),
        ("ltrace", "ELF libc call tracing (strcmp/strtoul/getenv)", "apt install ltrace / pacman -S ltrace"),
        ("capa", "Optional MITRE ATT&CK capability rules", "pip install flare-capa"),
        ("floss", "Optional obfuscated/stack string decoder", "pip install flare-floss"),
    ]
    for cmd, role, hint in sys_tools:
        ok = shutil.which(cmd) is not None
        if ok:
            status = "[green]OK[/green]"
        elif cmd in ("strace", "ltrace", "readelf", "strings"):
            status = "[red]MISSING[/red]"
        else:
            status = "[yellow]optional[/yellow]"
        t.add_row(cmd, role, status, "-" if ok else hint)

    for mod, role, hint in [
        ("pefile", "Windows PE static parser", "pip install pefile"),
        ("speakeasy", "Windows PE safe CPU/API emulator", 'pip install speakeasy-emulator "setuptools<81"'),
    ]:
        try:
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore", message=".*pkg_resources.*")
                __import__(mod)
            t.add_row(mod, role, "[green]OK[/green]", "-")
        except Exception as exc:
            t.add_row(mod, role, f"[yellow]ERROR ({type(exc).__name__})[/yellow]", hint)

    console.print(Panel(t, title="[bold]binscope doctor - environment check[/bold]", border_style="cyan"))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="binscope",
        description="Understand quickly what a Linux ELF or Windows PE binary expects and what it does.",
        epilog=(
            "Examples:\n"
            "  binscope ./target\n"
            "  binscope ./target --explain\n"
            "  binscope analyze ./target --auto-stub --md report.md\n"
            "  binscope doctor"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"binscope {__version__}")
    sub = parser.add_subparsers(dest="command")

    ap = sub.add_parser("analyze", help="analyze an ELF or PE binary (default if you pass a file directly)")
    ap.add_argument("target", help="path to the ELF or PE binary")
    ap.add_argument("--json", dest="json_out", metavar="FILE", help="write a JSON report to FILE ('-' for stdout)")
    ap.add_argument("--md", dest="md_out", metavar="FILE", help="write a Markdown report to FILE ('-' for stdout)")
    ap.add_argument("--auto-stub", action="store_true",
                    help="create fake files for missing paths and re-run")
    ap.add_argument("--timeout", type=float, default=2.0,
                    help="per-pass timeout in seconds (default: 2.0)")
    ap.add_argument("--explain", action="store_true",
                    help="include a beginner-friendly guide explaining technical terms")

    sub.add_parser("doctor", help="check installed tools and optional dependencies")
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
    raw = list(sys.argv[1:] if argv is None else argv)
    if raw and not any(tok in ("analyze", "doctor", "-h", "--help", "--version") for tok in raw):
        raw = ["analyze"] + raw

    parser = build_parser()
    args = parser.parse_args(raw)
    console = Console()

    if args.command == "doctor":
        return run_doctor(console)

    if args.command != "analyze":
        parser.print_help()
        return 0

    target = os.path.abspath(args.target)
    if not os.path.exists(target):
        console.print(f"[red]error:[/red] no such file: {args.target}")
        return 2

    result = analyze(target, auto_stub=args.auto_stub, timeout=args.timeout)

    machine_to_stdout = args.json_out == "-" or args.md_out == "-"
    if args.json_out:
        _emit(args.json_out, to_json(result), console)
    if args.md_out:
        _emit(args.md_out, to_markdown(result), console)

    if not machine_to_stdout:
        render_console(result, console, explain=args.explain)
    return 0


if __name__ == "__main__":
    sys.exit(main())
