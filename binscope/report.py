"""Report rendering: rich terminal output plus JSON and Markdown exports."""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import List, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .model import AnalysisResult


def _yn(value) -> str:
    if value is None:
        return "?"
    return "Yes" if value else "No"


def _prot_style(ok, good: bool = True) -> str:
    if ok is None:
        return "dim"
    if ok is good:
        return "green"
    return "yellow"


# --------------------------------------------------------------------------- #
# Analyst synthesis
# --------------------------------------------------------------------------- #

def build_synthesis(result: AnalysisResult) -> List[str]:
    """Produce 3-5 plain-language bullet points describing the binary."""
    idn = result.identity
    if idn.format == "PE":
        return _build_synthesis_pe(result)
    if idn.format == "UNKNOWN":
        return [
            f"Unsupported file format ({idn.arch or idn.file_type or 'unknown'}), {idn.size} bytes, sha256 {idn.sha256[:16]}...",
            "Dynamic tracing skipped because target is neither Linux ELF nor Windows PE.",
        ]
    return _build_synthesis_elf(result)


def _build_synthesis_elf(result: AnalysisResult) -> List[str]:
    idn = result.identity
    prot = result.protections
    stim = result.stimuli
    beh = result.behavior
    caps = result.capabilities
    bullets: List[str] = []

    arch = idn.arch or "unknown arch"
    kind = "PIE executable" if prot.pie else "non-PIE executable"
    strip = "not stripped (symbols present)" if idn.stripped is False else "stripped"
    bullets.append(
        f"ELF {idn.bits or '?'}-bit {arch} {kind}, {strip}, "
        f"{idn.size} bytes, sha256 {idn.sha256[:16]}..."
    )

    prot_bits = []
    prot_bits.append(("NX", prot.nx))
    prot_bits.append(("Canary", prot.canary))
    if prot.relro:
        prot_bits.append((f"RELRO={prot.relro}", True))
    prot_txt = ", ".join(f"{name}: {'on' if v else 'off'}" for name, v in prot_bits if v is not None)
    bullets.append("Protections: " + (prot_txt or "none detected") + ".")

    bullets.append(_stimuli_sentence(stim))
    bullets.append(_behaviour_sentence(beh))

    hints = []
    if caps.interesting_strings:
        hints.append("notable strings: " + ", ".join(caps.interesting_strings[:5]))
    if caps.capa:
        hints.append(f"capa: {caps.capa.get('count', 0)} rule(s) matched")
    if caps.floss:
        hints.append(f"floss: {len(caps.floss)} decoded string(s)")
    if hints:
        bullets.append("Static hints: " + "; ".join(hints) + ".")

    return bullets[:5]


def _build_synthesis_pe(result: AnalysisResult) -> List[str]:
    idn = result.identity
    prot = result.protections
    stim = result.stimuli
    beh = result.behavior
    caps = result.capabilities
    bullets: List[str] = []

    bits = f"{idn.bits}-bit" if idn.bits else ""
    bullets.append(
        f"Windows PE ({idn.elf_type or 'PE'}) {bits} {idn.arch or '?'} "
        f"{idn.subsystem or ''} binary, {idn.sections} section(s), "
        f"{idn.size} bytes, sha256 {idn.sha256[:16]}..."
    )
    if idn.packed_alert:
        sec = f"'{idn.max_entropy_section}' " if idn.max_entropy_section else ""
        bullets.append(
            f"Packing hint: section {sec}entropy {idn.max_entropy} > 7.0 - "
            "section may be compressed/encrypted (packer or embedded payload)."
        )

    prot_bits = [("ASLR", prot.aslr), ("DEP", prot.dep), ("CFG", prot.cfg),
                 ("SafeSEH", prot.safeseh), ("HighEntropyVA", prot.high_entropy_va)]
    prot_txt = ", ".join(f"{n}: {'on' if v else 'off'}" for n, v in prot_bits if v is not None)
    bullets.append("Protections: " + (prot_txt or "none detected") + ".")

    bullets.append(_stimuli_sentence(stim, pe=True))
    bullets.append(_behaviour_sentence(beh, pe=True))

    hints = []
    if caps.dlls:
        hints.append("DLLs: " + ", ".join(caps.dlls[:6]))
    if caps.api_categories:
        hints.append("API families: " + ", ".join(caps.api_categories.keys()))
    if caps.interesting_strings:
        hints.append("notable strings: " + ", ".join(caps.interesting_strings[:4]))
    if hints:
        bullets.append("Static hints: " + "; ".join(hints) + ".")

    return bullets[:6]


def _stimuli_sentence(stim, pe: bool = False) -> str:
    inputs = []
    if stim.argv:
        inputs.append("argv " + ", ".join(f"'{a}'" for a in stim.argv[:6]))
    if stim.env_vars:
        inputs.append("env " + ", ".join(stim.env_vars[:6]))
    if pe and stim.input_apis:
        inputs.append("input APIs " + ", ".join(stim.input_apis[:6]))
    if stim.missing_files:
        inputs.append("expected files " + ", ".join(stim.missing_files[:5]))
    if stim.files and not pe:
        inputs.append("files checked " + ", ".join(stim.files[:5]))
    if stim.comparisons:
        inputs.append("string checks " + ", ".join(f"'{c}'" for c in stim.comparisons[:5]))
    if stim.numeric_probes:
        inputs.append("numeric argv/stdin " + ", ".join(stim.numeric_probes[:6]))
    if stim.argc_expected is not None:
        inputs.append(f"~{stim.argc_expected} argument(s)")
    if stim.exit_code_changes:
        inputs.append("behaviour change " + ", ".join(stim.exit_code_changes[:3]))
    if stim.stdin_expected:
        inputs.append("stdin")
    if inputs:
        return "Waits for / reacts to: " + "; ".join(inputs) + "."
    return "No specific external input was observed to change behaviour."


def _behaviour_sentence(beh, pe: bool = False) -> str:
    actions = []
    if beh.execve:
        actions.append("spawns " + "; ".join(beh.execve[:4]))
    if beh.files_written:
        actions.append("writes " + ", ".join(beh.files_written[:4]))
    if beh.files_read:
        actions.append("reads " + ", ".join(beh.files_read[:4]))
    if beh.files_deleted:
        actions.append("deletes " + ", ".join(beh.files_deleted[:4]))
    if beh.network:
        actions.append("network " + ", ".join(beh.network[:4]))
    if beh.stdout_output:
        actions.append(("shows " if pe else "prints ") + " / ".join(beh.stdout_output[:3]))
    if beh.note:
        actions.append(beh.note)
    if not actions and beh.api_trace:
        actions.append("called " + " -> ".join(beh.api_trace[:6]))
    if beh.emulation_stop:
        actions.append(f"stopped at {beh.emulation_stop}")
    if actions:
        return "Observed actions: " + "; ".join(actions) + "."
    return "No child process, file write, network or notable output observed."


def build_next_steps(result: AnalysisResult) -> List[str]:
    """Actionable next steps tailored to the binary profile (beginner & expert)."""
    idn = result.identity
    stim = result.stimuli
    beh = result.behavior
    caps = result.capabilities
    steps: List[str] = []

    if idn.format == "UNKNOWN":
        return ["Pass a Linux ELF binary or a Windows PE (.exe/.dll) file."]

    if idn.format == "PE":
        if idn.packed_alert:
            sec = f"'{idn.max_entropy_section}'" if idn.max_entropy_section else "one section"
            steps.append(
                f"High entropy in {sec} ({idn.max_entropy}): inspect whether it holds encrypted data/payload or is packed."
            )
        if beh.emulation_stop and "unsupported_api" in beh.emulation_stop:
            steps.append(
                f"Emulation paused at {beh.emulation_stop}; inspect that caller address or cross-references to notable strings in Ghidra/x32dbg."
            )
        elif idn.subsystem == "GUI" and not (beh.execve or beh.files_written or beh.network):
            steps.append(
                "Windows GUI binary: interactive window/mouse events require static inspection (Ghidra/x32dbg) or a Windows VM."
            )
    else:
        if stim.missing_files and not (beh.execve or beh.network):
            steps.append("Missing file check detected: re-run with `--auto-stub` inside a sandbox to see stage two.")
        if stim.exit_code_changes or stim.output_changes:
            steps.append("Input triggers found above: test those exact arguments/stdin values directly to verify the unlocked path.")
        elif not any([stim.argv, stim.env_vars, stim.comparisons, stim.numeric_probes, stim.stdin_expected]):
            steps.append("No simple CLI/stdin trigger found: check imported functions or open in Ghidra/radare2/gdb.")

    if beh.execve or beh.network or beh.files_written:
        steps.append("Active process/file/network behaviour seen: handle and run this sample only inside an offline sandbox.")

    if not caps.tools_available.get("capa") or not caps.tools_available.get("floss"):
        steps.append("Tip: run inside the BlackArch lab (with capa & floss) for deeper MITRE capabilities and decoded strings.")

    return steps[:3]


def build_explanations(result: AnalysisResult) -> List[Tuple[str, str]]:
    """Plain-language glossary tailored to what appeared in this specific binary."""
    idn = result.identity
    prot = result.protections
    items: List[Tuple[str, str]] = []

    if idn.format == "PE":
        items.append(("PE32 / Subsystem", f"Windows executable ({idn.subsystem or 'unknown'} mode). GUI binaries wait for window/mouse events; Console binaries run in a terminal."))
        if idn.packed_alert:
            items.append(("Entropy > 7.0", "Measures randomness (0-8). Normal code is ~5-6; >7.0 usually means compressed/encrypted data or a packed binary."))
        if prot.aslr is not None:
            items.append(("ASLR / DEP", "ASLR randomizes memory addresses; DEP/NX prevents executing data as code (harder to exploit)."))
        items.append(("Speakeasy", "Safe CPU/Windows API emulator in Python: simulates execution without touching your real Linux/Windows system."))
    else:
        if idn.stripped is True:
            items.append(("Stripped = Yes", "Function and variable names were removed to make reverse engineering harder."))
        elif idn.stripped is False:
            items.append(("Stripped = No", "Debug/symbol names are still present, making disassembly much easier to read."))
        if prot.pie is not None or prot.nx is not None:
            items.append(("PIE / NX / Canary", "PIE randomizes code addresses; NX blocks shellcode on stack/heap; Canary detects stack buffer overflows."))
        items.append(("strace / ltrace", "strace records Linux kernel syscalls (files, network, execve); ltrace records library calls (strcmp, strtoul, getenv)."))

    return items


# --------------------------------------------------------------------------- #
# Terminal rendering
# --------------------------------------------------------------------------- #

def render_console(result: AnalysisResult, console: Console | None = None, explain: bool = False) -> None:
    console = console or Console()
    idn = result.identity
    prot = result.protections
    stim = result.stimuli
    beh = result.behavior
    caps = result.capabilities

    console.rule("[bold cyan]binscope[/bold cyan] - rapid binary triage")

    is_pe = idn.format == "PE"

    # 1. Identity
    t = Table(show_header=False, box=None, pad_edge=False)
    t.add_column(style="bold")
    t.add_column()
    t.add_row("Path", idn.path)
    if is_pe:
        t.add_row("Arch", f"{idn.bits}-bit {idn.arch}" if idn.bits else idn.arch)
        t.add_row("Type", idn.elf_type or "PE")
        t.add_row("Subsystem", idn.subsystem or "-")
        sec_lbl = f"{idn.max_entropy_section}=" if idn.max_entropy_section else "max entropy "
        t.add_row("Sections", f"{idn.sections} ({sec_lbl}{idn.max_entropy}"
                  + (" - [red]possibly packed/encrypted[/red])" if idn.packed_alert else ")"))
        t.add_row("Timestamp", idn.timestamp or "-")
        t.add_row("PDB path", idn.pdb_path or "-")
    elif idn.format == "UNKNOWN":
        t.add_row("Format", f"Unsupported ({idn.arch or idn.file_type or 'non-binary'})")
    else:
        t.add_row("Arch", f"{idn.bits}-bit {idn.arch} ({idn.endianness} endian)" if idn.bits else f"{idn.arch} ({idn.endianness} endian)")
        t.add_row("Type", idn.elf_type)
        t.add_row("Interp", idn.interp or "-")
        t.add_row("Stripped", _yn(idn.stripped) if idn.stripped is not None else "?")
    t.add_row("Size", f"{idn.size} bytes")
    t.add_row("SHA256", idn.sha256)
    console.print(Panel(t, title="[bold]1. Identity[/bold]", border_style="cyan"))

    pt = Table(show_header=False, box=None, pad_edge=False)
    pt.add_column(style="bold")
    pt.add_column()
    if is_pe:
        pt.add_row("ASLR", _yn(prot.aslr))
        pt.add_row("DEP / NX", _yn(prot.dep))
        pt.add_row("CFG", _yn(prot.cfg))
        pt.add_row("SafeSEH", _yn(prot.safeseh))
        pt.add_row("HighEntropyVA", _yn(prot.high_entropy_va))
        title = "Protections (DllCharacteristics)"
    else:
        pt.add_row("PIE", _yn(prot.pie))
        pt.add_row("NX", _yn(prot.nx))
        pt.add_row("Canary", _yn(prot.canary))
        pt.add_row("RELRO", prot.relro or "?")
        pt.add_row("FORTIFY", _yn(prot.fortify))
        title = "Protections (checksec)"
    console.print(Panel(pt, title=f"[bold]{title}[/bold]", border_style="cyan"))

    # 2. Stimuli
    st = Table(show_header=True, box=None, header_style="bold magenta")
    st.add_column("Kind")
    st.add_column("Values")
    if stim.argv:
        st.add_row("argv", ", ".join(stim.argv))
    if stim.env_vars:
        st.add_row("env", ", ".join(stim.env_vars))
    if stim.files:
        st.add_row("files checked", ", ".join(stim.files))
    if stim.missing_files:
        st.add_row("missing files", ", ".join(stim.missing_files))
    if stim.comparisons:
        st.add_row("string compare", ", ".join(stim.comparisons))
    if stim.numeric_probes:
        st.add_row("numeric input", ", ".join(stim.numeric_probes))
    if stim.argc_expected is not None:
        st.add_row("argc", f"expects ~{stim.argc_expected} argument(s)")
    if stim.input_apis:
        st.add_row("input APIs", ", ".join(stim.input_apis))
    if stim.trigger_notes:
        st.add_row("behaviour change", "\n".join(stim.trigger_notes))
    if stim.exit_code_changes:
        st.add_row("exit code trigger", "\n".join(stim.exit_code_changes))
    if stim.output_changes:
        st.add_row("output trigger", "\n".join(stim.output_changes))
    if stim.stdin_expected:
        st.add_row("stdin", "expected" + (f" ({', '.join(stim.stdin_patterns)})" if stim.stdin_patterns else ""))
    if stim.note:
        st.add_row("note", stim.note)
    if not any([stim.argv, stim.env_vars, stim.files, stim.missing_files, stim.comparisons,
                stim.numeric_probes, stim.exit_code_changes, stim.output_changes,
                stim.input_apis, stim.argc_expected is not None, stim.stdin_expected]):
        st.add_row("-", "no specific stimulus detected")
    body = st
    if stim.help_text:
        body = Table.grid()
        body.add_row(st)
        body.add_row(Text(""))
        body.add_row(Panel(stim.help_text, title="help output", border_style="dim"))
    console.print(Panel(body, title="[bold]2. Stimuli - what it expects[/bold]", border_style="magenta"))

    # 3. Behaviour
    bt = Table(show_header=True, box=None, header_style="bold green")
    bt.add_column("Kind")
    bt.add_column("Values")
    if beh.execve:
        bt.add_row("execve", "\n".join(beh.execve))
    if beh.files_read:
        bt.add_row("files read", "\n".join(beh.files_read))
    if beh.files_written:
        bt.add_row("files written", "\n".join(beh.files_written))
    if beh.files_deleted:
        bt.add_row("files deleted", "\n".join(beh.files_deleted))
    if beh.network:
        bt.add_row("network", "\n".join(beh.network))
    if beh.stdout_output:
        bt.add_row("stdout", "\n".join(beh.stdout_output))
    if beh.stderr_output:
        bt.add_row("stderr", "\n".join(beh.stderr_output))
    if beh.exit_codes:
        bt.add_row("exit codes", "\n".join(beh.exit_codes))
    if beh.api_trace:
        bt.add_row("API trace", " -> ".join(beh.api_trace[:20]))
    if beh.emulation_stop:
        bt.add_row("emulation stop", beh.emulation_stop)
    if beh.note:
        bt.add_row("registry", beh.note)
    if not any([beh.execve, beh.files_read, beh.files_written, beh.files_deleted,
                beh.network, beh.stdout_output, beh.stderr_output, beh.exit_codes,
                beh.api_trace, beh.emulation_stop, beh.note]):
        bt.add_row("-", "no significant action observed")
    console.print(Panel(bt, title="[bold]3. Behaviour - what it really does[/bold]", border_style="green"))

    # 4. Capabilities
    ct = Table(show_header=False, box=None)
    ct.add_column(style="bold")
    ct.add_column()
    if caps.dlls:
        ct.add_row("DLLs", ", ".join(caps.dlls))
    if caps.api_categories:
        cat_lines = [f"{cat}: {', '.join(apis)}" for cat, apis in caps.api_categories.items()]
        ct.add_row("APIs by category", "\n".join(cat_lines))
    if caps.imports and not caps.api_categories:
        ct.add_row("imports", ", ".join(caps.imports))
    if caps.strings_summary:
        ct.add_row("strings summary", "\n".join(caps.strings_summary))
    if caps.notable_ascii_strings:
        ct.add_row("notable strings (ASCII)", "\n".join(caps.notable_ascii_strings))
    if caps.unicode_strings:
        ct.add_row("notable strings (UTF-16)", "\n".join(caps.unicode_strings[:15]))
    if caps.interesting_strings and not caps.notable_ascii_strings:
        ct.add_row("notable strings", "\n".join(caps.interesting_strings))
    ct.add_row("capa", "available" if caps.tools_available.get("capa") else "not installed")
    ct.add_row("floss", "available" if caps.tools_available.get("floss") else "not installed")
    if caps.note:
        ct.add_row("note", caps.note)
    console.print(Panel(ct, title="[bold]4. Static capabilities & hints[/bold]", border_style="yellow"))

    # 5. Synthesis + Next steps
    syn = Text()
    for b in result.synthesis:
        syn.append("- ", style="bold")
        syn.append(b + "\n")
    steps = build_next_steps(result)
    if steps:
        syn.append("\nNext steps:\n", style="bold cyan")
        for s in steps:
            syn.append("  -> ", style="cyan")
            syn.append(s + "\n")
    console.print(Panel(syn, title="[bold]5. Analyst synthesis[/bold]", border_style="bright_blue"))

    if explain:
        et = Table(show_header=False, box=None, pad_edge=False)
        et.add_column(style="bold magenta", no_wrap=True)
        et.add_column()
        for term, desc in build_explanations(result):
            et.add_row(term, desc)
        console.print(Panel(et, title="[bold]6. Beginner guide (--explain)[/bold]", border_style="magenta"))

    if result.warnings:
        for w in result.warnings:
            console.print(f"[yellow]! {w}[/yellow]")


# --------------------------------------------------------------------------- #
# Exports
# --------------------------------------------------------------------------- #

def to_json(result: AnalysisResult) -> str:
    data = asdict(result)
    return json.dumps(data, indent=2, ensure_ascii=False)


def to_markdown(result: AnalysisResult) -> str:
    idn = result.identity
    prot = result.protections
    stim = result.stimuli
    beh = result.behavior
    caps = result.capabilities
    lines: List[str] = []
    lines.append("# binscope report\n")
    lines.append("## 1. Identity\n")
    lines.append(f"- **Path**: `{idn.path}`")
    if idn.format == "PE":
        lines.append(f"- **Arch**: {idn.arch} ({idn.bits}-bit)")
        lines.append(f"- **Type**: {idn.elf_type}")
        lines.append(f"- **Subsystem**: {idn.subsystem or '-'}")
        sec_lbl = f"{idn.max_entropy_section}=" if idn.max_entropy_section else "max entropy "
        lines.append(f"- **Sections**: {idn.sections} ({sec_lbl}{idn.max_entropy}"
                     + (" - **possibly packed/encrypted**)" if idn.packed_alert else ")"))
        lines.append(f"- **Timestamp**: {idn.timestamp or '-'}")
        lines.append(f"- **PDB path**: `{idn.pdb_path or '-'}`")
    else:
        lines.append(f"- **Arch**: {idn.bits} {idn.arch} ({idn.endianness} endian)")
        lines.append(f"- **Type**: {idn.elf_type}")
        lines.append(f"- **Interpreter**: {idn.interp or '-'}")
        lines.append(f"- **Stripped**: {'Yes' if idn.stripped else 'No' if idn.stripped is not None else '?'}")
    lines.append(f"- **Size**: {idn.size} bytes")
    lines.append(f"- **SHA256**: `{idn.sha256}`\n")
    lines.append("### Protections\n")
    if idn.format == "PE":
        lines.append(f"- ASLR: {_yn(prot.aslr)}")
        lines.append(f"- DEP/NX: {_yn(prot.dep)}")
        lines.append(f"- CFG: {_yn(prot.cfg)}")
        lines.append(f"- SafeSEH: {_yn(prot.safeseh)}")
        lines.append(f"- HighEntropyVA: {_yn(prot.high_entropy_va)}\n")
    else:
        lines.append(f"- PIE: {_yn(prot.pie)}")
        lines.append(f"- NX: {_yn(prot.nx)}")
        lines.append(f"- Canary: {_yn(prot.canary)}")
        lines.append(f"- RELRO: {prot.relro or '?'}")
        lines.append(f"- FORTIFY: {_yn(prot.fortify)}\n")

    lines.append("## 2. Stimuli - what it expects\n")
    if stim.argv:
        lines.append(f"- **argv**: {', '.join('`'+a+'`' for a in stim.argv)}")
    if stim.env_vars:
        lines.append(f"- **env vars**: {', '.join('`'+e+'`' for e in stim.env_vars)}")
    if stim.files:
        lines.append(f"- **files checked**: {', '.join('`'+f+'`' for f in stim.files)}")
    if stim.missing_files:
        lines.append(f"- **missing files**: {', '.join('`'+f+'`' for f in stim.missing_files)}")
    if stim.comparisons:
        lines.append(f"- **string comparisons**: {', '.join('`'+c+'`' for c in stim.comparisons)}")
    if stim.input_apis:
        lines.append(f"- **input APIs**: {', '.join('`'+a+'`' for a in stim.input_apis)}")
    if stim.numeric_probes:
        lines.append(f"- **numeric input**: {', '.join('`'+n+'`' for n in stim.numeric_probes)}")
    if stim.argc_expected is not None:
        lines.append(f"- **argc**: expects ~{stim.argc_expected} argument(s)")
    if stim.trigger_notes:
        lines.append("- **behaviour change**: " + "; ".join(f"`{c}`" for c in stim.trigger_notes))
    if stim.exit_code_changes:
        lines.append("- **exit code trigger**: " + "; ".join(f"`{c}`" for c in stim.exit_code_changes))
    if stim.output_changes:
        lines.append("- **output trigger**: " + "; ".join(f"`{c}`" for c in stim.output_changes))
    if stim.stdin_expected:
        lines.append("- **stdin**: expected")
    if not any([stim.argv, stim.env_vars, stim.files, stim.missing_files, stim.comparisons,
                stim.numeric_probes, stim.exit_code_changes, stim.output_changes,
                stim.input_apis, stim.argc_expected is not None, stim.stdin_expected]):
        lines.append("- No specific stimulus detected.")
    if stim.note:
        lines.append(f"- **note**: {stim.note}")
    if stim.help_text:
        lines.append("\n### Help output\n")
        lines.append("```\n" + stim.help_text + "\n```")
    lines.append("")

    lines.append("## 3. Behaviour - what it really does\n")
    if beh.execve:
        lines.append("- **execve**:")
        for e in beh.execve:
            lines.append(f"  - `{e}`")
    if beh.files_read:
        lines.append(f"- **files read**: {', '.join('`'+f+'`' for f in beh.files_read)}")
    if beh.files_written:
        lines.append(f"- **files written**: {', '.join('`'+f+'`' for f in beh.files_written)}")
    if beh.files_deleted:
        lines.append(f"- **files deleted**: {', '.join('`'+f+'`' for f in beh.files_deleted)}")
    if beh.network:
        lines.append(f"- **network**: {', '.join('`'+n+'`' for n in beh.network)}")
    if beh.stdout_output:
        lines.append("- **stdout output**:")
        for s in beh.stdout_output:
            lines.append(f"  - `{s}`")
    if beh.stderr_output:
        lines.append("- **stderr output**:")
        for s in beh.stderr_output:
            lines.append(f"  - `{s}`")
    if beh.exit_codes:
        lines.append(f"- **exit codes**: {', '.join('`'+e+'`' for e in beh.exit_codes)}")
    if beh.api_trace:
        lines.append("- **API trace**: " + " -> ".join(f"`{a}`" for a in beh.api_trace[:20]))
    if beh.emulation_stop:
        lines.append(f"- **emulation stop**: `{beh.emulation_stop}`")
    if beh.note:
        lines.append(f"- **registry**: {beh.note}")
    if not any([beh.execve, beh.files_read, beh.files_written, beh.files_deleted,
                beh.network, beh.stdout_output, beh.stderr_output, beh.exit_codes,
                beh.api_trace, beh.emulation_stop, beh.note]):
        lines.append("- No significant action observed.")
    lines.append("")

    lines.append("## 4. Static capabilities & hints\n")
    if caps.dlls:
        lines.append(f"- **DLLs**: {', '.join('`'+d+'`' for d in caps.dlls)}")
    if caps.api_categories:
        lines.append("- **APIs by category**:")
        for cat, apis in caps.api_categories.items():
            lines.append(f"  - **{cat}**: {', '.join('`'+a+'`' for a in apis)}")
    if caps.imports and not caps.api_categories:
        lines.append(f"- **imports**: {', '.join('`'+i+'`' for i in caps.imports)}")
    if caps.strings_summary:
        lines.append("- **strings summary**:")
        for s in caps.strings_summary:
            lines.append(f"  - `{s}`")
    if caps.notable_ascii_strings:
        lines.append("- **notable strings (ASCII)**:")
        for s in caps.notable_ascii_strings:
            lines.append(f"  - `{s}`")
    if caps.unicode_strings:
        lines.append("- **notable strings (UTF-16)**:")
        for s in caps.unicode_strings[:15]:
            lines.append(f"  - `{s}`")
    if caps.interesting_strings and not caps.notable_ascii_strings:
        lines.append("Notable strings:\n")
        for s in caps.interesting_strings:
            lines.append(f"- `{s}`")
    lines.append(f"\n- capa: {'available' if caps.tools_available.get('capa') else 'not installed'}")
    lines.append(f"- floss: {'available' if caps.tools_available.get('floss') else 'not installed'}\n")

    lines.append("## 5. Analyst synthesis\n")
    for b in result.synthesis:
        lines.append(f"- {b}")
    steps = build_next_steps(result)
    if steps:
        lines.append("\n### Next steps\n")
        for s in steps:
            lines.append(f"- {s}")
    lines.append("")
    return "\n".join(lines)
