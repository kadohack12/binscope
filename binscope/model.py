"""Data model shared by the analysis passes and the report renderers."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class Identity:
    path: str = ""
    arch: str = ""
    elf_type: str = ""
    bits: str = ""
    endianness: str = ""
    stripped: Optional[bool] = None
    interp: str = ""
    size: int = 0
    sha256: str = ""
    file_type: str = ""
    # PE-specific
    format: str = ""  # "ELF" or "PE"
    subsystem: str = ""
    sections: int = 0
    max_entropy: float = 0.0
    packed_alert: bool = False
    timestamp: str = ""
    pdb_path: str = ""


@dataclass
class Protections:
    nx: Optional[bool] = None
    pie: Optional[bool] = None
    canary: Optional[bool] = None
    relro: Optional[str] = None
    fortify: Optional[bool] = None
    bind_now: Optional[bool] = None
    # PE-specific
    aslr: Optional[bool] = None
    dep: Optional[bool] = None
    cfg: Optional[bool] = None
    safeseh: Optional[bool] = None
    high_entropy_va: Optional[bool] = None


@dataclass
class Stimuli:
    """Everything the binary appears to *wait for* as input."""

    argv: List[str] = field(default_factory=list)
    env_vars: List[str] = field(default_factory=list)
    files: List[str] = field(default_factory=list)
    missing_files: List[str] = field(default_factory=list)
    comparisons: List[str] = field(default_factory=list)
    stdin_expected: bool = False
    stdin_patterns: List[str] = field(default_factory=list)
    numeric_probes: List[str] = field(default_factory=list)
    argc_expected: Optional[int] = None
    exit_code_changes: List[str] = field(default_factory=list)
    output_changes: List[str] = field(default_factory=list)
    help_text: str = ""
    note: str = ""
    # PE-specific (emulation)
    input_apis: List[str] = field(default_factory=list)
    trigger_notes: List[str] = field(default_factory=list)


@dataclass
class Behavior:
    """Everything the binary *does* once it runs."""

    execve: List[str] = field(default_factory=list)
    files_read: List[str] = field(default_factory=list)
    files_written: List[str] = field(default_factory=list)
    files_deleted: List[str] = field(default_factory=list)
    network: List[str] = field(default_factory=list)
    stdout_output: List[str] = field(default_factory=list)
    stderr_output: List[str] = field(default_factory=list)
    exit_codes: List[str] = field(default_factory=list)
    note: str = ""

@dataclass
class Capabilities:
    strings: List[str] = field(default_factory=list)
    interesting_strings: List[str] = field(default_factory=list)
    strings_summary: List[str] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    capa: Optional[dict] = None
    floss: Optional[List[str]] = None
    tools_available: Dict[str, bool] = field(default_factory=dict)
    note: str = ""
    # PE-specific
    dlls: List[str] = field(default_factory=list)
    api_categories: Dict[str, List[str]] = field(default_factory=dict)
    unicode_strings: List[str] = field(default_factory=list)
    notable_ascii_strings: List[str] = field(default_factory=list)


@dataclass
class RunResult:
    """Result of a single stimulation pass."""

    label: str = ""
    argv: List[str] = field(default_factory=list)
    env: Dict[str, str] = field(default_factory=dict)
    stdin: str = ""
    exit_code: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    stdin_read: bool = False
    stub: Optional[str] = None
    new_files: List[str] = field(default_factory=list)
    files_written: List[str] = field(default_factory=list)
    files_read: List[str] = field(default_factory=list)
    connect_success: List[str] = field(default_factory=list)
    execve: List[str] = field(default_factory=list)
    timed_out: bool = False


@dataclass
class AnalysisResult:
    identity: Identity = field(default_factory=Identity)
    protections: Protections = field(default_factory=Protections)
    stimuli: Stimuli = field(default_factory=Stimuli)
    behavior: Behavior = field(default_factory=Behavior)
    capabilities: Capabilities = field(default_factory=Capabilities)
    synthesis: List[str] = field(default_factory=list)
    runs: List[RunResult] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
