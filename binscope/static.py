"""Static analysis: identity, protections and interesting strings.

All parsing is defensive: missing tools or unexpected output degrade to
``None``/empty values instead of raising, so ``binscope`` never crashes on a
weird binary.

Every external tool is invoked with ``LC_ALL=C``/``LANG=C`` so that parsing is
immune to the analyst's locale (localized ``readelf``/``file`` output used to
break the arch/bits/endianness extraction).
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
from typing import List, Optional

from .model import Capabilities, Identity, Protections

# Strings that usually reveal something an analyst cares about.
_INTERESTING_RE = re.compile(
    r"(/bin/|/usr/bin/|/etc/|/tmp/|/dev/|/sbin/|flag|password|passwd|"
    r"secret|token|http://|https://|ftp://|ssh|/bin/sh|cmd|shell|"
    r"RUN_|ENV_|\.sh\b|\.py\b|\.conf\b|\.log\b)",
    re.IGNORECASE,
)

# printf/scanf-style conversion specifiers inside a string.
_FORMAT_RE = re.compile(r"%[-#0-9.*lh]*[diouxXeEfFgGcspn]")
_URL_RE = re.compile(r"\b(?:https?|ftp|ssh|tcp|udp)://\S+", re.IGNORECASE)
_PATH_RE = re.compile(r"(?:^|\s)(/(?:bin|usr|etc|tmp|var|opt|home|root|dev|proc|sys)\S*)")

# Include-search paths left behind by the toolchain in DWARF - not analyst value.
_DWARF_PATH_RE = re.compile(r"^/(?:usr/)?(?:include|lib)/")

# Symbols that are pure C runtime plumbing, never interesting to an analyst.
_IMPORT_NOISE = {
    "__libc_start_main",
    "__gmon_start__",
    "_ITM_deregisterTMCloneTable",
    "_ITM_registerTMCloneTable",
    "__cxa_finalize",
}

# Toolchain/GCC strings that add no analyst value.
_GCC_NOISE_RE = re.compile(
    r"(GCC:|GNU C\d|GNU C\+\+|clang version|GLIBC_\d|\.c$|\.h$|\.o$|"
    r"\.debug_|\.eh_frame|\.symtab|\.strtab|\.gnu\.|__FRAME|\.note\b|"
    r"\.comment|\.shstrtab|\.dynstr|\.dynsym|\.rodata|\.text\b)",
    re.IGNORECASE,
)

_MESSAGE_RE = re.compile(
    r"(usage|error|invalid|denied|accept|grant|forbidden|success|fail|"
    r"welcome|flag|secret|password|unlock|correct|wrong|access|abort|"
    r"not found|try again|exit|usage:)",
    re.IGNORECASE,
)


def _run(cmd: List[str], timeout: int = 20) -> str:
    env = dict(os.environ)
    env.update({"LC_ALL": "C", "LANG": "C", "LANGUAGE": "C"})
    try:
        out = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            errors="replace",
            env=env,
        )
        return out.stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def _has(tool: str) -> bool:
    return shutil.which(tool) is not None


def sha256_file(path: str, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def analyze_identity(path: str) -> Identity:
    ident = Identity(path=path)
    try:
        ident.size = os.path.getsize(path)
    except OSError:
        ident.size = 0
    try:
        ident.sha256 = sha256_file(path)
    except OSError:
        ident.sha256 = ""

    ident.file_type = _run(["file", "-b", path]).strip()

    header = _run(["readelf", "-hW", path])
    # Class is rendered as "ELF64"/"ELF32" (or "32-bit"/"64-bit" locally);
    # keep only the numeric bit width.
    m = re.search(r"Class:\s+.*?(\d{2})", header)
    if m:
        ident.bits = m.group(1)
    m = re.search(r"Data:\s+.*?(little|big)\s+endian", header)
    if m:
        ident.endianness = m.group(1)
    m = re.search(r"Type:\s+(\S+)", header)
    if m:
        ident.elf_type = m.group(1)
    m = re.search(r"Machine:\s+(.+)", header)
    if m:
        ident.arch = m.group(1).strip()

    # Interpreter: prefer the program-header note, which is unambiguous.
    programs = _run(["readelf", "-lW", path])
    m = re.search(r"Requesting program interpreter:\s*([^\s\]]+)", programs)
    if not m:
        m = re.search(r"INTERP\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(\S+)", programs)
    if not m:
        m = re.search(r"interpreter\s+(\S+)", ident.file_type)
    if m:
        # Strip trailing punctuation that `file` appends (e.g. a comma).
        ident.interp = m.group(1).rstrip(",;.")

    # Stripped detection: `file` is authoritative, symbol table is the fallback.
    ft = ident.file_type.lower()
    if "not stripped" in ft:
        ident.stripped = False
    elif "stripped" in ft:
        ident.stripped = True
    else:
        syms = _run(["readelf", "-sW", path])
        ident.stripped = not bool(re.search(r"\bFUNC\b", syms))

    if not ident.arch:
        m = re.search(r"([a-zA-Z0-9_]+)\s*$", ident.file_type)
        if m:
            ident.arch = m.group(1)
    return ident


def analyze_protections(path: str) -> Protections:
    prot = Protections()
    programs = _run(["readelf", "-lW", path])
    dynamic = _run(["readelf", "-dW", path])
    symbols = _run(["readelf", "-sW", path]) + _run(["readelf", "--dyn-syms", "-W", path])
    strings_blob = _run(["strings", "-a", path])

    # NX: a GNU_STACK segment without the execute flag means NX is enforced.
    stack_line = ""
    for line in programs.splitlines():
        if "GNU_STACK" in line:
            stack_line = line
            break
    if stack_line:
        flags_part = stack_line.split()[-2] if len(stack_line.split()) >= 2 else ""
        prot.nx = "E" not in flags_part.upper()

    # PIE: ET_DYN executables are position independent.
    header = _run(["readelf", "-hW", path])
    m = re.search(r"Type:\s+(\S+)", header)
    if m:
        prot.pie = m.group(1).upper() == "DYN"

    # Canary: the stack-check failure handler must be linked in.
    prot.canary = bool(
        re.search(r"__stack_chk_fail", symbols)
        or re.search(r"__stack_chk_fail", strings_blob)
    )

    # RELRO: presence of a GNU_RELRO segment; full when BIND_NOW is set.
    has_relro = "GNU_RELRO" in programs
    bind_now = bool(
        re.search(r"BIND_NOW", dynamic) or re.search(r"FLAGS_1.*NOW", dynamic)
    )
    prot.bind_now = bind_now
    if has_relro:
        prot.relro = "Full" if bind_now else "Partial"
    elif programs:
        prot.relro = "None"

    # FORTIFY_SOURCE leaves *_chk symbols behind.
    prot.fortify = bool(re.search(r"__\w+_chk\b", symbols))
    return prot


def analyze_capabilities(path: str) -> Capabilities:
    caps = Capabilities()
    caps.tools_available = {
        "strings": _has("strings"),
        "capa": _has("capa"),
        "floss": _has("floss"),
    }

    raw = _run(["strings", "-a", "-n", "5", path])
    lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
    # De-duplicate while keeping order, cap the volume.
    seen = set()
    uniq: List[str] = []
    for ln in lines:
        if ln not in seen:
            seen.add(ln)
            uniq.append(ln)
    caps.strings = uniq[:200]
    caps.interesting_strings = [
        s for s in uniq
        if _INTERESTING_RE.search(s)
        and not re.fullmatch(r"_[A-Za-z0-9_]+", s)  # struct/DWARF field names
    ][:40]

    caps.imports = _analyze_imports(path)
    caps.strings_summary = _summarize_strings(uniq)

    if caps.tools_available["capa"]:
        caps.capa = _run_capa(path)
    if caps.tools_available["floss"]:
        caps.floss = _run_floss(path)

    if not caps.tools_available["capa"] and not caps.tools_available["floss"]:
        caps.note = "capa/floss not installed - static capability summary limited to imports and strings."
    return caps


def _analyze_imports(path: str) -> List[str]:
    """Interesting dynamic symbols the binary imports (nm -D or readelf --dyn-syms)."""
    names: List[str] = []
    out = _run(["nm", "-D", "--undefined-only", path])
    if out:
        for line in out.splitlines():
            parts = line.split()
            if parts:
                names.append(parts[-1])
    else:
        out = _run(["readelf", "--dyn-syms", "-W", path])
        for line in out.splitlines():
            m = re.search(r"\bUND\b\s+(\S+)$", line)
            if m:
                names.append(m.group(1))

    result: List[str] = []
    for n in names:
        base = n.split("@", 1)[0]
        if not base or base in _IMPORT_NOISE:
            continue
        if base.startswith("_") and base.endswith("@"):
            continue
        if base not in result:
            result.append(base)
    return result[:40]


def _summarize_strings(uniq: List[str]) -> List[str]:
    """A concise, de-noised digest of notable strings (no GCC/toolchain spam)."""
    summary: List[str] = []
    seen = set()

    def add(s: str) -> None:
        if s and s not in seen:
            seen.add(s)
            summary.append(s)

    for s in uniq:
        if _GCC_NOISE_RE.search(s) or len(s) < 4:
            continue
        if _URL_RE.search(s):
            add(f"url: {s.strip()}")
            continue
        for fmt in _FORMAT_RE.findall(s):
            add(f"format: {fmt}  ({s.strip()[:60]})")
            break
        pm = _PATH_RE.search(s)
        if pm:
            if not _DWARF_PATH_RE.match(pm.group(1)):
                add(f"path: {pm.group(1)}")
            continue
        if _MESSAGE_RE.search(s) and " " in s:
            add(f"message: {s.strip()[:80]}")
    return summary[:40]


def _run_capa(path: str) -> Optional[dict]:
    out = _run(["capa", "-q", path], timeout=120)
    if not out:
        return None
    findings = [ln.strip() for ln in out.splitlines() if ln.strip()]
    return {"count": len(findings), "top": findings[:30]}


def _run_floss(path: str) -> Optional[List[str]]:
    out = _run(["floss", "-q", path], timeout=120)
    if not out:
        return None
    return [ln.strip() for ln in out.splitlines() if ln.strip()][:40]
