"""Static analysis: identity, protections and interesting strings.

All parsing is defensive: missing tools or unexpected output degrade to
``None``/empty values instead of raising, so ``binscope`` never crashes on a
weird binary.
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


def _run(cmd: List[str], timeout: int = 20) -> str:
    try:
        out = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            errors="replace",
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
    m = re.search(r"Class:\s+(\S+)", header)
    if m:
        ident.bits = m.group(1)
    m = re.search(r"Data:\s+.*?(little|big) endian", header)
    if m:
        ident.endianness = m.group(1)
    m = re.search(r"Type:\s+(\S+)", header)
    if m:
        ident.elf_type = m.group(1)
    m = re.search(r"Machine:\s+(.+)", header)
    if m:
        ident.arch = m.group(1).strip()

    programs = _run(["readelf", "-lW", path])
    m = re.search(r"INTERP\s+.*?(/lib[^\s,]*)", programs)
    if not m:
        m = re.search(r"interpreter\s+(/\S+)", ident.file_type)
    if m:
        ident.interp = m.group(1)

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

    if caps.tools_available["capa"]:
        caps.capa = _run_capa(path)
    if caps.tools_available["floss"]:
        caps.floss = _run_floss(path)

    if not caps.tools_available["capa"] and not caps.tools_available["floss"]:
        caps.note = "capa/floss not installed - static capability summary limited to strings."
    return caps


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
