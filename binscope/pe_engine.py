"""Windows PE backend: static parsing (``pefile``) + emulation (``speakeasy``).

Both dependencies are optional at import time. If one is missing the module
degrades gracefully: the affected section is left empty and a warning explains
what to install, so ``binscope`` keeps working on a bare machine.

Emulation runs the sample inside Speakeasy (a Unicorn-based user-mode
emulator). Because it is a *sandbox*, nothing touches the real host: file,
registry and network APIs are intercepted and only reported. That makes the
Windows side safe to run even on live malware.
"""

from __future__ import annotations

import math
import os
import re
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from .model import Behavior, Capabilities, Identity, Protections, RunResult, Stimuli
from .static import (
    _GCC_NOISE_RE,
    _INTERESTING_RE,
    _MESSAGE_RE,
    _URL_RE,
    _run,
    _has,
    sha256_file,
)

try:  # pragma: no cover - exercised implicitly by the test-suite
    import pefile
except Exception:  # pragma: no cover
    pefile = None

try:  # pragma: no cover
    import speakeasy
except Exception:  # pragma: no cover
    speakeasy = None


# --------------------------------------------------------------------------- #
# DllCharacteristics flags (IMAGE_DLLCHARACTERISTICS_*)
# --------------------------------------------------------------------------- #

_DYNAMIC_BASE = 0x0040
_HIGH_ENTROPY_VA = 0x0020
_NX_COMPAT = 0x0100
_GUARD_CF = 0x4000
_NO_SEH = 0x0400

_ENTROPY_ALERT = 7.0

_MACHINE = {
    0x014C: ("x86", "32"),
    0x8664: ("x64", "64"),
    0x01C0: ("ARM", "32"),
    0x01C4: ("ARMv7", "32"),
    0xAA64: ("ARM64", "64"),
}

_SUBSYSTEM = {
    1: "Native",
    2: "GUI",
    3: "Console",
    5: "OS/2 Console",
    7: "POSIX Console",
    9: "Windows CE GUI",
    10: "EFI Application",
}

# API name -> category. Matched case-insensitively, longest prefix wins.
_API_CATEGORIES: Dict[str, Tuple[str, ...]] = {
    "Process": (
        "createprocess", "winexec", "shellexecute", "system", "createthread",
        "openprocess", "terminateprocess", "resumethread", "createremotethread",
        "setthreadcontext", "writeprocessmemory", "virtualalloc",
    ),
    "File": (
        "createfile", "readfile", "writefile", "deletefile", "copyfile",
        "movefile", "findfirstfile", "findnextfile", "gettemppath",
        "getmodulefilename", "getsystemdirectory", "getwindowsdirectory",
        "setfileattributes", "createdirectory", "fopen", "fwrite", "fread",
        "fgets", "remove", "unlink",
    ),
    "Registry": (
        "regopenkey", "regcreatekey", "regsetvalue", "regqueryvalue",
        "regdeletekey", "regdeletevalue", "reggetvalue", "regenumkey",
        "regclosekey",
    ),
    "Network": (
        "socket", "connect", "bind", "listen", "accept", "send", "recv",
        "wsastartup", "internetopen", "internetconnect", "httpopenrequest",
        "httpsendrequest", "urldownloadtofile", "gethostbyname", "inet_addr",
        "htons", "winhttp", "wsaconnect", "getaddrinfo", "closesocket",
    ),
    "Anti-Debug": (
        "isdebuggerpresent", "checkremotedebuggerpresent",
        "ntqueryinformationprocess", "outputdebugstring", "gettickcount",
        "queryperformancecounter", "ntglobalflag", "createtoolhelp32snapshot",
        "gettickcount64",
    ),
    "GUI": (
        "messagebox", "createwindowex", "getwindowtext", "setwindowtext",
        "dialogbox", "getdlgitemtext", "getforegroundwindow", "findwindow",
    ),
    "Crypto": ("crypt", "bcrypt", "ncrypt"),
    "Service": ("openscmanager", "createservice", "startservice", "controlservice"),
    "Environment": (
        "getenvironmentvariable", "getcommandline", "getcomputername",
        "getusername", "getsysteminfo", "expandenvironmentstrings",
    ),
    "Process-Injection": (
        "virtualprotect", "createtoolhelp32snapshot", "module32first",
        "loadlibrary", "getprocaddress", "queueuserapc", "setwindowshookex",
    ),
}

# APIs that indicate the binary *reads* something from its environment/input.
_INPUT_APIS = (
    "getcommandline", "getenvironmentvariable", "lstrcmp", "getwindowtext",
    "isdebuggerpresent", "strcmp", "strncmp", "memcmp", "strstr", "strchr",
    "regqueryvalue", "reggetvalue", "regopenkey", "getdlgitemtext",
    "getmodulefilename", "gettemppath",
)

# APIs whose string arguments reveal intent (message boxes, console writes).
_MESSAGE_APIS = (
    "messagebox", "writeconsole", "outputdebugstring", "putchar", "puts",
    "printf", "fputs",
)

# APIs that spawn a child process.
_EXEC_APIS = ("createprocess", "winexec", "shellexecute", "system")

# APIs that touch the network.
_NET_APIS = (
    "socket", "connect", "bind", "listen", "accept", "send", "recv",
    "wsastartup", "internetopen", "internetconnect", "httpopenrequest",
    "urldownloadtofile", "wsaconnect", "getaddrinfo",
)

# C-runtime / emulator plumbing that is never interesting to an analyst.
_API_NOISE = re.compile(
    r"^(?:_initterm|_onexit|malloc|free|calloc|realloc|exit|_exit|__\w+|"
    r"initializecriticalsection|setunhandledexceptionfilter|"
    r"gettlsvalue|settlsvalue|tlssetvalue|tlsgetvalue|"
    r"getlastError|setlasterror|rtlcapturecontext|encodePointer|"
    r"initializeSlistHead|isprocessorfeaturepresent|"
    r"getsystemtimeasfiletime|queryperformancecounter|getcurrentthreadid|"
    r"getcurrentprocessid|getcurrentprocess|getsysteminfo)",
    re.IGNORECASE,
)

# Argument-indexed "interesting literal" positions per API family.
_STR_ARG_HINT = re.compile(r"^[ -~]{3,}$")

# C-runtime / MinGW-w64 plumbing strings that carry no analyst value.
_PE_NOISE_RE = re.compile(
    r"^(?:Mingw-w64 runtime failure|Argument domain error|Overflow range error|"
    r"Partial loss of precision|Total loss of precision|Underflow range error|"
    r"Unknown error|Argument singularity|VirtualQuery failed|VirtualProtect failed|"
    r"_amsg_exit|_cexit|_onexit|abort|GetLastError|ErrorOpcode|ExceptionFlags|"
    r"ContextFlags|EFlags|_onexit_t|_invalid_parameter_handler|C Lexit|"
    r"program_invocation|__\w+)",
    re.IGNORECASE,
)

# A bare C identifier (single token, no spaces/punctuation).
_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# Strong keywords worth keeping even as a bare lowercase token.
_STRONG_KEYWORD_RE = re.compile(
    r"\b(?:flag|secret|password|passwd|token|shell|payload|admin|root|key)\b",
    re.IGNORECASE,
)

# Junk prefixes on DWARF/symbol leftovers ("( _onexit", "1abort", "$__mingw...").
_JUNK_PREFIX = '(["_$?0123456789@*'
_DRIVE_PATH_RE = re.compile(r"^[A-Za-z]:\\")
_PWLIKE_RE = re.compile(r"^[a-z0-9_]{3,20}$")


def _categorize(api: str) -> str:
    low = api.lower()
    for cat, prefixes in _API_CATEGORIES.items():
        for p in prefixes:
            if p in low:
                return cat
    return "Other"


def _ts_to_str(stamp: int) -> str:
    if not stamp:
        return ""
    try:
        return datetime.fromtimestamp(stamp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (OverflowError, OSError, ValueError):
        return str(stamp)


# --------------------------------------------------------------------------- #
# Static analysis (pefile)
# --------------------------------------------------------------------------- #

def analyze_pe_identity(path: str) -> Identity:
    ident = Identity(path=path, format="PE")
    try:
        ident.size = os.path.getsize(path)
    except OSError:
        ident.size = 0
    try:
        ident.sha256 = sha256_file(path)
    except OSError:
        ident.sha256 = ""

    if pefile is None:
        ident.file_type = _run(["file", "-b", path]).strip()
        return ident

    try:
        pe = pefile.PE(path, fast_load=False)
    except Exception:
        ident.file_type = _run(["file", "-b", path]).strip()
        return ident

    try:
        machine = pe.FILE_HEADER.Machine
        arch, bits = _MACHINE.get(machine, (hex(machine), ""))
        ident.arch = arch
        ident.bits = bits
        ident.endianness = "little"
        base_type = "PE32+" if pe.OPTIONAL_HEADER.Magic == 0x20B else "PE32"
        is_dll = bool(pe.FILE_HEADER.Characteristics & 0x2000)
        ident.elf_type = base_type + (" DLL" if is_dll else "")
        ident.subsystem = _SUBSYSTEM.get(pe.OPTIONAL_HEADER.Subsystem, f"#{pe.OPTIONAL_HEADER.Subsystem}")
        ident.timestamp = _ts_to_str(pe.FILE_HEADER.TimeDateStamp)

        sections = list(pe.sections)
        ident.sections = len(sections)
        entropies = []
        for s in sections:
            try:
                entropies.append(s.get_entropy())
            except Exception:
                pass
        if entropies:
            ident.max_entropy = round(max(entropies), 2)
            ident.packed_alert = ident.max_entropy > _ENTROPY_ALERT

        ident.pdb_path = _pe_pdb_path(pe)
        # `file` gives a nice one-liner for the report when available.
        ft = _run(["file", "-b", path]).strip()
        ident.file_type = ft or ident.elf_type
    finally:
        try:
            pe.close()
        except Exception:
            pass
    return ident


def _pe_pdb_path(pe) -> str:
    """Extract the PDB path from the debug directory, if present."""
    try:
        if not hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
            return ""
        for entry in pe.DIRECTORY_ENTRY_DEBUG:
            if entry.struct.Type != 2:  # IMAGE_DEBUG_TYPE_CODEVIEW
                continue
            data = entry.entry
            if getattr(data, "PdbFileName", None):
                name = data.PdbFileName
                if isinstance(name, bytes):
                    name = name.split(b"\x00", 1)[0].decode("utf-8", "replace")
                return name
    except Exception:
        return ""
    return ""


def analyze_pe_protections(path: str) -> Protections:
    prot = Protections()
    if pefile is None:
        return prot
    try:
        pe = pefile.PE(path, fast_load=False)
    except Exception:
        return prot
    try:
        dll = pe.OPTIONAL_HEADER.DllCharacteristics
        prot.aslr = bool(dll & _DYNAMIC_BASE)
        prot.dep = bool(dll & _NX_COMPAT)
        prot.nx = prot.dep
        prot.cfg = bool(dll & _GUARD_CF)
        prot.high_entropy_va = bool(dll & _HIGH_ENTROPY_VA)
        prot.pie = prot.aslr  # closest ELF analogue
        # SafeSEH: only meaningful on 32-bit; present when NO_SEH is clear and
        # the load config has a SEHandlerTable. Absent NO_SEH on x64 is normal.
        if pe.FILE_HEADER.Machine == 0x014C:
            prot.safeseh = not bool(dll & _NO_SEH)
    except Exception:
        pass
    finally:
        try:
            pe.close()
        except Exception:
            pass
    return prot


def analyze_pe_capabilities(path: str) -> Capabilities:
    caps = Capabilities()
    caps.tools_available = {
        "strings": _has("strings"),
        "capa": _has("capa"),
        "floss": _has("floss"),
    }

    if pefile is not None:
        dlls, imports = _pe_imports(path)
        caps.dlls = dlls
        caps.imports = imports
        categories: Dict[str, List[str]] = {}
        for api in imports:
            categories.setdefault(_categorize(api), []).append(api)
        # Drop the "Other" bucket if it is just C-runtime noise.
        caps.api_categories = {
            k: sorted(set(v)) for k, v in sorted(categories.items()) if k != "Other"
        }

    ascii_strings, unicode_strings = _pe_strings(path)
    caps.strings = ascii_strings[:200]
    caps.unicode_strings = unicode_strings[:60]
    caps.interesting_strings = _interesting(ascii_strings + unicode_strings)
    caps.strings_summary = _summarize(ascii_strings, unicode_strings)

    if caps.tools_available["capa"]:
        caps.capa = _run_capa(path)
    if caps.tools_available["floss"]:
        caps.floss = _run_floss(path)

    if not caps.tools_available["capa"] and not caps.tools_available["floss"]:
        caps.note = ("capa/floss not installed - static capability summary limited to "
                     "imports, API categories and strings.")
    return caps


def _pe_imports(path: str) -> Tuple[List[str], List[str]]:
    dlls: List[str] = []
    apis: List[str] = []
    try:
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
        )
    except Exception:
        return dlls, apis
    try:
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            dll = entry.dll.decode("utf-8", "replace")
            if dll not in dlls:
                dlls.append(dll)
            for imp in entry.imports:
                if not imp.name:
                    continue
                name = imp.name.decode("utf-8", "replace")
                if _API_NOISE.match(name):
                    continue
                if name not in apis:
                    apis.append(name)
    finally:
        try:
            pe.close()
        except Exception:
            pass
    return dlls, apis[:80]


def _pe_strings(path: str) -> Tuple[List[str], List[str]]:
    """Notable ASCII and UTF-16LE strings (Windows leans heavily on UTF-16)."""
    ascii_raw = _run(["strings", "-a", "-n", "5", path])
    unicode_raw = _run(["strings", "-a", "-n", "5", "-e", "l", path])

    def _clean(raw: str) -> List[str]:
        seen = set()
        out: List[str] = []
        for ln in raw.splitlines():
            ln = ln.strip()
            if len(ln) < 5 or ln in seen:
                continue
            if _GCC_NOISE_RE.search(ln):
                continue
            seen.add(ln)
            out.append(ln)
        return out

    return _clean(ascii_raw), _clean(unicode_raw)


def _interesting(strings: List[str]) -> List[str]:
    out: List[str] = []
    seen = set()
    for s in strings:
        if s in seen:
            continue
        if _PE_NOISE_RE.search(s):
            continue
        strong = bool(_STRONG_KEYWORD_RE.search(s))
        # Keep paths, URLs, human messages and strong keywords; drop bare
        # identifiers (C-runtime symbols, DWARF field names) and symbol
        # leftovers with a junk prefix - they are pure noise to an analyst.
        keep = (
            _INTERESTING_RE.search(s)
            or _MESSAGE_RE.search(s)
            or strong
        )
        if not keep:
            continue
        if s[0] in _JUNK_PREFIX and not _DRIVE_PATH_RE.match(s):
            continue
        if _IDENTIFIER_RE.match(s) and not strong:
            continue
        seen.add(s)
        out.append(s)
    return out[:40]


def _summarize(ascii_strings: List[str], unicode_strings: List[str]) -> List[str]:
    summary: List[str] = []
    seen = set()

    def add(s: str) -> None:
        if s and s not in seen:
            seen.add(s)
            summary.append(s)

    for s in list(ascii_strings) + list(unicode_strings):
        if _GCC_NOISE_RE.search(s) or _PE_NOISE_RE.search(s) or len(s) < 4:
            continue
        if _URL_RE.search(s):
            add(f"url: {s.strip()}")
            continue
        if re.match(r"^[A-Za-z]:\\", s) or s.startswith("\\\\"):
            add(f"path: {s.strip()[:80]}")
            continue
        if _MESSAGE_RE.search(s) and " " in s:
            add(f"message: {s.strip()[:80]}")
    return summary[:40]


def _run_capa(path: str) -> Optional[dict]:
    out = _run(["capa", "-q", path], timeout=180)
    if not out:
        return None
    findings = [ln.strip() for ln in out.splitlines() if ln.strip()]
    return {"count": len(findings), "top": findings[:30]}


def _run_floss(path: str) -> Optional[List[str]]:
    out = _run(["floss", "-q", path], timeout=180)
    if not out:
        return None
    return [ln.strip() for ln in out.splitlines() if ln.strip()][:40]


# --------------------------------------------------------------------------- #
# Dynamic analysis (speakeasy emulation)
# --------------------------------------------------------------------------- #

# Argv tokens worth trying: help switches and common CTF/malware gates.
_ARGV_TOKENS = ("--go", "-h", "--help", "1", "admin", "test", "flag", "secret")

# Environment variables a binary commonly gates on.
_ENV_PROBES = {
    "RUN_MODE": "1",
    "DEBUG": "1",
    "MODE": "1",
    "TEST": "1",
}


def _speakeasy_config(command_line: str, env: Dict[str, str], timeout: float) -> dict:
    """Build a config by extending Speakeasy's own default profile."""
    base = {}
    try:
        cfg_path = os.path.join(os.path.dirname(speakeasy.__file__), "configs", "default.json")
        import json
        with open(cfg_path, "r", encoding="utf-8") as fh:
            base = json.load(fh)
    except Exception:
        base = {"config_version": 0.2}
    base["timeout"] = max(1, int(math.ceil(timeout)))
    base["command_line"] = command_line
    env_block = dict(base.get("env") or {})
    # Speakeasy lowercases names when it resolves GetEnvironmentVariable, so
    # the config keys must be lowercase too or the lookup misses.
    env_block.update({k.lower(): v for k, v in env.items()})
    base["env"] = env_block
    return base


def _emulate(path: str, command_line: str, env: Dict[str, str],
             timeout: float) -> Tuple[List[dict], Optional[str]]:
    """Run one emulation pass; return the list of recorded API calls."""
    if speakeasy is None:
        return [], "speakeasy not installed"
    try:
        se = speakeasy.Speakeasy(config=_speakeasy_config(command_line, env, timeout))
        module = se.load_module(path)
        se.run_module(module)
        report = se.get_report()
    except Exception as exc:  # pragma: no cover - depends on sample
        return [], f"{type(exc).__name__}: {exc}"

    apis: List[dict] = []
    for ep in report.get("entry_points", []):
        for call in ep.get("apis", []):
            apis.append(call)
    return apis, None


def _api_base(name: str) -> str:
    return name.split(".", 1)[-1] if "." in name else name


def run_pe_emulation(
    path: str,
    static_strings: Optional[List[str]] = None,
    timeout: float = 4.0,
) -> Tuple[List[RunResult], Stimuli, Behavior, List[str]]:
    """Emulate the PE under Speakeasy across a few argv/env stimuli."""
    stimuli = Stimuli()
    behavior = Behavior()
    warnings: List[str] = []
    runs: List[RunResult] = []

    if speakeasy is None:
        warnings.append("speakeasy not installed - dynamic PE emulation skipped "
                        "(pip install speakeasy-emulator).")
        stimuli.note = "dynamic emulation unavailable"
        return runs, stimuli, behavior, warnings

    name = os.path.basename(path)

    # -- Pass 1: baseline, to discover consulted env vars ----------------- #
    acc = _PeBehaviorAccumulator()
    baseline_apis, err = _emulate(path, name, {}, timeout)
    discovered_env: List[str] = []
    if err and "not installed" not in err:
        warnings.append(f"emulation (baseline) failed: {err}")
    if not err:
        runs.append(RunResult(label="baseline", argv=[], env={}))
        for call in baseline_apis:
            base = _api_base(call.get("api_name", ""))
            if "getenvironmentvariable" in base.lower():
                for a in call.get("args", []):
                    if isinstance(a, str) and re.match(r"^[A-Za-z_]\w{0,30}$", a):
                        if a not in discovered_env:
                            discovered_env.append(a)
            acc.add(base, base.lower(), call.get("args", []))

    # -- Build the remaining passes: argv tokens + env (probed & discovered) #
    passes: List[Tuple[str, List[str], Dict[str, str]]] = []
    passes += [(f"argv {tok}", [tok], {}) for tok in _ARGV_TOKENS]
    env_names: List[str] = []
    for var in list(_ENV_PROBES) + discovered_env:
        if var not in env_names:
            env_names.append(var)
    for var in env_names:
        passes.append((f"env {var}=1", [], {var: "1"}))

    baseline_api_set = {c.get("api_name", "") for c in baseline_apis} if not err else set()
    env_consulted: List[str] = list(discovered_env)
    argv_hits: List[str] = []
    env_hits: List[str] = []

    for label, extra_argv, env in passes:
        cmdline = " ".join([name] + extra_argv)
        apis, err = _emulate(path, cmdline, env, timeout)
        if err:
            if "not installed" not in err:
                warnings.append(f"emulation ({label}) failed: {err}")
            continue

        run_apis = {c.get("api_name", "") for c in apis}
        runs.append(RunResult(label=label, argv=list(extra_argv), env=dict(env)))

        for call in apis:
            base = _api_base(call.get("api_name", ""))
            low = base.lower()
            if "getenvironmentvariable" in low:
                for a in call.get("args", []):
                    if isinstance(a, str) and re.match(r"^[A-Za-z_]\w{0,30}$", a):
                        if a not in env_consulted:
                            env_consulted.append(a)
            acc.add(base, low, call.get("args", []))

        new = run_apis - baseline_api_set
        if extra_argv and new:
            argv_hits.append(f"argv {extra_argv[0]} -> new APIs: "
                             + ", ".join(sorted(_api_base(a) for a in new)[:5]))
        if env and new:
            var = next(iter(env))
            env_hits.append(f"env {var}={env[var]} -> new APIs: "
                            + ", ".join(sorted(_api_base(a) for a in new)[:5]))

    # -- stimuli ---------------------------------------------------------- #
    stimuli.argv = sorted({t for t in _ARGV_TOKENS if any(h.startswith(f"argv {t} ") for h in argv_hits)})
    stimuli.env_vars = sorted(set(env_consulted))
    stimuli.files = acc.files_read + acc.files_written
    stimuli.comparisons = acc.literals[:12]
    stimuli.numeric_probes = []
    stimuli.trigger_notes = argv_hits[:6] + env_hits[:4]
    if acc.message_strings:
        stimuli.output_changes = [f"MessageBox/console: {s}" for s in acc.message_strings[:4]]
    stimuli.input_apis = acc.input_apis
    stimuli.note = "emulated with Speakeasy (sandbox: no real file/registry/network side effects)"

    # -- behavior --------------------------------------------------------- #
    behavior.execve = acc.exec_calls
    behavior.files_read = acc.files_read
    behavior.files_written = acc.files_written
    behavior.network = acc.network
    behavior.stdout_output = acc.message_strings
    reg_bits = []
    if acc.reg_reads:
        reg_bits.append("registry read: " + ", ".join(acc.reg_reads))
    if acc.reg_writes:
        reg_bits.append("registry written: " + ", ".join(acc.reg_writes))
    if reg_bits:
        behavior.note = "; ".join(reg_bits)
    return runs, stimuli, behavior, warnings


class _PeBehaviorAccumulator:
    """Collects and de-duplicates interesting API-driven behaviour."""

    def __init__(self) -> None:
        self.input_apis: List[str] = []
        self.exec_calls: List[str] = []
        self.files_read: List[str] = []
        self.files_written: List[str] = []
        self.reg_reads: List[str] = []
        self.reg_writes: List[str] = []
        self.network: List[str] = []
        self.message_strings: List[str] = []
        self.literals: List[str] = []

    @staticmethod
    def _add(seq: List[str], value: str) -> None:
        if value and value not in seq:
            seq.append(value)

    def add(self, base: str, low: str, args: List) -> None:
        str_args = [a for a in args if isinstance(a, str) and _STR_ARG_HINT.match(a)]

        if any(p in low for p in _INPUT_APIS):
            self._add(self.input_apis, base)

        if any(p in low for p in _EXEC_APIS):
            desc = f"{base}: {str_args[0]}" if str_args else base
            self._add(self.exec_calls, desc)

        if "createfile" in low or low in ("fopen", "readfile", "writefile"):
            path_arg = next((a for a in str_args if re.match(r"^[A-Za-z]:\\", a)), None)
            if path_arg:
                joined = " ".join(str(a) for a in args).upper()
                if any(k in joined for k in ("WRITE", "CREATE_ALWAYS", "OPEN_ALWAYS")):
                    self._add(self.files_written, path_arg)
                else:
                    self._add(self.files_read, path_arg)

        if low.startswith(("regopenkey", "regqueryvalue", "reggetvalue", "regenumkey")):
            key = next((a for a in str_args if "\\" in a), None)
            if key:
                self._add(self.reg_reads, key)
        if low.startswith(("regsetvalue", "regcreatekey", "regdelete")):
            key = next((a for a in str_args if "\\" in a), None)
            if key:
                self._add(self.reg_writes, key)

        if any(p in low for p in _NET_APIS):
            self._add(self.network, base)
            for a in args:
                if isinstance(a, str) and re.match(r"^\d+\.\d+\.\d+\.\d+:\d+$", a):
                    self._add(self.network, a)

        if any(p in low for p in _MESSAGE_APIS):
            for a in str_args:
                if len(a) > 3:
                    self._add(self.message_strings, a)

        for a in str_args:
            if re.match(r"^--?[A-Za-z][\w-]{0,20}$", a):
                self._add(self.literals, a)

