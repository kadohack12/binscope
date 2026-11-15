"""Dynamic stimulation engine.

Runs the target several times inside an isolated temporary directory, under
``strace -f`` and ``ltrace -f``, and turns the raw traces into a small set of
analyst-relevant facts (stimuli + behaviour).

The strategy is a bounded discovery loop:

* seed passes: no args, ``-h``/``--help``, 1..3 dummy args, common stdin patterns
* every fact discovered (env var consulted, compared literal, option-like string,
  missing file) schedules follow-up passes that inject that hint
* system noise (library loading, ``ld.so.cache``, locale files ...) is filtered
"""

from __future__ import annotations

import os
import re
import shutil
import signal
import subprocess
import tempfile
from typing import Dict, List, Optional, Sequence, Set, Tuple

from .model import Behavior, RunResult, Stimuli

STRACE_SET = (
    "execve,access,openat,open,openat2,stat,newfstatat,lstat,faccessat,"
    "connect,socket,bind,sendto,unlink,unlinkat,rename,creat,read,write,"
    "getdents64,mkdir,chmod"
)

_NOISE_PREFIXES = (
    "/lib/",
    "/lib64/",
    "/usr/lib/",
    "/usr/lib64/",
    "/usr/local/lib/",
    "/etc/ld.so",
    "/usr/share/locale",
    "/usr/share/zoneinfo",
    "/usr/lib/locale",
    "/proc/",
    "/sys/",
    "/dev/null",
    "/dev/urandom",
    "/dev/tty",
    "/etc/nsswitch.conf",
    "/etc/localtime",
)
_NOISE_MARKERS = (
    ".so",
    "ld-linux",
    "ld.so",
    "gconv",
    "locale",
    "nss_",
    "libc.so",
    "libgcc_s",
    "libstdc++",
    "libpthread",
    "librt.so",
    "libdl.so",
    "libm.so",
    "ld.so.cache",
)

_OPTION_RE = re.compile(r"^--?[A-Za-z][A-Za-z0-9_-]{0,24}$")
# Options embedded inside longer strings (e.g. "--go" in a usage line).
_OPTION_FIND = re.compile(r"(?:^|\s)(--?[A-Za-z][A-Za-z0-9_-]{0,24})")
_WORD_RE = re.compile(r"^[A-Za-z0-9_.@/-]{2,40}$")

# Boundary integers used to probe strtol/atoi/strtod-style parsing, including
# the signed/unsigned traps (a "-2" read as unsigned wraps to a huge value).
_NUMERIC_PROBES = ("0", "1", "-1", "-2", "2", "42", "1337", "2147483647", "4294967295")



def _is_noise(path: str) -> bool:
    if not path:
        return True
    if path in (".", "..", "/"):
        return True
    if path.startswith(_NOISE_PREFIXES):
        return True
    low = path.lower()
    if any(marker in low for marker in _NOISE_MARKERS):
        return True
    return False


def _stubbable(path: str, workdir: str) -> bool:
    """Only auto-create files inside the sandbox (workdir or /tmp)."""
    if not path:
        return False
    if os.path.isabs(path):
        return path.startswith("/tmp/") or path.startswith(workdir)
    return True


def _unquote_args(blob: str) -> List[str]:
    return re.findall(r'"((?:[^"\\]|\\.)*)"', blob)


def _ret_failed(ret: str) -> bool:
    return ret.lstrip().startswith("-1")


def _errno(ret: str) -> str:
    m = re.search(r"\b(E[A-Z]+)\b", ret)
    return m.group(1) if m else ""


def _net_addr(blob: str) -> str:
    """Turn a strace sockaddr blob into a compact ``ip:port`` string."""
    if "AF_INET6" in blob:
        m6 = re.search(r'sin6_addr=inet_pton\(AF_INET6,\s*"([^"]+)"', blob)
        mp6 = re.search(r"sin6_port=htons\((\d+)\)", blob)
        if m6 and mp6:
            return f"[{m6.group(1)}]:{mp6.group(1)}"
        return "AF_INET6"
    if "AF_UNIX" in blob:
        m = re.search(r'sun_path="([^"]*)"', blob)
        return f"unix:{m.group(1)}" if m else "unix"
    mi = re.search(r'sin_addr=inet_addr\("([^"]+)"\)', blob)
    mp = re.search(r"sin_port=htons\((\d+)\)", blob)
    if mi and mp:
        return f"{mi.group(1)}:{mp.group(1)}"
    if mi:
        return mi.group(1)
    return blob.strip()[:60]


# --------------------------------------------------------------------------- #
# Trace parsing
# --------------------------------------------------------------------------- #

_LINE_RE = re.compile(r"^(?:\[pid\s+\d+\]\s+|\d+\s+)?(\w+)\((.*)\)\s*=\s*(.*)$")


def _decode_strace_path(s: str) -> str:
    raw = s.encode("utf-8", "surrogateescape")
    raw = re.sub(rb"\\([0-7]{1,3})", lambda m: bytes([int(m.group(1), 8)]), raw)
    raw = re.sub(rb"\\x([0-9a-fA-F]{2})", lambda m: bytes([int(m.group(1), 16)]), raw)
    raw = raw.replace(b'\\"', b'"').replace(b"\\\\", b"\\")
    return raw.decode("utf-8", "replace")


def parse_strace(text: str, target: str, workdir: str) -> dict:
    """Extract analyst-relevant syscalls from raw strace output."""
    res = {
        "execve": [],
        "files_read": [],
        "files_written": [],
        "files_deleted": [],
        "files_accessed": [],
        "missing_files": [],
        "network": [],
        "connect_success": [],
        "stdin_read": False,
    }
    target_abs = os.path.abspath(target)
    workdir_abs = os.path.abspath(workdir)

    def _noise(path: str) -> bool:
        # The sandbox dir itself is CWD noise, never an analyst-relevant path.
        if os.path.abspath(path) == workdir_abs:
            return True
        return _is_noise(path)

    for raw in text.splitlines():
        line = raw.strip()
        if not line or " = " not in line:
            continue
        m = _LINE_RE.match(line)
        if not m:
            continue
        func, args, ret = m.groups()
        failed = _ret_failed(ret)

        if func == "execve":
            em = re.match(r'\s*"([^"]*)"\s*,\s*\[([^\]]*)\]', args)
            if not em:
                continue
            path = _decode_strace_path(em.group(1))
            argv = _unquote_args(em.group(2))
            if os.path.realpath(path) == os.path.realpath(target_abs):
                continue  # our own launch
            res["execve"].append((path, argv))

        elif func in ("access", "faccessat"):
            pm = re.search(r'"([^"]*)"', args)
            if not pm:
                continue
            path = pm.group(1)
            if _noise(path):
                continue
            if failed:
                res["missing_files"].append((path, _errno(ret)))
            else:
                res["files_accessed"].append(path)

        elif func in ("open", "openat", "openat2", "creat"):
            pm = re.search(r'"([^"]*)"', args)
            if not pm:
                continue
            path = pm.group(1)
            if _noise(path):
                continue
            flags = args
            if func == "creat" or re.search(r"O_CREAT|O_WRONLY|O_RDWR|O_TRUNC|O_APPEND", flags):
                if failed:
                    res["missing_files"].append((path, _errno(ret)))
                else:
                    res["files_written"].append(path)
            else:
                if failed:
                    res["missing_files"].append((path, _errno(ret)))
                else:
                    res["files_read"].append(path)

        elif func in ("stat", "newfstatat", "lstat", "statx"):
            pm = re.search(r'"([^"]*)"', args)
            if not pm:
                continue
            path = pm.group(1)
            if _noise(path):
                continue
            if failed:
                res["missing_files"].append((path, _errno(ret)))
            else:
                res["files_accessed"].append(path)

        elif func in ("unlink", "unlinkat", "rmdir"):
            pm = re.search(r'"([^"]*)"', args)
            if pm and not _is_noise(pm.group(1)) and not failed:
                res["files_deleted"].append(pm.group(1))

        elif func == "connect":
            addr = _net_addr(args)
            res["network"].append(addr)
            if not failed:
                res["connect_success"].append(addr)

        elif func == "bind":
            res["network"].append("bind:" + _net_addr(args))

        elif func in ("sendto", "sendmsg"):
            if re.search(r"AF_INET|:53", args):
                res["network"].append("dns/send:" + _net_addr(args))

        elif func == "socket":
            if "AF_INET" in args:
                res["network"].append("socket(" + args.split(",")[1].strip() + ")")

        elif func == "read":
            if re.match(r"\s*0\s*,", args):
                res["stdin_read"] = True

    return res


_LTRACE_RE = re.compile(
    r"^(?:\[pid\s+\d+\]\s+|\d+\s+)?(?:(?P<caller>[\w./+\-]+)->)?"
    r"(?P<func>\w+)\((?P<args>.*)\)\s*=\s*(?P<ret>.*)$"
)


def parse_ltrace(text: str, target: str, injected: Set[str] | None = None) -> dict:
    """Extract env lookups and literal comparisons from raw ltrace output.

    ``injected`` is the set of values *we* fed to this run (argv tokens, stdin
    lines, env values). A comparison literal equal to one of them is our own
    probe echoing back, so only the *other* side of the comparison is a real
    discovery (a constant held by the binary).
    """
    injected = injected or set()
    res = {"env_vars": [], "comparisons": [], "stdin_calls": False, "exec": [],
           "numeric_calls": [], "getopt": False, "ptrace": False, "input_calls": []}
    base = os.path.basename(target)
    # system()/popen() spawn /bin/sh (and the programs it runs), whose internal
    # string comparisons are pure noise. ltrace prints the traced process first,
    # so we keep only calls from that main PID.
    main_pid: Optional[str] = None
    for raw in text.splitlines():
        m = re.match(r"(\d+)\s", raw)
        if m:
            main_pid = m.group(1)
            break

    for raw in text.splitlines():
        pm = re.match(r"(\d+)\s", raw)
        if main_pid and pm and pm.group(1) != main_pid:
            continue
        # system()/popen() lines may end with "<no return ...>" instead of "= v".
        sm = re.search(r'\b(?:system|popen)\("([^"]*)"', raw)
        if sm and sm.group(1) not in res["exec"]:
            res["exec"].append(sm.group(1))
        line = raw.strip()
        if " = " not in line:
            continue
        m = _LTRACE_RE.match(line)
        if not m:
            continue
        caller, func, args, ret = m.group("caller"), m.group("func"), m.group("args"), m.group("ret")
        # Ignore libc-internal plumbing (getenv uses strncmp internally).
        if caller and caller not in (base, target) and "libc" in caller:
            continue

        if func == "getenv":
            gm = re.match(r'\s*"([^"]*)"', args)
            if gm:
                res["env_vars"].append(gm.group(1))

        elif func in ("strcmp", "strncmp", "strcasecmp", "strncasecmp", "memcmp"):
            lits = _unquote_args(args)
            if func == "memcmp" and len(lits) < 2:
                continue
            # getenv() internal strncmp("NAME", "NAME=value", n) -> ignore.
            if len(lits) == 2 and lits[1].startswith(lits[0] + "="):
                continue
            constants = [l for l in lits if l.rstrip("\n") not in injected and l not in injected]
            for lit in constants:
                res["comparisons"].append((func, [lit]))

        elif func in ("strtol", "strtoul", "strtoll", "strtoull", "atoi", "atol",
                      "atoll", "strtod", "strtof", "strtold"):
            # Record the numeric conversion family and its base when visible.
            res["numeric_calls"].append((func, args.strip()))

        elif func in ("sscanf", "scanf", "__isoc99_scanf", "fscanf",
                      "__isoc99_sscanf", "__isoc99_fscanf"):
            res["stdin_calls"] = True
            res["input_calls"].append(func)

        elif func == "getopt" or func == "getopt_long" or func == "getopt_long_only":
            res["getopt"] = True

        elif func == "ptrace":
            res["ptrace"] = True

        elif func in ("fgets", "gets", "getline", "getdelim", "fread", "readline"):
            res["stdin_calls"] = True
            res["input_calls"].append(func)

        elif func == "strlen":
            res["input_calls"].append("strlen")

        elif func in ("read",) and re.match(r"\s*0\s*,", args):
            res["stdin_calls"] = True

    return res


# --------------------------------------------------------------------------- #
# Execution
# --------------------------------------------------------------------------- #

def _run_tracer(
    target: str,
    argv: Sequence[str],
    env: Dict[str, str],
    stdin_data: str,
    workdir: str,
    tracer: str,
    timeout: float,
) -> Tuple[str, Optional[int], bool, str, str]:
    """Run one pass under a tracer.

    Returns ``(trace, exit_code, timed_out, stdout, stderr)``.
    """
    tracefile = os.path.join(workdir, f".binscope.{tracer}.trace")
    if tracer == "strace":
        cmd = ["strace", "-f", "-qq", "-s", "512", "-e", "trace=" + STRACE_SET, "-o", tracefile, target]
    else:
        # No -e filter: ltrace -f -e makes getenv/strcmp output lose their
        # "= value" result, which is exactly what we need to capture.
        cmd = ["ltrace", "-f", "-s", "256", "-o", tracefile, target]
    cmd += list(argv)

    full_env = dict(os.environ)
    full_env.update({"LC_ALL": "C", "LANG": "C", "PWD": workdir})
    full_env.update(env)

    trace_text = ""
    exit_code: Optional[int] = None
    timed_out = False
    stdout_text = ""
    stderr_text = ""
    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=workdir,
            env=full_env,
            text=True,
            start_new_session=True,
        )
    except OSError:
        return "", None, False, "", ""

    try:
        out, err = proc.communicate(input=stdin_data, timeout=timeout)
        stdout_text = out or ""
        stderr_text = err or ""
        exit_code = proc.returncode
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except OSError:
            pass
        try:
            out, err = proc.communicate(timeout=5)
            stdout_text = out or ""
            stderr_text = err or ""
        except Exception:
            pass

    try:
        with open(tracefile, "r", errors="replace") as fh:
            trace_text = fh.read()
    except OSError:
        trace_text = ""
    return trace_text, exit_code, timed_out, stdout_text, stderr_text


def _snapshot(workdir: str) -> Set[str]:
    out: Set[str] = set()
    for root, _dirs, files in os.walk(workdir):
        for f in files:
            if f.startswith(".binscope."):
                continue
            out.add(os.path.join(root, f))
    return out


class _Attempt:
    __slots__ = ("label", "argv", "env", "stdin", "stub")

    def __init__(self, label: str, argv: Sequence[str], env: Dict[str, str],
                 stdin: str, stub: Optional[str] = None):
        self.label = label
        self.argv = list(argv)
        self.env = dict(env)
        self.stdin = stdin
        self.stub = stub

    def key(self) -> tuple:
        return (tuple(self.argv), tuple(sorted(self.env.items())), self.stdin, self.stub)


def run_stimulation(
    target: str,
    static_strings: Sequence[str] = (),
    auto_stub: bool = False,
    timeout: float = 2.0,
    max_runs: int = 64,
) -> Tuple[List[RunResult], Stimuli, Behavior, List[str]]:
    """Execute the multi-pass stimulation loop and aggregate the findings."""
    warnings: List[str] = []
    have_strace = shutil.which("strace") is not None
    have_ltrace = shutil.which("ltrace") is not None
    if not have_strace:
        warnings.append("strace not found - dynamic behaviour analysis disabled.")
    if not have_ltrace:
        warnings.append("ltrace not found - string/env comparison capture disabled.")

    workdir = tempfile.mkdtemp(prefix="binscope_")
    target_abs = os.path.abspath(target)

    option_tokens = sorted({
        tok
        for s in static_strings
        for tok in _OPTION_FIND.findall(s)
    })[:20]
    word_tokens = sorted({
        s for s in static_strings
        if _WORD_RE.match(s) and not _is_noise(s)
        and not s.startswith(".") and "@" not in s
        and not re.search(r"\.(c|h|so|o|py|debug)", s)
    })[:20]

    stimuli = Stimuli()
    behavior = Behavior()
    runs: List[RunResult] = []

    env_vars: Set[str] = set()
    literals: Set[str] = set()
    missing_files: Set[str] = set()
    numeric_calls: Set[str] = set()
    argv_hits: List[str] = []
    stdin_hits: List[str] = []
    uses_getopt: List[bool] = [False]
    anti_debug: List[bool] = [False]

    seen: Set[tuple] = set()
    tried_combos: Set[tuple] = set()
    tried_numeric: Set[str] = set()
    tried_argc: Set[int] = set()
    queue: List[_Attempt] = []
    high: List[_Attempt] = []  # discovery-driven passes run before token guesses

    def enqueue(attempt: _Attempt) -> None:
        if attempt.key() in seen:
            return
        seen.add(attempt.key())
        queue.append(attempt)

    # --- seed passes ------------------------------------------------------- #
    enqueue(_Attempt("pass1: no args, empty stdin", [], {}, ""))
    enqueue(_Attempt("pass2: -h", ["-h"], {}, "help\n"))
    enqueue(_Attempt("pass2: --help", ["--help"], {}, "help\n"))
    # argc ladder: identical empty stdin to the baseline, only the arg count varies.
    enqueue(_Attempt("pass2: argc 1", ["1"], {}, ""))
    enqueue(_Attempt("pass2: argc 2", ["1", "2"], {}, ""))
    enqueue(_Attempt("pass2: argc 3", ["1", "2", "3"], {}, ""))
    enqueue(_Attempt("pass2: argc 4", ["1", "2", "3", "4"], {}, ""))
    enqueue(_Attempt("pass2: argc 5", ["1", "2", "3", "4", "5"], {}, ""))
    enqueue(_Attempt("pass2: stdin 'test'", [], {}, "test\n"))
    enqueue(_Attempt("pass2: stdin 'admin'", [], {}, "admin\n"))
    enqueue(_Attempt("pass2: stdin multiline", [], {}, "help\n1\nadmin\n"))

    baseline_sig: Optional[tuple] = None
    baseline_run: Optional[RunResult] = None
    run_count = 0

    def execute(attempt: _Attempt) -> RunResult:
        nonlocal run_count
        # A stub file is created only for this pass and removed right after, so
        # it cannot leak into the baseline of later passes.
        if attempt.stub:
            try:
                os.makedirs(os.path.dirname(attempt.stub) or workdir, exist_ok=True)
                with open(attempt.stub, "w") as fh:
                    fh.write("binscope-stub\n")
            except OSError:
                pass
        try:
            return _execute_inner(attempt)
        finally:
            if attempt.stub:
                try:
                    os.remove(attempt.stub)
                except OSError:
                    pass

    def _execute_inner(attempt: _Attempt) -> RunResult:
        nonlocal run_count
        before = _snapshot(workdir)
        run = RunResult(label=attempt.label, argv=list(attempt.argv), env=dict(attempt.env), stdin=attempt.stdin)
        run.stub = attempt.stub

        injected: Set[str] = set(attempt.argv)
        injected.update(attempt.env.values())
        injected.update(attempt.stdin.splitlines())

        strace_text = ""
        ltrace_text = ""
        if have_strace:
            strace_text, exit_code, timed_out, out, err = _run_tracer(
                target, attempt.argv, attempt.env, attempt.stdin, workdir, "strace", timeout
            )
            run.exit_code = exit_code
            run.timed_out = timed_out
            run.stdout = out
            run.stderr = err
            parsed = parse_strace(strace_text, target_abs, workdir)
            run.execve = [f"{p} {' '.join(a[1:])}".strip() for p, a in parsed["execve"]]
            run.connect_success = parsed["connect_success"]
            run.files_written = parsed["files_written"]
            run.files_read = parsed["files_read"]
            _merge(behavior, parsed)
            _merge_stimuli_files(stimuli, parsed)
            for path, err_name in parsed["missing_files"]:
                if err_name == "ENOENT" and not _is_noise(path):
                    missing_files.add(path)
            if parsed["stdin_read"]:
                run.stdin_read = True

        if have_ltrace:
            ltrace_text, _ec, _to, _out, _err = _run_tracer(
                target, attempt.argv, attempt.env, attempt.stdin, workdir, "ltrace", timeout
            )
            lparsed = parse_ltrace(ltrace_text, target_abs, injected)
            for name in lparsed["env_vars"]:
                env_vars.add(name)
            for func, lits in lparsed["comparisons"]:
                for lit in lits:
                    if len(lit) >= 2 and not _is_noise(lit) and len(lit) <= 64:
                        literals.add(lit)
            for func, call_args in lparsed["numeric_calls"]:
                numeric_calls.add(func)
                base_m = re.search(r",\s*(\d+)\s*\)", call_args)
                if base_m:
                    numeric_calls.add(f"{func}(base {base_m.group(1)})")
            if lparsed["getopt"]:
                uses_getopt[0] = True
            if lparsed["ptrace"]:
                anti_debug[0] = True
            if lparsed["stdin_calls"]:
                run.stdin_read = True
            for cmd in lparsed["exec"]:
                if cmd and cmd not in behavior.execve:
                    behavior.execve.append(cmd)

        after = _snapshot(workdir)
        run.new_files = sorted(after - before)

        run_count += 1
        return run

    while (high or queue) and run_count < max_runs:
        attempt = high.pop(0) if high else queue.pop(0)
        run = execute(attempt)
        runs.append(run)

        if baseline_sig is None and attempt.label.startswith("pass1"):
            baseline_sig = _run_events(run)
            baseline_run = run
            continue

        # Discovery-driven passes take priority over blind token guesses.
        _schedule_discoveries(high, seen, env_vars, literals, missing_files,
                              workdir, auto_stub)
        _schedule_combos(high, seen, tried_combos, env_vars, option_tokens)
        _schedule_numeric(high, seen, tried_numeric, numeric_calls)
        _schedule_tokens(queue, seen, option_tokens, word_tokens)

    _finalize(stimuli, behavior, env_vars, literals, missing_files,
              baseline_run, runs, numeric_calls, uses_getopt[0], anti_debug[0])
    if not runs:
        warnings.append("No pass could be executed (tracer unavailable?).")
    return runs, stimuli, behavior, warnings


def _merge(behavior: Behavior, parsed: dict) -> None:
    for entry in parsed["execve"]:
        path, argv = entry
        rendered = f"{path} {' '.join(argv[1:])}".strip()
        if rendered not in behavior.execve:
            behavior.execve.append(rendered)
    for f in parsed["files_read"]:
        if f not in behavior.files_read:
            behavior.files_read.append(f)
    for f in parsed["files_written"]:
        if f not in behavior.files_written:
            behavior.files_written.append(f)
    for f in parsed["files_deleted"]:
        if f not in behavior.files_deleted:
            behavior.files_deleted.append(f)
    for n in parsed["network"]:
        if n not in behavior.network:
            behavior.network.append(n)


def _merge_stimuli_files(stimuli: Stimuli, parsed: dict) -> None:
    for f in parsed["files_accessed"]:
        if f not in stimuli.files:
            stimuli.files.append(f)


def _schedule_discoveries(queue, seen, env_vars, literals, missing_files,
                          workdir, auto_stub) -> None:
    """Passes driven by what we actually discovered - run first."""
    def add(label, argv, env, stdin, stub=None):
        a = _Attempt(label, argv, env, stdin, stub=stub)
        if a.key() not in seen:
            seen.add(a.key())
            queue.append(a)

    for name in sorted(env_vars):
        add(f"pass3: {name}=1", [], {name: "1"}, "test\n")
        add(f"pass3: {name}=test", [], {name: "test"}, "test\n")

    for lit in sorted(literals):
        core = lit.rstrip("\n")
        if _OPTION_RE.match(core):
            add(f"pass3: argv {core}", [core], {}, "test\n")
        add(f"pass3: stdin {core!r}", [], {}, core + "\n")

    for path in sorted(missing_files):
        if auto_stub and _stubbable(path, workdir):
            real = path if os.path.isabs(path) else os.path.join(workdir, path)
            add(f"pass3: stub {path}", [], {}, "test\n", stub=real)


def _schedule_tokens(queue, seen, option_tokens, word_tokens) -> None:
    """Blind guesses from static strings - run after the discoveries."""
    def add(label, argv, env, stdin):
        a = _Attempt(label, argv, env, stdin)
        if a.key() not in seen:
            seen.add(a.key())
            queue.append(a)

    for tok in option_tokens:
        add(f"pass3: argv {tok}", [tok], {}, "test\n")
    for tok in word_tokens:
        if _OPTION_RE.match(tok):
            continue
        add(f"pass3: argv {tok}", [tok], {}, "test\n")
        add(f"pass3: stdin {tok!r}", [], {}, tok + "\n")


def _schedule_combos(queue, seen, tried_combos, env_vars, option_tokens) -> None:
    """Cross env vars with option tokens to unlock gated branches."""
    if not env_vars or not option_tokens:
        return
    for name in sorted(env_vars):
        for tok in sorted(option_tokens):
            for val in ("1", "test"):
                key = (name, val, tok)
                if key in tried_combos:
                    continue
                tried_combos.add(key)
                argv = [tok]
                env = {name: val}
                a = _Attempt(f"pass3: {name}={val} + argv {tok}", argv, env, "test\n")
                if a.key() not in seen:
                    seen.add(a.key())
                    queue.append(a)


def _schedule_numeric(queue, seen, tried_numeric, numeric_calls) -> None:
    """Once a numeric conversion is seen, probe boundary integers on argv[1]/stdin."""
    if not numeric_calls:
        return
    for probe in _NUMERIC_PROBES:
        if probe in tried_numeric:
            continue
        tried_numeric.add(probe)
        for label, argv, stdin in (
            (f"pass3: numeric argv {probe}", [probe], f"{probe}\n"),
            (f"pass3: numeric stdin {probe!r}", [], f"{probe}\n"),
        ):
            a = _Attempt(label, argv, {}, stdin)
            if a.key() not in seen:
                seen.add(a.key())
                queue.append(a)


def _run_events(run: RunResult) -> tuple:
    """The externally visible *actions* a run produced (for unlock detection)."""
    events = []
    events += ["exec:" + e for e in run.execve]
    events += ["net:" + n for n in run.connect_success]
    events += ["write:" + f for f in run.files_written]
    events += ["new:" + f for f in run.new_files]
    return (run.exit_code, tuple(sorted(events)))


_TRACER_NOISE_RE = re.compile(r"^(?:\+\+\+|strace:|ltrace:|binscope)")


def _clean_output(text: str) -> str:
    """Drop tracer diagnostics and normalise whitespace for comparison."""
    lines = [
        ln for ln in (text or "").splitlines()
        if ln.strip() and not _TRACER_NOISE_RE.match(ln.strip())
    ]
    return "\n".join(ln.rstrip() for ln in lines).strip()


def _describe_run(run: RunResult) -> str:
    """A compact, human-readable description of what a pass varied."""
    bits = []
    if run.argv:
        bits.append("argv " + " ".join(run.argv))
    if run.env:
        bits.append("env " + " ".join(f"{k}={v}" for k, v in sorted(run.env.items())))
    stdin_val = run.stdin.strip()
    if not bits and stdin_val:
        bits.append(f"stdin {stdin_val!r}")
    if run.stub:
        bits.append(f"stub {run.stub}")
    return ", ".join(bits) or run.label


# Output substrings that indicate the pass revealed a *meaningful* result
# (accepted password, a flag, a spawned payload) rather than a rejection.
_REVEAL_RE = re.compile(
    r"(flag\{|accepted|unlocked|granted|correct|secret|payload|success|"
    r"stage_two|welcome)",
    re.IGNORECASE,
)


def _trigger_score(run: RunResult, output_blob: str) -> int:
    """Lower is better: prefer the clearest, least-confounded trigger."""
    score = 0
    if not _REVEAL_RE.search(output_blob):
        score += 10  # a reveal beats a plain rejection
    if run.stdin.strip():
        score += 0  # stdin is the primary channel for these challenges
    else:
        score += 1
    score += len(run.env) + max(0, len(run.argv) - 1)  # fewer dimensions is clearer
    if run.stub:
        score += 1
    return score


def _finalize(stimuli, behavior, env_vars, literals, missing_files,
              baseline_run, runs, numeric_calls=frozenset(),
              uses_getopt=False, anti_debug=False) -> None:
    stimuli.env_vars = sorted(env_vars)
    stimuli.comparisons = sorted(literals)
    stimuli.missing_files = sorted(missing_files)
    # Only claim numeric probing when a numeric conversion was actually seen.
    stimuli.numeric_probes = (
        [p for p in _NUMERIC_PROBES if p in _tested_probes(runs)]
        if numeric_calls else []
    )

    notes = []
    if uses_getopt:
        notes.append("uses getopt-style option parsing")
    if anti_debug:
        notes.append("calls ptrace() (possible anti-debug)")
    if numeric_calls:
        families = sorted({f for f in numeric_calls if "(" not in f})
        notes.append("numeric parsing via " + ", ".join(families))
    stimuli.note = "; ".join(notes)

    # --- unlock attribution (action events) -------------------------------- #
    baseline_events = _run_events(baseline_run) if baseline_run else (None, ())

    def new_events(run: RunResult) -> bool:
        return bool(set(_run_events(run)[1]) - set(baseline_events[1]))

    argv_hits: List[str] = []
    stdin_hits: List[str] = []
    for run in runs:
        if run is baseline_run or not new_events(run):
            continue
        has_env = bool(run.env)
        has_argv = bool(run.argv)
        stdin_val = run.stdin.strip()
        if has_argv:
            for tok in run.argv:
                if tok not in argv_hits:
                    argv_hits.append(tok)
        if (not has_env and not has_argv and stdin_val
                and run.stdin_read and not run.stub):
            if stdin_val not in stdin_hits:
                stdin_hits.append(stdin_val)

    stimuli.argv = argv_hits
    stimuli.stdin_patterns = stdin_hits
    stimuli.stdin_expected = bool(stdin_hits) or any(r.stdin_read for r in runs)

    # --- exit-code / stdout / stderr triggers ------------------------------ #
    # A pass that flips the exit code or produces different output than the
    # baseline revealed something, even without execve/network/file activity.
    base_ec = baseline_run.exit_code if baseline_run else None
    base_out = _clean_output(baseline_run.stdout) if baseline_run else ""
    base_err = _clean_output(baseline_run.stderr) if baseline_run else ""
    base_blob = base_out + "\n" + base_err

    stdout_seen: List[str] = []
    stderr_seen: List[str] = []
    seen_out: Set[str] = set()
    seen_err: Set[str] = set()

    # Keep one representative pass per distinct transition, preferring the
    # clearest trigger (revealing output, stdin over argv, fewest dimensions).
    exit_best: Dict[str, Tuple[int, RunResult]] = {}
    out_best: Dict[str, Tuple[int, str, RunResult]] = {}

    for run in runs:
        if run is baseline_run or run.timed_out:
            continue
        out = _clean_output(run.stdout)
        err = _clean_output(run.stderr)
        score = _trigger_score(run, out + "\n" + err)

        if run.exit_code is not None and base_ec is not None and run.exit_code != base_ec:
            key = str(run.exit_code)
            if key not in exit_best or score < exit_best[key][0]:
                exit_best[key] = (score, run)

        for kind, blob in (("stdout", out), ("stderr", err)):
            base_for_kind = base_out if kind == "stdout" else base_err
            if not blob or blob == base_for_kind:
                continue
            first = blob.splitlines()[0][:80]
            key = f"{kind}:{first}"
            if key not in out_best or score < out_best[key][0]:
                out_best[key] = (score, kind, run)

        if out and out != base_out and out not in seen_out:
            seen_out.add(out)
            stdout_seen.extend(out.splitlines()[:2])
        if err and err != base_err and err not in seen_err:
            seen_err.add(err)
            stderr_seen.extend(err.splitlines()[:2])

    exit_changes = []
    for code in sorted(exit_best, key=lambda c: int(c) if c.lstrip("-").isdigit() else 0):
        _score, run = exit_best[code]
        exit_changes.append(f"{_describe_run(run)} -> exit {code} (baseline {base_ec})")
    output_changes = []
    for _key, (_score, kind, run) in sorted(out_best.items(), key=lambda kv: kv[1][0]):
        blob = _clean_output(run.stdout if kind == "stdout" else run.stderr)
        first = blob.splitlines()[0][:80] if blob else ""
        output_changes.append(f"{_describe_run(run)} -> {kind}: {first}")

    stimuli.exit_code_changes = exit_changes[:5]
    stimuli.output_changes = output_changes[:6]
    behavior.stdout_output = stdout_seen[:12]
    behavior.stderr_output = stderr_seen[:12]

    exit_code_map: List[str] = []
    if baseline_run is not None and base_ec is not None:
        exit_code_map.append(f"{base_ec} (baseline)")
    for code in sorted(exit_best, key=lambda c: int(c) if c.lstrip("-").isdigit() else 0):
        _score, run = exit_best[code]
        exit_code_map.append(f"{code} via {_describe_run(run)}")
    behavior.exit_codes = exit_code_map[:8]

    # --- argc sensitivity -------------------------------------------------- #
    # Compare the dedicated argc ladder (same empty stdin as the baseline) to
    # find the smallest argument count that changes exit code or output.
    argc_candidates = set()
    for run in runs:
        if not run.label.startswith("pass2: argc") or run.timed_out:
            continue
        blob = _clean_output(run.stdout) + "\n" + _clean_output(run.stderr)
        changed = (run.exit_code is not None and base_ec is not None
                   and run.exit_code != base_ec) or (blob != base_blob)
        if changed:
            argc_candidates.add(len(run.argv))
    if argc_candidates:
        stimuli.argc_expected = min(argc_candidates)

    # Surface help text captured by a -h/--help pass, but only when the output
    # actually looks like usage/help (avoids "access denied" style messages).
    for run in runs:
        if run.argv[:1] not in (["-h"], ["--help"]):
            continue
        out = run.stdout.strip()
        low = out.lower()
        if out and ("usage" in low or "option" in low or "help" in low
                    or "-h" in out or "--help" in out):
            stimuli.help_text = out
            break

    # Collapse the "/bin/sh -c -- CMD" wrapper emitted by system()/popen().
    collapsed: List[str] = []
    for cmd in behavior.execve:
        if " -c -- " in cmd:
            inner = cmd.split(" -c -- ", 1)[1]
            if inner in behavior.execve:
                continue
        if cmd not in collapsed:
            collapsed.append(cmd)
    behavior.execve = collapsed


def _tested_probes(runs) -> Set[str]:
    probes: Set[str] = set()
    for run in runs:
        for tok in run.argv:
            if tok in _NUMERIC_PROBES:
                probes.add(tok)
        sv = run.stdin.strip()
        if sv in _NUMERIC_PROBES:
            probes.add(sv)
    return probes
