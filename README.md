# binscope

Rapid triage of **Linux ELF** and **Windows PE** binaries for malware analysts
and CTF players (Reverse / PWN). In one command it answers two questions:

* **What does this binary expect as input?** (argv, env vars, files, string
  comparisons, stdin)
* **What does it really do?** (spawned processes, files read/written/deleted,
  network activity)

Instead of reading thousands of `strace` lines, you get a short, structured
report. The format is detected automatically from the magic bytes: ELF files go
through the strace/ltrace engine, PE files (`.exe`/`.dll`, PE32 and PE32+)
through a `pefile` + Speakeasy emulation backend. Reports can be exported as
JSON (`--json`) or Markdown (`--md`).

## Install

Requires Python 3.9+. `pefile` (PE parsing) and `rich` (terminal rendering) are
installed automatically.

```bash
pip install -e .
# ELF dynamic analysis (system tools):
sudo apt-get install -y strace ltrace file binutils
# PE dynamic analysis (optional, enables the emulation backend):
pip install -e ".[pe]"        # installs speakeasy-emulator
# optional static tooling:
pip install flare-capa    # 'capa'  (or use the standalone release)
pip install flare-floss   # 'floss'
```

`pefile` is a hard dependency; `speakeasy-emulator` is optional and only needed
for the dynamic PE section. If it is missing, binscope still produces the full
static PE report and warns that emulation was skipped. The `[pe]` extra also
pins `setuptools<81`: Speakeasy's `unicorn` needs `distutils.sysconfig` and
`pkg_resources` at runtime, and both only ship with older setuptools on
Python 3.12+.

## Usage

```bash
binscope ./target_binary                       # shortcut: 'analyze' is implied
binscope analyze ./target_binary
binscope analyze ./target_binary --json report.json --md report.md
binscope analyze ./target_binary --explain      # add a beginner-friendly glossary
binscope analyze ./target_binary --auto-stub    # create fake files for missing paths (ELF)
binscope analyze ./target_binary --timeout 5    # per-pass timeout (s)
binscope doctor                                 # check installed tools / optional deps
```

Passing a file directly (`binscope ./target`) is a shortcut for `analyze`. A
non-executable file is handled too: binscope traces it via a temporary
executable copy and notes the missing `+x`. `binscope doctor` prints which
system tools and optional dependencies are present, with the exact command to
install any that are missing.

The terminal report has five sections (plus a "Next steps" footer, and an
optional sixth with `--explain`):

1. **Identity** - arch, type, stripped/subsystem, size, SHA256, protections.
   * ELF: arch, ELF type, interpreter, stripped, checksec (PIE / NX / Canary /
     RELRO / FORTIFY).
   * PE: arch (x86/x64), PE32 vs PE32+, subsystem (Console/GUI), section count
     and max entropy (packing hint), compile timestamp, PDB path, and
     DllCharacteristics (ASLR / DEP / CFG / SafeSEH / HighEntropyVA).
2. **Stimuli** - what the binary expects: argv that changed behaviour, env vars
   consulted, files checked, `strcmp`/`memcmp` literals, numeric-input probes,
   argc expectations, exit-code / stdout / stderr triggers, stdin prompts.
   * PE: also the input APIs (`GetCommandLineA`, `GetEnvironmentVariableA`,
     `strcmp`, ...) and which argv/env pass unlocked new APIs.
3. **Behaviour** - `execve` with full args, files read/written/deleted (library
   loading noise filtered out), network sockets/connections, revealed stdout /
   stderr output, observed exit codes.
   * PE: `WinExec`/`CreateProcess`/`ShellExecute` commands, `CreateFile` paths,
   registry keys read/written, and Winsock `socket`/`connect` with IP:port.
4. **Static capabilities** - imported dynamic symbols (minus C-runtime plumbing),
   a de-noised strings digest (URLs, paths, `printf` formats, messages), plus
   `capa`/`floss` summaries when installed.
   * PE: imported DLLs, APIs grouped by family (Process, Process-Injection,
     File, Registry, Network, GUI, Anti-Debug, Crypto, Service, Environment),
     matched by exact API name so `SendMessageA` stays under GUI and
     `GetSystemMetrics` is not read as a process API; notable ASCII strings
     (paths, flags, `printf` formats) are listed next to the notable UTF-16LE
     ones.
5. **Analyst synthesis** - 3-5 plain-language bullet points, followed by a
   **Next steps** footer with concrete follow-up actions for this sample.
6. **Beginner guide** (`--explain` only) - a glossary that decodes the
   technical terms (PIE, RELRO, strace, `getenv`, ...) used in the report.

### Example

```
$ binscope analyze ./sample_env_cmd
  1. Identity      ELF 64-bit, PIE, not stripped, 17584 bytes, sha256 414fb1e2...
  Protections      PIE: Yes  NX: Yes  Canary: No  RELRO: Partial  FORTIFY: No
  2. Stimuli       argv '--go'; env RUN_MODE; string compare '--go'
                   output trigger: argv --go + env RUN_MODE=1 -> stdout: payload_executed
  3. Behaviour     execve /bin/echo payload_executed; stdout: payload_executed
  4. Capabilities  imports: getenv, puts, strcmp, system
                   notable strings: RUN_MODE, /bin/echo payload_executed, ...
  5. Synthesis     - Waits for / reacts to: argv '--go'; env RUN_MODE.
                   - Observed actions: spawns /bin/echo payload_executed.
  Next steps       -> test those exact arguments/stdin values to verify the path
                   -> active process/file/network behaviour: sandbox only
```

## How it works

### Linux ELF: multi-pass stimulation

The target runs several times inside an isolated temporary directory under
`strace -f` and `ltrace -f`, with short timeouts:

* **Pass 1** - raw execution, no args, empty stdin (the baseline).
* **Pass 2** - `-h`, `--help`, 1..5 dummy args, common stdin patterns.
* **Pass 3** - re-execution driven by what passes 1-2 discovered:
  * `getenv("X")` -> re-run with `X=1` and `X=test`
  * `strcmp(input, "secret")` -> inject `"secret"` as argv and on stdin
  * `strtol`/`strtoul`/`atoi`/`strtod` seen -> probe boundary integers on
    `argv[1]` and stdin (`0, 1, -1, -2, 2, 42, 1337, 2147483647, 4294967295`)
  * `access("/tmp/flag")` / `openat` returning `ENOENT` -> with `--auto-stub`,
    create a fake file in a sandboxed path and re-run to reveal the next stage
  * option-like strings extracted from the binary -> tried as argv
  * env vars crossed with option tokens to unlock gated branches
  * several argv lengths (1..5) to detect a required argument count

A pass is flagged whenever it **changes behaviour**, not only when it spawns a
process or touches the network: an exit-code flip (e.g. `1 -> 0`) or different
`stdout`/`stderr` is reported as a stimulus and surfaced in the behaviour
section. The engine also records, per pass, the return code, `stdout` and
`stderr`.

System noise (`/lib`, `/usr/lib`, `ld.so.cache`, locale files, ...) is filtered
so only analyst-relevant activity is shown. All static tooling runs with
`LC_ALL=C` so parsing is immune to the analyst's locale.

### Windows PE: emulation, never execution

The PE is never executed on the host. It is loaded into **Speakeasy**, a
Unicorn-based user-mode emulator, which intercepts every Win32 call. That makes
it safe to analyse live malware: file, registry and network APIs are reported,
not performed. The engine runs a handful of passes:

* a baseline pass (no arguments),
* one pass per candidate argv token (`--go`, `-h`, `--help`, `1`, `admin`,
  `test`, `flag`, `secret`),
* one pass per probed environment variable (`RUN_MODE=1`, `DEBUG=1`,
  `MODE=1`, `TEST=1`).

Each pass records the sequence of API calls and their arguments. A pass that
unlocks **new APIs** is reported as a stimulus (e.g. `--go -> new APIs: WinExec`).
The collected API calls are then distilled into the report: input APIs, spawned
commands, file reads/writes, registry access and network endpoints.

## Tests

Integration tests compile real C programs and run the full analysis on them - no
mocks. The suite has 63 tests covering both backends plus the CLI surface
(`doctor`, the direct-file shortcut, `--explain`, next steps, non-`+x` handling).

**ELF** (`tests/fixtures/*.c`, built with `gcc`):

* `sample_env_cmd` - `RUN_MODE=1` + `--go` -> `execve` a payload
* `sample_stdin_file` - stdin password (`strcmp`) -> file write + TCP connect
* `sample_check_file` - `access()` gate + `--auto-stub`
* `sample_num_arg` - `strtoul(argv[1], ..., 10)` signed/unsigned trap (`-2`)

**PE** (`tests/fixtures/sample_pe_*.c`, built with `x86_64-w64-mingw32-gcc`):

* `sample_pe_env_cmd` - `RUN_MODE=1` + `--go` -> `WinExec` a payload
* `sample_pe_file_net` - `CreateFile` + `RegOpenKeyEx` + Winsock `connect`
* `sample_pe_check_file` - `GetFileAttributesA` gate -> stage-two file write
* `sample_pe_gui` - GUI subsystem: `USER32` APIs (`SendMessageA`,
  `GetSystemMetrics`) + an ASCII flag-like format string (`FCSC{%.32s}`)
  alongside UTF-16 messages (`Catch me if you can`, `Gone!`)

```bash
sudo apt-get install -y gcc mingw-w64    # build the fixtures
pip install -e ".[test,pe]"
pytest -v
```

PE tests are skipped automatically when `mingw-w64` or `speakeasy` is absent.

## License

Released under the [MIT License](LICENSE). © 2026 kadohack12.
