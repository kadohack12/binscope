# binscope

Rapid triage of Linux ELF binaries for malware analysts and CTF players
(Reverse / PWN). In one command it answers two questions:

* **What does this binary expect as input?** (argv, env vars, files, string
  comparisons, stdin)
* **What does it really do?** (spawned processes, files read/written/deleted,
  network activity)

Instead of reading thousands of `strace` lines, you get a short, structured
report.

## Install

```bash
pip install -e .
# system tools used for dynamic analysis:
sudo apt-get install -y strace ltrace file binutils
# optional static tooling:
pip install flare-capa    # 'capa'  (or use the standalone release)
pip install flare-floss   # 'floss'
```

## Usage

```bash
binscope analyze ./target_binary
binscope analyze ./target_binary --json report.json --md report.md
binscope analyze ./target_binary --auto-stub   # create fake files for missing paths
binscope analyze ./target_binary --timeout 5    # per-pass timeout (s)
```

The terminal report has five sections:

1. **Identity** - arch, ELF type, stripped, size, SHA256, checksec
   (PIE / NX / Canary / RELRO / FORTIFY).
2. **Stimuli** - what the binary expects: argv that changed behaviour, env vars
   consulted, files checked, `strcmp`/`memcmp` literals, numeric-input probes,
   argc expectations, exit-code / stdout / stderr triggers, stdin prompts.
3. **Behaviour** - `execve` with full args, files read/written/deleted (library
   loading noise filtered out), network sockets/connections, revealed stdout /
   stderr output, observed exit codes.
4. **Static capabilities** - imported dynamic symbols (minus C-runtime plumbing),
   a de-noised strings digest (URLs, paths, `printf` formats, messages), plus
   `capa`/`floss` summaries when installed.
5. **Analyst synthesis** - 3-5 plain-language bullet points.

## How it works: multi-pass stimulation

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

## Tests

Integration tests compile four real C programs (`tests/fixtures/*.c`) and run
the full analysis on them:

* `sample_env_cmd` - `RUN_MODE=1` + `--go` -> `execve` a payload
* `sample_stdin_file` - stdin password (`strcmp`) -> file write + TCP connect
* `sample_check_file` - `access()` gate + `--auto-stub`
* `sample_num_arg` - `strtoul(argv[1], ..., 10)` signed/unsigned trap (`-2`)

```bash
pip install -e ".[test]"
pytest -v
```
