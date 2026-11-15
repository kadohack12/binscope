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
   consulted, files checked, `strcmp`/`memcmp` literals, stdin prompts.
3. **Behaviour** - `execve` with full args, files read/written/deleted (library
   loading noise filtered out), network sockets/connections.
4. **Static capabilities** - notable strings, plus `capa`/`floss` summaries when
   installed.
5. **Analyst synthesis** - 3-5 plain-language bullet points.

## How it works: multi-pass stimulation

The target runs several times inside an isolated temporary directory under
`strace -f` and `ltrace -f`, with short timeouts:

* **Pass 1** - raw execution, no args, empty stdin (the baseline).
* **Pass 2** - `-h`, `--help`, 1..3 dummy args, common stdin patterns.
* **Pass 3** - re-execution driven by what passes 1-2 discovered:
  * `getenv("X")` -> re-run with `X=1` and `X=test`
  * `strcmp(input, "secret")` -> inject `"secret"` as argv and on stdin
  * `access("/tmp/flag")` / `openat` returning `ENOENT` -> with `--auto-stub`,
    create a fake file in a sandboxed path and re-run to reveal the next stage
  * option-like strings extracted from the binary -> tried as argv
  * env vars crossed with option tokens to unlock gated branches

System noise (`/lib`, `/usr/lib`, `ld.so.cache`, locale files, ...) is filtered
so only analyst-relevant activity is shown.

## Tests

Integration tests compile three real C programs (`tests/fixtures/*.c`) and run
the full analysis on them:

```bash
pip install -e ".[test]"
pytest -v
```
