"""Integration tests: binscope must reveal the real stimuli and behaviour of
the compiled C fixtures. These tests exercise the real strace/ltrace paths -
no mocks.
"""

import json
import os
import subprocess

import pytest

from binscope.cli import analyze
from binscope.report import to_json, to_markdown


@pytest.fixture(scope="module")
def env_result(bins):
    return analyze(bins["sample_env_cmd"], timeout=3.0)


@pytest.fixture(scope="module")
def stdin_result(bins):
    return analyze(bins["sample_stdin_file"], timeout=3.0)


@pytest.fixture(scope="module")
def file_result(bins):
    return analyze(bins["sample_check_file"], timeout=3.0)


@pytest.fixture(scope="module")
def file_result_stub(bins):
    return analyze(bins["sample_check_file"], auto_stub=True, timeout=3.0)


@pytest.fixture(scope="module")
def num_result(bins):
    return analyze(bins["sample_num_arg"], timeout=3.0)


@pytest.fixture(scope="module")
def stripped_result(bins, tmp_path_factory):
    """A stripped copy of a fixture, to exercise ELF-header parsing."""
    import shutil
    src = bins["sample_stdin_file"]
    dst = tmp_path_factory.mktemp("stripped") / "aaarg"
    shutil.copy(src, dst)
    subprocess.run(["strip", "-o", str(dst), src], check=True)
    return analyze(str(dst), timeout=3.0)


# --------------------------------------------------------------------------- #
# Identity / protections
# --------------------------------------------------------------------------- #

def test_identity(env_result):
    idn = env_result.identity
    assert idn.arch  # non-empty machine
    assert idn.bits in ("32", "64")
    assert idn.endianness in ("little", "big")
    assert idn.size > 0
    assert len(idn.sha256) == 64
    assert idn.stripped is False  # compiled with -g, not stripped


def test_identity_parsing_clean(stripped_result):
    """v0.2: bits is numeric, endianness present, interp has no stray comma."""
    idn = stripped_result.identity
    assert idn.bits == "64"
    assert idn.endianness == "little"
    assert idn.stripped is True
    assert idn.interp.startswith("/lib64/ld-linux")
    assert not idn.interp.endswith(",")
    assert idn.elf_type == "DYN"


def test_protections_present(env_result):
    prot = env_result.protections
    assert prot.nx in (True, False)
    assert prot.pie in (True, False)
    assert prot.canary in (True, False)


# --------------------------------------------------------------------------- #
# Fixture 1: env var + argv -> exec
# --------------------------------------------------------------------------- #

def test_env_var_detected(env_result):
    assert "RUN_MODE" in env_result.stimuli.env_vars


def test_env_argv_combo_unlocks_exec(env_result):
    joined = " ".join(env_result.behavior.execve)
    assert "payload_executed" in joined, env_result.behavior.execve


def test_env_cmd_help_captured(env_result):
    assert "RUN_MODE" in env_result.stimuli.help_text


# --------------------------------------------------------------------------- #
# Fixture 2: stdin password -> file write + network
# --------------------------------------------------------------------------- #

def test_stdin_password_compared(stdin_result):
    assert "hunter2" in stdin_result.stimuli.comparisons


def test_stdin_expected(stdin_result):
    assert stdin_result.stimuli.stdin_expected is True
    assert "hunter2" in stdin_result.stimuli.stdin_patterns


def test_file_written(stdin_result):
    assert any("binscope_pwned.txt" in f for f in stdin_result.behavior.files_written)


def test_network_connect(stdin_result):
    net = " ".join(stdin_result.behavior.network)
    assert "127.0.0.1:9999" in net


# --------------------------------------------------------------------------- #
# Fixture 3: access() gate + auto-stub
# --------------------------------------------------------------------------- #

def test_missing_file_detected(file_result):
    assert "/tmp/binscope_marker" in file_result.stimuli.missing_files


def test_gate_blocks_without_stub(file_result):
    assert "stage_two" not in " ".join(file_result.behavior.execve)


def test_auto_stub_unlocks_stage_two(file_result_stub):
    joined = " ".join(file_result_stub.behavior.execve)
    assert "stage_two" in joined
    # the stub must not linger on disk
    assert not os.path.exists("/tmp/binscope_marker")


# --------------------------------------------------------------------------- #
# Synthesis + exports
# --------------------------------------------------------------------------- #

def test_synthesis_bullets(env_result):
    assert 3 <= len(env_result.synthesis) <= 5
    assert all(isinstance(b, str) and b for b in env_result.synthesis)


def test_json_export_roundtrip(stdin_result):
    data = json.loads(to_json(stdin_result))
    assert "hunter2" in data["stimuli"]["comparisons"]
    assert data["behavior"]["network"]


def test_markdown_export(stdin_result):
    md = to_markdown(stdin_result)
    assert "# binscope report" in md
    assert "127.0.0.1:9999" in md
    assert "hunter2" in md


# --------------------------------------------------------------------------- #
# Noise filtering
# --------------------------------------------------------------------------- #

def test_library_noise_filtered(stdin_result):
    blob = " ".join(
        stdin_result.behavior.files_read
        + stdin_result.behavior.files_written
        + stdin_result.stimuli.files
    )
    assert "libc.so" not in blob
    assert "ld.so" not in blob


# --------------------------------------------------------------------------- #
# v0.2: static section 4 (imports + strings summary without capa/floss)
# --------------------------------------------------------------------------- #

def test_imports_extracted(stripped_result):
    """Imported dynamic symbols are listed, minus C-runtime plumbing."""
    caps = stripped_result.capabilities
    assert caps.imports, "no imports extracted"
    assert "__libc_start_main" not in caps.imports
    assert "__gmon_start__" not in caps.imports
    assert any(i in caps.imports for i in ("strcmp", "fgets", "socket", "connect"))


def test_strings_summary_concise(stdin_result):
    caps = stdin_result.capabilities
    assert caps.strings_summary
    blob = " ".join(caps.strings_summary)
    # No GCC / toolchain spam leaked into the digest.
    assert "GCC:" not in blob
    assert ".debug_" not in blob
    # But real paths/messages are surfaced.
    assert any("binscope_pwned.txt" in s for s in caps.strings_summary)


# --------------------------------------------------------------------------- #
# v0.2: numeric stimulation + exit-code / stdout triggers (fixture #4)
# --------------------------------------------------------------------------- #

def test_strtoul_detected(num_result):
    """The strtoul(..., base 10) usage is captured as a stimulus."""
    note = num_result.stimuli.note
    assert "strtoul" in note, note


def test_numeric_probes_ran(num_result):
    assert "-2" in num_result.stimuli.numeric_probes
    assert "2147483647" in num_result.stimuli.numeric_probes


def test_numeric_exit_code_change(num_result):
    """Feeding -2 flips the exit code from 1 to 0 - reported even with no I/O."""
    joined = " ".join(num_result.stimuli.exit_code_changes)
    assert "-2" in joined
    assert "exit 0" in joined


def test_numeric_secret_revealed_on_stdout(num_result):
    """The secret printed on the winning pass is surfaced in behaviour."""
    joined = " ".join(num_result.behavior.stdout_output)
    assert "flag{numeric_bypass_signed_unsigned}" in joined
    triggers = " ".join(num_result.stimuli.output_changes)
    assert "flag{numeric_bypass_signed_unsigned}" in triggers


def test_numeric_argc_detected(num_result):
    assert num_result.stimuli.argc_expected == 1


def test_numeric_json_and_md(num_result):
    data = json.loads(to_json(num_result))
    assert "strtoul" in data["stimuli"]["note"]
    assert any("flag{" in s for s in data["behavior"]["stdout_output"])
    md = to_markdown(num_result)
    assert "flag{numeric_bypass_signed_unsigned}" in md
    assert "-2" in md


# --------------------------------------------------------------------------- #
# v0.2: new ltrace families on the existing fixtures
# --------------------------------------------------------------------------- #

def test_getopt_or_strlen_family_seen(stdin_result):
    """getopt/strlen-style parsing calls are recorded (stdin fixture uses strlen)."""
    # The stdin fixture calls strcspn/strcmp; the point is that the engine
    # no longer crashes and still captures the string comparison.
    assert "hunter2" in stdin_result.stimuli.comparisons


def test_exit_codes_recorded(stdin_result):
    assert stdin_result.behavior.exit_codes
