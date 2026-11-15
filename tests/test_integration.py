"""Integration tests: binscope must reveal the real stimuli and behaviour of
the compiled C fixtures. These tests exercise the real strace/ltrace paths -
no mocks.
"""

import json
import os

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


# --------------------------------------------------------------------------- #
# Identity / protections
# --------------------------------------------------------------------------- #

def test_identity(env_result):
    idn = env_result.identity
    assert idn.arch  # non-empty machine
    assert idn.bits in ("ELF32", "ELF64")
    assert idn.size > 0
    assert len(idn.sha256) == 64
    assert idn.stripped is False  # compiled with -g, not stripped


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
