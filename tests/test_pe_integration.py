"""Integration tests for the Windows PE backend.

The fixtures are real PE32+ binaries compiled with mingw-w64 and emulated with
Speakeasy - no mocks. Tests are skipped if the toolchain or the optional
``speakeasy`` dependency is unavailable.
"""

import json

import pytest

from binscope.cli import analyze, detect_format
from binscope.report import to_json, to_markdown

speakeasy = pytest.importorskip("speakeasy", reason="speakeasy not installed")


@pytest.fixture(scope="module")
def env_result(pe_bins):
    return analyze(pe_bins["sample_pe_env_cmd"], timeout=5.0)


@pytest.fixture(scope="module")
def file_net_result(pe_bins):
    return analyze(pe_bins["sample_pe_file_net"], timeout=5.0)


@pytest.fixture(scope="module")
def check_result(pe_bins):
    return analyze(pe_bins["sample_pe_check_file"], timeout=5.0)


@pytest.fixture(scope="module")
def dll_result(pe_bins):
    return analyze(pe_bins["sample_pe_dll"], timeout=5.0)


@pytest.fixture(scope="module")
def gui_result(pe_bins):
    return analyze(pe_bins["sample_pe_gui"], timeout=5.0)


# --------------------------------------------------------------------------- #
# Format detection
# --------------------------------------------------------------------------- #

def test_detect_format_pe(pe_bins):
    assert detect_format(pe_bins["sample_pe_env_cmd"]) == "PE"


def test_detect_format_elf(bins):
    assert detect_format(bins["sample_env_cmd"]) == "ELF"


def test_detect_format_unknown(tmp_path):
    junk = tmp_path / "notabinary.bin"
    junk.write_bytes(b"just some text, definitely not a PE or ELF\n")
    assert detect_format(str(junk)) == ""


# --------------------------------------------------------------------------- #
# Identity / protections
# --------------------------------------------------------------------------- #

def test_identity_pe(env_result):
    idn = env_result.identity
    assert idn.format == "PE"
    assert idn.arch in ("x64", "x86", "ARM64", "ARM")
    assert idn.bits in ("32", "64")
    assert idn.elf_type in ("PE32", "PE32+")
    assert idn.subsystem in ("Console", "GUI")
    assert idn.sections > 0
    assert idn.sha256 and len(idn.sha256) == 64
    assert idn.size > 0


def test_entropy_reported(env_result):
    assert 0.0 <= env_result.identity.max_entropy <= 8.0


def test_protections_pe(env_result):
    prot = env_result.protections
    # mingw-w64 enables ASLR + DEP by default on x64.
    assert prot.aslr is True
    assert prot.dep is True
    assert prot.nx is True


# --------------------------------------------------------------------------- #
# Stimuli - what the binary expects
# --------------------------------------------------------------------------- #

def test_env_var_discovered(env_result):
    """The fixture consults GetEnvironmentVariableA("RUN_MODE")."""
    assert "RUN_MODE" in env_result.stimuli.env_vars


def test_argv_token_discovered(env_result):
    """Passing --go changes behaviour, so it must be reported as a stimulus."""
    assert "--go" in env_result.stimuli.argv


def test_input_apis_reported(env_result):
    joined = " ".join(env_result.stimuli.input_apis)
    assert "GetEnvironmentVariableA" in joined
    assert "GetCommandLineA" in joined


def test_trigger_notes(env_result):
    """The env/argv passes must show which APIs they newly unlocked."""
    joined = " ".join(env_result.stimuli.trigger_notes)
    assert "--go" in joined
    assert "RUN_MODE" in joined


def test_env_value_injection_writes_file(env_result):
    """RUN_MODE=1 makes the fixture create C:\\mode_ok.txt."""
    assert any("mode_ok" in f for f in env_result.behavior.files_written)


# --------------------------------------------------------------------------- #
# Behaviour - what the binary really does
# --------------------------------------------------------------------------- #

def test_execve_captured(env_result):
    joined = " ".join(env_result.behavior.execve)
    assert "WinExec" in joined
    assert "payload_executed" in joined


def test_messagebox_text_captured(env_result):
    joined = " ".join(env_result.behavior.stdout_output)
    assert "access granted to payload" in joined


def test_file_read_reported(file_net_result):
    assert any("secret.txt" in f for f in file_net_result.behavior.files_read)


def test_network_reported(file_net_result):
    joined = " ".join(file_net_result.behavior.network)
    assert "connect" in joined
    assert "127.0.0.1:9999" in joined


def test_registry_reported(file_net_result):
    assert "Binscope" in file_net_result.behavior.note


def test_check_file_stage_two(check_result):
    """The marker file exists in the emulated FS, so stage two is reached."""
    joined = " ".join(check_result.behavior.files_written)
    assert "stage_two" in joined


def test_dll_identity(dll_result):
    assert dll_result.identity.elf_type.endswith("DLL")


def test_dll_env_adaptive_probe(dll_result):
    """DllMain consults DLL_MODE; the engine must probe it and reveal the write."""
    assert "DLL_MODE" in dll_result.stimuli.env_vars
    assert any("dll_stage" in f for f in dll_result.behavior.files_written)


# --------------------------------------------------------------------------- #
# Static capabilities
# --------------------------------------------------------------------------- #

def test_dlls_reported(env_result):
    joined = " ".join(env_result.capabilities.dlls)
    assert "KERNEL32.dll" in joined


def test_api_categories(env_result):
    cats = env_result.capabilities.api_categories
    assert "Process" in cats  # WinExec
    assert "Environment" in cats  # GetEnvironmentVariableA


def test_interesting_strings(env_result):
    joined = " ".join(env_result.capabilities.interesting_strings)
    assert "payload_executed" in joined or "access granted" in joined


def test_gui_subsystem(gui_result):
    assert gui_result.identity.subsystem == "GUI"
    assert gui_result.identity.format == "PE"


def test_gui_apis_not_miscategorized(gui_result):
    """SendMessageA is USER32 (GUI) and GetSystemMetrics is not a process API."""
    cats = gui_result.capabilities.api_categories
    gui_apis = " ".join(cats.get("GUI", []))
    assert "SendMessageA" in gui_apis
    assert "GetSystemMetrics" in gui_apis
    # Regression: loose substring matching filed these under the wrong family.
    assert "SendMessageA" not in " ".join(cats.get("Network", []))
    assert "GetSystemMetrics" not in " ".join(cats.get("Process", []))
    assert "MessageBoxA" in gui_apis


def test_notable_strings_include_ascii_format(gui_result):
    """The ASCII flag-like format string must appear in the notable ASCII list."""
    ascii_notable = gui_result.capabilities.notable_ascii_strings
    assert any("FCSC{" in s for s in ascii_notable)
    # ...and the UTF-16 messages must still be reported on their own side.
    unicode_strings = gui_result.capabilities.unicode_strings
    assert any("Catch me if you can" in s for s in unicode_strings)


def test_notable_strings_render_both_encodings(gui_result):
    md = to_markdown(gui_result)
    assert "notable strings (ASCII)" in md
    assert "FCSC{" in md
    assert "notable strings (UTF-16)" in md
    assert "Catch me if you can" in md


# --------------------------------------------------------------------------- #
# Synthesis & exports
# --------------------------------------------------------------------------- #

def test_synthesis_mentions_pe(env_result):
    joined = " ".join(env_result.synthesis)
    assert "Windows PE" in joined
    assert 3 <= len(env_result.synthesis) <= 6


def test_json_export_roundtrip(env_result):
    data = json.loads(to_json(env_result))
    assert data["identity"]["format"] == "PE"
    assert data["identity"]["subsystem"]
    assert "dlls" in data["capabilities"]
    assert "input_apis" in data["stimuli"]


def test_markdown_export(env_result):
    md = to_markdown(env_result)
    assert "## 1. Identity" in md
    assert "Subsystem" in md
    assert "ASLR" in md
    assert "## 5. Analyst synthesis" in md


def test_unknown_binary_degrades_gracefully(tmp_path):
    junk = tmp_path / "blob.bin"
    junk.write_bytes(b"\x00\x01\x02 not a real executable \x03")
    result = analyze(str(junk))
    assert result.warnings  # a warning is emitted
    assert result.synthesis  # synthesis still produced
