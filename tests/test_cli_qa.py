"""End-to-end CLI QA tests (doctor, direct file shortcut, --explain, non-+x)."""

import json
import os
import shutil

from binscope.cli import main


def test_cli_doctor_runs(capsys):
    rc = main(["doctor"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "binscope doctor" in out
    assert "strace" in out
    assert "pefile" in out


def test_cli_direct_shortcut_and_explain(bins, capsys):
    rc = main([bins["sample_num_arg"], "--explain"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Beginner guide (--explain)" in out
    assert "Next steps:" in out


def test_cli_json_stdout_is_pure_json(bins, capsys):
    rc = main([bins["sample_env_cmd"], "--json", "-"])
    assert rc == 0
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["identity"]["format"] == "ELF"
    assert "RUN_MODE" in data["stimuli"]["env_vars"]


def test_cli_handles_non_executable_elf(bins, tmp_path, capsys):
    no_x = tmp_path / "downloaded_sample.txt"
    shutil.copy2(bins["sample_num_arg"], no_x)
    os.chmod(no_x, 0o644)
    assert not os.access(no_x, os.X_OK)

    rc = main([str(no_x), "--json", "-"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert "0" in data["stimuli"]["numeric_probes"]
    assert any("numeric_bypass_signed_unsigned" in s for s in data["behavior"]["stdout_output"])


def test_cli_missing_and_non_binary(tmp_path, capsys):
    assert main([str(tmp_path / "missing.bin")]) == 2

    txt = tmp_path / "note.txt"
    txt.write_text("hello world\n", encoding="utf-8")
    assert main([str(txt)]) == 0
    out = capsys.readouterr().out
    assert "does not look like an ELF or PE binary" in " ".join(out.split())


def test_cli_non_ascii_path_no_self_execve(bins, tmp_path, capsys):
    accent_dir = tmp_path / "Téléchargements"
    accent_dir.mkdir()
    sample = accent_dir / "aaarg.txt"
    shutil.copy2(bins["sample_num_arg"], sample)
    os.chmod(sample, 0o644)

    rc = main([str(sample), "--json", "-"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["behavior"]["execve"] == []
