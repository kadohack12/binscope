"""Shared fixtures for the binscope test-suite."""

import os
import shutil
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "fixtures")
SAMPLES = ["sample_env_cmd", "sample_stdin_file", "sample_check_file", "sample_num_arg"]
PE_SAMPLES = ["sample_pe_env_cmd", "sample_pe_file_net", "sample_pe_check_file"]


@pytest.fixture(scope="session", autouse=True)
def compiled_fixtures():
    """Compile the C fixtures once per session (real gcc build, no mocks)."""
    if not os.path.exists("/usr/bin/gcc"):
        pytest.skip("gcc not available")
    for name in SAMPLES:
        src = os.path.join(FIXTURES, name + ".c")
        out = os.path.join(FIXTURES, name)
        if not os.path.exists(out) or os.path.getmtime(out) < os.path.getmtime(src):
            subprocess.run(["gcc", "-O0", "-g", "-fno-inline", "-o", out, src], check=True)
    return {name: os.path.join(FIXTURES, name) for name in SAMPLES}


@pytest.fixture(scope="session")
def bins():
    return {name: os.path.join(FIXTURES, name) for name in SAMPLES}


@pytest.fixture(scope="session")
def pe_bins():
    """Build the Windows PE fixtures with mingw-w64 (skip if unavailable)."""
    cc = shutil.which("x86_64-w64-mingw32-gcc")
    if not cc:
        pytest.skip("x86_64-w64-mingw32-gcc not available")
    built = {}
    for name in PE_SAMPLES:
        src = os.path.join(FIXTURES, name + ".c")
        out = os.path.join(FIXTURES, name + ".exe")
        if not os.path.exists(out) or os.path.getmtime(out) < os.path.getmtime(src):
            subprocess.run([cc, "-O0", "-o", out, src, "-lws2_32"], check=True)
        built[name] = out
    # The DLL fixture needs the -shared flag.
    src = os.path.join(FIXTURES, "sample_pe_dll.c")
    out = os.path.join(FIXTURES, "sample_pe_dll.dll")
    if not os.path.exists(out) or os.path.getmtime(out) < os.path.getmtime(src):
        subprocess.run([cc, "-O0", "-shared", "-o", out, src], check=True)
    built["sample_pe_dll"] = out
    return built


def pytest_configure(config):
    sys.path.insert(0, os.path.dirname(HERE))
