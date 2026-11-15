"""Shared fixtures for the binscope test-suite."""

import os
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "fixtures")
SAMPLES = ["sample_env_cmd", "sample_stdin_file", "sample_check_file", "sample_num_arg"]


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


def pytest_configure(config):
    sys.path.insert(0, os.path.dirname(HERE))
