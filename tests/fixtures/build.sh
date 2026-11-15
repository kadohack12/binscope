#!/usr/bin/env bash
# Compile the C fixtures used by the integration tests.
set -eu
cd "$(dirname "$0")"
for src in sample_env_cmd.c sample_stdin_file.c sample_check_file.c sample_num_arg.c; do
    out="${src%.c}"
    gcc -O0 -g -fno-inline -o "$out" "$src"
    echo "built $out"
done
