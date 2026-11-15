#!/usr/bin/env bash
# Compile the Windows PE fixtures used by the integration tests.
# Requires mingw-w64 (x86_64-w64-mingw32-gcc). Skips cleanly if absent.
set -eu
cd "$(dirname "$0")"

if ! command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
    echo "x86_64-w64-mingw32-gcc not found - skipping PE fixtures" >&2
    exit 0
fi

CC=x86_64-w64-mingw32-gcc
for src in sample_pe_env_cmd.c sample_pe_file_net.c sample_pe_check_file.c; do
    out="${src%.c}.exe"
    $CC -O0 -o "$out" "$src" -lws2_32
    echo "built $out"
done
# GUI-subsystem sample (SendMessageA/GetSystemMetrics + ASCII flag + UTF-16 text).
$CC -O0 -mwindows -o sample_pe_gui.exe sample_pe_gui.c
echo "built sample_pe_gui.exe"
$CC -O0 -shared -o sample_pe_dll.dll sample_pe_dll.c
echo "built sample_pe_dll.dll"
