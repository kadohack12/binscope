/*
 * PE fixture: gates on an environment variable and a CLI switch, then runs a
 * child process. Mirrors sample_env_cmd.c on the Windows side.
 *
 * Avoids the C stdio runtime so Speakeasy emulation reaches the Win32 calls
 * (printf-style APIs hit an unimplemented msvcrt.__iob_func and halt early).
 */
#include <windows.h>

int main(int argc, char **argv) {
    char *cmd = GetCommandLineA();
    char mode[64] = {0};
    GetEnvironmentVariableA("RUN_MODE", mode, sizeof(mode));

    if (mode[0] && lstrcmpA(mode, "1") == 0) {
        CreateFileA("C:\\mode_ok.txt", GENERIC_WRITE, 0, NULL,
                    CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    }

    if (strstr(cmd, "--go")) {
        WinExec("cmd.exe /c echo payload_executed", SW_HIDE);
        MessageBoxA(NULL, "access granted to payload", "binscope", MB_OK);
    } else {
        MessageBoxA(NULL, "usage: pass --go", "binscope", MB_OK);
    }

    IsDebuggerPresent();
    return 0;
}
