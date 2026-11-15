/*
 * PE fixture: a DLL whose DllMain consults an environment variable. Exercises
 * DLL identity detection and the emulated module-entry (DllMain) path.
 */
#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        char mode[64] = {0};
        GetEnvironmentVariableA("DLL_MODE", mode, sizeof(mode));
        if (mode[0]) {
            CreateFileA("C:\\dll_stage.txt", GENERIC_WRITE, 0, NULL,
                        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        }
    }
    return TRUE;
}

__declspec(dllexport) int exported_func(void) { return 42; }
