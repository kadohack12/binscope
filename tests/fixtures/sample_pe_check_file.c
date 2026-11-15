/*
 * PE fixture: checks for a marker file with GetFileAttributesA before doing
 * anything else. Mirrors sample_check_file.c on the Windows side.
 */
#include <windows.h>

int main(void) {
    DWORD attr = GetFileAttributesA("C:\\marker.txt");

    if (attr == INVALID_FILE_ATTRIBUTES) {
        MessageBoxA(NULL, "marker missing", "binscope", MB_OK);
        return 1;
    }

    CreateFileA("C:\\stage_two.txt", GENERIC_WRITE, 0, NULL,
                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    MessageBoxA(NULL, "marker found, stage two reached", "binscope", MB_OK);
    return 0;
}
