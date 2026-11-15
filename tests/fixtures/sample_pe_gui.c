/*
 * PE fixture: a GUI-subsystem binary mirroring a typical CTF "CATCHME.EXE".
 *
 * It exists to exercise two static-analysis paths that used to misbehave:
 *   - API categorisation: SendMessageA (USER32) was filed under Network and
 *     GetSystemMetrics under Process because of loose substring matching.
 *   - notable strings: an ASCII flag-like format string ("FCSC{%.32s}") sat
 *     next to UTF-16 messages ("Catch me if you can", "Gone!") and was missed.
 *
 * Built with -mwindows so the PE subsystem is GUI, like the real sample.
 */
#include <windows.h>

static const char FLAG_FMT[] = "FCSC{%.32s}";
static const wchar_t MSG_WELCOME[] = L"Catch me if you can";
static const wchar_t MSG_GONE[] = L"Gone!";

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow) {
    char buf[64];
    HWND desktop = GetDesktopWindow();
    int metrics = GetSystemMetrics(SM_CXSCREEN);

    wsprintfA(buf, FLAG_FMT, "candidate");

    SendMessageA(desktop, WM_CLOSE, 0, 0);
    MessageBoxA(NULL, buf, "binscope", MB_OK);
    MessageBoxW(NULL, MSG_WELCOME, L"binscope", MB_OK);
    MessageBoxW(NULL, MSG_GONE, L"binscope", MB_OK);

    (void)hInst; (void)hPrev; (void)lpCmd; (void)nShow; (void)metrics;
    return 0;
}
