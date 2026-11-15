/*
 * PE fixture: opens/creates a marker file, reads a registry key and opens a
 * TCP connection. Mirrors sample_stdin_file.c on the Windows side, and
 * exercises the file / registry / network reporting paths.
 */
#include <winsock2.h>
#include <windows.h>

int main(int argc, char **argv) {
    char *cmd = GetCommandLineA();

    if (strstr(cmd, "--go")) {
        HANDLE h = CreateFileA("C:\\secret.txt", GENERIC_READ, 0, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h == INVALID_HANDLE_VALUE) {
            CreateFileA("C:\\secret.txt", GENERIC_WRITE, 0, NULL,
                        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        } else {
            CloseHandle(h);
        }

        HKEY k;
        RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Binscope", 0, KEY_READ, &k);

        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) == 0) {
            SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (s != INVALID_SOCKET) {
                struct sockaddr_in sa;
                sa.sin_family = AF_INET;
                sa.sin_port = htons(9999);
                sa.sin_addr.s_addr = inet_addr("127.0.0.1");
                connect(s, (struct sockaddr *)&sa, sizeof(sa));
                closesocket(s);
            }
            WSACleanup();
        }
    }

    MessageBoxA(NULL, "binscope file/network demo", "binscope", MB_OK);
    return 0;
}
