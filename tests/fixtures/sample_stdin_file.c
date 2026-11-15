/*
 * sample_stdin_file.c - fixture #2
 *
 * Reads stdin, compares the line to the password "hunter2" with strcmp.
 * On success it writes /tmp/binscope_pwned.txt and connects to 127.0.0.1:9999.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(void) {
    char buf[128] = {0};
    if (fgets(buf, sizeof(buf), stdin) == NULL) {
        printf("no input\n");
        return 1;
    }
    buf[strcspn(buf, "\n")] = '\0';

    if (strcmp(buf, "hunter2") == 0) {
        FILE *fp = fopen("/tmp/binscope_pwned.txt", "w");
        if (fp) {
            fprintf(fp, "unlocked\n");
            fclose(fp);
        }
        int s = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in a;
        memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET;
        a.sin_port = htons(9999);
        inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
        connect(s, (struct sockaddr *)&a, sizeof(a));
        printf("password accepted\n");
    } else {
        printf("access denied\n");
    }
    return 0;
}
