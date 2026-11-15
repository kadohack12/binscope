/*
 * sample_env_cmd.c - fixture #1
 *
 * Expects the environment variable RUN_MODE=1 AND the argv option --go.
 * When both are present it runs "/bin/echo payload_executed" via system().
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    const char *mode = getenv("RUN_MODE");
    int has_go = (argc > 1 && strcmp(argv[1], "--go") == 0);

    if (mode != NULL && strcmp(mode, "1") == 0 && has_go) {
        system("/bin/echo payload_executed");
    } else {
        printf("usage: set RUN_MODE=1 and pass --go\n");
    }
    return 0;
}
