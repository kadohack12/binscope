/*
 * sample_check_file.c - fixture #3
 *
 * Checks for the marker file /tmp/binscope_marker with access() before
 * running the "real" behaviour (exec /bin/echo stage_two).
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    if (access("/tmp/binscope_marker", F_OK) == 0) {
        printf("marker found, continuing\n");
        system("/bin/echo stage_two");
    } else {
        printf("marker /tmp/binscope_marker not found, aborting\n");
    }
    return 0;
}
