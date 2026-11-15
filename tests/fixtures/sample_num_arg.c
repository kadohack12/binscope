/*
 * sample_num_arg.c - fixture #4
 *
 * Parses argv[1] as an unsigned long with strtoul(..., base 10).
 *   - missing/invalid argument  -> prints usage, returns 1
 *   - any positive value        -> returns 1
 *   - the value "-2" (which wraps to ULONG_MAX-1 when read unsigned)
 *                               -> prints the secret, returns 0
 *
 * This exercises binscope's numeric stimulation: it must notice the strtoul()
 * call, probe boundary integers, and report that "-2" flips the exit code and
 * reveals the secret on stdout.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("usage: %s <number>\n", argv[0]);
        return 1;
    }

    char *end = NULL;
    unsigned long value = strtoul(argv[1], &end, 10);

    /* Reject anything that is not a clean base-10 number. */
    if (end == argv[1] || *end != '\0') {
        printf("invalid number\n");
        return 1;
    }

    /* Signed/unsigned trap: "-2" is parsed as a huge unsigned value whose
     * low bits equal 0xFFFFFFFFFFFFFFFE. Only that specific value passes. */
    if (value == (unsigned long)-2L) {
        printf("flag{numeric_bypass_signed_unsigned}\n");
        return 0;
    }

    printf("value accepted but not special\n");
    return 1;
}
