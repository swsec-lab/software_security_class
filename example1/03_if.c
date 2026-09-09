/* 03_if: branching — watch cmp/jle in the disassembly and eflags
 * try: run with different arguments, step through each branch
 * try: break after atoi, then "set var n = 200" to force another branch
 */
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
    int n;

    if (argc < 2) {
        printf("usage: %s <number>\n", argv[0]);
        return 1;
    }

    n = atoi(argv[1]);

    if (n > 100) {
        printf("%d is big\n", n);
    } else if (n > 0) {
        printf("%d is small\n", n);
    } else {
        printf("%d is not positive\n", n);
    }

    return 0;
}
