/* ex6: reach the hidden function by editing the .text section.
 *
 * hidden6() sits behind a condition that is never true, so it never runs.
 * Patch the branch in main so that hidden6() is always called.
 *
 * hint: find the conditional jump (e.g. jne) that skips hidden6() and
 *       neutralize it (NOP it out, or turn it into the branch you want).
 */
#include <stdio.h>

void hidden6(void)
{
    printf("hidden function #6 called!\n");
}

int main(int argc, char *argv[])
{
    if (argc == 999) {
        hidden6();
    } else {
        printf("access denied\n");
    }
    return 0;
}
