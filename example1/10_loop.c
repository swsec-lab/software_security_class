/* 10_loop (buggy): should count 3,2,1,0 and stop — but it never ends.
 *
 * [ASM TRACK — built without -g] the reason is visible in the jump used.
 * try: objdump -d -M intel ./10_loop
 *   1) find the loop-condition test "i >= 0". Because i is UNSIGNED, gcc
 *      emits an UNSIGNED compare + jump. Watch which jcc it picks:
 *        cmp DWORD PTR [ebp-X], 0
 *        jae <top>        ; "above or equal" (unsigned) — NOT jge (signed)
 *      For unsigned values "i >= 0" is always true, so the loop is endless.
 *   2) contrast with a signed int, which would compile to jns/jge and
 *      terminate when i goes negative.
 *   while it hangs: Ctrl+C in gdb, "info registers" — watch i wrap past 0
 *   to 0xffffffff instead of going negative.
 */
#include <stdio.h>

int main(void)
{
    unsigned int i;

    for (i = 3; i >= 0; i--) {
        printf("i = %u\n", i);
    }

    printf("done\n");
    return 0;
}
