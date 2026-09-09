/* 05_for: sum 1..10  [ASM TRACK — built without -g]
 *
 * "print sum" / "watch sum" won't work: there are no variable names left,
 * so you must read the assembly.  (Function symbols like main are still
 * there, so objdump can find the code.)
 *
 * try: objdump -d -M intel ./05_for   (or "disassemble main" in gdb)
 *   1) find the loop: a backward jump near a "cmp ...,0xa" + "jle".
 *   2) the accumulator is the stack slot [ebp-X] that an "add" writes to
 *      every iteration — that is `sum`. The counter [ebp-Y] is `i`.
 *   3) watch it by address:  watch *(int*)($ebp-X)   then continue.
 * Intel syntax tip:  set disassembly-flavor intel   (see README.md)
 */
#include <stdio.h>

int main(void)
{
    int sum = 0;
    int i;

    for (i = 1; i <= 10; i++) {
        sum += i;
    }

    printf("1..10 sum = %d\n", sum);
    return 0;
}
