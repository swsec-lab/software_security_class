/* 07_sum (buggy): should print "1..10 sum = 55" but prints a wrong value.
 *
 * [ASM TRACK — built without -g] find the bug by reading the disassembly.
 * try: objdump -d -M intel ./07_sum
 *   1) locate the loop-condition test at the bottom of the loop:
 *        cmp DWORD PTR [ebp-X], 9      ; the counter i is compared to 9
 *        jle <top of loop>
 *   2) "jle 9" means the loop keeps going while i <= 9, i.e. i < 10 — so
 *      i never reaches 10 and the last term is dropped. That is the bug.
 *   3) what should the immediate / jump be to include 10?  (compare with
 *      05_for, which uses <= 10 and prints 55.)
 */
#include <stdio.h>

int main(void)
{
    int sum = 0;
    int i;

    for (i = 1; i < 10; i++) {
        sum += i;
    }

    printf("1..10 sum = %d\n", sum);
    return 0;
}
