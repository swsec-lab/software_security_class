/* ex7: inject code into the .text section (code cave).
 *
 * hidden7() exists but nothing calls it. main() contains a run of NOPs
 * (0x90) that acts as free space. Write a 'call hidden7' instruction into
 * that cave so hidden7() runs between "start" and "end".
 *
 * hint: the cave is 16 bytes of 0x90 inside main. A near call is 5 bytes:
 *       e8 <rel32>, rel32 = addr(hidden7) - (addr(cave) + 5). Leave the
 *       remaining NOPs untouched.
 */
#include <stdio.h>

void hidden7(void)
{
    printf("hidden function #7 called!\n");
}

int main(void)
{
    printf("start\n");
    asm volatile(
        ".byte 0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90\n\t"
        ".byte 0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90\n\t"
    );
    printf("end\n");
    return 0;
}
