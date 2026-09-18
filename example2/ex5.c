/* ex5: call the hidden function by editing the .text section.
 *
 * main() calls dummy(). Your job is to patch the binary so that
 * hidden5() is called instead, without recompiling.
 *
 * hint: disassemble main (objdump -d ./ex5), find the 'call dummy'
 *       instruction (opcode e8 + rel32), and rewrite the rel32 so it
 *       points to hidden5. new_rel32 = addr(hidden5) - (addr(call) + 5)
 */
#include <stdio.h>

void hidden5(void)
{
    printf("hidden function #5 called!\n");
}

void dummy(void)
{
    printf("just a dummy...\n");
}

int main(void)
{
    dummy();
    return 0;
}
