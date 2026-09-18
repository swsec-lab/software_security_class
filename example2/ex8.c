/* ex8: call the hidden function from the .data section.
 *
 * main() jumps into the global array `code`, which lives in .data.
 * By default .data is not executable, so running this crashes.
 *
 * Two edits are required:
 *   1) ELF program (segment) header: give the data PT_LOAD segment the
 *      execute flag (RW -> RWX).
 *   2) .data section: overwrite `code` with a 'call hidden8' + 'ret'
 *      so control reaches hidden8() and then returns cleanly.
 *
 * hint: rel32 = addr(hidden8) - (addr(code) + 5); bytes = e8 <rel32> c3
 */
#include <stdio.h>

unsigned char code[64] = { 0xc3 };  /* initially just 'ret' -> forced into .data */

void hidden8(void)
{
    printf("hidden function #8 called!\n");
}

int main(void)
{
    printf("jumping into data...\n");
    ((void (*)(void))code)();
    printf("back from data\n");
    return 0;
}
