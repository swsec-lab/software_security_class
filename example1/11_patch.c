/* 11_patch: change the execution flow by patching bytes (NOP the branch)
 *
 * [ASM TRACK — built without -g] `allowed` is 0 and the code never sets it
 * to 1, so this always prints "ACCESS DENIED". Your job: WITHOUT recompiling,
 * patch the binary on disk so it prints "ACCESS GRANTED".
 *
 * Idea: the "if (allowed)" compiles to a compare + conditional jump that
 * skips the GRANTED branch. Neutralize that jump (overwrite it with NOPs,
 * 0x90) so control falls through into GRANTED every time.
 *
 * Steps:
 *   1) objdump -d -M intel ./11_patch
 *      find in main:   cmp DWORD PTR [ebp-X], 0
 *                      je  <addr of the else/denied branch>   ; 2 bytes: 74 xx
 *   2) note that instruction's address, then convert it to a FILE OFFSET.
 *      With -no-pie the load base is 0x08048000; a quick way is:
 *        objdump -d ./11_patch      # note the vaddr of the je
 *        # file_off = vaddr - (vaddr of a byte whose offset you know), or
 *        readelf -S ./11_patch      # .text: find its addr and its offset
 *        # file_off = je_vaddr - .text_addr + .text_offset
 *   3) overwrite those 2 bytes with 0x90 0x90:
 *        printf '\x90\x90' | dd of=./11_patch bs=1 seek=<file_off> \
 *               count=2 conv=notrunc
 *      (or in Python:  b=open('11_patch','r+b'); b.seek(off);
 *                      b.write(b'\x90\x90'); b.close())
 *   4) ./11_patch    ->  ACCESS GRANTED
 *
 * Variations to try:
 *   - instead of NOPping "je", flip it to "jne" (74 -> 75) and see what
 *     happens: now GRANTED shows only when allowed is non-zero (it never is),
 *     so it stays DENIED — proof you understood the condition.
 *   - do the same patch live in gdb without touching the file:
 *       break main ; run ; then at the je:  set $eip = <granted addr>
 */
#include <stdio.h>

int main(void)
{
    int allowed = 0;   /* never changed to 1 anywhere in the code */

    if (allowed) {
        printf("ACCESS GRANTED\n");
    } else {
        printf("ACCESS DENIED\n");
    }
    return 0;
}
