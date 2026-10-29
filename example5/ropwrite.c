/* ropwrite: a ROP write-what-where primitive (lecture 7-2, slides 7-13).
 *
 * The gadget `mov [ptr], 0x41414141; ret` almost never exists, so we build the
 * write out of three tiny gadgets chained by their ret instructions:
 *
 *     A: pop eax ; ret          -> eax = &key      (the "where")
 *     B: pop ebx ; ret          -> ebx = 0x41414141 (the "what")
 *     C: mov [eax], ebx ; ret   -> *key = 0x41414141
 *
 * Stack:  [A][&key][B][0x41414141][C][&win]
 *
 * After the write, the chain returns into win(), which checks key and spawns a
 * shell. To guarantee the exact gadgets from the slides exist, this binary
 * ships a small gadget farm (never called -- we only jump into its bytes).
 *
 * See solution5/solve_ropwrite.py.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

unsigned int key = 0;                 /* the write target (fixed addr, no PIE) */

void win(void)
{
    if (key == 0x41414141) {
        puts("key set by ROP -> spawning shell");
        system("/bin/sh");
    } else {
        printf("key = 0x%08x, no shell\n", key);
    }
    _exit(0);
}

/* Gadget farm: guarantees pop eax;ret / pop ebx;ret / mov [eax],ebx;ret exist.
 * Never called; the exploit returns straight into these bytes. */
void gadgets(void)
{
    __asm__ __volatile__(
        "pop %eax\n\t"
        "ret\n\t"
        "pop %ebx\n\t"
        "ret\n\t"
        "mov %ebx, (%eax)\n\t"
        "ret\n\t");
}

void vuln(void)
{
    char buf[64];
    printf("rop me:\n");
    read(0, buf, 256);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    vuln();
    return 0;
}
