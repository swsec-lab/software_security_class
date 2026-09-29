/* nx_demo: Data Execution Prevention / NX (lecture 5, Mitigation #2).
 *
 * Built WITHOUT -z execstack, so the stack is non-executable (NX on, the
 * default). The return-to-stack shellcode from example3 now FAILS: jumping
 * into the stack raises a page-fault (the injected bytes are not executable).
 *
 * But DEP does NOT stop the overflow itself, only code ON the stack. Returning
 * to EXISTING code still works -- overwrite the return address with win()
 * (lecture "Revisiting Week 1: Returning to Existing Code"). This is the seed
 * of ret2libc / ROP.
 *
 * Canary is off (-fno-stack-protector) to isolate NX.
 * Query the stack flag:  execstack -q ./nx_demo   ('-' = NX on, 'X' = exec)
 * checksec:              pwn checksec ./nx_demo    (NX enabled)
 *
 * See solution4/solve_nx_demo.py (ret2win works; stack shellcode does not).
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void win(void)
{
    printf("returned to existing code!\n");
    system("/bin/sh");
}

int main(void)
{
    char buf[64];

    setvbuf(stdout, NULL, _IONBF, 0);
    printf("buf is at %p\n", (void *)buf);   /* for the (failing) shellcode attempt */
    printf("input: ");
    read(0, buf, 512);
    return 0;
}
