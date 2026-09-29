/* vuln1: ret2win -- overwrite the return address to reach the hidden win().
 *
 * Stage 1 of practicing the lecture's stack overflow (4. Code Injection
 * Attacks) with pwntools. No shellcode needed: just redirect the return
 * address to win() and you get a shell.
 *
 * Goal (see solution3/solve_vuln1.py):
 *   - use cyclic / cyclic_find to get the offset from buf to the return addr
 *   - read win's address from ELF('./vuln1').symbols['win']
 *   - build the payload with flat({offset: win}) and sendline it
 *
 * gets() is gone in glibc 2.34+, so we overflow with read() instead
 * (read is binary-safe -- reused by the shellcode stages too).
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void win(void)
{
    printf("you hijacked the control flow!\n");
    system("/bin/sh");
}

void vuln(void)
{
    char buf[64];
    printf("overflow me:\n");
    read(0, buf, 512);          /* up to 512 bytes into a 64-byte buffer */
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    vuln();
    printf("normal exit\n");
    return 0;
}
