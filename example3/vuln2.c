/* vuln2: return-to-stack -- inject shellcode into the stack buffer and point
 * the return address back at it.
 *
 * Stage 2 of the lecture's "Return-to-Stack Exploit". You need the buffer's
 * address, so for teaching the program prints buf's address itself (real
 * exploits solve this with an address leak / brute force / NOP sled).
 *
 * Goal (see solution3/solve_vuln2.py):
 *   - read the leaked buf address with recvline
 *   - build execve("/bin/sh") shellcode with asm(shellcraft.sh())
 *   - fill buf with [NOP sled][shellcode] and overwrite the return addr with buf
 *   - to just confirm control first, use asm('jmp $') (eb fe, infinite loop)
 *
 * Built with an executable stack (-z execstack) so stack shellcode runs.
 * The VM disables ASLR (kernel.randomize_va_space=0) so addresses are stable.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void)
{
    char buf[256];

    setvbuf(stdout, NULL, _IONBF, 0);
    printf("buf is at %p\n", (void *)buf);   /* teaching-only address leak */
    printf("send your payload:\n");
    read(0, buf, 1024);                        /* up to 1024 into a 256-byte buffer */
    return 0;
}
