/* ret2syscall: a pure-ROP execve via the int 0x80 syscall (lecture 7-2).
 *
 * On 32-bit, return-to-libc needs libc functions like system(). ROP lets us go
 * lower: instead of calling a function, we chain gadgets to set up a raw
 * syscall and run execve("/bin/sh", NULL, NULL) ourselves -- no libc call at
 * all. This is the 32-bit counterpart to the x86-64 "ROP for x86-64" section
 * of the slides, where arguments are loaded into registers before the call:
 *
 *     execve on 32-bit Linux = int 0x80 with
 *         eax = 11 (__NR_execve)
 *         ebx = &"/bin/sh"
 *         ecx = 0   (argv)
 *         edx = 0   (envp)
 *
 * so the ROP chain is:
 *
 *     [pop eax;ret][11][pop ebx;ret][&binsh][pop ecx;ret][0][pop edx;ret][0][int 0x80]
 *
 * To guarantee the exact gadgets exist, the binary ships a gadget farm (never
 * called -- we only jump into its bytes) and a "/bin/sh" string.
 *
 * Built NX on, no canary, no PIE. Run with ASLR off.
 *
 * See solution5/solve_ret2syscall.py.
 */
#include <stdio.h>
#include <unistd.h>

char binsh[] = "/bin/sh";             /* the execve filename (fixed addr, no PIE) */

/* Gadget farm: guarantees pop eax/ebx/ecx/edx;ret and int 0x80 all exist.
 * Never called; the exploit returns straight into these bytes. */
void gadgets(void)
{
    __asm__ __volatile__(
        "pop %eax\n\t"
        "ret\n\t"
        "pop %ebx\n\t"
        "ret\n\t"
        "pop %ecx\n\t"
        "ret\n\t"
        "pop %edx\n\t"
        "ret\n\t"
        "int $0x80\n\t");
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
    printf("normal exit\n");
    return 0;
}
