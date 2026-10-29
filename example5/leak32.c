/* leak32: defeat ASLR with a leaked libc pointer, 32-bit (lecture 7-2, 46-50).
 *
 * With ASLR on, libc loads at a random base each run, so the hard-coded
 * addresses from Problems 1-4 no longer work. But ASLR only randomizes the
 * BASE of each segment -- the relative offsets inside libc are fixed
 * (slide 50). So one leaked libc address is enough:
 *
 *     libc_base = leaked_puts - libc.sym.puts
 *     system    = libc_base   + libc.sym.system
 *
 * then ret2libc as in Problem 1. This bridges lecture 6 (memory disclosure):
 * the leak is the disclosure, the chain is the hijack.
 *
 * To keep the lab focused on the ASLR bypass itself, this program *simulates*
 * the disclosure by printing a real, ASLR-randomized libc address (puts, via
 * dlsym) -- a stand-in for a format-string or overread leak from lecture 6. The
 * same run then takes an overflow for the ret2libc stage.
 *
 * Run with ASLR ON:  sudo sysctl -w kernel.randomize_va_space=2
 * See solution5/solve_leak32.py.
 */
#define _GNU_SOURCE             /* for RTLD_DEFAULT */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>

void vuln(void)
{
    char buf[64];
    printf("overflow me:\n");
    read(0, buf, 256);
}

int main(void)
{
    void *leak;
    setvbuf(stdout, NULL, _IONBF, 0);

    /* The "memory disclosure": a genuine, ASLR-randomized libc address. */
    leak = dlsym(RTLD_DEFAULT, "puts");
    printf("[leak] puts @ %p\n", leak);

    vuln();                     /* the ret2libc stage uses the leak above */
    printf("normal exit\n");
    return 0;
}
