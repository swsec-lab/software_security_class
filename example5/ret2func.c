/* ret2func: return into a function already compiled into THIS binary
 * (lecture 8-1, slide 6: "We Can Still Corrupt Return Address").
 *
 * DEP/NX (example3, Part B) only stops *executing the stack*. It says
 * nothing about which already-executable code the hijacked return address
 * points to. The overflow still lets us overwrite the return address, so
 * instead of injecting shellcode we redirect control flow to a function
 * that is already part of the program's own .text but that normal control
 * flow never calls: foo(), which spawns a shell.
 *
 * This mirrors the slide almost exactly:
 *
 *   int main(){ int x = 42; echo(); return 0; }
 *   void echo(){ char buf[32]; gets(buf); puts(buf); }
 *   void foo(){ system("/bin/sh"); }
 *
 * It is the simplest possible code-reuse attack: no libc address is needed
 * at all, because the "backdoor" function lives inside the vulnerable
 * binary itself and -no-pie fixes its address at link time (readelf -s /
 * objdump -d ./ret2func | grep foo). Return-to-libc (ret2libc.c, Problem 1)
 * is the generalization of this exact idea: instead of a function the
 * programmer happened to leave lying around, reuse a function that is
 * *always* lying around -- system(), in libc.
 *
 * The slide's echo() reads with gets(buf); glibc >= 2.32 (this VM ships
 * 2.35) removed gets() entirely, so -- like the rest of this course's
 * examples (see example3/vuln1.c) -- we read with read() instead. The
 * overflow is identical, just binary-safe.
 *
 * Built with NX on, no canary, no PIE -- the same flags as ret2libc, and
 * the exact setup the slide assumes (DEP is already in place; it just
 * doesn't help).
 *
 * See solution5/solve_ret2func.py.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void echo(void);
void foo(void);

int main(void)
{
    int x = 42;
    (void)x;                        /* matches the slide's unused local */
    setvbuf(stdout, NULL, _IONBF, 0);
    echo();
    return 0;
}

void echo(void)
{
    char buf[32];
    printf("overflow me:\n");
    read(0, buf, 256);              /* up to 256 bytes into a 32-byte buffer */
    puts(buf);
}

/* Never called by main() / echo() -- reachable only by corrupting the
 * return address, exactly like the slide's foo(). */
void foo(void)
{
    system("/bin/sh");
}
