/* morris: the finger-service buffer overflow exploited by the 1988 Morris
 * Worm (lecture slides 7-26) -- return-to-stack shellcode injection.
 *
 * The slide code is kept verbatim:
 *     char buf[0x400];
 *     gets(buf);          // no bounds check -> overwrites the return address
 *     return 0;
 *
 * gets() was removed in glibc 2.34+, so to preserve the historic code we
 * provide our own equally-unsafe (no bounds check) gets().
 *
 * Unlike vuln2, this program does NOT leak an address -- "how do you learn
 * the buffer address" is the real challenge from the lecture (slides 27-30).
 * The solution finds buf via a core dump and absorbs slack with a NOP sled
 * (see solution3/solve_morris.py).
 */
#include <stdio.h>

/* Minimal gets() for glibc 2.34+ (no bounds check, just like the original). */
char *gets(char *s);
char *gets(char *s)
{
    int c;
    char *p = s;
    while ((c = getchar()) != EOF && c != '\n')
        *p++ = (char)c;         /* keeps writing with no bounds check */
    *p = '\0';
    return s;
}

int main(int argc, char *argv[])
{
    char buf[0x400];

    setvbuf(stdout, NULL, _IONBF, 0);
    gets(buf);
    return 0;
}
