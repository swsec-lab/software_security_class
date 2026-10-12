/* fmt_got: control-flow hijack with a format string (lecture 6-2, slides 43-44).
 *
 * The finale: a format string write becomes a control-flow hijack. The program
 * never calls win() itself. We use the %n write primitive to overwrite the GOT
 * entry of a libc function that runs AFTER the vulnerable printf -- here the
 * final puts("bye") -- so that call lands in win() instead.
 *
 * Unlike a buffer overflow, a format string can write to an ARBITRARY address
 * (slide 44), so we target the GOT directly and never touch the stack / return
 * address. Built with partial RELRO (-Wl,-z,norelro) so the GOT stays writable;
 * full RELRO would make the GOT read-only and defeat this specific trick.
 *
 * See solution4/solve_fmt_got.py.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void win(void)
{
    /* NOTE: puts@GOT now points HERE, so win() must NOT call puts() -- that
     * would recurse into win() forever. Use write() for the banner. */
    const char *m = "control flow hijacked via format string!\n";
    write(1, m, strlen(m));
    system("/bin/sh");
    _exit(0);
}

int main(void)
{
    char buf[256];
    int n;

    setvbuf(stdout, NULL, _IONBF, 0);
    printf("hijack me. win() is at %p:\n", (void *)&win);

    n = (int)read(0, buf, sizeof(buf) - 1);
    if (n < 0) return 1;
    buf[n] = '\0';

    printf(buf);        /* VULN: overwrite puts@GOT with win here */
    puts("bye");        /* this call is redirected to win() */
    return 0;
}
