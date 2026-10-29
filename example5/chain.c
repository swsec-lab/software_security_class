/* chain: chaining two libc calls with ESP lifting (lecture 7-1, slides 16-28).
 *
 * A single ret2libc calls one function. To call TWO in a row we must clean up
 * the first call's argument before the second runs, or the arguments collide
 * on the stack (slide 21). The fix is a small "pop; ret" gadget that lifts ESP
 * past the consumed argument (slides 22-28, "ESP lifting"):
 *
 *     [ &setuid ][ pop;ret ][ 0 ][ &system ][ fake ret ][ &"/bin/sh" ]
 *
 * main ret -> setuid(0); setuid ret -> pop;ret removes the 0; ret -> system,
 * which now sees "/bin/sh" as its argument.
 *
 * setuid(0) only elevates if the binary is setuid-root; as a normal user it
 * returns -1 harmlessly and you still get a (non-root) shell -- the point here
 * is the *chaining mechanism*. The README shows how to make it setuid-root to
 * actually pop a root shell, the way the attack mattered historically.
 *
 * See solution5/solve_chain.py.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void vuln(void)
{
    char buf[64];
    printf("chain me:\n");
    read(0, buf, 256);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    vuln();
    printf("normal exit\n");
    return 0;
}
