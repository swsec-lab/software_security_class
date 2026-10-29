/* ret2libc: return-to-libc, the simplest DEP bypass (lecture 7-1, slides 10-14).
 *
 * NX is on, so shellcode on the stack will not run. But NX does not stop the
 * overflow, so we reuse code that is already executable: the system() function
 * in libc. We overwrite the return address with:
 *
 *     [ &system ][ fake return ][ &"/bin/sh" ]
 *
 * and main's ret lands in system("/bin/sh"). The "/bin/sh" string is already
 * embedded in libc (slide 14: strings libc.so.6 | grep /bin/sh), so no new
 * code or data is injected.
 *
 * Built with NX on, no canary, no PIE. Run in the VM with ASLR off
 * (the default here) so the libc base is fixed.
 *
 * See solution5/solve_ret2libc.py.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void vuln(void)
{
    char buf[64];
    printf("overflow me:\n");
    read(0, buf, 256);          /* 256 bytes into a 64-byte buffer */
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    vuln();
    printf("normal exit\n");
    return 0;
}
