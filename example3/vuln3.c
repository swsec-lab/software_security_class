/* vuln3: data-only stack smash -- overwrite an ADJACENT variable, not the
 * return address.
 *
 * A different primitive from vuln1/vuln2/morris: no control-flow hijack and
 * no shellcode. Overflowing buf corrupts the neighbouring `auth` field, and
 * setting it to the exact expected value bypasses the check.
 *
 * buf and auth live in one struct, so auth is GUARANTEED to sit right after
 * buf in memory (members are laid out in declaration order). That makes the
 * overflow deterministic regardless of compiler local-variable ordering.
 *
 * Goal (see solution3/solve_vuln3.py):
 *   - overflow buf with a cyclic pattern; the program prints the corrupted
 *     auth value, so cyclic_find() gives the exact buf -> auth offset
 *   - write p32(0xdeadbeef) at that offset to pass the check
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void)
{
    struct {
        char buf[32];
        int  auth;
    } s;

    s.auth = 0;

    setvbuf(stdout, NULL, _IONBF, 0);
    printf("name: ");
    read(0, s.buf, 128);            /* overflows buf into auth */

    if (s.auth == 0xdeadbeef) {
        printf("access granted\n");
        system("/bin/sh");
    } else {
        printf("access denied (auth=0x%x)\n", s.auth);
    }
    return 0;
}
