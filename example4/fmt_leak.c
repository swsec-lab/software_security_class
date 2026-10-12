/* fmt_leak: classic printf(user_input) -> read memory (lecture 6-2, slides 7-9).
 *
 * The program prints user input with printf(buf), so the input is treated as a
 * format string. A secret lives on the stack; %p / positional params (%N$p)
 * walk the stack and leak it (slides 15-16, "%x" reads stack slots).
 *
 * Built WITH a stack canary (-fstack-protector-all) on purpose: the same
 * technique also leaks the canary value, which is the "Attack #2: leaking the
 * canary" bridge from lecture 6-1 (slide 4). Leaking the canary here is a
 * stepping stone to defeating it in example3's canary problems.
 *
 * See solution4/solve_fmt_leak.py.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void)
{
    char buf[128];
    volatile unsigned int secret = 0xc0ffee42;   /* one stack slot to find */
    int n;

    setvbuf(stdout, NULL, _IONBF, 0);
    printf("secret 0x%08x is somewhere on my stack. leak it:\n", secret);

    n = (int)read(0, buf, sizeof(buf) - 1);
    if (n < 0) return 1;
    buf[n] = '\0';

    printf(buf);              /* VULN: user input used as the format string */
    printf("\n");
    return (int)secret;       /* keep `secret` live so it is not optimized out */
}
