/* fmt_write: arbitrary memory WRITE via %n (lecture 6-2, slides 10-42).
 *
 * printf(buf) again, but now we use %n to write. The goal is to overwrite the
 * global `key` with the magic value and unlock win(). `key` is a global in a
 * non-PIE binary, so its address is fixed and the program even prints it for
 * you (teaching aid, like example3's address-leaking targets).
 *
 * The lecture builds the write up in stages:
 *   - %n writes the number of chars printed so far      (slides 12-19)
 *   - a width field inflates that count cheaply          (slides 21-27)
 *   - %hn does 2-byte "short writes" to avoid huge output (slides 28-36)
 *   - positional params %N$ pick the stack slot directly  (slides 38-42)
 *
 * The magic value 0x08042222 is the exact value from the slide-34 short-write
 * example. The reference solution uses pwntools fmtstr_payload (which performs
 * the short writes and positional params for you); the README shows the
 * hand-built payload that matches the slides.
 *
 * See solution4/solve_fmt_write.py.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

unsigned int key = 0;                 /* target: fixed address (no PIE) */
#define MAGIC 0x08042222u

void win(void)
{
    puts("key unlocked -> spawning shell");
    system("/bin/sh");
    _exit(0);
}

int main(void)
{
    char buf[256];
    int n;

    setvbuf(stdout, NULL, _IONBF, 0);
    printf("write 0x%08x to key @ %p:\n", MAGIC, (void *)&key);

    n = (int)read(0, buf, sizeof(buf) - 1);
    if (n < 0) return 1;
    buf[n] = '\0';

    printf(buf);                      /* VULN */

    if (key == MAGIC)
        win();
    else
        printf("\nkey = 0x%08x, no shell\n", key);
    return 0;
}
