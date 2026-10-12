/* uninit: uninitialized memory read -> leaks a freed secret (lecture 6-1).
 *
 * Mirrors the slide-9 "crypto key" example: a secret is stored in a heap
 * chunk, the chunk is freed WITHOUT being wiped, then a new allocation of the
 * SAME size reuses that chunk and is sent out before being initialized.
 * Because free() does not erase memory and glibc hands back the most recently
 * freed same-size chunk, the secret leaks through the new buffer. (glibc does
 * write bookkeeping -- the tcache next pointer and key, 8 bytes on 32-bit --
 * into the START of a freed chunk, so the first few bytes of the secret are
 * overwritten; the rest leaks intact.)
 *
 * Build two ways (see the Makefile):
 *   uninit        : the bug -- leaks the secret
 *   uninit_fixed  : -DFIX   -- the slide-10 patch (memset before free AND
 *                             initialize the new buffer before use)
 *
 * See solution4/solve_uninit.py.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SZ 64
#define SECRET "SECRET-KEY-6f3a9c2b-do-not-leak"

static void use_secret(void)
{
    char *key = malloc(SZ);
    strcpy(key, SECRET);        /* store and "use" a sensitive value */
    /* ... pretend to do some cryptography with key ... */
#ifdef FIX
    memset(key, 0, SZ);         /* slide 10: wipe sensitive data before free */
#endif
    free(key);                  /* freed -- but the bytes stay in the chunk */
}

static void serve_request(void)
{
    char *buf = malloc(SZ);     /* same size -> allocator reuses the freed chunk */
#ifdef FIX
    memset(buf, 0, SZ);         /* slide 10: initialize before use */
#endif
    /* BUG: buf is sent out without being initialized first */
    write(1, buf, SZ);          /* leaks whatever was left in the chunk */
    free(buf);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    use_secret();
    serve_request();            /* the freed secret leaks here */
    putchar('\n');
    return 0;
}
