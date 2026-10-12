/* heartbleed: a Heartbleed-style memory overread (lecture 6-1, slides 18-22).
 *
 * A tiny model of the TLS Heartbeat bug (CVE-2014-0160). One heartbeat
 * request arrives on stdin:
 *
 *     [type:1][len:2 big-endian][payload ...]
 *
 * The "server" copies `len` bytes of the payload into a response and writes it
 * back -- but it TRUSTS len instead of checking it against the number of
 * payload bytes actually received. A request that claims a large len but sends
 * a tiny payload makes memcpy(resp, record, len) read past the payload chunk
 * into adjacent heap memory, where a secret happens to live.
 *
 * This is exactly the slide-20 picture: memcpy(p2, p1, length), length chosen
 * by the attacker.
 *
 * See solution4/solve_heartbleed.py.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define HB_REQUEST  1
#define HB_RESPONSE 2
#define RECORD_SZ   0x80

static void heartbeat(const unsigned char *in, int n)
{
    unsigned char type = in[0];
    unsigned int  len  = ((unsigned int)in[1] << 8) | in[2];   /* attacker-controlled */
    int payload_len = n - 3;                                   /* bytes really sent */

    /* p1: copy the received payload into a heap record. A secret is allocated
     * right after it, so it sits just past the record in memory. */
    unsigned char *record = malloc(RECORD_SZ);
    char *secret = malloc(RECORD_SZ);
    strcpy(secret, "SECRET=heap-overread-flag-7e11b3");

    if (payload_len > RECORD_SZ) payload_len = RECORD_SZ;
    memcpy(record, in + 3, payload_len);

    if (type != HB_REQUEST) return;

    /* p2: the response. BUG -- `len` is trusted, not payload_len, so this can
     * read far past `record` into `secret` and beyond. */
    unsigned char *resp = malloc(0x1000);
    resp[0] = HB_RESPONSE;
    resp[1] = in[1];
    resp[2] = in[2];
    memcpy(resp + 3, record, len);          /* <-- the overread */
    write(1, resp, 3 + len);
}

int main(void)
{
    unsigned char in[0x1000];
    int n;

    setvbuf(stdout, NULL, _IONBF, 0);
    n = (int)read(0, in, sizeof(in));
    if (n < 3) { fprintf(stderr, "short request\n"); return 1; }
    heartbeat(in, n);
    return 0;
}
