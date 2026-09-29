/* canary_server: brute-force the stack canary (lecture 5, "Attack #1:
 * Byte-to-Byte Brute Forcing").
 *
 * A forking server. On Linux the canary is initialized ONCE at startup and
 * inherited unchanged by every fork(), so a child crash does not reroll it.
 * That lets an attacker recover the canary one byte at a time: for each
 * position, try 0x00..0xff and keep the byte that does NOT crash the child.
 *
 * Oracle: the child prints "OK" only if handle() returns (canary survived).
 * A wrong guess corrupts the canary -> __stack_chk_fail -> the child aborts
 * and the connection closes with no "OK".
 *
 * Built WITH the canary; win() is existing code (no shellcode / NX needed).
 * See solution4/solve_canary_server.py.
 *
 * Run:  ./canary_server &   (listens on 127.0.0.1:4004)
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define PORT 4004

void win(void)
{
    puts("win! spawning shell");
    system("/bin/sh");
    _exit(0);
}

void handle(void)
{
    char buf[64];
    read(0, buf, 512);          /* overflow reaches the canary and beyond */
}

int main(void)
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    struct sockaddr_in a = {0};

    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(PORT);
    if (bind(s, (struct sockaddr *)&a, sizeof(a)) < 0) { perror("bind"); return 1; }
    listen(s, 16);
    signal(SIGCHLD, SIG_IGN);            /* auto-reap children */
    printf("listening on 127.0.0.1:%d\n", PORT);
    fflush(stdout);

    for (;;) {
        int c = accept(s, NULL, NULL);
        if (c < 0) continue;
        if (fork() == 0) {               /* child: canary is the same as parent's */
            close(s);
            dup2(c, 0); dup2(c, 1); dup2(c, 2);
            handle();
            puts("OK");                  /* reached only if the canary survived */
            _exit(0);
        }
        close(c);
    }
    return 0;
}
