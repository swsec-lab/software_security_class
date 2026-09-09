/* 06_func: mini crackme  [FINAL CHALLENGE — no -g AND stripped]
 *
 * No symbols at all: even function names are gone, so objdump shows only
 * addresses. Find the expected code with your tools — no source peeking!
 * try: objdump -d -M intel ./06_func   /   gdb ./06_func
 *   1) main has two calls: atoi, then a check function. Step into the
 *      second call (or read it) — it builds a value in a small loop
 *      (acc = acc*10 + (i+3), i = 0..3) using imul/lea + add.
 *   2) find the "cmp eax, <imm>" that compares your code to that value.
 *      Read the immediate: it is 0xd80 = 3456. Run: ./06_func 3456
 *   3) alternative win without knowing the number: break on the cmp and
 *      "set $eax = <the other operand>", or force the branch (see 11_patch
 *      and README for NOP/branch patching).
 */
#include <stdio.h>
#include <stdlib.h>

int check(int code)
{
    int acc = 0;
    int i;

    for (i = 0; i < 4; i++) {
        acc = acc * 10 + (i + 3);
    }

    if (code == acc) {
        return 1;
    }
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("usage: %s <code>\n", argv[0]);
        return 1;
    }

    if (check(atoi(argv[1]))) {
        printf("correct!\n");
    } else {
        printf("wrong.\n");
    }
    return 0;
}
