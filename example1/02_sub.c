/* 02_sub: subtraction with a negative result (two's complement)
 * try: print diff / print/x diff / print/u diff / info registers eax
 */
#include <stdio.h>

int main(void)
{
    int a = 10;
    int b = 42;
    int diff;

    diff = a - b;

    printf("%d - %d = %d\n", a, b, diff);
    printf("as unsigned: %u\n", (unsigned int)diff);
    return 0;
}
