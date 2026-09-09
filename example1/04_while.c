/* 04_while: countdown loop
 * try: "watch count" then continue — gdb stops every time count changes
 * try: "set var count = 3" while stopped, and see how the loop ends earlier
 */
#include <stdio.h>

int main(void)
{
    int count = 5;

    while (count > 0) {
        printf("count = %d\n", count);
        count--;
    }

    printf("done\n");
    return 0;
}
