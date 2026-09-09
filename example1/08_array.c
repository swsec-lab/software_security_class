/* 08_array (buggy): secret should stay 42, but something changes it.
 *
 * [ASM TRACK — built without -g] recover the stack layout from assembly.
 * try: objdump -d -M intel ./08_array
 *   1) in the prologue find the ebp-relative slots: `secret`, `arr[0..3]`,
 *      and the counter `i`. Note each one's offset [ebp-X].
 *   2) the write "arr[i] = i*i" compiles to a store like
 *        mov DWORD PTR [ebp-0x18+eax*4], edx     ; base + index*4
 *      and the loop runs i = 0..4 (five stores) into a 4-int array.
 *   3) work out which offset arr[4] lands on — it is the same slot the
 *      prologue used for `secret`. That off-by-one store is the culprit.
 *   Confirm live:  watch *(int*)($ebp-X)   on secret's slot, then continue.
 */
#include <stdio.h>

int main(void)
{
    int secret = 42;
    int arr[4];
    int i;

    for (i = 0; i <= 4; i++) {
        arr[i] = i * i;
    }

    for (i = 0; i < 4; i++) {
        printf("arr[%d] = %d\n", i, arr[i]);
    }
    printf("secret = %d\n", secret);
    return 0;
}
