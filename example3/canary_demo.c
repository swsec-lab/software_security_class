/* canary_demo: see the stack canary catch an overflow (lecture 5, Mitigation #1).
 *
 * Built WITH -fstack-protector-all, so the compiler inserts a canary between
 * the locals and the saved ebp / return address. Overflowing buf corrupts the
 * canary, and the epilogue's check aborts with:
 *     *** stack smashing detected ***: terminated
 *
 * Inspect the canary in the disassembly (lecture "GCC Stack Canary
 * Implementation"):
 *     objdump -d -M intel ./canary_demo | grep -n -E 'gs:0x14|stack_chk'
 *   prologue:  mov eax, gs:0x14 ; mov [ebp-0xc], eax    (store canary)
 *   epilogue:  mov eax, [ebp-0xc] ; xor eax, gs:0x14 ; je ok ; call __stack_chk_fail
 *
 * Compare protections:  pwn checksec ./canary_demo   (Canary found)
 */
#include <stdio.h>
#include <unistd.h>

void vuln(void)
{
    char buf[64];
    printf("input: ");
    read(0, buf, 200);          /* overflow past the canary */
    printf("you said: %s\n", buf);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    vuln();
    printf("returned normally\n");   /* not reached on a detected overflow */
    return 0;
}
