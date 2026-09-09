/* 09_crash (buggy): ./09_crash 1 works, ./09_crash 5 crashes.
 *
 * [ASM TRACK — built without -g] find the cause in the disassembly.
 * try: objdump -d -M intel ./09_crash   and run under gdb with "run 5".
 *   1) in main, spot the sequence:  call lookup ; ... ; call strcpy
 *      lookup's return value comes back in eax and is passed straight to
 *      strcpy as the source pointer.
 *   2) when the crash hits, "info registers eax" shows eax = 0 (NULL):
 *      lookup(5) returned NULL, and strcpy dereferences it -> SIGSEGV.
 *   3) "disassemble" + "x/i $pc" show exactly which instruction faults;
 *      "bt" shows you are inside strcpy called from main.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *lookup(int id)
{
    if (id == 1) return "alice";
    if (id == 2) return "bob";
    return NULL;
}

int main(int argc, char *argv[])
{
    char name[16];
    int id = (argc > 1) ? atoi(argv[1]) : 1;

    strcpy(name, lookup(id));
    printf("user %d: %s\n", id, name);
    return 0;
}
