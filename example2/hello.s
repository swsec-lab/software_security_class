# hello.s -- 32-bit x86 Linux "Hello, world!" (GAS .intel_syntax)
#
# Calls Linux system calls directly. No libc, so the entry point is _start.
#   write(fd=1, buf=msg, count=len)  ->  eax=4
#   exit(status=0)                   ->  eax=1
# 32-bit syscall convention: number in eax, args in ebx/ecx/edx..., via int 0x80.
#
# build (gcc assembles + links in one step, no libc, fixed addresses):
#   gcc -m32 -nostdlib -no-pie hello.s -o hello
# run:
#   ./hello

.intel_syntax noprefix

.section .data
msg:
    .ascii "Hello, world!\n"       # message + newline (\n = 0x0a)
    len = . - msg                  # length computed at assembly time = 14

.section .text
.global _start

_start:
    # write(1, msg, len)
    mov eax, 4              # sys_write
    mov ebx, 1             # fd = 1 (stdout)
    mov ecx, offset msg    # buf = address of msg
    mov edx, len          # count = 14
    int 0x80              # enter the kernel

    # exit(0)
    mov eax, 1            # sys_exit
    xor ebx, ebx        # status = 0 (make 0 with xor)
    int 0x80           # enter the kernel
