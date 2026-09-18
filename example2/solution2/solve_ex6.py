#!/usr/bin/env python3
"""ex6 solution: neutralize the branch that skips hidden6().

Idea:
  main compiles to roughly:
      cmp argc, 999
      jne  .else        ; <- skips the hidden6() call
      call hidden6
      jmp  .end
    .else:
      call printf("access denied")
    .end:
  NOP-ing out the conditional jump makes execution fall through to
  `call hidden6` every time (and the following `jmp .end` still skips
  the else branch).

Run:  python3 solve_ex6.py     ->  writes ./ex6 (patched, executable)
"""
import os
from pwn import ELF, log
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "..", "ex6")
OUT = os.path.join(HERE, "ex6")

COND_JUMPS = {
    "je", "jne", "jz", "jnz", "jg", "jge", "jl", "jle",
    "ja", "jae", "jb", "jbe", "js", "jns", "jo", "jno", "jp", "jnp",
}

e = ELF(SRC, checksec=False)
main = e.symbols["main"]

md = Cs(CS_ARCH_X86, CS_MODE_32)
patched = None
for insn in md.disasm(e.read(main, 256), main):
    if insn.mnemonic in COND_JUMPS:
        e.write(insn.address, b"\x90" * insn.size)   # replace jcc with NOPs
        patched = insn
        break

if patched is None:
    raise SystemExit("no conditional jump found in main")

e.save(OUT)
os.chmod(OUT, 0o755)
log.success("NOP'd %s @ %#x (%d bytes)" % (patched.mnemonic, patched.address, patched.size))
log.success("wrote %s  (run: ./ex6)" % OUT)
