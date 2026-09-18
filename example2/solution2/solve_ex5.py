#!/usr/bin/env python3
"""ex5 solution: redirect an existing call in .text to hidden5().

Idea:
  main() contains `call dummy` encoded as  e8 <rel32>.
  A near call's target is relative to the *next* instruction:
      target = call_addr + 5 + rel32
  To make it call hidden5 instead, recompute rel32:
      rel32 = addr(hidden5) - (call_addr + 5)

Run:  python3 solve_ex5.py     ->  writes ./ex5 (patched, executable)
"""
import os
from pwn import ELF, p32, log
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "..", "ex5")
OUT = os.path.join(HERE, "ex5")

e = ELF(SRC, checksec=False)
main = e.symbols["main"]
dummy = e.symbols["dummy"]
hidden5 = e.symbols["hidden5"]

md = Cs(CS_ARCH_X86, CS_MODE_32)
call_addr = None
for insn in md.disasm(e.read(main, 256), main):
    if insn.mnemonic == "call" and insn.op_str.startswith("0x") \
            and int(insn.op_str, 16) == dummy:
        call_addr = insn.address
        break
    if insn.mnemonic == "ret":
        break

if call_addr is None:
    raise SystemExit("could not find 'call dummy' inside main")

rel32 = (hidden5 - (call_addr + 5)) & 0xffffffff
e.write(call_addr, b"\xe8" + p32(rel32))
e.save(OUT)
os.chmod(OUT, 0o755)

log.success("call @ %#x : dummy(%#x) -> hidden5(%#x)" % (call_addr, dummy, hidden5))
log.success("wrote %s  (run: ./ex5)" % OUT)
