#!/usr/bin/env python3
"""ex7 solution: inject a `call hidden7` into the NOP code cave in .text.

Idea:
  main contains 16 bytes of 0x90 (NOP) that we can freely overwrite.
  A near call is 5 bytes (e8 <rel32>); write it at the start of the cave
  and leave the remaining NOPs in place so the flow stays valid:
      rel32 = addr(hidden7) - (cave_addr + 5)

Run:  python3 solve_ex7.py     ->  writes ./ex7 (patched, executable)
"""
import os
from pwn import ELF, p32, log
from capstone import Cs, CS_ARCH_X86, CS_MODE_32  # noqa: F401 (kept for parity)

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "..", "ex7")
OUT = os.path.join(HERE, "ex7")

e = ELF(SRC, checksec=False)
main = e.symbols["main"]
hidden7 = e.symbols["hidden7"]

# find the first run of >= 8 consecutive NOPs inside main
blob = e.read(main, 512)
run = 0
cave = None
for i, b in enumerate(blob):
    run = run + 1 if b == 0x90 else 0
    if run >= 8:
        cave = main + i - run + 1
        break

if cave is None:
    raise SystemExit("NOP cave not found in main")

rel32 = (hidden7 - (cave + 5)) & 0xffffffff
e.write(cave, b"\xe8" + p32(rel32))
e.save(OUT)
os.chmod(OUT, 0o755)

log.success("cave @ %#x : injected call hidden7(%#x)" % (cave, hidden7))
log.success("wrote %s  (run: ./ex7)" % OUT)
