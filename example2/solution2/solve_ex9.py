#!/usr/bin/env python3
"""ex9 solution: make .data executable and feed shellcode via input.txt.

Two things:
  1) ELF program (segment) header: give the data PT_LOAD segment the
     execute bit (RW -> RWX), same as ex8.
  2) Build input.txt whose bytes are executed from the global `buf`:
        e8 <rel32>   ; call hidden9
        c3           ; ret
     rel32 = addr(hidden9) - (addr(buf) + 5)

Run:  python3 solve_ex9.py     ->  writes ./ex9 and ./input.txt
      then:  ./ex9 input.txt
"""
import os
from pwn import ELF, p32, log

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "..", "ex9")
OUT = os.path.join(HERE, "ex9")
INP = os.path.join(HERE, "input.txt")


def make_data_executable(e):
    data_vaddr = e.get_section_by_name(".data").header.sh_addr
    phoff = e.header.e_phoff
    phent = e.header.e_phentsize
    for idx, seg in enumerate(e.iter_segments()):
        h = seg.header
        if (h.p_type == "PT_LOAD"
                and h.p_vaddr <= data_vaddr < h.p_vaddr + h.p_memsz
                and (h.p_flags & 0x2)):
            new_flags = h.p_flags | 0x1
            e.write(e.address + phoff + idx * phent + 24, p32(new_flags))
            log.success("segment #%d flags %d -> %d (RW -> RWX)"
                        % (idx, h.p_flags, new_flags))
            return
    raise SystemExit("writable data segment not found")


e = ELF(SRC, checksec=False)
buf = e.symbols["buf"]
hidden9 = e.symbols["hidden9"]

make_data_executable(e)
e.save(OUT)
os.chmod(OUT, 0o755)
log.success("wrote %s" % OUT)

rel32 = (hidden9 - (buf + 5)) & 0xffffffff
payload = b"\xe8" + p32(rel32) + b"\xc3"        # call hidden9 ; ret
with open(INP, "wb") as f:
    f.write(payload)
log.success("buf @ %#x : call hidden9(%#x) ; ret" % (buf, hidden9))
log.success("wrote %s (%d bytes)  (run: ./ex9 input.txt)" % (INP, len(payload)))
