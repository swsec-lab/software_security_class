#!/usr/bin/env python3
"""ex8 solution: make .data executable, then run code from it.

Two edits:
  1) ELF program (segment) header: the PT_LOAD segment that holds .data is
     RW (flags = 6). Add the execute bit -> RWX (flags = 7). p_flags sits
     at offset 24 in each 32-byte Elf32_Phdr; the phdr table is mapped at
     (load base + e_phoff).
  2) .data: overwrite the global `code[]` with
        e8 <rel32>   ; call hidden8
        c3           ; ret
     rel32 = addr(hidden8) - (addr(code) + 5)

Run:  python3 solve_ex8.py     ->  writes ./ex8 (patched, executable)
"""
import os
from pwn import ELF, p32, log

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "..", "ex8")
OUT = os.path.join(HERE, "ex8")


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
code = e.symbols["code"]
hidden8 = e.symbols["hidden8"]

make_data_executable(e)

rel32 = (hidden8 - (code + 5)) & 0xffffffff
e.write(code, b"\xe8" + p32(rel32) + b"\xc3")   # call hidden8 ; ret
log.success("code[] @ %#x : call hidden8(%#x) ; ret" % (code, hidden8))

e.save(OUT)
os.chmod(OUT, 0o755)
log.success("wrote %s  (run: ./ex8)" % OUT)
