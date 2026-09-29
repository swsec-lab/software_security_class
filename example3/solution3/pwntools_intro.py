#!/usr/bin/env python3
"""Problem 0 -- pwntools warm-up.  START HERE, before Part A (Problems 1-4).

A runnable tour of the pwntools API the lecture introduces (slides 33-38),
before you use it to exploit anything. Each section prints what it does and
asserts the result, so you can see the pieces work and read the code that
made them.

Covered (lecture "The Core Toolbox" / "the API Map"):
  1. packing        p32/p64, u32/u64
  2. offsets        cyclic / cyclic_find  (find a BOF offset, no counting)
  3. assembling     asm / disasm, and asm(..., vma=...) for a correct rel32
  4. ELF info       ELF().symbols, vaddr_to_offset()
  5. shellcode      shellcraft.sh() + asm()
  6. tubes          process(), recvuntil / sendline / recvall

Run:  cd example3 && make && python3 solution3/pwntools_intro.py
The pure-API sections (1-3, 5) work even before `make`; sections 4 and 6
need ./vuln1, and print a hint if it is missing.
"""
import os
from pwn import *

# i386 so asm()/shellcraft target 32-bit x86; quiet the library's own logging
# so the tutorial's prints are the only output.
context.update(arch="i386", os="linux", log_level="error")

HERE = os.path.dirname(os.path.abspath(__file__))
VULN1 = os.path.join(HERE, "..", "vuln1")


def section(title):
    print("\n" + "=" * 60 + "\n# " + title + "\n" + "=" * 60)


def show(expr, value):
    print(f"  {expr:<44} = {value!r}")


def part1_packing():
    section("1. packing: p32/p64, u32/u64")
    print("  int -> little-endian bytes, and back. This is how an address")
    print("  becomes 4 payload bytes.")
    packed = p32(0x41424344)
    show("p32(0x41424344)", packed)
    assert packed == b"\x44\x43\x42\x41", "p32 is little-endian"
    show("u32(b'\x44\x43\x42\x41')", hex(u32(b"\x44\x43\x42\x41")))
    assert u32(packed) == 0x41424344, "u32 is the inverse of p32"
    show("p64(0xdeadbeef)", p64(0xDEADBEEF))
    # flat(): pad up to an offset, then place a value there (used by every solve).
    payload = flat({16: 0xDEADBEEF})
    show("flat({16: 0xdeadbeef})", payload)
    assert len(payload) == 20 and payload[16:] == p32(0xDEADBEEF)
    print("  flat pads with zero bytes by default, then writes p32 at the offset.")


def part2_cyclic():
    section("2. offsets: cyclic / cyclic_find")
    print("  A de Bruijn pattern: every 4-byte window is unique, so the 4")
    print("  bytes that land in EIP tell you the exact overflow offset --")
    print("  no counting bytes by hand.")
    pat = cyclic(32)
    show("cyclic(32)", pat)
    window = pat[16:20]                     # pretend these 4 bytes hit EIP
    off = cyclic_find(window)
    show(f"cyclic_find({window!r})", off)
    assert off == 16, "cyclic_find recovers the offset of the window"
    print("  In an exploit: cyclic_find(core.eip) gives buf -> return offset.")


def part3_asm():
    section("3. assembling: asm / disasm, and vma for rel32")
    show("asm('nop')", asm("nop"))
    assert asm("nop") == b"\x90"
    show("asm('xor eax, eax; ret')", enhex(asm("xor eax, eax; ret")))
    assert asm("xor eax, eax; ret") == bytes.fromhex("31c0c3")
    show("disasm(b'\x31\xc0\xc3')", disasm(bytes.fromhex("31c0c3")).replace("\n", " | "))
    print("  The lecture's key point: a call's rel32 depends on WHERE it lives,")
    print("  so pass vma= (the address of the call) and let pwntools compute it.")
    call = asm("call 0x8049176", vma=0x80491DC)
    show("asm('call 0x8049176', vma=0x80491dc)", enhex(call))
    assert call == bytes.fromhex("e895ffffff"), "rel32 = target-(vma+5)"


def part4_elf():
    section("4. ELF info: symbols, vaddr_to_offset  (needs ./vuln1)")
    if not os.path.exists(VULN1):
        print("  ./vuln1 not built yet -- run `make`, then re-run. Skipping.")
        return
    e = ELF(VULN1, checksec=False)
    win = e.symbols["win"]
    show("ELF('./vuln1').symbols['win']", hex(win))
    show("e.vaddr_to_offset(win)", hex(e.vaddr_to_offset(win)))
    print("  symbols[] replaces `nm`; vaddr_to_offset() is the file offset to")
    print("  seek to in a hex editor (used in the patching labs).")


def part5_shellcode():
    section("5. shellcode: shellcraft.sh() + asm()")
    sc = asm(shellcraft.sh())               # execve("/bin/sh", 0, 0)
    show("len(asm(shellcraft.sh()))", len(sc))
    show("asm(shellcraft.sh()) [hex]", enhex(sc))
    print("  Problem 4 asks you to hand-write this instead (solution3/shellcode.s).")


def part6_tubes():
    section("6. tubes: process / recvuntil / sendline  (needs ./vuln1)")
    if not os.path.exists(VULN1):
        print("  ./vuln1 not built yet -- run `make`, then re-run. Skipping.")
        return
    print("  One interface for a local binary or a remote service. Here we just")
    print("  talk to vuln1 politely (no overflow): read the prompt, send a short")
    print("  line, and read the rest. The exploit problems send an OVERFLOWING line instead.")
    io = process(VULN1)
    prompt = io.recvuntil(b"overflow me:\n")
    show("io.recvuntil(b'overflow me:\n')", prompt)
    io.sendline(b"hello")                   # short input -> returns normally
    rest = io.recvall(timeout=2)
    show("io.recvall()", rest)
    io.close()
    print("  Swap process(...) for remote('host', port) and the same script")
    print("  runs against a CTF service unchanged.")


def main():
    part1_packing()
    part2_cyclic()
    part3_asm()
    part4_elf()
    part5_shellcode()
    part6_tubes()
    print("\nDone. You now have every pwntools piece the exploits use. Next: Part A, Problem 1.")


if __name__ == "__main__":
    main()
