# example3 — Stack Overflow Exploitation with pwntools (Code Injection)

The hands-on part of lecture **4. Code Injection Attacks**. Overflow a stack
buffer to overwrite the return address and hijack control flow, then go
further and inject shellcode onto the stack to spawn a shell — all automated
with pwntools.

> Work inside the Vagrant VM (`/vagrant/labs/example3`), which has the 32-bit
> toolchain and pwntools. The VM disables ASLR
> (`kernel.randomize_va_space=0`) so stack addresses are stable, and it writes
> core dumps to the current directory (`core.%p`).

## Build

```sh
make          # build vuln1, vuln2, morris
make check    # pwn checksec (expect: No canary / NX disabled / No PIE)
make clean
```

The build options match the lecture slides: `-m32 -fno-stack-protector
-no-pie -z execstack -fcf-protection=none`. That means **no canary + an
executable stack + fixed addresses**, so classic code injection reproduces
directly.

---

## Problem 0 — pwntools warm-up (start here)

Before exploiting anything, learn the tool. The lecture's pwntools part
(slides 33-38) introduces a handful of functions the exploits lean on;
`solution3/pwntools_intro.py` is a runnable tour that demonstrates each one and
asserts the result, so you see the pieces work and can read the code behind
them.

```sh
make                                     # build vuln1 (used by 2 of the sections)
python3 solution3/pwntools_intro.py
```

It walks through, in order:

| Section | API | Why it matters |
|---------|-----|----------------|
| 1 | `p32`/`u32`, `p64`, `flat` | turn an address into payload bytes and back |
| 2 | `cyclic` / `cyclic_find` | find the overflow offset without counting |
| 3 | `asm` / `disasm`, `asm(..., vma=...)` | assemble, and get a correct `call` rel32 |
| 4 | `ELF().symbols`, `vaddr_to_offset` | read `win`'s address; find its file offset |
| 5 | `shellcraft.sh()` + `asm()` | ready-made `execve("/bin/sh")` shellcode |
| 6 | `process`, `recvuntil`, `sendline` | drive the target (local or remote) |

Sections 1-3 and 5 are pure API and run even before `make`; sections 4 and 6
talk to `./vuln1` and print a hint if it is not built yet.

### Where each piece is used later

This warm-up is not a separate topic — every piece reappears in Problems 1-5.
When a later problem says "use `cyclic`" or "assemble the shellcode", it means
exactly the call you ran here.

| Problem 0 piece | Shows up in |
|-----------------|-------------|
| `cyclic` / `cyclic_find` | **all of 1-5** — every problem finds its offset this way |
| `process` + `recvuntil`/`sendline`/`interactive` | **all of 1-5** — how each script talks to the target |
| `p32` | **all of 1-5** — an address or value as 4 payload bytes |
| `flat({offset: value})` | **Problem 1** — build the ret2win payload |
| `ELF().symbols['win']` | **Problem 1** — read `win`'s address (also `example4`) |
| `asm(shellcraft.sh())` | **Problems 2 and 3** — ready-made `/bin/sh` shellcode |
| `asm(...)` on your own source | **Problem 5** — assemble the shellcode you wrote by hand |
| `corefile` / `core.search` | **Problem 3** — recover the buffer address with no leak |

`asm(..., vma=...)` and `vaddr_to_offset` (sections 3-4) are the exception:
they matter most in the **binary-patching labs (`example1`/`example2`)**, where
you compute a `call`'s rel32 and seek to a file offset in a hex editor. The
lecture introduces pwntools as one toolbox for both patching and exploitation,
so they are here for completeness.

### Also try it from the shell (pwn CLI)

The same conversions the lecture shows on slides 38-39, as one-liners:

```sh
pwn checksec ./vuln1                 # protections: No canary / NX disabled / No PIE
pwn cyclic 32                        # a de Bruijn pattern
pwn cyclic -l 0x61616166             # which offset those 4 bytes are
pwn asm -c i386 'xor eax,eax; ret'   # -> 31c0c3
pwn disasm -c i386 31c0c3            # -> xor eax, eax ; ret
pwn shellcraft -f hex i386.linux.sh  # /bin/sh shellcode as hex
```

Once these feel familiar, move on to Problem 1.

## Problem 1 — vuln1: ret2win (hijack without shellcode)

> **pwntools used here** (from Problem 0): `cyclic`/`cyclic_find`, `ELF().symbols`,
> `flat`, `p32`, `process`, `recvuntil`, `interactive`. No shellcode yet.

`read()` overflows `buf[64]` in `vuln()`. Overwrite the return address with
the address of the hidden `win()` (which calls `system("/bin/sh")`) and you
get a shell. The easiest first step: no shellcode, no buffer address needed.

Steps:

1. Send `cyclic(300)` to crash it, then feed the core dump's `eip` to
   `cyclic_find()` to get the **buf → return address offset** automatically.
2. Read win's address from `ELF('./vuln1').symbols['win']`.
3. Build the payload with `flat({offset: win})` and `sendline` it.

```sh
python3 solution3/solve_vuln1.py
```

The point is to find the offset with `cyclic`/`cyclic_find` instead of
counting bytes by hand.

## Problem 2 — vuln2: return-to-stack (shellcode injection)

> **pwntools used here** (from Problem 0): adds `asm(shellcraft.sh())` for the
> shellcode, on top of the Problem 1 pieces. `recvline_startswith` parses the leak.

Put shellcode in `buf[256]` and return into that buffer to run it on the
stack (lecture "Return-to-Stack Exploit"). For teaching, the program prints
buf's address, so you focus on building the payload instead of guessing an
address.

Steps:

1. Parse the leaked `buf is at 0x...` line with `recvline`.
2. Build `execve("/bin/sh")` shellcode with `asm(shellcraft.sh())`.
3. Fill the buffer with `[NOP sled][shellcode]` and overwrite the return
   address with `buf`. Returning lands in the NOP sled and slides down into
   the shellcode (lecture "NOP Sled").

```sh
python3 solution3/solve_vuln2.py
```

To confirm control first, swap the shellcode for `asm('jmp $')` (= `eb fe`,
an infinite loop). If the program hangs, you have hijacked the return address.

## Problem 3 — morris: the 1988 Morris Worm overflow (no leak)

> **pwntools used here** (from Problem 0): the Problem 2 pieces plus `corefile`
> and `core.search` — with no leak, you recover the buffer address from a core
> dump. This is the most pwntools-heavy problem.

The historic `finger` bug from the lecture (slides 7-26): `char buf[0x400];
gets(buf);`. Same return-to-stack shellcode injection as vuln2, but with **no
address leak** — learning the buffer address is the real challenge (slides
27-30, "Exploit w/ or w/o GDB", "Why Different?").

Because `gets()` was removed in glibc 2.34+, `morris.c` ships a minimal,
equally-unsafe `gets()` so the historic code stays intact.

The solution finds the address without a leak:

1. With a **fixed (empty) environment**, crash with a cyclic pattern so the
   stack layout is deterministic.
2. Recover the offset with `cyclic_find(core.eip)`.
3. Locate buf by searching the core dump for the pattern
   (`next(core.search(...))`).
4. Exploit a fresh run (same environment) with a NOP sled + shellcode.

```sh
python3 solution3/solve_morris.py
```

## Problem 4 — vuln3: overwrite an adjacent variable (data-only smash)

> **pwntools used here** (from Problem 0): the lightest set — just `cyclic`/
> `cyclic_find`, `p32`, and a `process` tube. No shellcode, no `ELF` symbols.

A different, simpler primitive: no control-flow hijack and no shellcode.
`buf` and an `auth` flag live in one struct, so overflowing `buf` corrupts
`auth`. Set it to the exact expected value (`0xdeadbeef`) to pass the check
and get a shell.

Steps:

1. Overflow with a cyclic pattern; the program prints the corrupted
   `auth=0x...`, and `cyclic_find(p32(value))` gives the **buf → auth offset**.
2. Send `b'A'*offset + p32(0xdeadbeef)`.

```sh
python3 solution3/solve_vuln3.py
```

This shows that an overflow corrupts whatever sits next on the stack, and
that the corruption can be a precise, attacker-chosen value.

## Problem 5 — vuln2 revisited: write your own shellcode (homework)

> **pwntools used here** (from Problem 0): the Problem 2 pieces, but `asm()`
> now assembles *your* `shellcode.s` instead of `shellcraft.sh()` — the same
> `asm` from section 3 of the warm-up, pointed at your own source.

The lecture's stated homework (slide 25, *"Writing a shellcode for spawning
/bin/sh is your homework"*). Same return-to-stack target as Problem 2, but you
may **not** use `shellcraft.sh()` — every byte of the shellcode is written by
hand in `solution3/shellcode.s` and assembled with `asm()`.

Do it in the two steps the lecture shows:

1. **Confirm control first** with the 2-byte infinite-loop shellcode `jmp $`
   (`eb fe`, lecture "Simplistic Shellcode"). If the process hangs, the return
   address is yours.

   ```sh
   python3 solution3/solve_vuln4.py --confirm    # should hang; Ctrl-C to stop
   ```

2. **Inject your real shellcode.** Write `execve("/bin/sh", NULL, NULL)` by
   hand, then reuse the Problem 2 layout (`[NOP sled][shellcode][ret = buf]`).

   ```sh
   python3 solution3/solve_vuln4.py              # drops a shell
   ```

The reference `solution3/shellcode.s` uses the classic 25-byte, **null-free**
sequence: zero `eax`, push the string `"/bin//sh"` (NUL-terminated), point `ebx` at it, build
`argv = {ebx, NULL}` in `ecx`, clear `edx`, then `SYS_execve` (`eax=0xb`) via
`int 0x80`. Null-free is not required here (`read()` is binary-safe) but is the
habit to build for string-copy bugs, where a `0x00` would truncate the payload.

Inspect the bytes the historic way from the lecture, then compare with the
pwntools assembly:

```sh
gcc -m32 -c solution3/shellcode.s -o /tmp/sc.o && objdump -d -M intel /tmp/sc.o
```

---

## pwntools essentials (the lecture's pwntools part)

### Python API

| Purpose | pwntools | Notes |
|---------|----------|-------|
| int → bytes | `p32(n)`, `p64(n)` | short for `struct.pack('<I', n)` |
| bytes → int | `u32(b)`, `u64(b)` | for verification |
| assembly → bytes | `asm('call 0x8049176', vma=0x80491dc)` | `vma` computes rel32 |
| bytes → assembly | `disasm(b, vma=addr)` | verify a patch |
| symbol address | `ELF('vuln1').symbols['win']` | instead of nm |
| vaddr → file offset | `e.vaddr_to_offset(0x80491dc)` | where to seek in a hex editor |
| find the offset | `cyclic(n)` / `cyclic_find(x)` | derive the crash offset |
| build a payload | `flat({off: val})` | pad + place |
| shellcode | `asm(shellcraft.sh())` | execve("/bin/sh") |
| protections | `checksec` | RELRO/canary/NX/PIE |

### Tubes — same code for local and remote

```python
io = process('./vuln2')            # run locally
io = remote('ctf.host', 31337)     # connect to a remote service (CTF)
io = gdb.debug('./vuln2')          # run under gdb

io.sendline(b'payload')            # send one line
io.recvuntil(b'payload:\n')        # read up to a marker
io.recvline_startswith(b'buf is')  # read a specific line
io.interactive()                   # drive the shell by hand
```

The same script runs against a local process and a remote target.

### One-liners from the shell (pwn CLI)

```sh
pwn checksec ./vuln1                 # protections
pwn cyclic 100                       # generate a de Bruijn pattern
pwn cyclic -l 0x61616166             # which offset that value is
pwn asm -c i386 'xor eax,eax; ret'   # assemble -> 31c0c3
pwn disasm -c i386 e895ffffff        # disassemble
pwn shellcraft -f hex i386.linux.sh  # /bin/sh shellcode as hex
pwn hex ABC   /   pwn unhex 41424344 # hex encode / decode
pwn phd core                         # pretty hexdump
pwn template ./vuln1 > exploit.py    # generate an exploit skeleton
```

> Note: the CLI `pwn asm`/`pwn disasm` default `vma` to 0, so a `call`'s
> relative target comes out wrong. When rel32 matters, use
> `asm(..., vma=...)` in Python.

---

## Going further (lecture homework)

- Hand-written shellcode is now **Problem 5** above — start there, then shrink
  it: can you get under 25 bytes, or keep it null-free with different tricks?
- Remove vuln2's address-leaking `printf` and find buf with `gdb.debug()`,
  then complete the same exploit (lecture "Exploit w/ or w/o GDB",
  "Why Different?").
- Shrink the NOP sled until the exploit stops working, and observe when.
