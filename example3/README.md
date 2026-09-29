# example3 — Stack Overflow Exploitation and Defenses (Lectures 4-5)

The merged hands-on lab for **4. Code Injection Attacks** and **5. Stack Smash
Protection**. It runs in two parts:

- **Part A — Code injection (lecture 4).** Overflow a stack buffer to hijack
  control flow, then inject shellcode onto the stack to spawn a shell.
- **Part B — Stack-smash protection (do AFTER lecture 5).** Meet the two
  mitigations — DEP/NX and the stack canary — and build up from no defense to
  both, one at a time, watching the same overflow go from code injection to
  code reuse.

> **Ordering:** do **Problem 0** and **Part A (Problems 1-4)** after lecture 4.
> Do **Part B (Problems 5-8)** only after lecture 5.

> Work inside the Vagrant VM (`/vagrant/labs/example3`), which has the 32-bit
> toolchain and pwntools. The VM disables ASLR
> (`kernel.randomize_va_space=0`) so stack addresses are stable, and it writes
> core dumps to the current directory (`core.%p`).

## Build

```sh
make          # build every binary (Part A and Part B)
make check    # pwn checksec on all of them (see expected output below)
make clean
```

Different problems need different protections, so the Makefile builds with
different flags. Part B compiles **the same `canary_server.c` three ways**:

| Binary | Flags | checksec | Used by |
|--------|-------|----------|---------|
| `vuln1` `vuln2` `vuln3` `morris` | `-fno-stack-protector -z execstack` | No canary / NX disabled | Part A |
| `canary_demo` | `-fstack-protector-all` | Canary found / NX enabled | Part B intro |
| `canary_server_nc` | `-fno-stack-protector -z execstack` | No canary / NX disabled | Problem 5 |
| `nx_demo` | `-fno-stack-protector` | No canary / NX enabled | Problem 6 |
| `canary_server_x` | `-fstack-protector-all -z execstack` | Canary found / NX disabled | Problem 7 |
| `canary_server` | `-fstack-protector-all` | Canary found / NX enabled | Problem 8 |

The base flags (`-m32 -mpreferred-stack-boundary=2 -O0 -fno-pic -no-pie
-fcf-protection=none`) match the lecture slides: 32-bit, no optimization, fixed
addresses, simple offsets, no Intel CET.

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

This warm-up is not a separate topic — every piece reappears in the problems.
When a later problem says "use `cyclic`" or "assemble the shellcode", it means
exactly the call you ran here.

| Problem 0 piece | Shows up in |
|-----------------|-------------|
| `cyclic` / `cyclic_find` | **almost every problem** — how each one finds its offset |
| `process` / `remote` + `recvuntil`/`sendline`/`interactive` | **every problem** — how each script talks to the target |
| `p32` | **every problem** — an address or value as 4 payload bytes |
| `flat({offset: value})` | **Problem 6** (nx_demo) — build a ret2win payload |
| `ELF().symbols['win']` | **Problems 5-8** — read `win`'s address |
| `asm(shellcraft.sh())` | **Problems 1, 2, 7** — ready-made `/bin/sh` shellcode |
| `corefile` / `core.search` | **Problems 2, 6, 7** — recover an address / offset with no leak |

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

Once these feel familiar, move on to Part A, Problem 1.

---

# Part A — Code injection (lecture 4)

Inject *your own* code. All four targets are built with no canary, an
executable stack, and fixed addresses, so classic code injection reproduces
directly.

## Problem 1 — vuln2: return-to-stack (shellcode injection)

> **pwntools used here** (from Problem 0): `cyclic`/`cyclic_find`,
> `asm(shellcraft.sh())`, `p32`, `process`, `recvline_startswith` (parses the
> leak), `interactive`.

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

## Problem 2 — morris: the 1988 Morris Worm overflow (no leak)

> **pwntools used here** (from Problem 0): the Problem 1 pieces plus `corefile`
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

## Problem 3 — vuln3: overwrite an adjacent variable (data-only smash)

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

## Problem 4 — vuln2 revisited: write your own shellcode (homework)

> **pwntools used here** (from Problem 0): the Problem 1 pieces, but `asm()`
> now assembles *your* `shellcode.s` instead of `shellcraft.sh()` — the same
> `asm` from section 3 of the warm-up, pointed at your own source.

The lecture's stated homework (slide 25, *"Writing a shellcode for spawning
/bin/sh is your homework"*). Same return-to-stack target as Problem 1, but you
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
   hand, then reuse the Problem 1 layout (`[NOP sled][shellcode][ret = buf]`).

   ```sh
   python3 solution3/solve_vuln4.py              # drops a shell
   ```

The reference `solution3/shellcode.s` uses the classic 25-byte, **null-free**
sequence: zero `eax`, push the string `"/bin//sh"` (NUL-terminated), point
`ebx` at it, build `argv = {ebx, NULL}` in `ecx`, clear `edx`, then
`SYS_execve` (`eax=0xb`) via `int 0x80`. Null-free is not required here
(`read()` is binary-safe) but is the habit to build for string-copy bugs, where
a `0x00` would truncate the payload.

Inspect the bytes the historic way from the lecture, then compare with the
pwntools assembly:

```sh
gcc -m32 -c solution3/shellcode.s -o /tmp/sc.o && objdump -d -M intel /tmp/sc.o
```

---

# Part B — Stack-smash protection (do AFTER lecture 5)

Part B introduces the two mitigations against stack overflows — **DEP/NX** and
the **stack canary** — and builds up from no defense to both, one at a time:

| Problem | Binary | Defenses on | What you must do |
|---------|--------|-------------|------------------|
| 5 | `canary_server_nc` | none | one overflow -> `win()` |
| 6 | `nx_demo` | NX | ret2win — NX blocks stack shellcode, so **reuse existing code** |
| 7 | `canary_server_x` | canary (+ executable stack) | bypass the canary, then **inject shellcode** |
| 8 | `canary_server` | canary + NX | bypass the canary, then **reuse existing code** |

Problems 5, 7 and 8 are the **same forking `canary_server`** built three ways
(no canary; canary + executable stack; canary + NX). Problem 6 (`nx_demo`) is a
small standalone binary that isolates NX on its own. The three servers all
listen on `127.0.0.1:4004`, so run **one at a time** and stop the previous one
before starting the next.

The servers' shared oracle: each connection is handled by a `fork()`ed child
that prints `OK` only if `handle()` returns. A crash (a corrupted canary trips
`__stack_chk_fail`; a bad return address faults) closes the connection with no
`OK`. Because the canary is set once at startup and inherited unchanged by
every child, we can recover it one byte at a time.

## Problem 5 — canary_server, no canary (baseline)

> **pwntools used here** (from Problem 0): `remote`, `recvall`,
> `ELF().symbols['win']`, `p32`. The offset comes from growing an all-`A` fill
> until it stops returning `OK` — no `cyclic` needed.

Built with `-fno-stack-protector` (`canary_server_nc`): no canary stands
between the buffer and the return address, so a single overflow reaches it. No
brute force, no shellcode — jump straight to `win()`. This is the "before
defenses" baseline the next problems make harder.

```sh
./canary_server_nc &                              # 127.0.0.1:4004
python3 solution3/solve_csrv_nocanary.py
```

The script grows the fill until `OK` disappears to find the buf → return
address offset, then sends `fill + p32(win)`.

## Problem 6 — nx_demo: DEP/NX and the code-reuse bypass

> **pwntools used here** (from Problem 0): `cyclic`/`cyclic_find`,
> `ELF().symbols['win']`, `flat`, `process`. The commented-out path also uses
> `asm(shellcraft.sh())` to show stack shellcode faulting under NX.

The first defense: **DEP/NX** marks the stack non-executable. `nx_demo` is a
small local binary (no canary) built without `-z execstack`. The
return-to-stack shellcode from Part A now crashes — the injected bytes are not
executable. But NX does not stop the overflow, so **returning to existing
code** (`win()`) still works.

Steps:

1. Crash with a cyclic pattern, then `cyclic_find(core.eip)` for the offset.
2. `flat({offset: win})` returns into `win()` — no shellcode on the stack.

```sh
python3 solution3/solve_nx_demo.py
```

The commented-out path in the script shows the stack-shellcode version, which
faults under NX. Key point from the lecture: **DEP prevents return-to-stack,
not buffer overflows.** Code reuse (ret2libc / ROP) defeats it. Problems 7 and
8 add the canary on top.

## Problem 7 — canary_server, canary + executable stack: code injection

> **pwntools used here** (from Problem 0): `remote`, `recvall`,
> `asm(shellcraft.sh())`, `cyclic`, `Corefile`/`core.search`, `p32`.

Now bring back the forking server and add the **canary**, but keep the stack
executable (`-fstack-protector-all -z execstack`, `canary_server_x`). Before
attacking, see the canary itself:

```sh
printf 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' | ./canary_demo
# *** stack smashing detected ***: terminated
objdump -d -M intel ./canary_demo | grep -n -E 'gs:0x14|stack_chk'
```

Because the stack is still executable, once you defeat the canary you can
**inject shellcode** — the thing Problem 8 (canary + NX) cannot do. Three steps:

1. **Offset** — grow an all-`A` fill until `OK` disappears (buf → canary).
2. **Canary** — recover the 4 bytes one at a time: keep the byte that still
   returns `OK`; a wrong byte trips `__stack_chk_fail`.
3. **Address** — there is no leak, so crash one child with a cyclic pattern and
   read buf's address out of the **core dump** it drops (the Morris trick from
   Problem 2). ASLR is off, so every child shares that address.

Then inject: fill buf with `[NOP sled][shellcode]`, keep the real canary, and
set the return address to buf.

```sh
./canary_server_x &                               # 127.0.0.1:4004
python3 solution3/solve_csrv_inject.py
```

> Needs core dumps in the server's working directory (the VM sets
> `kernel.core_pattern = core.%p`; if not, `ulimit -c unlimited` and set it).

## Problem 8 — canary_server, canary + NX: code reuse

> **pwntools used here** (from Problem 0): `remote`, `recvall`,
> `ELF().symbols['win']`, `p32`. No shellcode.

The full defense: canary on **and** NX on (`-fstack-protector-all`, no
`-z execstack`, `canary_server`). You bypass the canary exactly as in Problem 7,
but now injected shellcode would fault under NX — so you **return to existing
code** instead. Recover the canary, then send
`fill + canary + saved-ebp + p32(win)`.

```sh
./canary_server &                                 # 127.0.0.1:4004
python3 solution3/solve_canary_server.py
```

This is the direct contrast with Problem 7: same canary bypass, but NX forces
code reuse instead of injection — combining the two lessons from Problems 6 and
7. Other bypasses from the lecture: **Attack #2, leaking the canary** through a
separate memory-disclosure bug (a later class).

---

## pwntools essentials (the lecture's pwntools part)

### Python API

| Purpose | pwntools | Notes |
|---------|----------|-------|
| int -> bytes | `p32(n)`, `p64(n)` | short for `struct.pack('<I', n)` |
| bytes -> int | `u32(b)`, `u64(b)` | for verification |
| assembly -> bytes | `asm('call 0x8049176', vma=0x80491dc)` | `vma` computes rel32 |
| bytes -> assembly | `disasm(b, vma=addr)` | verify a patch |
| symbol address | `ELF('vuln1').symbols['win']` | instead of nm |
| vaddr -> file offset | `e.vaddr_to_offset(0x80491dc)` | where to seek in a hex editor |
| find the offset | `cyclic(n)` / `cyclic_find(x)` | derive the crash offset |
| build a payload | `flat({off: val})` | pad + place |
| shellcode | `asm(shellcraft.sh())` | execve("/bin/sh") |
| protections | `checksec` | RELRO/canary/NX/PIE |

### Tubes — same code for local and remote

```python
io = process('./vuln2')            # run locally
io = remote('127.0.0.1', 4004)     # connect to a service (the canary servers)
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

- Hand-written shellcode is **Problem 4** above — start there, then shrink it:
  can you get under 25 bytes, or keep it null-free with different tricks?
- Remove vuln2's address-leaking `printf` and find buf with `gdb.debug()`,
  then complete the same exploit (lecture "Exploit w/ or w/o GDB",
  "Why Different?").
- Shrink the NOP sled until the exploit stops working, and observe when.
- In Problem 6 (nx_demo), uncomment the stack-shellcode path and watch it fault
  under NX — then explain why the `ret2win` path still works.
- `vuln1` is the Problem 0 warm-up's sample binary; `solution3/solve_vuln1.py`
  is a minimal standalone `ret2win` (no canary, no server) if you want the
  simplest possible version before the Part B servers.
