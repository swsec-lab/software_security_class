# example4 — Memory Disclosure and Format String Attacks (Lecture 6)

The hands-on lab for **6-1. Memory Disclosure Attacks** and **6-2. Format
String Attacks**. It runs in two parts:

- **Part A — Memory disclosure (lecture 6-1).** Leak secrets *without*
  corrupting memory: an uninitialized-memory read that reuses a freed chunk,
  and a Heartbleed-style memory overread that trusts an attacker-supplied
  length.
- **Part B — Format string (lecture 6-2).** Turn an unsafe `printf(user_input)`
  into a memory *read*, then an arbitrary memory *write* with `%n`, and finally
  a control-flow hijack.

> **Ordering:** Part A after lecture 6-1, Part B after lecture 6-2. Part B
> builds directly on the canary idea from lecture 6-1 (Problem 3 leaks the
> canary), and on example3's exploitation workflow.

> Work inside the Vagrant VM (`/vagrant/labs/example4`), which has the 32-bit
> toolchain and pwntools. The VM disables ASLR (`kernel.randomize_va_space=0`)
> so addresses are stable, and the non-PIE builds keep code and global
> addresses fixed.

## Build

```sh
make          # build every binary (Part A and Part B)
make check    # pwn checksec on all of them (see expected output below)
make clean
```

Different problems need different protections, so the Makefile builds with
different flags. `uninit.c` is compiled **twice** — once as the bug, once with
`-DFIX` for the patched version.

| Binary | Flags | checksec | Used by |
|--------|-------|----------|---------|
| `uninit` | `-fno-stack-protector` | No canary / NX enabled | Problem 1 (bug) |
| `uninit_fixed` | `-fno-stack-protector -DFIX` | No canary / NX enabled | Problem 1 (patch) |
| `heartbleed` | `-fno-stack-protector` | No canary / NX enabled | Problem 2 |
| `fmt_leak` | `-fstack-protector-all` | Canary found / NX enabled | Problem 3 |
| `fmt_write` | `-fno-stack-protector` | No canary / NX enabled | Problem 4 |
| `fmt_got` | `-fno-stack-protector -Wl,-z,norelro` | No canary / NX / No RELRO | Problem 5 |

The base flags (`-m32 -O0 -mpreferred-stack-boundary=2 -fno-pic -no-pie
-fcf-protection=none`) match the lecture slides and example3: 32-bit, no
optimization, fixed addresses, simple offsets. The format-string targets add
`-Wno-format-security` so `printf(buf)` compiles (distro hardening otherwise
turns the warning into an error).

> **Why some targets differ.** `fmt_leak` is built *with* a canary on purpose,
> so the same leak that reads the secret also reads the canary — the "Attack
> #2: leak the canary" bypass from lecture 6-1. `fmt_got` is built with
> **partial RELRO** (`norelro`) so its GOT stays writable; full RELRO would
> make the GOT read-only and block Problem 5's specific trick.

---

# Part A — Memory disclosure (lecture 6-1)

The theme of lecture 6-1: **memory safety is not only about preventing
corruption — it is also about preventing unintended disclosure.** Both
problems here leak a secret while never overwriting a return address or a
canary.

## Problem 1 — uninit: uninitialized memory read (freed-chunk reuse)

This is the slide-9 "crypto key" example made runnable. A secret is stored in
a heap chunk and the chunk is freed **without being wiped**. A later
`malloc()` of the same size hands back that exact chunk, and the program sends
it out **before initializing it** — so the freed secret leaks.

```sh
make
python3 solution4/solve_uninit.py
```

The script runs both builds and asserts the difference:

- `uninit` leaks the secret through the reused, uninitialized buffer. glibc
  writes its own bookkeeping (the tcache `next` pointer and key, 8 bytes on
  32-bit) into the start of the freed chunk, so the first few bytes are
  clobbered and the leak shows the secret's *tail* — the script matches a
  token past those first bytes.
- `uninit_fixed` (built with `-DFIX`) applies the slide-10 patch — `memset`
  the key before `free()`, and initialize the new buffer before use — and
  leaks nothing.

Key point: `free()` does not erase memory, and the allocator returns the most
recently freed same-size chunk first. Two small mistakes (not wiping, not
initializing) combine into an information leak. This is the class of bug behind
the QEMU and Linux CVEs on slides 11-12, including the **struct-padding** leak
(even fully-assigned fields can leave padding bytes uninitialized).

## Problem 2 — heartbleed: memory overread (Heartbleed)

A tiny model of CVE-2014-0160 (slides 15-24). One heartbeat request arrives on
stdin:

```
[type:1][len:2 big-endian][payload ...]
```

The server copies `len` payload bytes into its response — but it trusts `len`
instead of checking it against the bytes actually received. This is the
slide-20 picture exactly: `memcpy(p2, p1, length)` with `length` chosen by the
attacker.

```sh
python3 solution4/solve_heartbleed.py
```

The script sends a 5-byte payload (`hello`) but claims `len = 0x300`. The
server over-reads past the payload chunk into an adjacent heap allocation and
returns the secret sitting there. The script searches the response for
`SECRET=...` and prints it.

Key point: **never trust an attacker-supplied length.** Heartbleed leaked up to
64 KB of server memory per request — private keys, passwords, session tokens —
from one missing bounds check (slide 23).

---

# Part B — Format string (lecture 6-2)

One unsafe line, `printf(buf)` where `buf` is user input, grows from a harmless
mistake into a memory read, an arbitrary write, and finally a control-flow
hijack. All three targets are 32-bit and non-PIE, so the stack-argument layout
matches the lecture diagrams and global/code addresses are fixed.

Every Part B solution auto-detects the **format-argument offset** the same way:
send `AAAA%N$p` for growing `N` and find the `N` whose output contains
`0x41414141`. That `N` is the stack slot where our buffer begins — exactly what
`fmtstr_payload(N, ...)` needs.

## Problem 3 — fmt_leak: read memory (and leak the canary)

`printf(buf)` treats input as a format string, so `%p` walks the stack
(slides 15-16). A known secret `0xc0ffee42` sits on the stack; positional
params `%N$p` (slide 38) read a chosen slot directly.

```sh
python3 solution4/solve_fmt_leak.py
```

The script probes stack slots one at a time (`%N$p` alone per request, so the
short `buf[128]` can never truncate the format string), prints the dump, finds
the slot holding the secret, and reports the exact `%N$p` that reads it.
Because `fmt_leak` is built **with a canary**, the same probe also exposes the
canary (a 4-byte slot whose least-significant byte is `00` and whose upper
three bytes are random) — this is the lecture 6-1 "leak the canary" bypass, and
the leaked canary is what you would splice into an overflow against example3's
canary servers.

## Problem 4 — fmt_write: arbitrary write with %n -> win()

Now we write. The goal is to overwrite the global `key` with the magic value
`0x08042222` so `main()` calls `win()`. The program prints `key`'s address for
you (a teaching aid, like example3's address-leaking targets).

```sh
python3 solution4/solve_fmt_write.py
```

The reference solution uses pwntools `fmtstr_payload`, which performs the full
technique chain from the slides automatically:

- **`%n`** writes the number of characters printed so far (slides 12-19).
- A **width field** inflates that count cheaply instead of printing megabytes
  (slides 21-27).
- **`%hn` short writes** split a 4-byte value into two 2-byte writes to keep
  the output small (slides 28-36).
- **Positional params `%N$`** target the right stack slots directly
  (slides 38-42).

The magic value `0x08042222` is the exact value from the slide-34 short-write
walkthrough. If you want to see the hand-built payload behind the library call,
the slides construct it like this (write `0x08040102` to `0x42424242`):

```sh
# the slide-29 form, with positional params (slide 39):
printf 'BBBBDBBB%250d%1$hn%1784d%2$hn' | ./fmt_write    # illustrative
```

- `BBBB` is the low target address `0x42424242`, `DBBB` is `0x42424244`.
- `%250d` makes the printed length `8 + 250 = 258 = 0x0102`; `%1$hn` writes it
  to `0x42424242`.
- `%1784d` brings the total to `258 + 1784 = 2052 = 0x0804`; `%2$hn` writes it
  to `0x42424244`.
- Little-endian, the two short writes combine into `0x08040102`.

`fmtstr_payload` computes these counts for the real target address and value
for you; read its output with `-v` to see the generated format string.

## Problem 5 — fmt_got: control-flow hijack (GOT overwrite)

The finale (slides 43-44). The program never calls `win()`. We use the `%n`
write primitive to overwrite the **GOT entry of `puts`** with `win`'s address,
so the final `puts("bye")` jumps into `win()` and spawns a shell.

```sh
python3 solution4/solve_fmt_got.py
```

Unlike a buffer overflow, a format string can write to an **arbitrary address**
(slide 44), so we target the GOT and never touch the stack or the return
address. This needs a writable GOT, which is why `fmt_got` is built with
partial RELRO.

Inspect the target the historic way before you exploit it:

```sh
objdump -R ./fmt_got | grep puts      # the puts GOT slot address
nm ./fmt_got | grep ' win'            # win's address
```

---

## Mitigations (lecture 6-2, slides 45-46)

The fixes the lecture ends on, and how to see them here:

- **Never use user input as the format string.** `printf("%s", buf)` is safe;
  `printf(buf)` is the whole bug. Try changing one target to the safe form and
  watch every Part B exploit stop working.
- **Compiler help.** GCC/Clang warn on a non-literal format string
  (`-Wformat-security`); we had to pass `-Wno-format-security` to compile these
  on purpose. Some compilers also disable `%n` in `printf` entirely.
- **Memory disclosure (Part A).** Initialize before use, wipe secrets before
  `free()`, and bounds-check every length taken from untrusted input.

## checksec summary

```
uninit / uninit_fixed / heartbleed -> No canary   / NX enabled  / No PIE
fmt_leak                           -> Canary found / NX enabled  / No PIE
fmt_write                          -> No canary    / NX enabled  / No PIE
fmt_got                            -> No canary    / NX enabled  / No PIE / No RELRO
```

## Going further (lecture homework)

- **Chain Part B into example3.** Use the canary leaked in Problem 3 as the
  canary bytes in an overflow against example3's `canary_server_x` /
  `canary_server` — this is the "leak, don't brute-force" path from lecture
  6-1.
- **Remove the teaching leak.** Delete the `printf("... @ %p ...")` line in
  `fmt_write`/`fmt_got` and recover the needed address another way (a Problem 3
  style leak, or a fixed non-PIE address you read with `nm`/`objdump`).
- **Return-address overwrite.** Instead of the GOT, point `fmt_got`'s write at
  the saved return address on the stack (you will need a stack-address leak
  first — reuse Problem 3).
- **Overread tuning.** In Problem 2, shrink `CLAIM` until the secret no longer
  appears, and explain what that tells you about the heap layout. Then grow the
  payload and watch the leak boundary move.
- **Struct padding.** Extend Problem 1 with a struct that has padding between
  fields, assign every field, and show that the padding bytes still leak
  (slide 12).

## Safety note

These programs are deliberately vulnerable and are for learning exploitation in
this controlled VM only. Do not deploy them or run the techniques against
systems you do not own or have permission to test.
