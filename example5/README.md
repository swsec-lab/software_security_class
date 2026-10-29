# example5 — Code Reuse Attacks: Return-to-libc and ROP

The hands-on lab for **Return-to-libc** and **Return-Oriented Programming**.
DEP/NX makes injected shellcode non-executable (example3), so here we stop
injecting code and **reuse code that is already executable** — first a
function already sitting in the vulnerable binary, then libc functions, then
small instruction gadgets — to get a shell anyway.

- **Part 0 — Return into the binary's own code.** DEP stops the *stack* from
  executing, not the overflow itself: corrupt the return address to reach a
  function the program never calls.
- **Part A — Return-to-libc.** Return into `system()` in libc instead of a
  hand-planted function, then chain two calls with an ESP-lifting `pop; ret`.
- **Part B — ROP and ASLR.** Build a write primitive from gadgets, do
  register-loading ROP into a raw `execve` syscall, and finally defeat ASLR
  with a leaked libc pointer.

> **Ordering:** after example3 (overflow + DEP/NX), which this lab builds on
> directly.

> Work inside the Vagrant VM (`/vagrant/labs/example5`). It has the 32-bit
> toolchain. **Problem 0 works with ASLR either way** (it never
> touches libc); **Problems 1-4 need ASLR off; Problem 5 needs it on.**

> **Everything in this lab is x86 32-bit**, to match the course toolchain and
> example3/example4. The lecture's "ROP for x86-64" slides are realized here by
> Problem 4, whose 32-bit syscall ROP loads registers before the call exactly
> the way the x86-64 chain loads RDI/RSI/RDX — same idea, 32-bit `int 0x80`.

## Build

```sh
make          # build every binary
make check    # pwn checksec (all: No canary / NX enabled / No PIE)
make aslr-off # echo 0 > randomize_va_space   (Problems 1-4)
make aslr-on  # echo 2 > randomize_va_space   (Problem 5)
make clean
```

> **Running the binaries directly.** The shared folder `/vagrant` is mounted
> `noexec`, so `./ret2libc` gives "Permission denied". To run a binary, copy
> it to a local disk first: `cp ret2libc /tmp && /tmp/ret2libc`.

All targets share `-m32 -mpreferred-stack-boundary=2 -O0 -fno-stack-protector
-fno-pic -no-pie -fcf-protection=none`. Crucially we do **not** pass
`-z execstack`: NX is ON, which is exactly why code injection fails and code
reuse is needed.

| Binary | Arch | What you do |
|--------|------|-------------|
| `ret2func` | x86 | return into `foo()`, a function already in the binary |
| `ret2libc` | x86 | one `system("/bin/sh")` call |
| `chain` | x86 | `setuid(0)` then `system("/bin/sh")` (ESP lifting) |
| `ropwrite` | x86 | write-what-where ROP chain -> `win()` |
| `ret2syscall` | x86 | load syscall registers, `int 0x80` -> `execve("/bin/sh")` |
| `leak32` | x86 | ret2libc with **ASLR on**, using a leaked libc pointer |

---

# Part 0 — Return into the binary's own code

DEP/NX stops the CPU from *executing the stack*; it does nothing about the
overflow that corrupts the return address in the first place. The simplest
way to see this: redirect the return address to a function that is already
compiled into the vulnerable program itself, but that normal control flow
never calls.

## Problem 0 — ret2func: return into a function in the binary

`ret2func.c` mirrors the slide almost line for line:

```c
int main(){ int x = 42; echo(); return 0; }
void echo(){ char buf[32]; gets(buf); puts(buf); }
void foo(){ system("/bin/sh"); }
```

`foo()` is never called by `main()` or `echo()` — it is only reachable by
overwriting `echo()`'s return address with `foo()`'s address. Because the
binary is built `-no-pie`, that address is fixed at link time: no libc
address, no leak, nothing else needed.

Craft a payload so that `foo()` gets called.

This is the whole idea behind code reuse in one function: **return-to-libc
(Problem 1, below) is exactly this same trick, except the function we reuse
is one that is *always* present — `system()` in libc — instead of one the
programmer happened to leave lying around.**

---

# Part A — Return-to-libc

DEP does not stop the overflow; it only stops executing the stack. So instead
of jumping to shellcode we jump to `system()`, which is already in memory
and executable.

We'll turn ASLR off for this part.

Check the current ASLR status:

```sh
cat /proc/sys/kernel/randomize_va_space   # 0=off, 1=conservative, 2=full (default)
```

Turn ASLR off (keep it off through Problems 1-4):

```sh
make aslr-off
# under the hood: echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

Turn it back on before moving to other labs:

```sh
make aslr-on
# under the hood: echo 2 | sudo tee /proc/sys/kernel/randomize_va_space
```

## Problem 1 — ret2libc: one libc call

Overwrite the return address with the classic 32-bit ret2libc frame:

```
[ &system ][ fake return addr ][ &"/bin/sh" ]
```

When `main` returns, it "returns into" `system`, which reads its argument from
where it expects the caller to have pushed it — our `&"/bin/sh"`. The string is
already inside libc (`strings libc.so.6 | grep /bin/sh`).

```sh
make aslr-off
```

Craft a payload with this frame and send it.

## Problem 2 — chain: two calls with ESP lifting

One frame calls one function. To call two, the first call's argument must be
removed from the stack before the second runs, or the arguments collide. The
fix is a `pop; ret` gadget that lifts ESP past the consumed argument:

```
[ &setuid ][ pop;ret ][ 0 ][ &system ][ &exit ][ &"/bin/sh" ]
```

`main` ret → `setuid(0)`; `setuid` ret → `pop;ret` drops the `0`; ret →
`system("/bin/sh")`.

Craft a payload with this chain and send it.

As a normal user `setuid(0)` returns -1 and you get a **non-root** shell — the
lesson is the chaining mechanism. To see why ret2libc mattered historically,
make the binary setuid-root and watch the chain pop a **root** shell:

```sh
cp chain /tmp/chain && sudo chown root:root /tmp/chain && sudo chmod u+s /tmp/chain
```

Then run the same exploit against `/tmp/chain` and confirm `id` reports
`uid=0(root)`.

---

# Part B — ROP and ASLR

Return-to-libc needs whole libc functions. ROP generalizes it: chain tiny
instruction sequences ("gadgets") that each end in `ret`, so the stack becomes
a little program.

## Problem 3 — ropwrite: a write-what-where primitive

The gadget `mov [ptr], 0x41414141; ret` almost never exists, so we synthesize
the write from three gadgets:

```
A: pop eax ; ret          -> eax = &key
B: pop ebx ; ret          -> ebx = 0x41414141
C: mov [eax], ebx ; ret   -> *key = 0x41414141
stack: [A][&key][B][0x41414141][C][&win]
```

After the write, the chain returns into `win()`, which checks `key` and spawns
a shell. The binary ships a small **gadget farm** so the exact slide gadgets
exist.

Craft a payload with this chain. You can also find the gadgets by hand:

```sh
ROPgadget --binary ropwrite | grep -E 'pop eax ; ret|pop ebx ; ret|mov dword ptr \[eax\], ebx'
```

## Problem 4 — ret2syscall: register-loading ROP into a raw syscall

The x86-64 slides (the "ROP for x86-64" section) load arguments into registers
RDI, RSI, RDX, ... with `pop` gadgets before the call. The 32-bit syscall ABI
is the same idea: set the registers, then fire the syscall. We skip libc's
`system()` entirely and invoke `execve("/bin/sh", NULL, NULL)` ourselves via
`int 0x80`:

```
eax = 11 (__NR_execve)   ebx = &"/bin/sh"   ecx = 0 (argv)   edx = 0 (envp)

[pop eax;ret][11][pop ebx;ret][&binsh][pop ecx;ret][0][pop edx;ret][0][int 0x80]
```

The binary ships a **gadget farm** (the four `pop reg; ret` gadgets plus
`int 0x80`) and a `"/bin/sh"` string, so the exact pieces exist.

Craft a payload with this chain.

This is a *pure* ROP exploit — no libc function is called at all — and the
32-bit counterpart to the slides' x86-64 register-ROP example.

## Problem 5 — leak32: defeat ASLR with a leaked pointer

With ASLR on, the libc base is random each run, so Problems 1-4's fixed
addresses break. But ASLR randomizes only the **base**; offsets inside libc are
fixed. One leaked libc address is enough:

To confirm ASLR is actually on:

```sh
cat /proc/sys/kernel/randomize_va_space   # should read 2
```

Or run `leak32` twice in a row and check that the libc address it prints
changes each time.

```
libc_base = leaked_puts - libc.sym.puts
system    = libc_base   + libc.sym.system
```

then the same 32-bit ret2libc frame as Problem 1. The leak **is** a memory
disclosure; this binary simulates it by printing a real, ASLR-randomized
libc address (`puts`, via `dlsym`) in place of a format-string or overread bug.

```sh
make aslr-on
```

Use the formula above to compute the libc base and craft a payload. When
you're done, restore ASLR for other labs:

```sh
sudo sysctl -w kernel.randomize_va_space=0
```

---

## Mitigations and the bigger picture

- **DEP/NX** (example3) stops stack shellcode but not the overflow, so code
  reuse (Problems 1-4) walks right past it.
- **ASLR + PIE** randomize segment bases and make fixed addresses fail
  (Problems 1-4 require `make aslr-off`). Modern Linux enables both by default.
- **Bypassing ASLR:**
  - **Leaked pointer** (Problem 5) — reliable, and the modern norm. Derive the
    whole libc layout from one leaked address.
  - **Brute force** — x86 ASLR has ~16 bits of entropy, and a
    forking server's children reuse the parent's layout, so an attacker can
    retry until a guess hits. Try it as homework: fork `ret2libc` behind a
    loop and brute-force the libc base with ASLR on.

## Going further

- **ret2libc execve instead of syscall**: Problem 4 goes straight to the
  kernel; contrast it with calling libc's `execve`/`system` (Problems 1-2) and
  note that the syscall path needs no libc symbol at all.
- **Unintended gadgets**: disassemble `ret2syscall` from a mid-instruction byte
  (`objdump -d` vs starting one byte in) and find a gadget the compiler never
  emitted.
- **ret2libc without a leak under ASLR**: combine with example4's format-string
  leak (Problem 3 there) to obtain the libc address, then run Problem 5's frame.
- **x86-64 ROP (slides, "ROP for x86-64")**: the same chain on a 64-bit build
  loads RDI/RSI/RDX with `pop` gadgets instead of stacking args; the register
  discipline in Problem 4 is the direct 32-bit analog.

## Safety note

These programs are deliberately vulnerable and are for learning exploitation in
this controlled VM only. Do not deploy them or run the techniques against
systems you do not own or have permission to test.
