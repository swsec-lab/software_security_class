# example1 — From gdb Basics to Assembly Analysis and Binary Patching

Debug 32-bit x86 programs with gdb, read the **assembly (Intel syntax)
directly** with no symbols, and finally edit bytes to change control flow —
all in one folder, step by step.

## Build

```sh
make          # build everything
make clean    # clean up
```

All binaries are built with `-m32 -O0 -fno-stack-protector -no-pie`. Work in
the Vagrant VM (`/vagrant/labs/example1`), which has the 32-bit toolchain.

## Four tracks

| Track | Programs | Build | What you do |
|-------|----------|-------|-------------|
| **A. gdb basics** | 01_add · 02_sub · 03_if · 04_while | `-g` (symbols) | watch variables with `break`/`next`/`print`/`set var`/`watch` |
| **B. assembly analysis** | 05_for · 07_sum · 08_array · 09_crash · 10_loop | no `-g`, not stripped | `print var` fails, so you must read the disassembly (function symbols remain, so you can still locate code) |
| **C. binary patching** | 11_patch | no `-g`, not stripped | neutralize a branch with a NOP to change control flow |
| **D. final crackme** | 06_func | no `-g` + stripped | solve with no symbols at all |

Track A teaches gdb; track B solves the same kinds of problems in assembly;
track C edits bytes directly; track D is the no-symbols challenge.

---

## Tooling (Intel syntax)

Everything here uses **Intel syntax** (`mov eax, ebx`). The Linux default is
AT&T (`mov %ebx, %eax`), so switch it:

```sh
# objdump: always print Intel
objdump -d -M intel ./05_for

# gdb: set per session, or add one line to ~/.gdbinit
(gdb) set disassembly-flavor intel
echo 'set disassembly-flavor intel' >> ~/.gdbinit
```

Common gdb commands:

| Command | Description |
|---------|-------------|
| `disassemble main` | disassemble a whole function |
| `x/i $pc` / `x/10i $pc` | current / next 10 instructions |
| `info registers` (`i r eax`) | register values |
| `break *0x08049abc` | breakpoint at an address |
| `watch *(int*)($ebp-0x4)` | watch a stack slot by address (no symbols) |
| `set $eax = 3456` / `set $eip = 0x...` | force a register / execution point |

---

## 32-bit registers

| Register | Common use |
|----------|------------|
| `eax` | arithmetic accumulator, **function return value** |
| `ebx` `ecx` `edx` | general (ecx = counter, edx = high half of multiply) |
| `esi` `edi` | src/dst for string/memory copies |
| `esp` | stack top pointer |
| `ebp` | current frame base (reference for locals) |
| `eip` | address of the next instruction |
| `eflags` | compare-result flags: **ZF** (equal) · **SF** (negative) · **CF** (unsigned borrow) · **OF** (signed overflow) |

`cmp`/`test` only set these flags; the conditional jump right after reads them.

## Common instructions

| Instruction | Meaning |
|-------------|---------|
| `mov dst, src` | copy a value |
| `lea dst, [expr]` | compute an address only (no memory access); also used for arithmetic |
| `add` / `sub` | add / subtract |
| `imul` | multiply |
| `cmp a, b` | compute `a - b`, discard it, set flags |
| `test a, b` | compute `a & b`, discard it, set flags (often `test eax,eax` to check for 0) |
| `push` / `pop` | push onto / pop off the stack |
| `call addr` | push return address, jump to addr |
| `ret` | pop return address, jump to it |
| `jmp` | unconditional jump |
| `nop` (`0x90`) | do nothing (used for patching) |

## Conditional jumps — signed vs unsigned (key to 10_loop)

| Signed | Unsigned | Meaning |
|--------|----------|---------|
| `jl`  / `jge` | `jb`  / `jae` | `<` / `>=` |
| `jle` / `jg`  | `jbe` / `ja`  | `<=` / `>` |
| `je` / `jne` | (same) | `==` / `!=` |

The compiler picks signed (jl/jge) vs unsigned (jb/jae) based on the
**variable's type**. An `unsigned` `i >= 0` is always true, so it compiles to
`jae`, which is why 10_loop never ends.

## Function prologue / epilogue and the stack frame

```
prologue             epilogue
push ebp             leave        ; = mov esp,ebp ; pop ebp
mov  ebp, esp        ret
sub  esp, N          ; reserve N bytes for locals
```

cdecl calling convention: arguments are **pushed right-to-left**, the return
value comes back in `eax`.

```
high address
  ...            [ebp+8]  first argument (argc, ...)
  return addr    [ebp+4]
  saved ebp      [ebp+0]  <- ebp points here
  local 1        [ebp-4]
  local 2        [ebp-8]
  ...            (grows toward esp)
low address
```

With no symbols, variables are told apart only by these `[ebp-X]` offsets. In
08_array you confirm that `arr[4]` overwrites the `secret` slot using this
offset math.

## C construct → assembly pattern

| C code | Assembly pattern | Practice file |
|--------|------------------|---------------|
| `sum = a + b;` | `mov eax,[..]; add eax,[..]; mov [..],eax` | 01_add |
| `if (x > n)` | `cmp ...,n; jle/jg ...` | 03_if, 07_sum |
| `for/while` | backward jump + a `cmp`/`jcc` at the bottom | 04_while, 05_for, 10_loop |
| `arr[i]` | `[base + index*scale]` (e.g. `[ebp-0x18+eax*4]`) | 08_array |
| function call | `push args; call fn; ...eax = return value` | 06_func, 09_crash |
| disable a condition | overwrite `je`/`jne` with `90 90` (nop) | 11_patch |

---

## Binary patching quick reference (11_patch)

Find the instruction to change in the disassembly, convert its address to a
**file offset**, then overwrite the bytes.

```sh
# 1) find the virtual address (vaddr) of the conditional jump
objdump -d -M intel ./11_patch        # e.g. je at 0x08049abc, bytes 74 xx

# 2) vaddr -> file offset (relative to .text)
readelf -S ./11_patch                 # look at .text's Addr and Off
# file_off = je_vaddr - text_Addr + text_Off

# 3) overwrite the two bytes with NOP (0x90), keeping the file size (conv=notrunc)
printf '\x90\x90' | dd of=./11_patch bs=1 seek=<file_off> count=2 conv=notrunc

# 4) confirm the control flow changed
./11_patch                            # ACCESS GRANTED
```

You can also change the flow live in gdb without touching the file:

```
(gdb) break main
(gdb) run
(gdb) set $eip = <granted branch address>   # or edit registers/flags at the jump
```
