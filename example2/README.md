# example2 — x86 Assembly Hello World, Binary Tooling, and Binary Patching

This folder now holds **three** exercises:

1. **Assembly hello world and inspection** (`hello.s`) — write a 32-bit x86
   hello world in assembly (GAS `.intel_syntax`, built with `gcc`); this is also
   the sample binary the tooling demos analyze.
2. **Binary tooling** (`ex1`~`ex4`) — the four tools from Lecture 3 "Binary
   Tooling" (slides 41–51): `readelf`, `objdump`, `xxd`, and `python3 struct`.
   Each is a runnable demo that inspects (and patches) the `hello` binary.
3. **Binary patching** (`ex5`~`ex9`, `solution2/`) — without recompiling, edit
   bytes so hidden functions (`hidden5`~`hidden9`) get called. Each source's top
   comment and `solution2/solve_ex*.py` contain the walkthrough.

> Renumbering note: the patching exercises used to be `ex1`~`ex5`. Binary
> tooling was added in front as `ex1`~`ex4`, so patching is now `ex5`~`ex9`
> (its `hidden1`~`hidden5` became `hidden5`~`hidden9`).

Work in the Vagrant VM. The default share is mounted at `/vagrant`, so this
folder is `/vagrant/example2` (the custom `/vagrant/labs` mount is not restored
after a `vagrant reload` from a saved VM).

```sh
make          # build hello (gcc) + ex5~ex9 (gcc)
make hello.bin  # extract raw .text bytes (used by the objdump raw demo)
make tooling  # run all four tooling demos (ex1~ex4) on ./hello
make clean
```

> vboxsf caveat: on the VirtualBox shared folder, **do not `chmod`** a file —
> it strips the execute permission and running it then fails with "Permission
> denied". Files created there are already mode `0777`, so just run them. The
> tooling demos avoid `chmod` for this reason.

---

# Exercise 1 — `hello.s`: x86 Assembly Hello World and Binary Inspection

Write a 32-bit x86 "Hello, world!" in assembly (GAS `.intel_syntax`), run it,
and inspect the resulting binary with `xxd` and `objdump`. This `hello` binary
is also the sample analyzed by the tooling demos below.

> The full-file dumps below are example output from the VM; address values may
> differ per environment. The opcode bytes themselves are the same anywhere.
> (`hello.s` is GAS `.intel_syntax` assembly — `gcc` assembles and links it in
> one step, so no separate assembler is needed.)

## Build and run

```sh
make hello    # gcc -m32 -nostdlib -no-pie hello.s -o hello
make run      # build then run
./hello       # Hello, world!
```

One step — `gcc` assembles and links in a single command:

```sh
gcc -m32 -nostdlib -no-pie hello.s -o hello   # assemble + link (no libc)
```

`-nostdlib` drops libc (so the entry point stays `_start`), and `-no-pie` fixes
the load addresses. No libc — Linux system calls (`int 0x80`) are called
directly, so the entry point is `_start`, not `main`.

---

## How source becomes machine code

The `.text` of `hello.s` encodes to these 31 bytes. The left column is the
actual bytes, the right is the instruction. Only the 4 address bytes of
`mov ecx, offset msg` depend on linking; the rest are fixed.

```
B8 04 00 00 00     mov eax, 4          ; sys_write
BB 01 00 00 00     mov ebx, 1          ; fd = stdout
B9 xx xx xx xx     mov ecx, offset msg ; buf address (xx = msg's linked address)
BA 0E 00 00 00     mov edx, 14         ; len = 0x0e
CD 80              int 0x80            ; write() call
B8 01 00 00 00     mov eax, 1          ; sys_exit
31 DB              xor ebx, ebx        ; status = 0
CD 80              int 0x80            ; exit() call
```

The `.data` message `"Hello, world!\n"` is 14 ASCII bytes:

```
48 65 6c 6c 6f 2c 20 77 6f 72 6c 64 21 0a
 H  e  l  l  o  ,     w  o  r  l  d  !  \n
```

The `0x0e` in `mov edx, 14` is exactly this length of 14 bytes. (Exercises
`ex3` and `ex4` patch this `0e` to `05` so the program prints only `Hello`.)

---

## Inspecting with the four tools

To see everything at once:

```sh
make inspect
```

### 1) readelf — the ELF structure

```sh
readelf -h hello        # show the ELF header (class, entry point)
readelf -l hello        # list the program headers (segments)
readelf -S hello        # list the section headers (.text/.data)
readelf -s hello        # show the symbol table (_start, msg)
readelf -r hello        # show the relocation information
```

| Flag | Shows |
|------|-------|
| `-h` | the ELF header: magic `7f 45 4c 46`, class (ELF32), entry point |
| `-l` | the program headers (PT_LOAD segments and their `R/W/E` flags) |
| `-S` | the section headers (`.text`/`.data` Addr, file Off, Size) |
| `-s` | the symbol table (`_start`, `msg`, …) |
| `-r` | the relocation information (a static `hello` usually has none) |

`readelf` parses the ELF *structure* only; it never disassembles code. The
entry point in `-h` is `0x8049000`, which matches `_start` — not `main` (there
is no libc `main` here).

### 2) objdump — turning bytes back into instructions

objdump interprets the raw bytes back into instructions.

```sh
objdump -f hello                 # file header: architecture, entry (start address)
objdump -h hello                 # section list (.text/.data sizes and addresses)
objdump -d -M intel hello        # disassemble .text (Intel syntax)
objdump -s -j .data hello        # raw byte dump of the .data section
```

Example `_start` from `objdump -d -M intel hello` (addresses vary):

```
08049000 <_start>:
 8049000: b8 04 00 00 00        mov    eax,0x4
 8049005: bb 01 00 00 00        mov    ebx,0x1
 804900a: b9 00 a0 04 08        mov    ecx,0x804a000
 804900f: ba 0e 00 00 00        mov    edx,0xe
 8049014: cd 80                 int    0x80
 8049016: b8 01 00 00 00        mov    eax,0x1
 804901b: 31 db                 xor    ebx,ebx
 804901d: cd 80                 int    0x80
```

The middle byte column is exactly the machine code. For example `mov edx,0xe`
is `ba 0e 00 00 00`, and `0x0e` is the message length 14. The
`mov ecx,0x804a000` address is stored little-endian in the file as
`00 a0 04 08` — objdump turns it back into the human-readable `0x804a000`.

### 3) xxd — offset + hex + ASCII

```sh
xxd hello | head
```

Example output (the beginning):

```
00000000: 7f45 4c46 0101 0100 0000 0000 0000 0000  .ELF............
00000010: 0200 0300 0100 0000 ...                  ................
```

- The first 4 bytes `7f 45 4c 46` are the ELF magic number, shown as `.ELF` in
  the ASCII column. It is the common signature of every ELF file.
- Left is the file offset, middle is hex in 2-byte groups, right is printable
  characters (others shown as `.`).
- Near where `.data` sits (offset `0x2000`) you can see the `Hello, world!`
  string in the ASCII column.

To see only the code bytes, extract `.text`:

```sh
make hello.bin        # extract .text with objcopy, then xxd
```

You will see the same `B8 04 00 00 00 BB 01 ...` bytes from "How source becomes
machine code" above, and the middle hex column lines up with what objdump
disassembled just above.

### 4) python3 struct — build and place exact patch bytes

`struct.pack` turns numbers into raw bytes and `struct.unpack` reads them back,
so you can produce the exact bytes to write at a known file offset.

```python
>>> import struct
>>> struct.pack('<I', 0x401136)      # 4-byte little-endian address
>>> struct.pack('BB', 0x90, 0x90)    # two single bytes: a 2-byte NOP pad
>>> struct.unpack('<Q', data)[0]     # bytes back to a number

# patch a file at a known offset
>>> f = open('target', 'rb+')
>>> f.seek(0x1050)
>>> f.write(struct.pack('<I', 0x401136)); f.close()
```

Format string = byte order + size codes: `<` little-endian (x86), `>`
big-endian, `=` native; `B`=1, `H`=2, `I`=4, `Q`=8 bytes. Opening with `'rb+'`
edits in place and keeps the file size.

---

## The four tools at a glance

| Tool | What it shows / does | When to use |
|------|----------------------|-------------|
| `readelf` | ELF structure: headers, segments, sections, symbols | check the entry point and where sections load |
| `objdump -d` | bytes -> assembly instructions | interpret what the code actually is |
| `xxd` | offset + hex + ASCII | quickly scan bytes and find strings |
| `python3 struct` | build exact bytes; `seek`+`write` to patch | produce and place a precise patch at an offset |

Key idea: **readelf shows the ELF's structure, objdump turns bytes into
instructions, xxd shows the raw bytes as-is, and `struct` builds the exact bytes
to patch.** Line up the same offset across the outputs and you can trace one
source line into the bytes it becomes and where it is stored.

## Going further

- Change `mov edx, len` to `mov edx, 5`, rebuild, and it prints only "Hello".
  Confirm that `0e` became `05` in xxd. (This is what `ex3`/`ex4` patch at the
  byte level, without rebuilding.)
- Change the message, then run `objdump -s -j .data hello` to see how the
  `.data` bytes change.
- Run `readelf -h hello` to view the ELF header and confirm the entry point
  matches `_start`'s address in objdump.

## Assignment: sum 1..10 with a loop

Write a 32-bit x86 assembly program (GAS `.intel_syntax`, same toolchain as
`hello.s` above) that uses a **loop** to add the integers 1 through 10 and
returns the sum (55) as the process exit status. Hand this one in — no full
solution is given here, only hints.

Requirements:

- Start at `_start`, no libc — build exactly like `hello.s`.
- Use a loop: keep a counter and a running total in registers; on each pass add
  the counter to the total and advance it, until you have added 1 through 10.
  Drive the loop with a compare and a conditional jump (e.g. `cmp` + `jle`/`jg`).
- Return the total with `sys_exit` (`eax = 1`, `ebx = sum`, `int 0x80`).

Hints (the loop is only a handful of instructions):

- Pseudocode:

  ```
  sum = 0
  for i = 1; i <= 10; i++:
      sum = sum + i
  exit(sum)
  ```

- Suggested registers: one register holds the counter `i` (start at 1), another
  holds the running `sum` (start at 0, e.g. `xor` it to zero).
- Loop body: `add sum, i`, then `inc i`; then `cmp i, 10` and jump back while
  `i` is still `<= 10` (`jle`). Fall through into the same `sys_exit` you wrote
  in `hello.s`, but with the sum in `ebx`.
- No printing is needed: the exit status is one byte (0–255), and 55 fits.

Build and verify with the exit status:

```sh
gcc -m32 -nostdlib -no-pie sum.s -o sum
./sum; echo $?        # expected: 55
```

Stretch goal: instead of returning it, convert the sum to ASCII and `sys_write`
"55" to stdout, the way `hello.s` prints its message.

---

# Exercise 2 — Binary Tooling (`ex1`~`ex4`)

Four command-line tools for working with binaries. `readelf` and `objdump`
*read* an ELF; `xxd` and `python3 struct` also *write* bytes to patch one. All
four demos operate on the `hello` binary from Exercise 1, so build it first:

```sh
make hello hello.bin
```

## ex1 — `readelf`: inspect the ELF structure

```sh
bash ex1_readelf.sh          # or: readelf -h/-l/-S/-s/-r hello
```

| Flag | Shows |
|------|-------|
| `-h` | ELF header: magic `7f 45 4c 46`, class (ELF32), entry point |
| `-l` | program headers = segments (PT_LOAD load address + `R/W/E` flags) |
| `-S` | section headers (`.text`/`.data` Addr, file Off, Size) |
| `-s` | symbol table (`_start`, `msg`, …) |
| `-r` | relocation info (a statically linked hello usually has none) |

`readelf` parses *structure* only; it never disassembles code. The entry point
in `-h` is `0x8049000`, which matches `_start` — not `main` (there is no libc
`main` here).

## ex2 — `objdump`: turn bytes back into instructions

```sh
bash ex2_objdump.sh
```

```sh
objdump -f hello                         # file header (arch, entry)
objdump -d -M intel hello                # disassemble .text (Intel syntax)
objdump -s -j .data hello                # raw dump of .data (see the string)
objdump -D -b binary -m i386 -M intel hello.bin   # raw, headerless bytes
```

The last command is the key one from slide 46: `-b binary` treats the input as
**headerless raw bytes** and `-m i386` supplies the architecture objdump can no
longer read from a (missing) header. `hello.bin` is the `.text` extracted by
`objcopy` (`make hello.bin`), so it disassembles from offset 0 with no ELF
around it. To pretend it loads somewhere, add `--adjust-vma=0x8049000`.

## ex3 — `xxd`: view bytes, then patch with `-r`

```sh
bash ex3_xxd.sh
```

`xxd` shows raw bytes as hex + ASCII with no format parsing; `xxd -r` turns a
hex dump back into bytes, which is how you patch.

```sh
xxd hello | head                    # offset + hex + ASCII
xxd -s 0x2000 -l 16 hello           # jump to .data: "Hello, world!" in ASCII
```

The demo then patches the output length `mov edx, 14` down to `5` so the
program prints only `Hello`:

1. Find the instruction `ba 0e 00 00 00` with `objdump -d`; its vaddr is
   `0x804900f`, so the `0e` operand byte is at vaddr `0x8049010`.
2. Convert to a file offset with `.text` VMA/File-off from `objdump -h`:
   `0x8049010 - 0x8049000 + 0x1000 = 0x1010`.
3. Feed one `offset: byte` line back through `xxd -r` to patch a copy:

```sh
cp hello hello_xxd
printf '%08x: 05\n' 0x1010 | xxd -r - hello_xxd
./hello_xxd        # -> Hello
```

## ex4 — `python3 struct`: build the exact patch bytes

```sh
python3 ex4_struct.py
```

`struct.pack` turns numbers into raw bytes and `struct.unpack` reads them back.
Format string = byte order + size codes: `<` little-endian (x86), `>`
big-endian, `=` native; `B`=1, `H`=2, `I`=4, `Q`=8 bytes.

```python
struct.pack('<I', 0x401136)     # b'6\x11@\x00'  (4-byte little-endian)
struct.pack('BB', 0x90, 0x90)   # b'\x90\x90'    (two NOP bytes)
struct.unpack('<Q', data)[0]    # bytes back to a number
```

The demo finds `ba 0e 00 00 00` in the file, then patches the same offset
`0x1010` by seeking and writing — the disciplined way to patch at a known
offset:

```python
f = open('hello_struct', 'rb+')     # rb+ keeps the file size
f.seek(0x1010)
f.write(struct.pack('<I', 5))       # 14 -> 5
```

Both `ex3` and `ex4` independently compute the same patch offset `0x1010` and
produce a binary that prints `Hello`.

## The four tools at a glance

| Tool | Reads / Writes | Use |
|------|----------------|-----|
| `readelf` | read | ELF structure: headers, segments, sections, symbols |
| `objdump` | read | disassemble code; dump a section; raw-binary disassembly |
| `xxd` | read + write | hex/ASCII view; `-r` patches bytes back |
| `python3 struct` | write | build exact bytes; `seek`+`write` to patch an offset |

---

# Exercise 3 — Binary Patching (`ex5`~`ex9`)

Without recompiling, edit bytes so a hidden function runs. Build the targets,
then run the matching solver in `solution2/`:

```sh
make                       # builds ex5~ex9
python3 solution2/solve_ex5.py     # writes solution2/ex5 (patched)
```

| Ex | Technique | Hidden fn |
|----|-----------|-----------|
| `ex5` | redirect an existing `call dummy` in `.text` to `hidden5` (rewrite the `e8` rel32) | `hidden5` |
| `ex6` | neutralize the conditional jump that skips the call (NOP out the `jcc`) | `hidden6` |
| `ex7` | inject a `call` into a NOP code cave inside `.text` | `hidden7` |
| `ex8` | flip the data `PT_LOAD` segment to RWX, then write `call+ret` into `.data` | `hidden8` |
| `ex9` | make `.data` executable, then feed `call+ret` shellcode via `input.txt` | `hidden9` |

Each `ex*.c` top comment explains the idea and the byte math
(`rel32 = target - (call_addr + 5)`); each `solve_ex*.py` automates it with
pwntools. Run the patched outputs from `/tmp` if the shared folder blocks
execution.
