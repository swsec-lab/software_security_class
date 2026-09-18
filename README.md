# Emerging Topics in Information Security

**Software Security — Fall 2026 (2026, 2nd semester)**
**Credits / hours:** 3 credits (3-3-0) · Course code 2313-5023-00
**Class time:** Wed 19:00–22:00, Room 5607
**Language:** English (lectures, materials, assignments, exams, and presentations)

This repository holds the hands-on lab materials for the course. Each `example`
folder is self-contained and has its own `README.md`.

## Course description

This course provides an in-depth understanding of software attack and defense
techniques, together with the fundamental technologies used to detect software
vulnerabilities. Major topics include memory vulnerabilities, control-flow
hijacking, binary program analysis, and software testing. To build both
theoretical knowledge and practical skill, the course combines lectures with
hands-on assignments and research-paper reading.

### Objectives

- Understand the principles behind software vulnerabilities and the attack
  techniques that exploit them.
- Learn defense techniques for improving software security.
- Acquire binary-analysis and software-testing techniques for detecting
  vulnerabilities.
- Follow recent trends in software security and develop research capability.

### Prerequisites

- Systems Programming (required)
- C/C++ Programming (required)
- Compilers (recommended)
- Computer Architecture (recommended)

## Grading

| Component | Weight |
|-----------|-------:|
| Midterm exam | 30% |
| Final exam | 35% |
| Assignments | 25% |
| — Paper critiques | 5% |
| — Laboratory assignments | 10% |
| — Team project | 10% |
| Class participation | 10% |

## Weekly schedule

| Week | Topic |
|-----:|-------|
| 1 | Introduction: course overview |
| 2 | x86 assembly and debugging |
| 3 | Shellcoding |
| 4 | Code injection attacks |
| 5 | Code-reuse attacks |
| 6 | Memory disclosure, format-string attacks |
| 7 | Heap exploitation & hardening |
| 8 | **Midterm exam** |
| 9 | Modern defenses |
| 10 | Binary analysis |
| 11 | Obfuscation |
| 12 | Fuzz testing |
| 13 | Advanced topic #1 |
| 14 | Project presentation |
| 15 | **Final exam** |

## Lab environment

The laboratory assignments require an x86-64 computer or an x86-64 virtual
machine. Everything in this repository is built and run inside a Vagrant VM
(Ubuntu 22.04) provisioned with the 32-bit toolchain, gdb + pwndbg, nasm, and
pwntools. The host folder is shared into the VM at `/vagrant/labs`.

```sh
vagrant up          # provision the VM (installs the toolchain)
vagrant ssh         # log in
cd /vagrant/labs    # the shared lab folder
```

The VM disables ASLR (`kernel.randomize_va_space=0`) and writes core dumps to
the current directory (`core.%p`) so the exploits are reproducible.

## Examples

| Folder | Topic | What you do |
|--------|-------|-------------|
| **example1** | gdb, assembly reading, binary patching | Debug with gdb, read Intel-syntax disassembly of stripped/no-symbol binaries, and NOP-patch a branch to change control flow. Includes an x86 cheat sheet. |
| **example2** | x86 assembly hello world, binary tooling, binary patching | Write a 32-bit x86 hello world, inspect binaries with `readelf`/`objdump`/`xxd`/`python3 struct`, and patch bytes to call hidden functions. |

### Building an example

Each folder has a `Makefile`:

```sh
cd example1
make          # build the binaries
```

## Safety note

These programs are deliberately vulnerable and are for learning exploitation in
this controlled VM only. Do not deploy them or run the techniques against
systems you do not own or have permission to test.
