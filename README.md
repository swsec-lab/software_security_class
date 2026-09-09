# Lab 1 — Binary Exploitation

**Course:** Emerging Topics in Information Security
**Instructor:** Hyungseok Kim

A hands-on lab that goes from reading assembly to writing working exploits and
then defeating exploit mitigations, all on 32-bit x86 Linux. Each `example`
folder is self-contained and has its own `README.md`.

## Environment

Everything is built and run inside a Vagrant VM (Ubuntu 22.04) provisioned with
the 32-bit toolchain, gdb + pwndbg, nasm, and pwntools. The host folder is
shared into the VM at `/vagrant/labs`.

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

## Building an example

Each folder has a `Makefile`:

```sh
cd example1
make          # build the binaries
```

## Safety note

These programs are deliberately vulnerable and are for learning exploitation in
this controlled VM only. Do not deploy them or run the techniques against
systems you do not own or have permission to test.
