#!/usr/bin/env python3
# ex4 (Binary Tooling): python3 struct — build the exact bytes to patch
#
# struct.pack turns numbers into raw bytes; struct.unpack does the reverse.
# Format string = byte order + size codes:
#   <  little-endian (x86/x86-64),  >  big-endian,  =  native
#   B=1 byte, H=2, I=4, Q=8
# Demo: change hello's output length mov edx,14 to 5 so it prints only "Hello".
#
# usage:  make hello && python3 ex4_struct.py
import struct, os, shutil, subprocess, sys

BIN = "hello"
if not os.path.exists(BIN):
    sys.exit("build hello first with 'make hello'")

print("########## struct.pack / unpack basics ##########")
print(r">>> struct.pack('<I', 0x401136)  ->", struct.pack('<I', 0x401136))
print(r">>> struct.pack('BB', 0x90, 0x90) ->", struct.pack('BB', 0x90, 0x90))
data = struct.pack('<I', 14)
print(r">>> struct.unpack('<I', pack('<I',14))[0] ->", struct.unpack('<I', data)[0])

print()
print("########## seek to a specific offset, then write to patch ##########")
# Find the length instruction 'mov edx, 14' = BA 0E 00 00 00 in the file
blob = open(BIN, "rb").read()
pat = struct.pack('<B', 0xBA) + struct.pack('<I', 14)   # ba 0e 00 00 00
off = blob.find(pat)
if off < 0:
    sys.exit("could not find the length instruction pattern (ba 0e 00 00 00)")
edx_operand = off + 1          # position of the 4-byte operand where 0e starts
print(f"'ba 0e 00 00 00' file offset=0x{off:x}, length operand offset=0x{edx_operand:x}")

# Keep the original, patch a copy (do not chmod on the vboxsf shared folder - it
# breaks the exec bit. copyfile keeps the source data; just run the copy.)
shutil.copyfile(BIN, "hello_struct")
with open("hello_struct", "rb+") as f:      # rb+ : read/write, keeps the file size
    f.seek(edx_operand)
    f.write(struct.pack('<I', 5))           # 14 -> 5 ("Hello")
print(">>> f.seek(0x%x); f.write(struct.pack('<I', 5))" % edx_operand)

print()
print("original run:", subprocess.run(["./" + BIN], capture_output=True, text=True).stdout.strip())
print("patched run: ", subprocess.run(["./hello_struct"], capture_output=True, text=True).stdout.strip())
print()
print("[summary] build the exact bytes with struct.pack, then place them at an offset with seek+write.")
