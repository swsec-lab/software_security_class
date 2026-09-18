#!/usr/bin/env bash
# ex2 (Binary Tooling): GNU objdump — turn bytes back into instructions
#
# Where readelf shows the 'structure', objdump disassembles a section's bytes
# into 'instructions'. At the end it also shows how to force a header-less raw
# binary to be interpreted as i386 code.
#
# usage:  make hello hello.bin && bash ex2_objdump.sh
set -e
BIN=${1:-hello}
[ -f "$BIN" ] || { echo "build $BIN first with 'make hello'"; exit 1; }

echo "########## objdump -f : file header (architecture, entry address) ##########"
objdump -f "$BIN"

echo
echo "########## objdump -d -M intel : disassemble .text (Intel syntax) ##########"
echo "# The byte column on the left is exactly the bytes you saw with xxd."
objdump -d -M intel "$BIN"

echo
echo "########## objdump -s -j .data : raw byte dump of the .data section ##########"
echo "# You can spot the 'Hello, world!' string in the ASCII column."
objdump -s -j .data "$BIN"

echo
echo "########## objdump -D -b binary -m i386 -M intel : raw binary ##########"
echo "# Force-interpret pure bytes with no ELF header (hello.bin = extracted .text only)."
if [ -f hello.bin ]; then
    objdump -D -b binary -m i386 -M intel hello.bin
    echo
    echo "# To pretend it loads somewhere and fix up the addresses, use --adjust-vma:"
    echo "\$ objdump -D -b binary -m i386 --adjust-vma=0x8049000 -M intel hello.bin"
else
    echo "(hello.bin is missing. Extract .text with 'make hello.bin'.)"
fi

echo
echo "[summary] xxd shows the bytes as-is; objdump shows those same bytes as instructions."
echo "          -d code / -s -j <sec> section dump / -D -b binary -m i386 raw disassembly"
