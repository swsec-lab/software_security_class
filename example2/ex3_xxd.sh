#!/usr/bin/env bash
# ex3 (Binary Tooling): xxd — view bytes and patch them back
#
# xxd shows raw bytes as hex+ASCII without parsing the file format.
# xxd -r turns a hex dump back into bytes, which is how you 'patch'.
# Demo: change hello's output length mov edx,14 to 5 so it prints only "Hello".
#
# usage:  make hello && bash ex3_xxd.sh
set -e
BIN=hello
[ -f "$BIN" ] || { echo "build $BIN first with 'make hello'"; exit 1; }

echo "########## xxd : offset + hex + ASCII ##########"
echo "\$ xxd $BIN | head"
xxd "$BIN" | head

echo
echo "########## xxd -s <offset> -l <len> : the string region in .data ##########"
# Get .data's 'file offset' with objdump -h (the File off, not the VMA)
DATA_OFF=$(objdump -h "$BIN" | awk '$2==".data"{print "0x"$6; exit}')
if [ -n "$DATA_OFF" ]; then
    echo "\$ xxd -s $DATA_OFF -l 16 $BIN   # see 'Hello, world!' in the ASCII column"
    xxd -s "$DATA_OFF" -l 16 "$BIN"
fi

echo
echo "########## in-place patch with xxd -r : mov edx,14 -> mov edx,5 ##########"
# 1) find the virtual address of the length instruction 'ba 0e 00 00 00' with objdump
VADDR=$(objdump -d -M intel "$BIN" | grep -iE 'ba 0e 00 00 00' | head -1 \
        | awk -F: '{gsub(/ /,"",$1); print $1}')
# 2) compute the file offset from .text's VMA/File-off (operand 0e is instruction start +1)
read TVMA TOFF < <(objdump -h "$BIN" | awk '$2==".text"{print "0x"$4, "0x"$6; exit}')
FOFF=$(( (0x$VADDR + 1) - TVMA + TOFF ))
printf "instr vaddr=0x%s, .text VMA=0x%x Off=0x%x  => file offset of the 0e byte=0x%x\n" \
       "$VADDR" "$TVMA" "$TOFF" "$FOFF"

# 3) keep the original, patch a copy (do not chmod on vboxsf - it breaks the exec bit)
cp "$BIN" hello_xxd
printf '%08x: 05\n' "$FOFF" | xxd -r - hello_xxd
echo -n "that byte after patching: "; xxd -s "$FOFF" -l 1 hello_xxd

echo
echo "original run: $(./"$BIN")"
echo "patched run:  $(./hello_xxd)"
echo
echo "[summary] view bytes with xxd, then feed one 'offset: bytes' line back through xxd -r to patch."
