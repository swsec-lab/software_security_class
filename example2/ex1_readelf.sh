#!/usr/bin/env bash
# ex1 (Binary Tooling): GNU readelf — look inside the ELF structure
#
# readelf parses an ELF file's structure (headers/segments/sections/symbols/
# relocations) and prints it in human-readable form. The target is the
# gcc-built hello binary in this folder.
#
# usage:  make hello && bash ex1_readelf.sh
set -e
BIN=${1:-hello}
[ -f "$BIN" ] || { echo "build $BIN first with 'make hello'"; exit 1; }

echo "########## readelf -h : ELF header (magic, class, entry point) ##########"
readelf -h "$BIN"

echo
echo "########## readelf -l : program headers = segments (load addr/perms) ##########"
echo "# PT_LOAD segments are what actually get mapped into memory. In Flg, E=exec, R=read, W=write"
readelf -l "$BIN"

echo
echo "########## readelf -S : section headers (.text/.data Addr/Off/Size) ##########"
echo "# Addr=load virtual address, Off=file offset -> use both to convert vaddr<->offset"
readelf -S "$BIN"

echo
echo "########## readelf -s : symbol table (addresses of _start, msg, ...) ##########"
readelf -s "$BIN" | grep -E "Symbol|_start|msg" || readelf -s "$BIN"

echo
echo "########## readelf -r : relocation info (a statically linked hello usually has none) ##########"
readelf -r "$BIN" || true

echo
echo "[summary] readelf shows the 'ELF structure' only; it does not interpret code."
echo "          -h header / -l segments / -S sections / -s symbols / -r relocations"
