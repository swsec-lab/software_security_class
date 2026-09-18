CC     = gcc
# -no-pie: fixed load addresses so patch targets are predictable
# symbols are kept (not stripped) so hidden functions are easy to locate with nm
CFLAGS = -m32 -O0 -fno-stack-protector -no-pie -g

# This folder holds three exercises (see README.md):
#   1) assembly hello   : hello.s (write it, then inspect with readelf/xxd/objdump)
#   2) binary tooling   : ex1~ex4 (readelf/objdump/xxd/python-struct on ./hello)
#   3) binary patching  : ex5~ex9 (patch bytes to call hidden functions)
BINS = ex5 ex6 ex7 ex8 ex9

all: $(BINS) hello

# ---- 3) patching exercises (C -> 32-bit executable) ----
ex%: ex%.c
	$(CC) $(CFLAGS) -o $@ $<

# ---- 1) hello world (GAS .intel_syntax -> ELF32) ----
# hello.s is GAS .intel_syntax; gcc assembles + links (no libc, fixed addrs)
hello: hello.s
	$(CC) -m32 -nostdlib -no-pie hello.s -o hello

run: hello
	./hello

# ---- 2) binary tooling demos (ex1~ex4) : run each tool on ./hello ----
# readelf(ex1) / objdump(ex2) / xxd(ex3) / python-struct(ex4)
tooling: hello hello.bin
	bash ex1_readelf.sh
	bash ex2_objdump.sh
	bash ex3_xxd.sh
	python3 ex4_struct.py

# Inspect the hello binary with readelf/objdump/xxd (see README.md)
inspect: hello
	@echo "=================== readelf header (-h) ==================="
	readelf -h hello
	@echo
	@echo "=================== objdump header (-f) ==================="
	objdump -f hello
	@echo
	@echo "=================== objdump disassembly (-d -M intel) ====="
	objdump -d -M intel hello
	@echo
	@echo "=================== xxd (hello executable) ================"
	xxd hello | head -20

# Extract only the .text machine code to inspect the raw code bytes
hello.bin: hello
	objcopy -O binary --only-section=.text hello hello.bin
	@echo "--- xxd hello.bin (raw .text bytes) ---"
	xxd hello.bin

clean:
	rm -f $(BINS) input.txt hello hello.bin hello_xxd hello_struct

.PHONY: all run tooling inspect clean
