CC      = gcc
CFLAGS  = -m32 -O0 -fno-stack-protector -no-pie

# Three tiers, see README.md:
#   A. gdb basics   (-g, symbols)         : learn gdb commands + variable watching
#   B. asm analysis (no -g, NOT stripped) : read the disassembly directly
#   C. final crackme (no -g + stripped)   : solve with no symbols at all
DEBUG_BINS    = 01_add 02_sub 03_if 04_while
ASM_BINS      = 05_for 07_sum 08_array 09_crash 10_loop 11_patch
STRIPPED_BINS = 06_func

all: $(DEBUG_BINS) $(ASM_BINS) $(STRIPPED_BINS)

# A: full debug info so "print var" / "watch var" work
$(DEBUG_BINS): %: %.c
	$(CC) $(CFLAGS) -g -o $@ $<

# B: no -g means no source lines / variable names, so you must read the
#    assembly. Function symbols (main, ...) are kept (no strip) so you can
#    still locate code. -fno-asynchronous-unwind-tables keeps objdump clean.
$(ASM_BINS): %: %.c
	$(CC) $(CFLAGS) -fno-asynchronous-unwind-tables -o $@ $<

# C: no -g AND stripped: even function names are gone
$(STRIPPED_BINS): %: %.c
	$(CC) $(CFLAGS) -o $@ $<
	strip $@

clean:
	rm -f $(DEBUG_BINS) $(ASM_BINS) $(STRIPPED_BINS)

.PHONY: all clean
