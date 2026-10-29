CC = gcc

# Shared base: no optimization, fixed addresses (no PIE), no CET, no canary.
# NX stays ON (we do NOT pass -z execstack) -- the whole point of code reuse is
# that the stack is non-executable, so we reuse existing code instead.
# Everything here is x86 32-bit to match the course toolchain and example3/4.
COMMON = -m32 -mpreferred-stack-boundary=2 -O0 -fno-stack-protector \
         -fno-pic -no-pie -fcf-protection=none

# --- Part 0: return into the binary's own code (lecture 8-1, slide 6) ---
#   ret2func    : return into foo(), a function already in THIS binary
# --- Part A: return-to-libc (lecture 7-1 / 8-1) --------------------------
#   ret2libc    : single system("/bin/sh") call
#   chain       : setuid(0) then system("/bin/sh") via a pop;ret (ESP lifting)
# --- Part B: ROP and ASLR (lecture 7-2) ---------------------------------
#   ropwrite    : write-what-where ROP chain -> win()
#   ret2syscall : pure-ROP execve via int 0x80 (register-loading ROP, 32-bit)
#   leak32      : ret2libc with ASLR ON, using a leaked libc pointer

BINS = ret2func ret2libc chain ropwrite ret2syscall leak32

all: $(BINS)

ret2func ret2libc chain ropwrite ret2syscall: %: %.c
	$(CC) $(COMMON) -o $@ $<

# dlsym lives in libc on glibc 2.34+, but -ldl is harmless on older ones.
leak32: leak32.c
	$(CC) $(COMMON) -o $@ $< -ldl

# Expected checksec (all): No canary / NX enabled / No PIE.
check: $(BINS)
	@for b in $(BINS); do echo "== $$b =="; pwn checksec ./$$b; done

# Problems 1-4 need ASLR off; Problem 5 needs it on.
aslr-off:
	echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
aslr-on:
	echo 2 | sudo tee /proc/sys/kernel/randomize_va_space

clean:
	rm -f $(BINS) core core.*

.PHONY: all check clean aslr-off aslr-on
