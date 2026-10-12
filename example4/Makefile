CC = gcc

# Shared base for every target: 32-bit, no optimization, fixed addresses,
# no CET, and a simple stack layout so offsets stay predictable. Matches the
# lecture slides and example3.
COMMON = -m32 -O0 -mpreferred-stack-boundary=2 -fno-pic -no-pie -fcf-protection=none

# printf(user_input) is the whole point here, so silence the format warnings
# (otherwise distro hardening may turn -Wformat-security into an error).
FMT = $(COMMON) -fno-stack-protector -Wno-format-security

# --- Part A: memory disclosure (lecture 6-1) ----------------------------
#   uninit        : uninitialized-read bug (leaks the freed secret)
#   uninit_fixed  : same source + -DFIX -> the slide-10 memset patch
#   heartbleed    : Heartbleed-style memory overread
A_FLAGS = $(COMMON) -fno-stack-protector

# --- Part B: format string (lecture 6-2) --------------------------------
#   fmt_leak   : read memory via %p (built WITH a canary, so you can leak it)
#   fmt_write  : arbitrary write via %n to unlock win()
#   fmt_got    : control-flow hijack by overwriting puts@GOT (needs writable GOT)

BINS = uninit uninit_fixed heartbleed fmt_leak fmt_write fmt_got

all: $(BINS)

uninit: uninit.c
	$(CC) $(A_FLAGS) -o $@ $<

uninit_fixed: uninit.c
	$(CC) $(A_FLAGS) -DFIX -o $@ $<

heartbleed: heartbleed.c
	$(CC) $(A_FLAGS) -o $@ $<

# Built WITH the canary on purpose: the leak also exposes the canary value.
fmt_leak: fmt_leak.c
	$(CC) $(COMMON) -fstack-protector-all -Wno-format-security -o $@ $<

fmt_write: fmt_write.c
	$(CC) $(FMT) -o $@ $<

# Partial RELRO (norelro) keeps the GOT writable for the hijack.
fmt_got: fmt_got.c
	$(CC) $(FMT) -Wl,-z,norelro -o $@ $<

# Expected checksec:
#   uninit / uninit_fixed / heartbleed -> No canary   / NX enabled  / No PIE
#   fmt_leak                           -> Canary found / NX enabled  / No PIE
#   fmt_write                          -> No canary    / NX enabled  / No PIE
#   fmt_got                            -> No canary    / NX enabled  / No PIE / No RELRO
check: $(BINS)
	@for b in $(BINS); do echo "== $$b =="; pwn checksec ./$$b; done

clean:
	rm -f $(BINS) core core.*

.PHONY: all check clean
