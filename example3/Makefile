CC = gcc

# Shared base for every target: 32-bit, no optimization, fixed addresses,
# no CET, and a simple stack layout so offsets stay predictable.
COMMON = -m32 -O0 -mpreferred-stack-boundary=2 -fno-pic -no-pie -fcf-protection=none

# --- Part A: code injection (lecture 4) ---------------------------------
# No canary + executable stack + NX off, so classic code injection works.
INJECT = $(COMMON) -fno-stack-protector -z execstack

INJECT_BINS = vuln1 vuln2 vuln3 morris

# --- Part B: defenses on the SAME server (lecture 5) --------------------
# canary_server.c is built three ways to toggle the canary and NX:
#   canary_server_nc : no canary,  executable stack  -> Problem 5 (baseline)
#   canary_server_x  : canary on,  executable stack  -> Problem 6 (canary + code injection)
#   canary_server    : canary on,  NX on             -> Problem 7 (canary + NX -> code reuse)
# canary_demo (see the canary) and nx_demo (NX without a canary) round it out.

BINS = $(INJECT_BINS) canary_demo canary_server_nc canary_server_x canary_server nx_demo

all: $(BINS)

$(INJECT_BINS): %: %.c
	$(CC) $(INJECT) -o $@ $<

# See the canary: canary on, NX on.
canary_demo: canary_demo.c
	$(CC) $(COMMON) -fstack-protector-all -o $@ $<

# Three builds of the forking server, all from canary_server.c:
canary_server_nc: canary_server.c
	$(CC) $(COMMON) -fno-stack-protector -z execstack -o $@ $<

canary_server_x: canary_server.c
	$(CC) $(COMMON) -fstack-protector-all -z execstack -o $@ $<

canary_server: canary_server.c
	$(CC) $(COMMON) -fstack-protector-all -o $@ $<

# NX without a canary (the minimal code-reuse-under-NX lesson).
nx_demo: nx_demo.c
	$(CC) $(COMMON) -fno-stack-protector -o $@ $<

# Expected checksec:
#   vuln1/vuln2/vuln3/morris -> No canary / NX disabled / No PIE
#   canary_demo              -> Canary found / NX enabled
#   canary_server_nc         -> No canary   / NX disabled (execstack)
#   canary_server_x          -> Canary found / NX disabled (execstack)
#   canary_server            -> Canary found / NX enabled
#   nx_demo                  -> No canary   / NX enabled
check: $(BINS)
	@for b in $(BINS); do echo "== $$b =="; pwn checksec ./$$b; done

clean:
	rm -f $(BINS) core core.*

.PHONY: all check clean
