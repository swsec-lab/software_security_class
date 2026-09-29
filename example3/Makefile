CC     = gcc
# Same options as the lecture slide "Replicating Historic Exploitation":
#   -m32                          : 32-bit
#   -mpreferred-stack-boundary=2  : no extra stack alignment -> simple offsets
#   -O0                           : no optimization
#   -fno-stack-protector          : no stack canary
#   -fno-pic -no-pie              : fixed load addresses
#   -z execstack                  : executable stack (so injected shellcode runs)
#   -fcf-protection=none          : no Intel CET (endbr)
CFLAGS = -m32 -mpreferred-stack-boundary=2 -O0 -fno-stack-protector \
         -fno-pic -no-pie -z execstack -fcf-protection=none

BINS = vuln1 vuln2 vuln3 morris

all: $(BINS)

$(BINS): %: %.c
	$(CC) $(CFLAGS) -o $@ $<

# Check protections (expect: No canary / NX disabled / No PIE)
check: $(BINS)
	pwn checksec ./vuln1
	pwn checksec ./vuln2
	pwn checksec ./vuln3
	pwn checksec ./morris

clean:
	rm -f $(BINS) core core.*

.PHONY: all check clean
