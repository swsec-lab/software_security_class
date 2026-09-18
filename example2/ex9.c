/* ex9: call the hidden function using an input file.
 *
 * main() reads a file into the global buffer `buf` (in .data) and then
 * executes it as code. Default .data is not executable, so this crashes.
 *
 * Two things are required:
 *   1) ELF program (segment) header: make the data PT_LOAD segment
 *      executable (RW -> RWX).
 *   2) Build input.txt containing machine code that calls hidden9() and
 *      returns, then run:  ./ex9 input.txt
 *
 * hint: rel32 = addr(hidden9) - (addr(buf) + 5); bytes = e8 <rel32> c3
 */
#include <stdio.h>

unsigned char buf[256] = { 0xc3 };  /* forced into .data */

void hidden9(void)
{
    printf("hidden function #9 called!\n");
}

int main(int argc, char *argv[])
{
    FILE *fp;
    size_t n;

    if (argc < 2) {
        printf("usage: %s <input>\n", argv[0]);
        return 1;
    }

    fp = fopen(argv[1], "rb");
    if (!fp) {
        perror("fopen");
        return 1;
    }
    n = fread(buf, 1, sizeof(buf), fp);
    fclose(fp);
    printf("read %zu bytes, executing...\n", n);

    ((void (*)(void))buf)();
    return 0;
}
