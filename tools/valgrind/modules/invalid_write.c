/* Ground-truth fixture: exactly one bug, InvalidWrite (heap buffer overflow write). */

#include <stdlib.h>

__attribute__((noinline)) static void write_oob(int *buf)
{
    buf[10] = 99; /* buf only has 4 elements */
}

int main(void)
{
    int *buf = malloc(4 * sizeof(int));
    write_oob(buf);
    volatile int sink = buf[0]; /* keep the write from being optimised away, without printf's own libc-internal noise */
    (void) sink;
    free(buf);
    return 0;
}
