/* Ground-truth fixture: exactly one bug, InvalidRead (heap buffer over-read). */

#include <stdlib.h>
#include <stdio.h>

__attribute__((noinline)) static int read_oob(int *buf)
{
    return buf[10]; /* buf only has 4 elements */
}

int main(void)
{
    int *buf = malloc(4 * sizeof(int));
    for (int i = 0; i < 4; i++) buf[i] = i;
    int v = read_oob(buf);
    free(buf);
    printf("v=%d\n", v);
    return 0;
}
