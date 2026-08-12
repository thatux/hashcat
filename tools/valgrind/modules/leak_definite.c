/* Ground-truth fixture: exactly one bug, DefinitelyLost (allocated, pointer dropped, never freed). */

#include <stdlib.h>
#include <stdio.h>

__attribute__((noinline)) static void leaky(void)
{
    int *p = malloc(4 * sizeof(int));
    p[0] = 1; /* pointer goes out of scope here, never freed */
}

int main(void)
{
    leaky();
    printf("done\n");
    return 0;
}
