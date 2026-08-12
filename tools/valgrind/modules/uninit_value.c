/* Ground-truth fixture: exactly one bug, ConditionalJumpUninitialised
 * (branch on a read of uninitialised heap memory). */

#include <stdlib.h>
#include <stdio.h>

__attribute__((noinline)) static int uses_uninit(int *p)
{
    if (*p == 42) /* conditional jump depends on uninitialised value */
        return 1;
    return 0;
}

int main(void)
{
    int *p = malloc(sizeof(int)); /* deliberately never initialised */
    int v = uses_uninit(p);
    free(p);
    printf("v=%d\n", v);
    return 0;
}
