/* Ground-truth fixture: exactly one bug, UseAfterFree (read through a freed pointer). */

#include <stdlib.h>
#include <stdio.h>

__attribute__((noinline)) static int read_after_free(int *p)
{
    free(p);
    return *p; /* use after free */
}

int main(void)
{
    int *p = malloc(sizeof(int));
    *p = 7;
    int v = read_after_free(p);
    printf("v=%d\n", v);
    return 0;
}
