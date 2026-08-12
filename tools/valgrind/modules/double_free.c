/* Ground-truth fixture: exactly one bug, InvalidFree (double free). */

#include <stdlib.h>
#include <stdio.h>

__attribute__((noinline)) static void buggy_free(int *p)
{
    free(p);
    free(p); /* double free */
}

int main(void)
{
    int *p = malloc(sizeof(int));
    *p = 42;
    buggy_free(p);
    printf("done\n");
    return 0;
}
