#include <stdio.h>
#include <stdlib.h>

int target_main()
{
    void *heap = malloc(0x10);
    free(heap);
    puts("all done!");

    return 0;
}
