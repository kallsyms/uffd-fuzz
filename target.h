#include <stdio.h>
#include <stdlib.h>

int target_main(int argc, char **argv)
{
    void *heap = malloc(0x10);
    printf("heap alloc at %p\n", heap);
    puts("all done!");

    return 0;
}
