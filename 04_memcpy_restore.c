#include "bench.h"

#include <string.h>  // memcpy

#include "target.h"

#define PAGE_SIZE 4096

typedef struct {
    uintptr_t addr;
    uint8_t data[PAGE_SIZE];
} page_t;

page_t *pages = NULL;
size_t n_pages = 0;

void find_regions()
{
    /*
     * basic idea:
     *   install a kprobe on kernels COW handler that gets the address being overwritten
     *   fork and run the target
     *   get the kprobe hits and save a page_t with the addr and data before changes for each hit
     * then later, we can fork, run the target, then use the page_t's to restore memory all in userland
     */

    // TODO: userfaultfd and UFFDIO_REGISTER_MODE_WP?
}

void restore_regions()
{
    if (!n_pages) {
        return;
    }

    for (int i = 0; i < n_pages; i++) {
        page_t *page = &pages[i];
        printf("Restoring %lx\n", page->addr);
        memcpy((void *)page->addr, page->data, PAGE_SIZE);
    }
}

void run_one()
{
    target_main();
    restore_regions();
}

BENCH_MAIN_INIT({ find_regions(); }, { run_one(); })
