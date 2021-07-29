#include "bench.h"

#include <string.h>  // memcpy
#include <linux/userfaultfd.h>
#include <sys/ioctl.h>  // ioctl

#include "target.h"
#include "pmparser.h"

#define __NR_userfaultfd 323  // this is wrong in asm-generic??
#define PAGE_SIZE 4096

typedef struct {
    uintptr_t addr;
    uint8_t data[PAGE_SIZE];
} page_t;

page_t *pages = NULL;
size_t n_pages = 0;

void find_regions()
{
    int uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);

    if (uffd < 0) {
        perror("userfaultfd");
        exit(1);
    }

    struct uffdio_api uffdio_api;
    uffdio_api.api = UFFD_API;
    uffdio_api.features = 0;

    if (ioctl(uffd, UFFDIO_API, &uffdio_api)) {
        fprintf(stderr, "UFFDIO_API\n");
        exit(1);
    }

    if (uffdio_api.api != UFFD_API) {
        fprintf(stderr, "UFFDIO_API error %Lu\n", uffdio_api.api);
        exit(1);
    }

    procmaps_iterator* maps = pmparser_parse(-1);

	if (maps == NULL) {
        perror("pmparser_parse");
        exit(1);
	}

	procmaps_struct* cur_map = NULL;

	while((cur_map = pmparser_next(maps)) != NULL){
        if (!cur_map->is_w) {
            continue;
        }

        // DEBUG
		pmparser_print(cur_map, 0);

        struct uffdio_register uffdio_register;
        uffdio_register.range.start = (unsigned long)cur_map->addr_start;
        uffdio_register.range.len = (unsigned long)cur_map->addr_end - (unsigned long)cur_map->addr_start;
        uffdio_register.mode = UFFDIO_REGISTER_MODE_WP;

        if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1) {
            perror("ioctl(UFFDIO_REGISTER)");
            exit(1);
        }

		printf("\n~~~~~~~~~~~~~~~~~~~~~~~~~\n");
	}

	pmparser_free(maps);
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
