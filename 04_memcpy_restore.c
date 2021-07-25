#include "bench.h"

#include <string.h>     // memcpy
#include <sys/ioctl.h>  // ioctl
#include <sys/mman.h>   // mmap, PROT_*, MAP_*
#include <signal.h>     // sigaction, sigemptyset
#include <sys/wait.h>   // wait

#include "target.h"
#include "pmparser.h"

#define PAGE_SIZE 4096

typedef struct {
    uintptr_t addr;
    uint8_t data[PAGE_SIZE];
} page_t;

typedef struct {
    size_t n_pages;
    page_t pages[];
} pages_t;

size_t n_maps = 0;
procmaps_struct *maps = NULL;
pages_t *pages = NULL;

void mark_write(int signal, siginfo_t *si, void *unused)
{
    page_t *page = &pages->pages[pages->n_pages];
    pages->n_pages++;
    page->addr = (uintptr_t)si->si_addr & ~(PAGE_SIZE - 1);
    memcpy(&page->data, (void *)page->addr, PAGE_SIZE);

    // XXX: should get the prot of page add PROT_WRITE
    mprotect((void *)page->addr, PAGE_SIZE, PROT_READ | PROT_WRITE);
}

void find_regions_runner_setup()
{
    // this stuff must not touch heap

    struct sigaction write_action = {
        .sa_sigaction = mark_write,
        .sa_flags = SA_SIGINFO,
    };

    sigemptyset(&write_action.sa_mask);
    sigaction(SIGSEGV, &write_action, NULL);

    for (int i = 0; i < n_maps; i++) {
        procmaps_struct *cur_map = &maps[i];
        int prot = (cur_map->is_r ? PROT_READ : 0) | (cur_map->is_w ? PROT_WRITE : 0) | (cur_map->is_x ? PROT_EXEC : 0);
        prot = prot & ~PROT_WRITE;
        mprotect((void *)cur_map->addr_start, cur_map->addr_end - cur_map->addr_start, prot);
	}
}

void find_regions()
{
    maps = mmap((void *)0x13370000, 10 * PAGE_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
    pages = mmap((void *)0x13380000, 10 * PAGE_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS|MAP_FIXED, -1, 0);

    if (!maps || !pages) {
        perror("mmap");
        exit(1);
    }

    pages->n_pages = 0;

    procmaps_iterator* maps_it = pmparser_parse(-1);

	if (maps == NULL) {
        perror("pmparser_parse");
        exit(1);
	}

	procmaps_struct* cur_map = NULL;

	while((cur_map = pmparser_next(maps_it)) != NULL){
        if (!cur_map->is_w) {
            continue;
        }

        if (cur_map->addr_start == maps || cur_map->addr_start == pages) {
            continue;
        }

        // TODO: move to a separate stack until we go to execute the program?
        if (!strncmp(cur_map->pathname, "[stack]", 7)) {
            continue;
        }

		pmparser_print(cur_map, 0);

        maps[n_maps] = *cur_map;
        n_maps++;
    }

	pmparser_free(maps_it);



    pid_t runner = fork();
    if (runner < 0) {
        perror("runner fork");
        exit(1);
    }

    if (runner == 0) {
        // child
        find_regions_runner_setup();
        target_main();
        _exit(0);
    } else {
        wait(NULL);
    }

    printf("Found %lu modified pages: ", pages->n_pages);
    for (int i = 0; i < pages->n_pages; i++) {
        printf("%lx ", pages->pages[i].addr);
    }
    printf("\n");
}

void restore_regions()
{
    if (!pages->n_pages) {
        return;
    }

    for (size_t i = 0; i < pages->n_pages; i++) {
        page_t *page = &pages->pages[i];
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
