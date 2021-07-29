#include <sys/mman.h>   // mmap, PROT_*, MAP_*
#include <asm/unistd.h> // __NR_*
#include <stdint.h>
#include <linux/userfaultfd.h>
#include <sys/ioctl.h>  // ioctl

#include "pmparser.h"

#define PAGE_SIZE 4096

void *tmpStack;
uintptr_t oldStack;

size_t n_maps = 0;
procmaps_struct *maps = NULL;

__attribute__((section(".remap"))) void *remap_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
    register int r10 __asm__("r10") = flags;
    register int r8 __asm__("r8") = fd;
    register off_t r9 __asm__("r9") = offset;
    
    void *ret;
    asm volatile
    (
         "syscall"
         : "=a" (ret)
         : "0" (__NR_mmap), "D"(addr), "S"(length), "d"(prot), "r"(r10), "r"(r8), "r"(r9)
         : "memory", "cc", "r11", "cx"
    );
    return ret;
}

__attribute__((section(".remap"))) int remap_mprotect(void *addr, size_t length, int prot)
{
    int ret;
    asm volatile
    (
         "syscall"
         : "=a" (ret)
         : "0" (__NR_mprotect), "D"(addr), "S"(length), "d"(prot)
         : "memory"
    );
    return ret;
}

__attribute__((section(".remap"))) int remap_munmap(void *addr, size_t length)
{
    int ret;
    asm volatile
    (
         "syscall"
         : "=a" (ret)
         : "0" (__NR_munmap), "D"(addr), "S"(length)
         : "memory"
    );
    return ret;
}

__attribute__((noinline, section(".remap"))) void remap()
{
    register size_t r_n_maps = n_maps;
    register procmaps_struct *r_maps = maps;

    for (off_t i = 0; i < r_n_maps; i++) {
        procmaps_struct *cur_map = &r_maps[i];
        int prot = (cur_map->is_r ? PROT_READ : 0) | (cur_map->is_w ? PROT_WRITE : 0) | (cur_map->is_x ? PROT_EXEC : 0);

        // copy from region to tmp
        uint8_t *tmp = remap_mmap((void *)0xdead0000, cur_map->length, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
        for (off_t j = 0; j < cur_map->length; j++) {
            tmp[j] = *((uint8_t *)(cur_map->addr_start) + j);
        }

        // unmap original
        remap_munmap(cur_map->addr_start, cur_map->length);

        // recreate RW in orignal's place
        uint8_t *new = remap_mmap(cur_map->addr_start, cur_map->addr_end - cur_map->addr_start, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);

        // copy back from tmp
        for (off_t j = 0; j < cur_map->length; j++) {
            new[j] = tmp[j];
        }

        // re-set permissions
        remap_mprotect(cur_map->addr_start, cur_map->addr_end - cur_map->addr_start, prot);
	}

    return;
}

void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
    puts("Intercepted call to mmap");
    return remap_mmap(addr, length, prot, flags, fd, offset);
}

int load_maps()
{
    procmaps_iterator* maps_it = pmparser_parse(-1);

	if (maps == NULL) {
        perror("pmparser_parse");
        return -1;
	}

	procmaps_struct* cur_map = NULL;

	while ((cur_map = pmparser_next(maps_it)) != NULL) {
        if (cur_map->addr_start == (void *)0x13370000 || cur_map->addr_start == tmpStack || cur_map->addr_start == maps) {
            continue;
        }

        if (!(cur_map->is_r || cur_map->is_w || cur_map->is_x)) {
            continue;
        }

        if (!strcmp(cur_map->pathname, "[vsyscall]") || !strcmp(cur_map->pathname, "[vvar]") || !strcmp(cur_map->pathname, "[vdso]")) {
            continue;
        }

		pmparser_print(cur_map, 0);

        maps[n_maps] = *cur_map;
        n_maps++;
    }

	pmparser_free(maps_it);

    return 0;
}

void remap_stack_swap()
{
    asm(
        "movq tmpStack, %%rax; addq $0x5000, %%rax; movq %%rsp, oldStack; movq %%rax, %%rsp"
        : // no out
        : // no in
        : "rax");

    remap();

    asm("movq oldStack, %rsp");
}


int main()
{
    tmpStack = mmap((void *)0x13380000, 10 * PAGE_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
    maps = mmap((void *)0x13390000, 10 * PAGE_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
    if (load_maps()) {
        return 1;
    }

    remap_stack_swap();

    puts("Hello from the anonymous side");

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
        return 1;
    }

    printf("Features: 0x%llx\n", uffdio_api.features);

    if (uffdio_api.api != UFFD_API) {
        fprintf(stderr, "UFFDIO_API error %Lu\n", uffdio_api.api);
        return 1;
    }

    for (off_t i = 0; i < n_maps; i++) {
        procmaps_struct *cur_map = &maps[i];

        struct uffdio_register uffdio_register;
        uffdio_register.range.start = (unsigned long)cur_map->addr_start;
        uffdio_register.range.len = (unsigned long)cur_map->addr_end - (unsigned long)cur_map->addr_start;
        uffdio_register.mode = UFFDIO_REGISTER_MODE_WP;

        if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1) {
            perror("ioctl(UFFDIO_REGISTER)");
            exit(1);
        }
    }

    return 0;
}
