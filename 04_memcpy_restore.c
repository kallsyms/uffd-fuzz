#include "bench.h"

#include <sys/mman.h>   // mmap, PROT_*, MAP_*
#include <asm/unistd.h> // __NR_*
#include <stdint.h>
#include <linux/userfaultfd.h>
#include <sys/ioctl.h>  // ioctl
#include <pthread.h>
#include <poll.h>

#include "pmparser.h"

#ifndef UFFDIO_WRITEPROTECT_MODE_WP
#include "uffdio_wp.h"
#endif

#include "target.h"

#define PAGE_SIZE 4096


// stack for the uffd handler thread.
__attribute__((section(".writeignored"))) uint8_t uffd_handler_stack[0x10000];
// stack used by run() before switching to old_stack to run the target code
__attribute__((section(".writeignored"))) uint8_t main_stack[0x10000];

// old stack to pivot back after everything is remapped
__attribute__((section(".writeignored"))) uintptr_t old_stack;

// These have to be all inline asm because syscall() and anything else will hit libc
#if defined(__x86_64__)
#include "syscalls_x86_64.h"
// TODO: lift "nice" C implementations here
//#define save_old_stack() asm(                                                                  \
        "leaq main_stack, %%rax; addq $0xf000, %%rax; movq %%rsp, old_stack; movq %%rax, %%rsp" \
        ::: "rax")
#define save_old_stack() do { register long sp __asm__ ("rsp"); old_stack = sp; sp = &main_stack[0xf000]; } while (0)
//#define restore_old_stack() asm("movq old_stack, %rsp")
#define restore_old_stack() do { register long sp __asm__("rsp") = old_stack; } while (0)
//#define swap_old_stack() asm("xchgq old_stack, %%rsp" ::: "memory")
#define swap_old_stack() do { register long sp __asm__("rsp"); register long tmp = old_stack; old_stack = sp; sp = tmp; } while (0)
//#define switch_uffd_handler_stack() asm("leaq uffd_handler_stack, %rsp; addq $0xf000, %rsp")
#define switch_uffd_handler_stack() do { register long sp __asm__("rsp") = &uffd_handler_stack[0xf000]; } while (0)

#elif defined(__aarch64__)
#include "syscalls_aarch64.h"
// commented things _may_ work
//#define save_old_stack() asm("ldr x0, =main_stack; add x0, x0, #0xf000; ldr x1, =old_stack; mov x2, sp; str x2, [x1]; mov sp, x0" ::: "x0", "x1", "x2")
#define save_old_stack() do { register long sp __asm__ ("sp"); old_stack = sp; sp = &main_stack[0xf000]; } while (0)
//#define restore_old_stack() asm("ldr x0, =old_stack; ldr x0, [x0]; mov sp, x0" ::: "x0")
#define restore_old_stack() do { register long sp __asm__("sp") = old_stack; } while (0)
//#define swap_old_stack() asm("ldr x0, =old_stack; ldr x1, [x0]; mov x2, sp; str x2, [x0]; mov sp, x1" ::: "x0", "x1", "x2", "memory")
#define swap_old_stack() do { register long sp __asm__("sp"); register long tmp = old_stack; old_stack = sp; sp = tmp; } while (0)
//#define switch_uffd_handler_stack() asm("ldr x0, =uffd_handler_stack; add x0, x0, #0xf000; mov sp, x0" ::: "x0")
#define switch_uffd_handler_stack() do { register long sp __asm__("sp") = &uffd_handler_stack[0xf000]; } while (0)

#else
#error Unimplemented arch
#endif

__attribute__((section(".remap"))) void *remap_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
    return (void *)my_syscall6(__NR_mmap, addr, length, prot, flags, fd, offset);
}

__attribute__((section(".remap"))) int remap_mprotect(void *addr, size_t length, int prot)
{
    return (int)my_syscall3(__NR_mprotect, addr, length, prot);
}

__attribute__((section(".remap"))) int remap_munmap(void *addr, size_t length)
{
    return (int)my_syscall2(__NR_mprotect, addr, length);
}


// marked writeignored so that they don't get pulled out from underneath us in remap()
__attribute__((section(".writeignored"))) size_t n_maps = 0;
__attribute__((section(".writeignored"))) procmaps_struct maps[0x100];

typedef struct {
    uintptr_t addr;
    uint8_t data[PAGE_SIZE];
} page_t;

__attribute__((section(".writeignored"))) size_t n_pages = 0;
__attribute__((section(".writeignored"))) page_t pages[50];

// stuff so the main thread can wait until UFFD write protecting is done
__attribute__((section(".writeignored"))) pthread_cond_t uffd_ready = PTHREAD_COND_INITIALIZER;
__attribute__((section(".writeignored"))) pthread_mutex_t uffd_ready_lock = PTHREAD_MUTEX_INITIALIZER;

__attribute__((noinline, section(".remap"))) void remap()
{
    for (off_t i = 0; i < n_maps; i++) {
        procmaps_struct *cur_map = &maps[i];
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

        // clean up tmp
        remap_munmap((void *)0xdead0000, cur_map->length);

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

    if (maps_it == NULL) {
        perror("pmparser_parse");
        return -1;
    }

    procmaps_struct* cur_map = NULL;

    while ((cur_map = pmparser_next(maps_it)) != NULL) {
        // ignore .remap and .writeignored
        if (cur_map->addr_start == (void *)0x13370000 || cur_map->addr_start == (void *)0x13380000) {
            continue;
        }

        // ignore --- regions (libc has a couple?)
        if (!(cur_map->is_r || cur_map->is_w || cur_map->is_x)) {
            printf("Skipping --- region at %p-%p\n", cur_map->addr_start, cur_map->addr_end);
            continue;
        }

        if (!strcmp(cur_map->pathname, "[vsyscall]") || !strcmp(cur_map->pathname, "[vvar]") || !strcmp(cur_map->pathname, "[vdso]")) {
            printf("Skipping %s region\n", cur_map->pathname);
            continue;
        }

        // only monitor the program BSS
        if (cur_map->addr_start == (void *)0x500000) {
            printf("Skipping .got.plt at %p-%p\n", cur_map->addr_start, cur_map->addr_end);
            continue;
        }

#ifdef DEBUG
        pmparser_print(cur_map, 0);
#endif

        // TODO: need some way to pre-fill the PLT for anything uffd_monitor_thread uses
        // XXX: right now just building statically

        maps[n_maps] = *cur_map;
        n_maps++;
    }

    pmparser_free(maps_it);

    return 0;
}

__attribute__((noreturn)) void *uffd_monitor_thread(void *data)
{
    switch_uffd_handler_stack();
    int uffd = *(int *)data;

    // TODO: ignore PLT writes (probably just set the section address in the linker args)

    for (off_t i = 0; i < n_maps; i++) {
        procmaps_struct *cur_map = &maps[i];

        struct uffdio_writeprotect wp = {0};
        wp.range.start = (unsigned long)cur_map->addr_start;
        wp.range.len = (unsigned long)cur_map->addr_end - (unsigned long)cur_map->addr_start;
        wp.mode = UFFDIO_WRITEPROTECT_MODE_WP;
        if (ioctl(uffd, UFFDIO_WRITEPROTECT, &wp) == -1) {
            perror("ioctl(UFFDIO_WRITEPROTECT)");
            _exit(1);
        }
    }

    pthread_cond_signal(&uffd_ready);

    // TODO: replace _exits with UFFD unregister, prints, exit

    for (;;) {
        struct uffd_msg msg;

        struct pollfd pollfd[1];
        pollfd[0].fd = uffd;
        pollfd[0].events = POLLIN;
        int pollres;

        pollres = poll(pollfd, 1, -1);
        switch (pollres) {
            case -1:
                // perror("poll");
                continue;
                break;
            case 0: continue; break;
            case 1: break;
        }
        if (pollfd[0].revents & POLLERR) {
            // fprintf(stderr, "POLLERR on userfaultfd\n");
            _exit(2);
        }
        if (!(pollfd[0].revents & POLLIN)) {
            continue;
        }

        int readret;
        readret = read(uffd, &msg, sizeof(msg));
        if (readret == -1) {
            if (errno == EAGAIN)
                continue;
            //perror("read userfaultfd");
            _exit(3);
        }
        if (readret != sizeof(msg)) {
            //fprintf(stderr, "short read, not expected, exiting\n");
            _exit(4);
        }

        if (msg.arg.pagefault.flags & UFFD_PAGEFAULT_FLAG_WP) {
            // record contents
            uintptr_t page_addr = msg.arg.pagefault.address & ~(PAGE_SIZE - 1);
            pages[n_pages].addr = page_addr;
            memcpy(pages[n_pages].data, (void *)page_addr, PAGE_SIZE);
            n_pages++;

            // send write unlock
            struct uffdio_writeprotect wp;
            wp.range.start = page_addr;
            wp.range.len = PAGE_SIZE;
            wp.mode = 0;
            if (ioctl(uffd, UFFDIO_WRITEPROTECT, &wp) == -1) {
                //perror("ioctl(UFFDIO_WRITEPROTECT)");
                _exit(5);
            }
        }
    }
}

int uffd_setup()
{
    int uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);

    if (uffd < 0) {
        perror("userfaultfd");
        return 0;
    }

    // UFFD "handshake" with the kernel
    struct uffdio_api uffdio_api;
    uffdio_api.api = UFFD_API;
    uffdio_api.features = 0;

    if (ioctl(uffd, UFFDIO_API, &uffdio_api)) {
        perror("ioctl(UFFDIO_API)");
        return 0;
    }

    if (uffdio_api.api != UFFD_API) {
        fprintf(stderr, "UFFDIO_API error %Lu\n", uffdio_api.api);
        return 0;
    }

    if (!(uffdio_api.features & UFFD_FEATURE_PAGEFAULT_FLAG_WP)) {
        fprintf(stderr, "UFFD doesn't have WP capability (kernel too old?)\n");
        return 0;
    }

    for (off_t i = 0; i < n_maps; i++) {
        procmaps_struct *cur_map = &maps[i];

        // could check for is_w here, but might as well not in case something mprotects

        struct uffdio_register uffdio_register = {0};
        uffdio_register.range.start = (unsigned long)cur_map->addr_start;
        uffdio_register.range.len = (unsigned long)cur_map->addr_end - (unsigned long)cur_map->addr_start;
        uffdio_register.mode = UFFDIO_REGISTER_MODE_WP;

        if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1) {
            perror("ioctl(UFFDIO_REGISTER)");
            return 0;
        }
    }

    return uffd;
}

int uffd_deregister(int uffd)
{
    for (off_t i = 0; i < n_maps; i++) {
        procmaps_struct *cur_map = &maps[i];

        // could check for is_w here, but might as well not in case something mprotects

        struct uffdio_range range = {0};
        range.start = (unsigned long)cur_map->addr_start;
        range.len = (unsigned long)cur_map->addr_end - (unsigned long)cur_map->addr_start;

        if (ioctl(uffd, UFFDIO_UNREGISTER, &range) == -1) {
            perror("ioctl(UFFDIO_UNREGISTER)");
            return 1;
        }
    }

    return 0;
}

void restore_pages()
{
#ifdef DEBUG
    printf("See %lu pages:\n", n_pages);
    for (size_t i = 0; i < n_pages; i++) {
        printf("  %p\n", (void *)pages[i].addr);
    }
#endif

    for (size_t i = 0; i < n_pages; i++) {
        page_t *cur_page = &pages[i];
        memcpy((void *)cur_page->addr, cur_page->data, PAGE_SIZE);
    }
}

int run()
{
    if (load_maps()) {
        return 1;
    }

    remap();

    puts("Hello from the anonymous side");

    // Do basic UFFD setup here mainly just for error handling's sake
    int uffd = uffd_setup();
    if (!uffd) {
        return 1;
    }

    pthread_t uffd_thread;
    pthread_create(&uffd_thread, NULL, uffd_monitor_thread, &uffd);

    puts("Waiting for uffd_monitor_thread");

    // could also like msgsnd/msgrcv?
    pthread_mutex_lock(&uffd_ready_lock);
    pthread_cond_wait(&uffd_ready, &uffd_ready_lock);

    puts("Ok here we go");

    redirect_stdout();
    setaffinity(3);

    for (int i = 0; i < ITERS; i++) {
        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);

        swap_old_stack();
        target_main();
        swap_old_stack();

        restore_pages();

        clock_gettime(CLOCK_MONOTONIC, &end);
        times[i] = timespecDiff(&end, &start);
    }
    dup2(stdout_fd, STDOUT_FILENO);
    report_times();

    return 0;
}

int main(int argc, char **argv)
{
    save_old_stack();
    register int ret = run();
    restore_old_stack();

    return ret;
}
