#define _GNU_SOURCE    // for sched_setaffinity

#include <stdio.h>     // perror
#include <unistd.h>    // fork, execve, dup, dup2
#include <sys/stat.h>  // open
#include <fcntl.h>     // O_WRONLY
#include <stdint.h>    // uint64_t
#include <time.h>      // clock_gettime, timespec
#include <sched.h>     // cpu_set_t, CPU_*, sched_setaffinity
#include <stdlib.h>    // exit, qsort

#include "params.h"

uint64_t timespecDiff(struct timespec *timeA_p, struct timespec *timeB_p)
{
    return ((timeA_p->tv_sec * 1000000000) + timeA_p->tv_nsec) -
           ((timeB_p->tv_sec * 1000000000) + timeB_p->tv_nsec);
}

static int qcmp(const void *a, const void *b) {
    return *(const uint64_t *)a - *(const uint64_t *)b;
}

int stdout_fd;

void redirect_stdout()
{
    // redirect stdout to /dev/null while testing
    int dev_null_fd = open("/dev/null", O_WRONLY);
    stdout_fd = dup(STDOUT_FILENO);
    dup2(dev_null_fd, STDOUT_FILENO);
}

void setaffinity(int core)
{
    // lock ourselves to a core
    cpu_set_t cpus;
    CPU_ZERO(&cpus);
    CPU_SET(core, &cpus);
    if (sched_setaffinity(0, sizeof(cpu_set_t), &cpus) < 0) {
        perror("sched_setaffinity");
        exit(1);
    }
}

__attribute__((section(".writeignored"))) uint64_t times[ITERS];

void report_times()
{
    // report
    qsort(times, ITERS, sizeof(uint64_t), qcmp);

    printf("Min: %luns\n", times[0]);
    printf("Median: %luns\n", times[ITERS/2]);
    printf("Max: %luns\n", times[ITERS - 1]);
}

#define BENCH_MAIN_INIT(init, run_one) \
    int main(int argc, char **argv) { \
        init \
        redirect_stdout(); \
        setaffinity(3); \
        for (int i = 0; i < ITERS; i++) { \
            struct timespec start, end; \
            clock_gettime(CLOCK_MONOTONIC, &start); \
            run_one \
            clock_gettime(CLOCK_MONOTONIC, &end); \
            times[i] = timespecDiff(&end, &start); \
        } \
        dup2(stdout_fd, STDOUT_FILENO); \
        report_times(); \
    }

#define BENCH_MAIN(run_one) BENCH_MAIN_INIT({}, run_one)
