#include "bench.h"

#include <stdio.h>     // perror
#include <stdlib.h>    // exit
#include <sys/types.h> // pid_t
#include <unistd.h>    // fork, execve
#include <sys/wait.h>  // wait

#include "params.h"    // TARGET, TARGET_ARGS

void run_one()
{
    pid_t pid = vfork();
    if (pid < 0) {
        perror("vfork");
        exit(1);
    }
    if (pid == 0) {
        // child
        execve(TARGET, TARGET_ARGS, NULL);
        perror("execve");
        _exit(1);
    } else {
        wait(NULL);
    }
}

BENCH_MAIN({
    run_one();
})
