#include "bench.h"

#include <stdio.h>     // perror
#include <stdlib.h>    // exit
#include <sys/types.h> // pid_t
#include <unistd.h>    // fork, execve
#include <sys/wait.h>  // wait

#include "target.h"

void run_one()
{
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        exit(1);
    }
    if (pid == 0) {
        // child
        target_main();
        _exit(1);
    } else {
        wait(NULL);
    }
}

BENCH_MAIN({
    run_one();
})
