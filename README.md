**WARNING: Super proof of concept code. Good luck reading it!**

# Basic outline
* `01_fork`: basic fork server for benchmarking against
* `02_vfork`: basic vfork server for benchmarking against
* `03_fork_server`: "persistent mode" fork server for benchmarking against
* `04_memcpy_restore`: the `userfaultfd`-based restore implementation
* `bench.h`: benchmarking utilities
* `Makefile`: idk
* `params.h`: benchmarking parameters (target program, number of iterations, etc.)
* `pmparser`: `/proc/pid/maps` parser from ([https://github.com/ouadev/proc_maps_parser](https://github.com/ouadev/proc_maps_parser)]
* `syscalls_*.h`: syscall wrappers to avoid hitting libc
* `target`: a sample target program which prints out the address from a `malloc`. if memory is restored correctly, this will return the same address everytime
* `uffdio_wp.h`: definitions for the userfaultfd write protect mode which may not be present on all machines even if your kernel supports it

# Misc notes
* Most of the "don't use libc" hackery isn't actually needed as-is since things are built statically - it's just there since I was planning on doing normal dynamically linked builds earlier and calling libc funcs could modify the [PLT](https://maskray.me/blog/2021-09-19-all-about-procedure-linkage-table).
