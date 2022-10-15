// https://github.com/torvalds/linux/blob/19d17ab7c68b62180e0537f92400a6f798019775/tools/include/nolibc/arch-aarch64.h
#define my_syscall0(num)                                                      \
({                                                                            \
        register long _num  __asm__ ("x8") = (num);                           \
        register long _arg1 __asm__ ("x0");                                   \
                                                                              \
        __asm__  volatile (                                                   \
                "svc #0\n"                                                    \
                : "=r"(_arg1)                                                 \
                : "r"(_num)                                                   \
                : "memory", "cc"                                              \
        );                                                                    \
        _arg1;                                                                \
})

#define my_syscall1(num, arg1)                                                \
({                                                                            \
        register long _num  __asm__ ("x8") = (num);                           \
        register long _arg1 __asm__ ("x0") = (long)(arg1);                    \
                                                                              \
        __asm__  volatile (                                                   \
                "svc #0\n"                                                    \
                : "=r"(_arg1)                                                 \
                : "r"(_arg1),                                                 \
                  "r"(_num)                                                   \
                : "memory", "cc"                                              \
        );                                                                    \
        _arg1;                                                                \
})

#define my_syscall2(num, arg1, arg2)                                          \
({                                                                            \
        register long _num  __asm__ ("x8") = (num);                           \
        register long _arg1 __asm__ ("x0") = (long)(arg1);                    \
        register long _arg2 __asm__ ("x1") = (long)(arg2);                    \
                                                                              \
        __asm__  volatile (                                                   \
                "svc #0\n"                                                    \
                : "=r"(_arg1)                                                 \
                : "r"(_arg1), "r"(_arg2),                                     \
                  "r"(_num)                                                   \
                : "memory", "cc"                                              \
        );                                                                    \
        _arg1;                                                                \
})

#define my_syscall3(num, arg1, arg2, arg3)                                    \
({                                                                            \
        register long _num  __asm__ ("x8") = (num);                           \
        register long _arg1 __asm__ ("x0") = (long)(arg1);                    \
        register long _arg2 __asm__ ("x1") = (long)(arg2);                    \
        register long _arg3 __asm__ ("x2") = (long)(arg3);                    \
                                                                              \
        __asm__  volatile (                                                   \
                "svc #0\n"                                                    \
                : "=r"(_arg1)                                                 \
                : "r"(_arg1), "r"(_arg2), "r"(_arg3),                         \
                  "r"(_num)                                                   \
                : "memory", "cc"                                              \
        );                                                                    \
        _arg1;                                                                \
})

#define my_syscall4(num, arg1, arg2, arg3, arg4)                              \
({                                                                            \
        register long _num  __asm__ ("x8") = (num);                           \
        register long _arg1 __asm__ ("x0") = (long)(arg1);                    \
        register long _arg2 __asm__ ("x1") = (long)(arg2);                    \
        register long _arg3 __asm__ ("x2") = (long)(arg3);                    \
        register long _arg4 __asm__ ("x3") = (long)(arg4);                    \
                                                                              \
        __asm__  volatile (                                                   \
                "svc #0\n"                                                    \
                : "=r"(_arg1)                                                 \
                : "r"(_arg1), "r"(_arg2), "r"(_arg3), "r"(_arg4),             \
                  "r"(_num)                                                   \
                : "memory", "cc"                                              \
        );                                                                    \
        _arg1;                                                                \
})

#define my_syscall5(num, arg1, arg2, arg3, arg4, arg5)                        \
({                                                                            \
        register long _num  __asm__ ("x8") = (num);                           \
        register long _arg1 __asm__ ("x0") = (long)(arg1);                    \
        register long _arg2 __asm__ ("x1") = (long)(arg2);                    \
        register long _arg3 __asm__ ("x2") = (long)(arg3);                    \
        register long _arg4 __asm__ ("x3") = (long)(arg4);                    \
        register long _arg5 __asm__ ("x4") = (long)(arg5);                    \
                                                                              \
        __asm__  volatile (                                                   \
                "svc #0\n"                                                    \
                : "=r" (_arg1)                                                \
                : "r"(_arg1), "r"(_arg2), "r"(_arg3), "r"(_arg4), "r"(_arg5), \
                  "r"(_num)                                                   \
                : "memory", "cc"                                              \
        );                                                                    \
        _arg1;                                                                \
})

#define my_syscall6(num, arg1, arg2, arg3, arg4, arg5, arg6)                  \
({                                                                            \
        register long _num  __asm__ ("x8") = (num);                           \
        register long _arg1 __asm__ ("x0") = (long)(arg1);                    \
        register long _arg2 __asm__ ("x1") = (long)(arg2);                    \
        register long _arg3 __asm__ ("x2") = (long)(arg3);                    \
        register long _arg4 __asm__ ("x3") = (long)(arg4);                    \
        register long _arg5 __asm__ ("x4") = (long)(arg5);                    \
        register long _arg6 __asm__ ("x5") = (long)(arg6);                    \
                                                                              \
        __asm__  volatile (                                                   \
                "svc #0\n"                                                    \
                : "=r" (_arg1)                                                \
                : "r"(_arg1), "r"(_arg2), "r"(_arg3), "r"(_arg4), "r"(_arg5), \
                  "r"(_arg6), "r"(_num)                                       \
                : "memory", "cc"                                              \
        );                                                                    \
        _arg1;                                                                \
})

