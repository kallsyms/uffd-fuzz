section .text
global _start

_start:
; _exit(0)
mov rdi, 0
mov rax, 231
syscall
