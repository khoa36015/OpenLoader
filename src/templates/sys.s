.intel_syntax noprefix
.text
.global do_syscall
do_syscall:
    push rbp
    mov rbp, rsp
    sub rsp, 0x28
    mov eax, ecx
    mov r11, rdx
    mov rcx, r8

    cmp r9, 0
    je _exe
    mov r10, [rcx]
    cmp r9, 1
    je _exe
    mov rdx, [rcx+8]
    cmp r9, 2
    je _exe
    mov r8, [rcx+16]
    cmp r9, 3
    je _exe
    push r14
    mov r14, r9
    mov r9, [rcx+24]
    cmp r14, 4
    jl _exe2
    push [rcx+32]
    cmp r14, 5
    jl _exe2
    push [rcx+40]
_exe2:
    pop r14
_exe:
    test r11, r11
    jz _er
    mov rsp, rbp
    pop rbp
    jmp r11
_er:
    mov rax, 0xC0000001
    mov rsp, rbp
    pop rbp
    ret
