; PSEUDO — syscall_stub.asm
; Indirect syscall stub.
; The syscall instruction executes inside ntdll address space.

section .text

; indirect_syscall_stub:
;   rax = syscall number
;   rdi = address of syscall instruction in ntdll
;   rcx, rdx, r8, r9 = params
global indirect_syscall_stub
indirect_syscall_stub:
    mov r10, rcx
    jmp rdi                 ; jump to ntdll's syscall instruction
