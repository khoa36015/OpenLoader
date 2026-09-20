; PSEUDO — loader_stub.asm
; Minimal position-independent shellcode stub.
; Assemble with: nasm -f elf64 loader_stub.asm

section .text

; exec_shellcode: jumps to shellcode at rdi
global exec_shellcode_stub
exec_shellcode_stub:
    jmp rdi

; inject_stub: jumps to address overwritten at runtime
global inject_stub
inject_stub:
    mov rax, 0x4141414141414141   ; placeholder
    jmp rax
