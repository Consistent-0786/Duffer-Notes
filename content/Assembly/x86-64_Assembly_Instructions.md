---
title: "x86-64 Assembly Instructions"
source: "x86-64 Assembly Instructions.html"
---

# x86-64 Assembly Instructions

## 🔹 Data Movement
- `mov rax, rbx` → Copy value from `rbx` into `rax`
- `mov rax, [rbp-8]` → Load value from memory into `rax`
- `mov [rbp-8], rax` → Store value of `rax` into memory
- `lea rax, [rbp-16]` → Load effective address

## 🔹 Arithmetic / Logic
- `add rax, rbx` → Addition  
- `sub rax, rbx` → Subtraction  
- `imul rax, rbx` → Signed multiplication  
- `idiv rbx` → Signed division (result in `rax`, remainder in `rdx`)  
- `and rax, rbx`, `or rax, rbx`, `xor rax, rax`  
- `shl rax, 1`, `shr rax, 1`

## 🔹 Control Flow
- `jmp label` → Unconditional jump  
- `cmp rax, rbx` → Compare values  
- `je label`, `jne label` → Conditional jumps  
- `jg label`, `jl label` → Greater/Less jumps  
- `call func` → Call function  
- `ret` → Return from function

## 🔹 Stack Operations
- `push rax` → Save register on stack  
- `pop rax` → Restore register from stack  
- `enter 16, 0` → Setup stack frame  
- `leave` → Tear down stack frame  

## 🔹 Syscall Instructions
- `mov rax, 1` → Syscall number (`write`)  
- `mov rdi, 1` → File descriptor (stdout)  
- `mov rsi, msg` → Pointer to buffer  
- `mov rdx, len` → Buffer length  
- `syscall` → Invoke kernel  
