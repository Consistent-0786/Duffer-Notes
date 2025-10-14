---
title: "Assembly Notes & System Call Info"
source: "Assembly Notes & System Call Info.html"
---

# Assembly Notes & System Call Info

## Assembly 3 Sections
- **.text section** → contains code
- **.data section** → contains initialized variable (known/set value)
- **.bss section** → contains uninitialized variable (comes from user input)

## System Call File Location (Linux-Debian)
```
/usr/include/x86_64-linux-gnu/asm/unistd_64.h
```

## To know input taken by a system call
```
man 2 write
```

## System Call Registers (x86-64 Linux)

| Register | Purpose             |
|----------|---------------------|
| rax      | System call         |
| rdi      | 1st argument        |
| rsi      | 2nd argument        |
| rdx      | 3rd argument        |
| r10      | 4th argument        |
| r8       | 5th argument        |
| r9       | 6th argument        |

## ✅ General-Purpose Registers (Non-Syscall)

| Register | Usage Category                         | Caller/Callee Saved | Description                                                                 |
|----------|-----------------------------------------|---------------------|-----------------------------------------------------------------------------|
| rbx      | Persistent across function calls        | Callee-saved        | General-purpose; must be preserved by called functions                     |
| rbp      | Stack frame management                  | Callee-saved        | Often used as a frame pointer for accessing local variables                |
| rsp      | Stack pointer                           | Special (not saved) | Always points to the top of the stack; used by push, pop, call, etc.       |
| rcx      | Temporary values / Loop counter / Shift | Caller-saved        | Commonly used in loops or shifts (e.g., `shl rcx`); not used for syscall args |
| r11      | Temporary scratch during syscall        | Caller-saved        | Overwritten by syscall; can be used for temporary values                   |
| r12      | Persistent across function calls        | Callee-saved        | General-purpose; must be saved/restored by called functions               |
| r13      | Persistent across function calls        | Callee-saved        | Same as above                                                               |
| r14      | Persistent across function calls        | Callee-saved        | Same as above                                                               |
| r15      | Persistent across function calls        | Callee-saved        | Same as above                                                               |
| r8–r11   | Temporary / Additional args in calls    | Caller-saved        | Used for 5th–8th arguments in function calls (System V ABI)               |

### ℹ️ Caller vs Callee Saved
- 🔹 **Callee-saved** → The function being called must save and restore the register if it uses it.  
- 🔹 **Caller-saved** → The calling function must assume the register will be overwritten.

### ✅ Grouped by Purpose

#### 🧱 Registers to store values that must persist across function calls
- rbx
- r12
- r13
- r14
- r15
- rbp (sometimes)

#### ⚙️ Registers for temporary values (can be overwritten)
- rcx
- r11
- r8, r9, r10 (in function calls — not in syscalls)

#### 📦 Stack handling
- `rsp` — stack pointer
- `rbp` — optional frame pointer

## Assembler & Linker Commands
```bash
# Assemble code to machine level
nasm -f elf64 file-name.asm -o file-name.o

# Link object file
ld file-name.o -o file-name
```

_Source: Assembly Notes & System Call Info.html._
