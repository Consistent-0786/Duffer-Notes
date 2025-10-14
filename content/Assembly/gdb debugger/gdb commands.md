---

title: "GDB Debugging Notes"

---



\# 🐞 GDB Debugging Notes



\## 🔹 Basic Commands

\- `info functions` → Show all function names in the binary.  

\- `disassemble main` (or `disassemble <function-name>`) → Show disassembly of a function.  



\## 🔹 Disassembly \& Code View

\- `set disassembly-flavor intel` → Switch to Intel syntax (`intel`, `att`).  

\- `disassemble main` → Convert machine code to assembly instructions.  

\- `run` → Start the program execution.  



\## 🔹 Breakpoints

\- `break \*<value>` → Set a breakpoint at a specific memory address.  



\## 🔹 Registers

\- `info registers` → Display current values of CPU registers.  



\## 🔹 Printing / Values

\- `print <value>` → Print a value (e.g., convert hex to decimal).  



\## 🔹 Stepping

\- `nexti` or `ni` → Execute next instruction.  

\- `si` → Step into instruction.  



\## 🔹 Examining Memory

\- `info files` → Show info about loaded files.  

\- `start` → Automatically starts at `\_start` function in `.text`.  

\- `x` → Examine memory.  

\- `x/30i <address-name>` or `x/30i $rip` → Show 30 instructions from an address or current instruction pointer.  



\### Format specifiers for `x`:

\- `a` → address  

\- `s` → string  

\- `h` → hex  



---



\## ⚡ Important Instructions for Code Logic

\- `call` → Function call  

\- `jmp` → Jump to another instruction  

\- `cmp` → Compare two values (used before conditional jumps)  



