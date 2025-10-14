---

title: "Radare2 Debugging Notes"

---



\# 🕵️ Radare2 (r2) Debugging Notes



\## 🔹 Launching \& Setup

\- `radare2` or `r2` → Launch radare2.  

\- `r2 -d <file-name>` → Debug binary file (`-d` means debug mode).  



\## 🔹 Binary Analysis

\- `aaa` → Analyze all (functions, code, references).  

\- `afl` → List functions of the binary.  



\## 🔹 Breakpoints \& Execution

\- `db main` or `db <address>` → Set breakpoint at function or address.  

\- `dc` → Continue execution (in debug mode).  



\## 🔹 Viewing Code

\- `pdf` → Print disassembled function code.  



---



\## 🔹 Visual Modes



\### 1. Visual Mode

\- `V` → Enter visual mode.  

\- `p` → Next page.  

\- `q` → Exit visual mode back to radare shell.  



\### 2. Visual Graph Mode

\- `VV` → Enter visual graph mode.  

\- Arrow keys → Navigate left/right, up/down.  

\- `R` → Change color scheme.  

\- `p` → Cycle different graph modes.  

\- `S` → Step to next line.  

\- `:` → Open radare command prompt.  

&nbsp; - Example: `ps@rbp-0x34` → View data stored in memory address.  

&nbsp; - Press \*\*Enter\*\* → Return to visual graph mode.  



---



\## 🔹 Debug Commands in Visual Graph Mode

\- `dc` → Continue execution.  

\- `ood` → Restart binary from beginning.  

\- `ood 12345678` → Restart with argument.  

\- `dc` → Continue again after restart.  

\- `dr` → Show register values.  

\- `drr` → Show extra info of register values.  



