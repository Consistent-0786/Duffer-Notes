
A **Change Advisory Board (CAB)** in cybersecurity (vulnerability management) is a group that reviews and approves system changes to make sure security fixes are applied safely.

### Simple combined explanation:

- When a vulnerability is found, a fix (like a patch or script) is created.
    
- First, the fix is **tested in a safe environment** **(sandbox / staging)**, not in production
    
- Then, the **CAB reviews the change **:
    
    - Is it safe?
        
    - Will it break anything?
        
    - What’s the risk and rollback plan?
        
- If approved, the change is **applied to the real production system**, usually at a controlled time.
    

### In short:

👉 **Test → CAB approval → Safe deployment in production**

Think of CAB as a **safety checkpoint team** that ensures fixes don’t create new problems while solving vulnerabilities.

---
