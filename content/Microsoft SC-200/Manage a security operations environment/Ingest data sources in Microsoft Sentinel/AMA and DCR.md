### AMA (Azure Monitor Agent) | DCR (Data Collection Rule)

## AMA (Azure Monitor Agent)

- **Azure Monitor Agent (AMA)** is a **single, modern agent** used to collect logs and metrics from operating systems (Windows, Linux) and send them to Azure services

- It runs on VMs and servers
- It collects OS logs (security events, syslog, performance data)
- It then sends data based on rules you define   

> In Simple , it is a **one agent for both security and monitoring**

## DCR (Data Collection Rule)

- A **Data Collection Rule (DCR)** defines **what data is collected, from where, and where to send**

- It controls that which **logs to collect** (security, performance, etc)
- From which **machines source**    
- To which **Log Analytics workspace** to send the data to

> **DCR = instructions for AMA**

## Explain with example 

- Suppose you have **VMs in two Azure subscriptions**    
- You have **two Log Analytics workspaces** :
	- One for **Microsoft Sentinel (security)**        
    - One for **Azure Monitor (just for observability)**
### How it works :

1. **Install AMA** on all VMs (only once)

2. **Create DCR #1 (Security logs)**
    - Collects **security event logs**
    - From **all 8 VMs**
    - Sends data to the **Sentinel workspace**
        
3. **Create DCR #2 (Observability logs)** ==as describe in pink in above photo==
        - Collects **performance / health logs**
        - From **only selected VMs**
        - Sends data to the **Azure Monitor workspace**
### Key Benefits (Very Simple) :

- One agent (AMA)
- Multiple rules (DCRs)
- Different logs → different destinations
- Security and observability handled separately but efficiently

> **In Simple :**  
> -  **`AMA :`** collects the data  
 >-  **`DCR :`** decides _what_ to collect and _where_ to send it
 
 ![[Pasted image 20260121184121.png]]

---

