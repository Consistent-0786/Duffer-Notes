# Defender for Servers : Agents

- Defender for Servers agents are **components installed on virtual machines** that collect **telemetry, security signals, and configuration data and send them to Microsoft Defender for Cloud via Log Analytics**
	- **Log Analytics**    
	    - Central ingestion point for all agent data
        - Acts as the backbone for Defender for Cloud

- It protects : 
	- Operating system telemetry
	- Security events and alerts
	- Malware and suspicious behavior
	- OS configuration and compliance state
	- Azure, multicloud, and on-premises servers

## Types of Agents

1. **Azure Monitor Agent (AMA) :**
    - Collects performance and system telemetry        
    - Not security-specific but required for visibility
        
2. **Microsoft Defender for Endpoint agent :**    
    - Provides EDR and antivirus         
    - Detects and responds to threats        
    - Generates security alerts
    
3. **Guest Configuration agent :**
    - Assesses OS configuration baselines         
    - Enables security and compliance recommendations
       
4. **Azure Arc agent :**    
    - Onboards non-Azure machines into Azure        
    - Enables Defender for Servers on on-prem and multi-cloud VMs        
    - Deploys Azure Monitor Agent outside Azure

- **Example :**
	- Normal behavior :
		- Agents collect logs and configuration data and send it to Log Analytics
	    
	- Suspicious behavior :
		- Defender for Endpoint detects malware on a VM and sends an alert through Log Analytics to Defender for Cloud 

> **In Simple :**
> 	- Defender for Servers uses **multiple agents** to collect data from VMs, send it to **Log Analytics**, and power **Defender for Cloud** insights 
> 	- Exact agents depend on where the VM runs and which Defender plans are enabled

![[Pasted image 20260125080706.png]]

---

