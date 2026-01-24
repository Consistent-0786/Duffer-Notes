# Defender for Resource Manager

- Microsoft Defender for Resource Manager is a Defender for Cloud plan that provides **threat detection for Azure Resource Manager operations**    
- Its main purpose is to **detect suspicious resource management activity**, not configuration hardening or vulnerability scanning
- Azure Resource Manager is the control layer for all Azure resources, if actions look risky or match known attack patterns it raises alerts
## What does it monitor ?

- **All requests sent to Azure Resource Manager**, including those coming from    
    - Azure Portal        
    - PowerShell        
    - Azure CLI        
    - REST API        
- These requests are evaluated alongside    
    - Authentication        
    - Azure Policy Engine        

## What does it detect ?

- Suspicious resource management operations    
- Use of exploitation toolkits like **PowerZure** ==(it's like a Metasploit for Azure exploitation)==    
- Lateral movement from the **Azure management layer to the data plane**    
- Requests coming from **suspicious IP addresses** based on Microsoft threat intelligence    
- Suspicious management sessions such as :   
    - Privilege elevation        
    - Unusual role assignments        

- **Example of Alerts :**

✅ Creating a virtual machine from a trusted location → normal behavior

🚨 Creating a virtual machine from a suspicious IP address → alert raised

🚨 Use of Azure exploitation or penetration testing toolkits

🚨 Suspicious elevation of permissions

🚨 Unusual role assignment operations

> Even if the operation itself is valid it can still trigger an alert if the **context is suspicious**

![[Pasted image 20260124195038.png]]

---
