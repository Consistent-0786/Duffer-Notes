## Azure Logic Apps in Sentinel Playbooks

- Cloud service used to **build automated workflows**
- Used by **Sentinel Playbooks**
- Can connect Sentinel with **Microsoft & third-party services**

# Azure Logic Apps Workflow
## Example 1: Sentinel → ServiceNow (ITSM Ticket Creation)

**What happens :**

1. **Sentinel incident occurs**    
2. **Playbook is triggered**    
3. Playbook calls an **Azure Logic App**    
4. Logic App :    
    - Uses **ServiceNow connector**        
    - Creates a **ServiceNow ticket**        
    - Includes **incident details from Sentinel**

**Why this is useful :**
- Many SOCs use **ServiceNow** for incident tracking    
- Enables **collaboration outside Sentinel**    
- No coding needed → **pre-built connector**

## Example 2: User → Sentinel (Incident Creation)

**What happens :**

1. User fills out a **Microsoft Form**    
2. Form triggers an **Azure Logic App**    
3. Logic App :    
    - Converts form data to **JSON**        
    - Sends data via **API**        
    - Creates an **incident in Sentinel**

**Why this is useful :**
- Lets **non-technical users** report incidents    
- No need for :    
    - SOC mailbox        
    - Manual ticket creation        
- Users interact **directly with the SOC**
- ![[Pasted image 20260127091641.png]]

## Logic App Connectors (Important Concept)

- Logic Apps have **hundreds of pre-built connectors**    
- Examples :    
    - **ServiceNow**        
    - **Microsoft Forms**        
    - **AWS (S3)**        
    - **VirusTotal**
	- Connectors provide **ready-made actions**, for eg =  **_Create ticket_, _Get file_, _Send data_**

> **In Simple :**
	- **Playbooks trigger Azure Logic Apps**
	- Logic Apps enable **cross-platform automation**
	- Pre-built connectors = **no custom code**
	- Users can create Sentinel incidents via **external services**
	- Logic Apps support **APIs & JSON**

---


