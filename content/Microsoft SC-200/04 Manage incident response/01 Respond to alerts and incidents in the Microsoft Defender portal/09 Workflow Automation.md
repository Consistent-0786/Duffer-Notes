# Workflow Automation in Defender for Cloud

- Workflow Automation allows you to use **Azure Logic Apps** to automate actions in Defender for Cloud
- It works with **security alerts and CSPM recommendations**, not only with workload protection alerts
- It is similar to automation used in Microsoft Sentinel

## What can trigger automation ?

- A **new security recommendation** from Defender for Cloud
- Recommendations can come from :     
    - Foundational CSPM        
    - Defender CSPM        
    - Paid Defender plans

## How does it work ?

- Defender for Cloud creates a new recommendation    
- An **API request** is triggered    
- The API request starts an **Azure Logic App**    
- The Logic App processes the data using a workflow    
- The workflow performs defined actions

- ![[Pasted image 20260124221855.png]]

> Logic Apps are **no code workflows** where you define conditions and actions visually

 - **In Simple :**
	- Defender for Cloud can trigger automations
    - Logic Apps handle the workflow without writing code
    - Security recommendations can automatically create tickets or actions in other systems

---
