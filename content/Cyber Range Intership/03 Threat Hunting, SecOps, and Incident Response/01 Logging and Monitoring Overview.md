# Azure Logging at Different Layers (Tenant, Activity, Resource) 

![[Pasted image 20260407134530.png|449]]


1. **AAD Logs (Azure Active Directory logs) :**
	-  These logs capture **identity-related events** in Azure AD, including authentication and directory changes
	- They help you monitor **who is accessing the system and what changes are made to identities**  
	- It **Captures Logs about :** 
		- Azure Tenant
	
	- **Example :** 
		- A user successfully signs in, a failed login attempt occurs, or an admin updates a user’s role
	
2. **Activity Log :**
	- This is a **subscription-level log** that records **management plane operations** performed on Azure resources
	- It tells you **what operation was executed, by whom, and when**
	- It **Captures Logs about :** 
		- Azure Subscription
	
	- **Example :** 
		- Creating a virtual machine, deleting a resource group, or modifying a storage account configuration
	
3. **Resource Logs :**
	- These logs provide **data plane insights**, meaning they capture **operations happening within a specific resource** 
	- They are more granular (extreme level of details) and service-specific  
    - It **Captures Logs about :** 
		- Azure Resources
	
    - **Example :** 
	    - Reading data from a **database, accessing a secret in Key Vault, or an API request** hitting an application

# Azure Monitoring and Security Architecture (Log Analytics & Sentinel)

![[Pasted image 20260407135755.png|636]]

# Data ingestion flow to Microsoft Sentinel

- This diagram illustrates the ==**flow of security and audit logs== from various Microsoft services into a centralized analysis and management platform**
	- **Data Sources :** 
		- Logs originate from Microsoft Defender for Endpoint (MDE), Microsoft Entra ID, and Azure Data & Management Plane
	- **Centralization :** 
		- These logs are collected and stored within Log Analytics
	- **Analysis :** 
		- The data in Log Analytics is analyzed and utilized by Microsoft Sentinel for security insights

![[Pasted image 20260407140452.png|662]]