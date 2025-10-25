# Public, Private, Hybrid & Multi Cloud

| Cloud Type    | Description                                                  | Examples                                                                 |
| ------------- | ------------------------------------------------------------ | ------------------------------------------------------------------------ |
| Public Cloud  | Services shared with multiple users over the internet        | AWS, Azure, GCP                                                          |
| Private Cloud | Used exclusively by one organization, on-site or hosted      | Azure Stack, AWS Outpost, Google Anthos, VMware Private Cloud, OpenStack |
| Hybrid Cloud  | Combination of public and private clouds; data/apps can move |                                                                          |
| Multi-Cloud   | Using multiple cloud providers for different needs           | AWS + GCP (Google Cloud) + Azure                                         |

---

# Azure Resource Hierarchy

1. **Management Groups**
    - The highest level, used to organize multiple subscriptions for unified policy and access management.
2. **Subscriptions**
    - Linked under management groups; each subscription holds resources and has its own billing and access controls.  
3. **Resource Groups**
    - Containers within subscriptions that group related resources for easier management.    
4. **Resources**
    - The actual services and components like virtual machines, databases, web apps, etc., that run your applications.

- **Management Groups** > **Subscriptions** > **Resource Groups** > **Resources**

This hierarchy helps organize, manage access, and apply policies efficiently across Azure environments

![[Pasted image 20251025234734.png]]

---
# Entra ID / Tenants

1. **Entra ID**
	- Formerly known as Azure Active Directory Tenant 
	- It represents the organization’s identity and access management control in the cloud
2. **Tenants** 
	- Tenant is like a Default / main directory
	- Each tenant has its own users, groups, applications, and policies
	- Tenants are **isolated** from each other, so data and identities are separate and secure

- ***In Simple***
	- In Entra ID Tenant, we have our identities like user , admin , etc and those identities actually access the **Azure resources** that reside in our subscriptions and resource
