# Automation Using APIs in Microsoft Sentinel

- Automating Sentinel by **directly interacting with REST APIs**
- Used when :    
    - We want to create **custom automation**        
    - We don’t want to use **Playbooks / Logic Apps**

- Example :
	- This is a Example of Sentinel Rest API
	- Not limit to this , there are more

| **API**                          | **What it is used for**                        | **Example Actions**                                         |
| -------------------------------- | ---------------------------------------------- | ----------------------------------------------------------- |
| **Sentinel Management API**      | Manage Sentinel resources                      | Create / Get / Update **Incidents** and **Analytics Rules** |
| **Microsoft Graph Security API** | Access security data across Microsoft products | Get / Post **alert information**                            |
| **HTTP Data Collector API**      | Ingest custom data                             | Send logs into **Log Analytics Workspace (LAW)**            |
| **Log Analytics API**            | Query stored logs                              | Run queries on **stored log data**                          |
- ![[Pasted image 20260127093646.png]]

> **In Simple :**
>  - APIs = **third way to automate** (besides Automation Rules & Playbooks)
>  - APIs enable **fully custom automation**

---

